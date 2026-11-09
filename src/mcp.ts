import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { AccessBroker, loadAccessPolicy } from './access';
import {
    createPlaywrightDriver,
    createPuppeteerDriver,
    createSecureBrowserTools,
    SecureBrowser,
    type AgentTool,
    type BrowserDriver,
} from './browser';
import { getDefaultVaultPath, SecretVault } from './vault';

/**
 * Zero-dependency MCP server (stdio, JSON-RPC 2.0, newline-delimited) that
 * exposes the secure browser + account tools to MCP clients such as Claude
 * Code, Claude Desktop, Cursor or VS Code.
 *
 * The vault passphrase never passes through the model or MCP traffic: it is
 * read from PROMPT_GUARD_PASSPHRASE_CMD (a command that prints it, e.g. a
 * password-manager CLI) or asked for in a native OS password dialog the
 * first time a tool needs the vault.
 */

export interface McpServerOptions {
    policyPath?: string;
    vaultPath?: string;
    browser?: 'playwright' | 'puppeteer';
    headless?: boolean;
    /** Persistent browser profile directory (keeps cookies between sessions). */
    profileDir?: string;
}

export function getDefaultPolicyPath(): string {
    return join(dirname(getDefaultVaultPath()), 'access-policy.json');
}

export function getDefaultProfileDir(): string {
    return join(dirname(getDefaultVaultPath()), 'browser-profile');
}

const SERVER_INFO = { name: 'prompt-guard', version: readVersion() };
const DEFAULT_PROTOCOL = '2025-06-18';

function readVersion(): string {
    try {
        return JSON.parse(readFileSync(join(__dirname, '..', 'package.json'), 'utf8')).version as string;
    } catch {
        return '0.0.0';
    }
}

/** Asks for a secret via a native OS dialog (stdin/stdout are the MCP channel). */
function askNative(title: string, message: string, hidden: boolean): string {
    const command = process.env.PROMPT_GUARD_PASSPHRASE_CMD;
    if (hidden && command) {
        return execFileSync(command, { shell: true, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).replace(
            /\r?\n$/,
            '',
        );
    }
    const opts = { encoding: 'utf8' as const, stdio: ['ignore', 'pipe', 'ignore'] as ['ignore', 'pipe', 'ignore'] };
    try {
        if (process.platform === 'win32') {
            const ps = hidden
                ? `$c = Get-Credential -UserName 'prompt-guard' -Message '${message}'; if ($c) { $c.GetNetworkCredential().Password }`
                : `Add-Type -AssemblyName Microsoft.VisualBasic; [Microsoft.VisualBasic.Interaction]::InputBox('${message}', '${title}')`;
            return execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps], opts).trim();
        }
        if (process.platform === 'darwin') {
            const script = `text returned of (display dialog "${message}" with title "${title}" default answer ""${hidden ? ' with hidden answer' : ''})`;
            return execFileSync('osascript', ['-e', script], opts).replace(/\n$/, '');
        }
        return execFileSync('zenity', hidden ? ['--password', `--title=${title}`] : ['--entry', `--title=${title}`, `--text=${message}`], opts).replace(/\n$/, '');
    } catch {
        throw new Error(
            'Could not show a passphrase dialog. Set PROMPT_GUARD_PASSPHRASE_CMD to a command that prints the vault passphrase (for example a password-manager CLI).',
        );
    }
}

async function loadModule(name: string): Promise<any> {
    try {
        return await import(name);
    } catch {
        throw new Error(`"${name}" is not installed. Run: npm i -g ${name} (then: npx ${name} install chromium for Playwright).`);
    }
}

class McpSession {
    private vault?: SecretVault;
    private broker?: AccessBroker;
    private secureBrowser?: SecureBrowser;
    private tools?: AgentTool[];
    private closeBrowser?: () => Promise<void>;

    constructor(private readonly options: McpServerOptions) {}

    /** Tool definitions for tools/list (no vault or browser needed). */
    static toolDefinitions(): Array<Pick<AgentTool, 'name' | 'description' | 'inputSchema'>> {
        const stub = {} as never;
        return createSecureBrowserTools(stub, { vault: stub, broker: stub }).map(({ name, description, inputSchema }) => ({
            name,
            description,
            inputSchema,
        }));
    }

    private async ready(): Promise<AgentTool[]> {
        if (this.tools) return this.tools;
        const policyPath = resolve(this.options.policyPath ?? getDefaultPolicyPath());
        if (!existsSync(policyPath)) {
            throw new Error(`No access policy at ${policyPath}. Run "prompt-guard mcp setup" first.`);
        }
        const policy = loadAccessPolicy(policyPath);
        const vaultPath = this.options.vaultPath ?? getDefaultVaultPath();
        if (!existsSync(vaultPath)) {
            throw new Error('No vault exists yet. Store secrets with "prompt-guard vault set <id>" first.');
        }
        let passphrase = askNative('Prompt Guard', 'Unlock the Prompt Guard vault for this agent session', true);
        if (!passphrase) throw new Error('Vault unlock was cancelled.');
        const vault = await SecretVault.open({ passphrase, path: vaultPath });
        passphrase = '';
        if (vault.requireTwoFactor()) {
            await vault.verifyTwoFactor(askNative('Prompt Guard', 'Enter your vault 2FA code', false));
        }
        this.vault = vault;
        this.broker = new AccessBroker(vault, policy, {
            auditLogPath: join(dirname(vaultPath), 'access-audit.jsonl'),
        });
        this.secureBrowser = new SecureBrowser(this.lazyDriver(), this.broker);
        this.tools = createSecureBrowserTools(this.secureBrowser, { vault, broker: this.broker });
        return this.tools;
    }

    /** Launches the browser on first use, so API-only sessions never open one. */
    private lazyDriver(): BrowserDriver {
        let driver: Promise<BrowserDriver> | undefined;
        const get = (): Promise<BrowserDriver> => (driver ??= this.launch());
        const methods: Array<keyof BrowserDriver> = [
            'listTabs', 'newTab', 'activateTab', 'closeTab', 'navigate', 'currentUrl', 'click', 'fill', 'readText',
        ];
        return Object.fromEntries(
            methods.map((m) => [m, async (...args: unknown[]) => ((await get())[m] as (...a: unknown[]) => unknown)(...args)]),
        ) as unknown as BrowserDriver;
    }

    private async launch(): Promise<BrowserDriver> {
        const headless = this.options.headless ?? false;
        const profileDir = this.options.profileDir ?? getDefaultProfileDir();
        mkdirSync(profileDir, { recursive: true, mode: 0o700 });
        if (this.options.browser === 'puppeteer') {
            const puppeteer = await loadModule('puppeteer');
            const browser = await (puppeteer.default ?? puppeteer).launch({ headless, userDataDir: profileDir });
            this.closeBrowser = () => browser.close();
            return createPuppeteerDriver(browser);
        }
        const { chromium } = await loadModule('playwright');
        const context = await chromium.launchPersistentContext(profileDir, { headless });
        this.closeBrowser = () => context.close();
        return createPlaywrightDriver(context);
    }

    async call(name: string, args: Record<string, unknown>): Promise<{ result: unknown; isError: boolean }> {
        const tools = await this.ready();
        const tool = tools.find((t) => t.name === name);
        if (!tool) return { result: { error: `Unknown tool "${name}".` }, isError: true };
        const result = await tool.execute(args);
        const isError = typeof result === 'object' && result !== null && 'error' in result;
        return { result, isError };
    }

    async close(): Promise<void> {
        await this.closeBrowser?.().catch(() => undefined);
        this.vault?.close();
    }
}

/** Runs the MCP server on stdin/stdout until stdin closes. */
export async function runMcpServer(options: McpServerOptions = {}): Promise<void> {
    const session = new McpSession(options);
    const send = (message: unknown) => process.stdout.write(`${JSON.stringify(message)}\n`);
    const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
    // Keep stray library logging off the protocol channel.
    console.log = (...args: unknown[]) => console.error(...args);

    const pending: Promise<unknown>[] = [];
    for await (const line of lines) {
        if (!line.trim()) continue;
        let msg: { id?: string | number; method?: string; params?: Record<string, unknown> };
        try {
            msg = JSON.parse(line);
        } catch {
            send({ jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } });
            continue;
        }
        const { id, method, params = {} } = msg;
        if (id === undefined) continue; // notifications (initialized, cancelled, ...)
        const reply = (result: unknown) => send({ jsonrpc: '2.0', id, result });
        const fail = (code: number, message: string) => send({ jsonrpc: '2.0', id, error: { code, message } });

        if (method === 'initialize') {
            reply({
                protocolVersion: typeof params.protocolVersion === 'string' ? params.protocolVersion : DEFAULT_PROTOCOL,
                capabilities: { tools: {} },
                serverInfo: SERVER_INFO,
                instructions:
                    'Browser and account tools guarded by Prompt Guard. Use prompt_guard_vault_catalog to find secret IDs and pass only IDs (never values) to browser_fill_secret, browser_fill_totp and api_request. Only origins granted in the user\'s access policy work.',
            });
        } else if (method === 'ping') {
            reply({});
        } else if (method === 'tools/list') {
            reply({ tools: McpSession.toolDefinitions() });
        } else if (method === 'tools/call') {
            const name = String(params.name ?? '');
            const args = (params.arguments ?? {}) as Record<string, unknown>;
            pending.push(
                session
                    .call(name, args)
                    .then(({ result, isError }) =>
                        reply({ content: [{ type: 'text', text: JSON.stringify(result ?? { ok: true }) }], isError }),
                    )
                    .catch((error: unknown) =>
                        reply({
                            content: [{ type: 'text', text: error instanceof Error ? error.message : 'Tool failed.' }],
                            isError: true,
                        }),
                    ),
            );
        } else {
            fail(-32601, `Method not found: ${method}`);
        }
    }
    await Promise.allSettled(pending);
    await session.close();
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

export const STARTER_POLICY = {
    allowedOrigins: ['https://github.com', 'https://*.github.com'],
    grants: [
        { secretId: 'github-password', origins: ['https://github.com'], actions: ['fill'] },
        { secretId: 'github-totp', origins: ['https://github.com'], actions: ['totp'] },
    ],
};

export interface SetupResult {
    policyPath: string;
    policyCreated: boolean;
    mcpJsonPath?: string;
    claudeCommand: string;
}

/**
 * Creates a starter access policy (if missing) and registers the server:
 * scope "project" merges into ./.mcp.json; "user" prints/returns the
 * `claude mcp add` command.
 */
export function setupMcp(options: { scope?: 'project' | 'user'; policyPath?: string; cwd?: string } = {}): SetupResult {
    const policyPath = resolve(options.policyPath ?? getDefaultPolicyPath());
    let policyCreated = false;
    if (!existsSync(policyPath)) {
        mkdirSync(dirname(policyPath), { recursive: true, mode: 0o700 });
        writeFileSync(policyPath, `${JSON.stringify(STARTER_POLICY, null, 2)}\n`, { mode: 0o600 });
        policyCreated = true;
    }
    const serverArgs = ['-y', '@ai-clyde/promptguard', 'mcp'];
    if (options.policyPath) serverArgs.push(`--policy=${policyPath}`);
    const claudeCommand = `claude mcp add prompt-guard --scope user -- npx ${serverArgs.join(' ')}`;
    const result: SetupResult = { policyPath, policyCreated, claudeCommand };

    if ((options.scope ?? 'project') === 'project') {
        const mcpJsonPath = join(options.cwd ?? process.cwd(), '.mcp.json');
        let config: { mcpServers?: Record<string, unknown> } = {};
        if (existsSync(mcpJsonPath)) {
            config = JSON.parse(readFileSync(mcpJsonPath, 'utf8'));
        }
        config.mcpServers = { ...(config.mcpServers ?? {}), 'prompt-guard': { command: 'npx', args: serverArgs } };
        writeFileSync(mcpJsonPath, `${JSON.stringify(config, null, 2)}\n`);
        result.mcpJsonPath = mcpJsonPath;
    }
    return result;
}

/** Home-relative display path. */
export function displayPath(p: string): string {
    const home = homedir();
    return p.startsWith(home) ? `~${p.slice(home.length)}` : p;
}

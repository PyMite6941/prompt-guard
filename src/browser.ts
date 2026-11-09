import { AccessBroker, originOf, type AuthorizedFetchOptions } from './access';
import { createVaultCatalogTool, type SecretVault } from './vault';

/**
 * Secure browser / tab control for agent harnesses.
 *
 * Prompt Guard does not drive a browser itself. The harness supplies a
 * BrowserDriver (Playwright, Puppeteer, a CDP client, a browser extension
 * bridge...) and SecureBrowser wraps it so that:
 *   - navigation is checked against the access policy (origin allow-list,
 *     no http, no credentials or vault placeholders in URLs);
 *   - secrets are filled only by ID, only on granted origins, and the
 *     origin is re-read from the tab at fill time;
 *   - the model cannot type raw secret values into pages;
 *   - page text, titles and URLs are redacted before they reach the model.
 */

export interface TabInfo {
    id: string;
    url: string;
    title: string;
    active?: boolean;
}

/** Minimal browser surface a harness implements. Selectors are driver-defined (CSS for Playwright). */
export interface BrowserDriver {
    listTabs(): Promise<TabInfo[]>;
    /** Opens a new tab (optionally at a URL) and returns its ID. */
    newTab(url?: string): Promise<string>;
    activateTab(tabId: string): Promise<void>;
    closeTab(tabId: string): Promise<void>;
    navigate(tabId: string, url: string): Promise<void>;
    currentUrl(tabId: string): Promise<string>;
    click(tabId: string, selector: string): Promise<void>;
    fill(tabId: string, selector: string, value: string): Promise<void>;
    readText(tabId: string): Promise<string>;
}

export interface LoginOptions {
    usernameSelector?: string;
    /** Plain username (not secret). Mutually exclusive with usernameSecretId. */
    username?: string;
    /** Vault secret holding the username / email. */
    usernameSecretId?: string;
    passwordSelector: string;
    passwordSecretId: string;
    submitSelector?: string;
}

export class SecureBrowser {
    constructor(
        private readonly driver: BrowserDriver,
        private readonly broker: AccessBroker,
    ) {}

    async listTabs(): Promise<TabInfo[]> {
        const tabs = await this.driver.listTabs();
        return Promise.all(
            tabs.map(async (tab) => ({
                ...tab,
                url: await this.broker.redact(tab.url),
                title: await this.broker.redact(tab.title),
            })),
        );
    }

    async openTab(url?: string): Promise<string> {
        if (url !== undefined) await this.checkUrl(url);
        return this.driver.newTab(url);
    }

    async switchTab(tabId: string): Promise<void> {
        await this.driver.activateTab(tabId);
    }

    async closeTab(tabId: string): Promise<void> {
        await this.driver.closeTab(tabId);
    }

    async navigate(tabId: string, url: string): Promise<void> {
        await this.checkUrl(url);
        await this.driver.navigate(tabId, url);
    }

    async click(tabId: string, selector: string): Promise<void> {
        await this.driver.click(tabId, selector);
    }

    /** Types model-supplied text. Raw vault values are refused — use fillSecret. */
    async type(tabId: string, selector: string, text: string): Promise<void> {
        await this.broker.assertNoSecretValues(text, 'typed text');
        await this.driver.fill(tabId, selector, text);
    }

    /** Fills a vault secret into a field if the tab's current origin is granted "fill". */
    async fillSecret(tabId: string, selector: string, secretId: string): Promise<void> {
        const origin = await this.tabOrigin(tabId);
        await this.broker.useSecret(secretId, origin, 'fill', (value) => this.driver.fill(tabId, selector, value));
    }

    /** Fills the current TOTP code for a vault-stored 2FA seed (grant action "totp"). */
    async fillTotp(tabId: string, selector: string, secretId: string): Promise<void> {
        const origin = await this.tabOrigin(tabId);
        await this.broker.useSecret(secretId, origin, 'totp', (code) => this.driver.fill(tabId, selector, code));
    }

    /** Username + password (+ submit) in one call. */
    async login(tabId: string, options: LoginOptions): Promise<void> {
        if (options.usernameSelector) {
            if (options.usernameSecretId) {
                await this.fillSecret(tabId, options.usernameSelector, options.usernameSecretId);
            } else if (options.username !== undefined) {
                await this.type(tabId, options.usernameSelector, options.username);
            }
        }
        await this.fillSecret(tabId, options.passwordSelector, options.passwordSecretId);
        if (options.submitSelector) await this.driver.click(tabId, options.submitSelector);
    }

    /** Page text with secrets and PII redacted. */
    async readText(tabId: string): Promise<string> {
        return this.broker.redact(await this.driver.readText(tabId));
    }

    private async checkUrl(url: string): Promise<void> {
        this.broker.assertNavigation(url);
        await this.broker.assertNoSecretValues(url, 'URL');
    }

    private async tabOrigin(tabId: string): Promise<string> {
        const origin = originOf(await this.driver.currentUrl(tabId));
        if (!origin) throw new Error('Prompt Guard: the tab is not on an http(s) page.');
        return origin;
    }
}

// ---------------------------------------------------------------------------
// Agent tool definitions
// ---------------------------------------------------------------------------

export interface AgentTool {
    name: string;
    description: string;
    inputSchema: {
        type: 'object';
        properties: Record<string, { type: string; description: string; enum?: string[] }>;
        required?: string[];
        additionalProperties: false;
    };
    /** Never throws: failures come back as { error } with no secret values. */
    execute: (input: Record<string, unknown>) => Promise<unknown>;
}

function str(input: Record<string, unknown>, key: string, required = true): string | undefined {
    const value = input[key];
    if (value === undefined && !required) return undefined;
    if (typeof value !== 'string' || value.length === 0) throw new Error(`"${key}" must be a non-empty string.`);
    return value;
}

function tool(
    name: string,
    description: string,
    properties: AgentTool['inputSchema']['properties'],
    required: string[],
    run: (input: Record<string, unknown>) => Promise<unknown>,
): AgentTool {
    return {
        name,
        description,
        inputSchema: { type: 'object', properties, required, additionalProperties: false },
        execute: async (input) => {
            try {
                return (await run(input ?? {})) ?? { ok: true };
            } catch (error) {
                return { error: error instanceof Error ? error.message : 'Operation failed.' };
            }
        },
    };
}

const tabId = { type: 'string', description: 'Tab ID from browser_list_tabs or browser_open_tab.' };
const selector = { type: 'string', description: 'CSS selector of the element.' };
const secretId = { type: 'string', description: 'Vault secret ID from prompt_guard_vault_catalog. Never a raw value.' };

/**
 * Tool definitions (JSON Schema) for any harness: register them with MCP,
 * the Vercel AI SDK, OpenAI/Anthropic tool calling, etc. Includes the vault
 * catalog so the model can discover secret IDs, and api_request when a
 * broker is supplied.
 */
export function createSecureBrowserTools(
    browser: SecureBrowser,
    options: { vault?: SecretVault; broker?: AccessBroker } = {},
): AgentTool[] {
    const tools: AgentTool[] = [
        tool('browser_list_tabs', 'List open tabs (URLs and titles are redacted).', {}, [], () => browser.listTabs()),
        tool(
            'browser_open_tab',
            'Open a new tab, optionally at a URL allowed by the access policy.',
            { url: { type: 'string', description: 'https URL to open.' } },
            [],
            async (input) => ({ tabId: await browser.openTab(str(input, 'url', false)) }),
        ),
        tool('browser_switch_tab', 'Bring a tab to the front.', { tabId }, ['tabId'], (input) =>
            browser.switchTab(str(input, 'tabId')!),
        ),
        tool('browser_close_tab', 'Close a tab.', { tabId }, ['tabId'], (input) => browser.closeTab(str(input, 'tabId')!)),
        tool(
            'browser_navigate',
            'Navigate a tab to a URL allowed by the access policy.',
            { tabId, url: { type: 'string', description: 'https URL.' } },
            ['tabId', 'url'],
            (input) => browser.navigate(str(input, 'tabId')!, str(input, 'url')!),
        ),
        tool('browser_click', 'Click an element.', { tabId, selector }, ['tabId', 'selector'], (input) =>
            browser.click(str(input, 'tabId')!, str(input, 'selector')!),
        ),
        tool(
            'browser_type',
            'Type non-secret text into a field. For passwords, tokens or codes use browser_fill_secret.',
            { tabId, selector, text: { type: 'string', description: 'Text to type.' } },
            ['tabId', 'selector', 'text'],
            (input) => browser.type(str(input, 'tabId')!, str(input, 'selector')!, str(input, 'text')!),
        ),
        tool(
            'browser_fill_secret',
            'Fill a vault secret (password, username, token) into a field by ID. Only works on origins the user granted; the value is never shown to you.',
            { tabId, selector, secretId },
            ['tabId', 'selector', 'secretId'],
            (input) => browser.fillSecret(str(input, 'tabId')!, str(input, 'selector')!, str(input, 'secretId')!),
        ),
        tool(
            'browser_fill_totp',
            'Fill the current 2FA code generated from a vault-stored TOTP seed.',
            { tabId, selector, secretId },
            ['tabId', 'selector', 'secretId'],
            (input) => browser.fillTotp(str(input, 'tabId')!, str(input, 'selector')!, str(input, 'secretId')!),
        ),
        tool('browser_read_text', 'Read the visible text of a tab (secrets and PII redacted).', { tabId }, ['tabId'], async (input) => ({
            text: await browser.readText(str(input, 'tabId')!),
        })),
    ];

    if (options.broker) {
        const broker = options.broker;
        tools.push(
            tool(
                'api_request',
                'Call an HTTP API with a vault credential attached as a header. Only granted origins; response is redacted.',
                {
                    url: { type: 'string', description: 'https API URL.' },
                    secretId,
                    method: { type: 'string', description: 'HTTP method (default GET).' },
                    scheme: { type: 'string', description: 'Authorization scheme.', enum: ['bearer', 'token'] },
                    body: { type: 'string', description: 'Request body (must not contain secret values).' },
                },
                ['url', 'secretId'],
                (input) => {
                    const fetchOptions: AuthorizedFetchOptions = { secretId: str(input, 'secretId')! };
                    const method = str(input, 'method', false);
                    const scheme = str(input, 'scheme', false);
                    const body = str(input, 'body', false);
                    if (method) fetchOptions.method = method;
                    if (scheme === 'bearer' || scheme === 'token') fetchOptions.scheme = scheme;
                    if (body !== undefined) fetchOptions.body = body;
                    return broker.authorizedFetch(str(input, 'url')!, fetchOptions);
                },
            ),
        );
    }

    if (options.vault) {
        const catalog = createVaultCatalogTool(options.vault);
        tools.push({
            name: catalog.name,
            description: catalog.description,
            inputSchema: { type: 'object', properties: {}, additionalProperties: false },
            execute: () => catalog.execute(),
        });
    }
    return tools;
}

// ---------------------------------------------------------------------------
// Playwright adapter (structural types — Playwright is not a dependency)
// ---------------------------------------------------------------------------

interface PlaywrightPageLike {
    url(): string;
    title(): Promise<string>;
    goto(url: string): Promise<unknown>;
    bringToFront(): Promise<void>;
    close(): Promise<void>;
    click(selector: string): Promise<void>;
    fill(selector: string, value: string): Promise<void>;
    innerText(selector: string): Promise<string>;
}

interface PlaywrightContextLike {
    pages(): PlaywrightPageLike[];
    newPage(): Promise<PlaywrightPageLike>;
}

/** Wraps a Playwright BrowserContext as a BrowserDriver. Tab IDs are stable per page. */
export function createPlaywrightDriver(context: PlaywrightContextLike): BrowserDriver {
    const ids = new WeakMap<PlaywrightPageLike, string>();
    let next = 1;
    const idOf = (page: PlaywrightPageLike): string => {
        let id = ids.get(page);
        if (!id) {
            id = `tab-${next++}`;
            ids.set(page, id);
        }
        return id;
    };
    const page = (tabId: string): PlaywrightPageLike => {
        const found = context.pages().find((p) => idOf(p) === tabId);
        if (!found) throw new Error(`Tab "${tabId}" is not open.`);
        return found;
    };
    return {
        listTabs: async () =>
            Promise.all(context.pages().map(async (p) => ({ id: idOf(p), url: p.url(), title: await p.title() }))),
        newTab: async (url) => {
            const p = await context.newPage();
            if (url) await p.goto(url);
            return idOf(p);
        },
        activateTab: (tabId) => page(tabId).bringToFront(),
        closeTab: (tabId) => page(tabId).close(),
        navigate: async (tabId, url) => {
            await page(tabId).goto(url);
        },
        currentUrl: async (tabId) => page(tabId).url(),
        click: (tabId, selector) => page(tabId).click(selector),
        fill: (tabId, selector, value) => page(tabId).fill(selector, value),
        readText: (tabId) => page(tabId).innerText('body'),
    };
}

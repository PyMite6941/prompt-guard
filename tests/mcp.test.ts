import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createPuppeteerDriver } from '../src/browser';
import { setupMcp, STARTER_POLICY } from '../src/mcp';
import { parseAccessPolicy } from '../src/access';

const CLI = join(__dirname, '..', 'dist', 'cli.js');

function rpc(messages: object[], env: Record<string, string>): Promise<any[]> {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [CLI, 'mcp'], { env: { ...process.env, ...env } });
        let out = '';
        child.stdout.on('data', (d) => (out += d));
        child.on('error', reject);
        child.on('close', () => resolve(out.split('\n').filter(Boolean).map((l) => JSON.parse(l))));
        child.stdin.end(messages.map((m) => JSON.stringify(m)).join('\n') + '\n');
    });
}

describe('MCP server', () => {
    it('speaks JSON-RPC: initialize, tools/list, tools/call errors, unknown methods', async () => {
        const dir = mkdtempSync(join(tmpdir(), 'pg-mcp-'));
        const responses = await rpc(
            [
                { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {} } },
                { jsonrpc: '2.0', method: 'notifications/initialized' },
                { jsonrpc: '2.0', id: 2, method: 'tools/list' },
                { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'browser_list_tabs', arguments: {} } },
                { jsonrpc: '2.0', id: 4, method: 'nope' },
            ],
            { PROMPT_GUARD_VAULT_PATH: join(dir, 'vault.json') },
        );
        const byId = Object.fromEntries(responses.map((r) => [r.id, r]));
        expect(responses).toHaveLength(4); // the notification gets no reply
        expect(byId[1].result.serverInfo.name).toBe('prompt-guard');
        expect(byId[1].result.capabilities).toEqual({ tools: {} });
        const names = byId[2].result.tools.map((t: { name: string }) => t.name);
        expect(names).toEqual(expect.arrayContaining(['browser_open_tab', 'browser_fill_secret', 'api_request', 'prompt_guard_vault_catalog']));
        expect(byId[3].result.isError).toBe(true);
        expect(byId[3].result.content[0].text).toMatch(/mcp setup/);
        expect(byId[4].error.code).toBe(-32601);
    }, 30000);
});

describe('setupMcp', () => {
    it('writes a valid starter policy and merges .mcp.json without clobbering other servers', () => {
        const dir = mkdtempSync(join(tmpdir(), 'pg-setup-'));
        writeFileSync(join(dir, '.mcp.json'), JSON.stringify({ mcpServers: { other: { command: 'x' } } }));
        const policyPath = join(dir, 'policy.json');
        const result = setupMcp({ scope: 'project', policyPath, cwd: dir });
        expect(result.policyCreated).toBe(true);
        expect(() => parseAccessPolicy(JSON.parse(readFileSync(policyPath, 'utf8')))).not.toThrow();
        const config = JSON.parse(readFileSync(join(dir, '.mcp.json'), 'utf8'));
        expect(config.mcpServers.other).toEqual({ command: 'x' });
        expect(config.mcpServers['prompt-guard'].args).toContain('mcp');
        expect(setupMcp({ scope: 'user', policyPath, cwd: dir }).policyCreated).toBe(false);
        expect(parseAccessPolicy(STARTER_POLICY).grants.length).toBeGreaterThan(0);
    });
});

describe('createPuppeteerDriver', () => {
    it('maps tabs and uses locator().fill', async () => {
        const filled: string[] = [];
        const makePage = (url: string) => ({
            url: () => url,
            title: async () => 'T',
            goto: async () => undefined,
            bringToFront: async () => undefined,
            close: async () => undefined,
            click: async () => undefined,
            locator: (sel: string) => ({ fill: async (v: string) => void filled.push(`${sel}=${v}`) }),
            evaluate: async () => 'body text',
        });
        const pages = [makePage('https://a.example')];
        const driver = createPuppeteerDriver({ pages: async () => pages, newPage: async () => {
            const p = makePage('https://b.example');
            pages.push(p);
            return p;
        } });
        const id = await driver.newTab();
        expect((await driver.listTabs()).map((t) => t.id)).toContain(id);
        await driver.fill(id, '#u', 'x');
        expect(filled).toEqual(['#u=x']);
        expect(await driver.readText(id)).toBe('body text');
        await expect(driver.click('missing', '#a')).rejects.toThrow(/not open/);
    });
});

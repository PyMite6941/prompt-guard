import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import {
    AccessBroker,
    originMatches,
    parseAccessPolicy,
    type AccessAuditEvent,
    type AccessPolicy,
} from '../src/access';
import { createSecureBrowserTools, SecureBrowser, type BrowserDriver, type TabInfo } from '../src/browser';
import { generateTOTP } from '../src/otp';
import { SecretVault } from '../src/vault';

const PASSWORD = 'correct-horse-battery-staple-91';
const TOKEN = 'tok_live_51HXmQ2eZvKYlo2C8a7fJ3';
const TOTP_SEED = 'JBSWY3DPEHPK3PXP';

class FakeDriver implements BrowserDriver {
    tabs = new Map<string, { url: string; title: string; text: string }>();
    filled: Array<{ tabId: string; selector: string; value: string }> = [];
    clicks: string[] = [];
    private next = 1;

    async listTabs(): Promise<TabInfo[]> {
        return [...this.tabs].map(([id, t]) => ({ id, url: t.url, title: t.title }));
    }
    async newTab(url?: string): Promise<string> {
        const id = `t${this.next++}`;
        this.tabs.set(id, { url: url ?? 'about:blank', title: '', text: '' });
        return id;
    }
    async activateTab(): Promise<void> {}
    async closeTab(tabId: string): Promise<void> {
        this.tabs.delete(tabId);
    }
    async navigate(tabId: string, url: string): Promise<void> {
        this.tab(tabId).url = url;
    }
    async currentUrl(tabId: string): Promise<string> {
        return this.tab(tabId).url;
    }
    async click(_tabId: string, selector: string): Promise<void> {
        this.clicks.push(selector);
    }
    async fill(tabId: string, selector: string, value: string): Promise<void> {
        this.filled.push({ tabId, selector, value });
    }
    async readText(tabId: string): Promise<string> {
        return this.tab(tabId).text;
    }
    tab(id: string) {
        const t = this.tabs.get(id);
        if (!t) throw new Error('no tab');
        return t;
    }
}

const policy: AccessPolicy = {
    grants: [
        { secretId: 'gh-password', origins: ['https://github.com'], actions: ['fill'] },
        { secretId: 'gh-totp', origins: ['https://github.com'], actions: ['totp'] },
        { secretId: 'api-token', origins: ['https://*.example.com', 'http://127.0.0.1:0'], actions: ['header'] },
    ],
};

let directory: string;
let vault: SecretVault;
let events: AccessAuditEvent[];

beforeEach(async () => {
    directory = await mkdtemp(join(tmpdir(), 'prompt-guard-access-'));
    vault = await SecretVault.open({ path: join(directory, 'vault.json'), passphrase: 'a-long-test-vault-passphrase' });
    await vault.setSecret('gh-password', PASSWORD);
    await vault.setSecret('gh-totp', TOTP_SEED);
    await vault.setSecret('api-token', TOKEN);
    events = [];
});

afterEach(async () => {
    vault.close();
    await rm(directory, { recursive: true, force: true });
});

function setup(p: AccessPolicy = policy) {
    const broker = new AccessBroker(vault, p, { onAudit: (e) => events.push(e) });
    const driver = new FakeDriver();
    const browser = new SecureBrowser(driver, broker);
    return { broker, driver, browser };
}

describe('access policy', () => {
    it('matches exact and single-label wildcard origins', () => {
        expect(originMatches('https://github.com', 'https://github.com')).toBe(true);
        expect(originMatches('https://github.com', 'https://github.com.evil.io')).toBe(false);
        expect(originMatches('https://*.example.com', 'https://api.example.com')).toBe(true);
        expect(originMatches('https://*.example.com', 'https://example.com')).toBe(false);
        expect(originMatches('https://*.example.com', 'https://a.b.example.com')).toBe(false);
        expect(originMatches('https://*.example.com', 'https://evilexample.com')).toBe(false);
        expect(originMatches('https://*.example.com', 'http://api.example.com')).toBe(false);
    });

    it('rejects malformed policies', () => {
        expect(() => parseAccessPolicy({})).toThrow(/grants/);
        expect(() => parseAccessPolicy({ grants: [{ secretId: 'x', origins: ['github.com'], actions: ['fill'] }] })).toThrow(
            /origin pattern/,
        );
        expect(() =>
            parseAccessPolicy({ grants: [{ secretId: 'x', origins: ['https://a.com'], actions: ['print'] }] }),
        ).toThrow(/unknown action/);
    });
});

describe('SecureBrowser', () => {
    it('fills a granted secret without exposing it, and audits the use', async () => {
        const { driver, browser } = setup();
        const tab = await browser.openTab('https://github.com/login');
        await browser.login(tab, {
            usernameSelector: '#login',
            username: 'octocat',
            passwordSelector: '#password',
            passwordSecretId: 'gh-password',
            submitSelector: 'button[type=submit]',
        });
        expect(driver.filled).toEqual([
            { tabId: tab, selector: '#login', value: 'octocat' },
            { tabId: tab, selector: '#password', value: PASSWORD },
        ]);
        expect(driver.clicks).toEqual(['button[type=submit]']);
        expect(events).toContainEqual({ event: 'secret_use', secretId: 'gh-password', origin: 'https://github.com', action: 'fill' });
        expect(JSON.stringify(events)).not.toContain(PASSWORD);
    });

    it('refuses to fill a secret on an origin that is not granted (checked at fill time)', async () => {
        const { driver, browser } = setup();
        const tab = await browser.openTab('https://github.com/login');
        driver.tab(tab).url = 'https://github.com.evil.io/login'; // page redirected after open
        await expect(browser.fillSecret(tab, '#password', 'gh-password')).rejects.toThrow(/denied/);
        expect(driver.filled).toEqual([]);
        expect(events.some((e) => e.event === 'secret_use_denied')).toBe(true);
    });

    it('refuses a secret for an action it was not granted', async () => {
        const { browser } = setup();
        const tab = await browser.openTab('https://github.com/login');
        await expect(browser.fillTotp(tab, '#otp', 'gh-password')).rejects.toThrow(/No grant/);
    });

    it('fills the current TOTP code from a stored seed', async () => {
        const { driver, browser } = setup();
        const tab = await browser.openTab('https://github.com/sessions/two-factor');
        await browser.fillTotp(tab, '#otp', 'gh-totp');
        expect(driver.filled[0]?.value).toBe(generateTOTP(TOTP_SEED));
        expect(driver.filled[0]?.value).toMatch(/^\d{6}$/);
    });

    it('blocks the model from typing a raw secret value', async () => {
        const { driver, browser } = setup();
        const tab = await browser.openTab('https://github.com/login');
        await expect(browser.type(tab, '#comment', `my password is ${PASSWORD}`)).rejects.toThrow(/gh-password/);
        expect(driver.filled).toEqual([]);
    });

    it('blocks navigation to http, non-allow-listed origins, and URLs carrying secrets', async () => {
        const { browser } = setup({ ...policy, allowedOrigins: ['https://github.com', 'https://*.example.com'] });
        await expect(browser.openTab('http://github.com')).rejects.toThrow(/Insecure/);
        await expect(browser.openTab('https://evil.io')).rejects.toThrow(/allow-list/);
        await expect(browser.openTab('javascript:alert(1)')).rejects.toThrow(/http\(s\)/);
        await expect(browser.openTab(`https://api.example.com/?t=${encodeURIComponent(TOKEN)}`)).rejects.toThrow(/secret/);
        await expect(browser.openTab('https://api.example.com/?t=[PROMPT_GUARD_SECRET:api-token]')).rejects.toThrow(
            /placeholder/,
        );
        await expect(browser.openTab('https://api.example.com/docs')).resolves.toBeTypeOf('string');
    });

    it('redacts vault values and PII from page text and tab titles', async () => {
        const { driver, browser } = setup();
        const tab = await browser.openTab('https://github.com/settings');
        driver.tab(tab).text = `Token: ${TOKEN}\nContact: jane.doe@example.org`;
        driver.tab(tab).title = `Settings for jane.doe@example.org`;
        const text = await browser.readText(tab);
        expect(text).toContain('[PROMPT_GUARD_SECRET:api-token]');
        expect(text).toContain('[REDACTED_EMAIL]');
        expect(text).not.toContain(TOKEN);
        const [info] = await browser.listTabs();
        expect(info?.title).not.toContain('jane.doe');
    });
});

describe('agent tools', () => {
    it('exposes tab-control tools that return errors instead of throwing', async () => {
        const { broker, browser } = setup();
        const tools = createSecureBrowserTools(browser, { vault, broker });
        const names = tools.map((t) => t.name);
        expect(names).toEqual(
            expect.arrayContaining([
                'browser_list_tabs',
                'browser_open_tab',
                'browser_switch_tab',
                'browser_close_tab',
                'browser_navigate',
                'browser_fill_secret',
                'browser_read_text',
                'api_request',
                'prompt_guard_vault_catalog',
            ]),
        );
        const open = tools.find((t) => t.name === 'browser_open_tab')!;
        const { tabId } = (await open.execute({ url: 'https://github.com/login' })) as { tabId: string };
        const fill = tools.find((t) => t.name === 'browser_fill_secret')!;
        expect(await fill.execute({ tabId, selector: '#password', secretId: 'api-token' })).toEqual({
            error: expect.stringMatching(/No grant/),
        });
        const catalog = await tools.find((t) => t.name === 'prompt_guard_vault_catalog')!.execute({});
        expect(JSON.stringify(catalog)).not.toContain(PASSWORD);
    });
});

describe('authorizedFetch', () => {
    let server: Server;
    let base: string;
    let seenAuth: string | undefined;

    beforeEach(async () => {
        seenAuth = undefined;
        server = createServer((req, res) => {
            seenAuth = req.headers.authorization;
            if (req.url === '/redirect') {
                res.writeHead(302, { location: 'https://evil.io/steal' }).end();
                return;
            }
            res.writeHead(200, { 'content-type': 'application/json' });
            res.end(JSON.stringify({ echo: req.headers.authorization, owner: 'jane.doe@example.org' }));
        });
        await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
        base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    });

    afterEach(async () => {
        await new Promise<void>((resolve) => server.close(() => resolve()));
    });

    it('attaches the credential and redacts it from the response', async () => {
        const { broker } = setup({ grants: [{ secretId: 'api-token', origins: [base], actions: ['header'] }] });
        const result = await broker.authorizedFetch(`${base}/user`, { secretId: 'api-token' });
        expect(seenAuth).toBe(`Bearer ${TOKEN}`);
        expect(result.status).toBe(200);
        expect(result.body).not.toContain(TOKEN);
        expect(result.body).toContain('[PROMPT_GUARD_SECRET:api-token]');
        expect(result.body).toContain('[REDACTED_EMAIL]');
    });

    it('does not follow redirects with credentials', async () => {
        const { broker } = setup({ grants: [{ secretId: 'api-token', origins: [base], actions: ['header'] }] });
        const result = await broker.authorizedFetch(`${base}/redirect`, { secretId: 'api-token' });
        expect(result.status).toBe(302);
        expect(result.redirectedTo).toBe('https://evil.io/steal');
    });

    it('denies origins without a header grant', async () => {
        const { broker } = setup({ grants: [{ secretId: 'api-token', origins: ['https://api.example.com'], actions: ['header'] }] });
        await expect(broker.authorizedFetch(`${base}/user`, { secretId: 'api-token' })).rejects.toThrow(/denied/);
        expect(seenAuth).toBeUndefined();
    });
});

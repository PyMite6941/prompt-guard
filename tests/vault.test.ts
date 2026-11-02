import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createCipheriv, randomBytes, scryptSync } from 'node:crypto';
import { createVaultCatalogTool, SecretVault } from '../src/vault';

const PASSPHRASE = 'a-long-test-vault-passphrase';
const directories: string[] = [];
const vaults: SecretVault[] = [];

function encryptFixture(key: Buffer, value: string) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return {
        iv: iv.toString('hex'),
        tag: cipher.getAuthTag().toString('hex'),
        ciphertext: ciphertext.toString('hex'),
    };
}

async function createVault(): Promise<{ path: string; vault: SecretVault }> {
    const directory = await mkdtemp(join(tmpdir(), 'prompt-guard-vault-'));
    directories.push(directory);
    const path = join(directory, 'vault.json');
    const vault = await SecretVault.open({ path, passphrase: PASSPHRASE });
    vaults.push(vault);
    return { path, vault };
}

afterEach(async () => {
    for (const vault of vaults.splice(0)) vault.close();
    for (const directory of directories.splice(0)) {
        await rm(directory, { recursive: true, force: true });
    }
});

describe('SecretVault', () => {
    it('encrypts secrets at rest and exposes only IDs when listing', async () => {
        const { path, vault } = await createVault();
        await vault.setSecret('deploy-token', 'token-value-that-must-not-be-plaintext');

        expect(vault.listSecrets()).toEqual(['deploy-token']);
        expect(await readFile(path, 'utf8')).not.toContain('token-value-that-must-not-be-plaintext');
        if (process.platform !== 'win32') {
            expect((await stat(path)).mode & 0o777).toBe(0o600);
        }
        expect(
            await vault.withSecret('deploy-token', (secret) => secret.toString('utf8')),
        ).toBe('token-value-that-must-not-be-plaintext');
    });

    it('reopens the vault and zeroes the temporary secret buffer after use', async () => {
        const { path, vault } = await createVault();
        await vault.setSecret('service-password', 'private-value');
        vault.close();

        const reopened = await SecretVault.open({ path, passphrase: PASSPHRASE });
        vaults.push(reopened);
        let temporary: Buffer | undefined;
        const result = await reopened.withSecret('service-password', (secret) => {
            temporary = secret;
            return secret.toString('utf8');
        });

        expect(result).toBe('private-value');
        expect(temporary?.every((byte) => byte === 0)).toBe(true);
    });

    it('rejects an incorrect passphrase', async () => {
        const { path } = await createVault();
        await expect(
            SecretVault.open({ path, passphrase: 'a-different-long-passphrase' }),
        ).rejects.toThrow('Incorrect vault passphrase');
    });

    it('validates IDs and reports unknown or deleted secrets', async () => {
        const { vault } = await createVault();
        await expect(vault.setSecret('../outside', 'value')).rejects.toThrow('Secret IDs');
        await expect(vault.withSecret('missing', () => undefined)).rejects.toThrow('not found');
        await vault.setSecret('toString', 'prototype-safe');
        expect(await vault.withSecret('toString', (secret) => secret.toString())).toBe('prototype-safe');
        await vault.deleteSecret('toString');
        await vault.setSecret('temporary', 'value');
        await vault.deleteSecret('temporary');
        expect(vault.listSecrets()).toEqual([]);
        await expect(vault.deleteSecret('temporary')).rejects.toThrow('not found');
    });

    it('captures prompt secrets and returns only safe agent metadata', async () => {
        const { path, vault } = await createVault();
        const apiKey = 'sk-proj-abcdefghijklmnopqrstuvwxyz0123456789';
        const result = await vault.captureAndRedactPrompt(`Use this API key: ${apiKey}`);
        const serializedForAgent = JSON.stringify(result);

        expect(result.prompt).not.toContain(apiKey);
        expect(result.prompt).toContain('[PROMPT_GUARD_SECRET:captured-');
        expect(serializedForAgent).not.toContain(apiKey);
        expect(result.secrets).toHaveLength(1);
        expect(result.secrets[0]?.title).toBe('API credential');
        expect(result.secrets[0]?.preview).not.toContain(apiKey);
        expect(result.secrets[0]?.usage).toContain('allow-listed local operation');
        expect(result.manualReviewRequired).toBe(true);
        expect(result.warning).toContain('best-effort');
        expect(await readFile(path, 'utf8')).not.toContain(apiKey);
    });

    it('requires manual review when an unknown unrecognized value remains', async () => {
        const { vault } = await createVault();
        const unknown = 'my-unusual-private-password-489x';
        const result = await vault.captureAndRedactPrompt(`Use password ${unknown}`);

        expect(result.prompt).toContain(unknown);
        expect(result.manualReviewRequired).toBe(true);
        expect(result.warning).toContain('Manually review');
    });

    it('migrates legacy plaintext metadata to encrypted opaque identifiers', async () => {
        const directory = await mkdtemp(join(tmpdir(), 'prompt-guard-legacy-'));
        directories.push(directory);
        const path = join(directory, 'vault.json');
        const salt = randomBytes(16);
        const key = scryptSync(PASSPHRASE, salt, 32, {
            N: 32768,
            r: 8,
            p: 1,
            maxmem: 64 * 1024 * 1024,
        });
        const secret = 'legacy-dummy-secret';
        await writeFile(
            path,
            JSON.stringify({
                version: 1,
                salt: salt.toString('hex'),
                verifier: encryptFixture(key, 'prompt-guard-vault-v1'),
                secrets: { 'legacy-api': encryptFixture(key, secret) },
                meta: { 'legacy-api': { name: 'Legacy Service', tag: 'API' } },
            }),
        );
        key.fill(0);

        const vault = await SecretVault.open({ path, passphrase: PASSPHRASE });
        vaults.push(vault);
        expect(vault.listSecretsWithMeta()).toEqual([
            { id: 'legacy-api', meta: { name: 'Legacy Service', tag: 'API' } },
        ]);
        expect(await vault.withSecret('legacy-api', (value) => value.toString('utf8'))).toBe(
            secret,
        );
        const migrated = await readFile(path, 'utf8');
        expect(JSON.parse(migrated).version).toBe(2);
        expect(migrated).not.toContain('legacy-api');
        expect(migrated).not.toContain('Legacy Service');
        expect(migrated).not.toContain(secret);
    });

    it('redacts previously stored values even when they do not match a scanner pattern', async () => {
        const { vault } = await createVault();
        await vault.setSecret('mailbox-password', 'violet-sunset-8421');

        const result = await vault.captureAndRedactPrompt(
            'Log in with password violet-sunset-8421 to continue.',
        );

        expect(result.prompt).not.toContain('violet-sunset-8421');
        expect(result.prompt).toContain('[PROMPT_GUARD_SECRET:mailbox-password]');
        expect(result.secrets.map(({ id }) => id)).toEqual(['mailbox-password']);
    });

    it('rejects secret values in agent-visible metadata', async () => {
        const { path, vault } = await createVault();
        const value = 'private-metadata-value';
        await vault.setSecret('metadata-test', value);
        await expect(
            vault.setSecretMeta('metadata-test', { name: `API ${value}` }),
        ).rejects.toThrow('must not contain the secret value');
        await vault.setSecretMeta('metadata-test', { name: 'Private service', tag: 'password' });
        const catalog = JSON.stringify(await vault.getAgentCatalog());
        expect(catalog).not.toContain('Private service');
        expect(catalog).not.toContain(value);
        expect(catalog).toContain('Password');
        const stored = await readFile(path, 'utf8');
        expect(stored).not.toContain('metadata-test');
        expect(stored).not.toContain('Private service');
        expect(stored).not.toContain('password');
        expect(JSON.parse(stored).version).toBe(2);
    });

    it('provides a harness catalog tool that cannot accept secret lookup arguments', async () => {
        const { vault } = await createVault();
        await vault.setSecret('tool-test', 'private-tool-value');
        const tool = createVaultCatalogTool(vault);
        const result = JSON.stringify(await tool.execute());

        expect(tool.name).toBe('prompt_guard_vault_catalog');
        expect(tool.inputSchema.additionalProperties).toBe(false);
        expect(result).toContain('tool-test');
        expect(result).not.toContain('private-tool-value');
    });

    it('requires a strong passphrase', async () => {
        await expect(
            SecretVault.open({ path: join(tmpdir(), 'unused-prompt-guard-vault.json'), passphrase: 'short' }),
        ).rejects.toThrow('at least 12 characters');
    });
});

describe('vault popup helpers', () => {
    it('derives valid read-only secret IDs from names', async () => {
        const { slugify } = await import('../src/vault-popup');
        expect(slugify('NVIDIA NIM API')).toBe('nvidia-nim-api');
        expect(slugify('***')).toBe('secret');
        expect(slugify('a'.repeat(200))).toMatch(/^[a-z0-9-]{1,120}$/);
    });
});

describe('vault export/import', () => {
    it('exports an encrypted backup bundle and restores it', async () => {
        const directory = await mkdtemp(join(tmpdir(), 'prompt-guard-export-'));
        directories.push(directory);
        const vaultPath = join(directory, 'vault.json');
        const exportPath = join(directory, 'backup.json');

        const vault = await SecretVault.open({ path: vaultPath, passphrase: PASSPHRASE });
        await vault.setSecret('deploy-token', 'super-secret-value');
        await vault.setSecretMeta('deploy-token', { name: 'Deploy', tag: 'token' });
        vaults.push(vault);

        await vault.exportTo(exportPath);
        const exported = await readFile(exportPath, 'utf8');
        expect(JSON.parse(exported).version).toBe(2);
        expect(exported).not.toContain('super-secret-value');

        // Restore into a different file with the same passphrase.
        const restorePath = join(directory, 'restored.json');
        const restored = await SecretVault.importFrom(exportPath, PASSPHRASE, restorePath);
        vaults.push(restored);

        expect(restored.listSecrets()).toEqual(['deploy-token']);
        expect(await restored.withSecret('deploy-token', (s) => s.toString('utf8'))).toBe(
            'super-secret-value',
        );
        const meta = restored.getSecretMeta('deploy-token');
        expect(meta?.name).toBe('Deploy');
        expect(meta?.tag).toBe('token');
    });

    it('rejects import with a wrong passphrase', async () => {
        const directory = await mkdtemp(join(tmpdir(), 'prompt-guard-import-bad-'));
        directories.push(directory);
        const vaultPath = join(directory, 'vault.json');
        const exportPath = join(directory, 'backup.json');

        const vault = await SecretVault.open({ path: vaultPath, passphrase: PASSPHRASE });
        await vault.setSecret('x', 'y');
        vaults.push(vault);
        await vault.exportTo(exportPath);
        vault.close();

        const restorePath = join(directory, 'restored.json');
        await expect(
            SecretVault.importFrom(exportPath, 'wrong-passphrase', restorePath),
        ).rejects.toThrow('Incorrect vault passphrase');
    });
});

describe('vault catalog filtering', () => {
    it('filters agent catalog by tag and name', async () => {
        const { path, vault } = await createVault();
        await vault.setSecret('aws-key', 'ak-value');
        await vault.setSecretMeta('aws-key', { name: 'AWS', tag: 'token' });
        await vault.setSecret('db-pass', 'db-value');
        await vault.setSecretMeta('db-pass', { name: 'DB', tag: 'password' });

        const byTag = await vault.getAgentCatalog({ tag: 'token' });
        expect(byTag.map((s) => s.id)).toEqual(['aws-key']);

        const byName = await vault.getAgentCatalog({ name: 'DB' });
        expect(byName.map((s) => s.id)).toEqual(['db-pass']);

        const none = await vault.getAgentCatalog({ tag: 'nonexistent' });
        expect(none).toEqual([]);
    });
});

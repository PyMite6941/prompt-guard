import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SecretVault } from '../src/vault';

const PASSPHRASE = 'a-long-test-vault-passphrase';
const directories: string[] = [];
const vaults: SecretVault[] = [];

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

    it('requires a strong passphrase', async () => {
        await expect(
            SecretVault.open({ path: join(tmpdir(), 'unused-prompt-guard-vault.json'), passphrase: 'short' }),
        ).rejects.toThrow('at least 12 characters');
    });
});

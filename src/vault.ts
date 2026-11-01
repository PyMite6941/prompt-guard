import {
    createCipheriv,
    createDecipheriv,
    randomBytes,
    scrypt,
    timingSafeEqual,
} from 'node:crypto';
import { promises as fs } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
const VERIFIER = Buffer.from('prompt-guard-vault-v1');
const KEY_LENGTH = 32;
const SCRYPT_OPTIONS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

interface EncryptedValue {
    iv: string;
    tag: string;
    ciphertext: string;
}

interface VaultDocument {
    version: 1;
    salt: string;
    verifier: EncryptedValue;
    secrets: Record<string, EncryptedValue>;
}

export interface SecretVaultOptions {
    passphrase: string;
    path?: string;
}

export function getDefaultVaultPath(): string {
    if (process.env.PROMPT_GUARD_VAULT_PATH) {
        return process.env.PROMPT_GUARD_VAULT_PATH;
    }

    const home = homedir();
    const root =
        process.env.APPDATA ||
        (process.platform === 'darwin'
            ? join(home, 'Library', 'Application Support')
            : join(process.env.XDG_DATA_HOME || join(home, '.local', 'share')));
    return join(root, 'prompt-guard', 'vault.json');
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isEncryptedValue(value: unknown): value is EncryptedValue {
    return (
        isRecord(value) &&
        typeof value.iv === 'string' &&
        typeof value.tag === 'string' &&
        typeof value.ciphertext === 'string' &&
        /^[0-9a-f]{24}$/i.test(value.iv) &&
        /^[0-9a-f]{32}$/i.test(value.tag) &&
        /^[0-9a-f]*$/i.test(value.ciphertext)
    );
}

function parseDocument(serialized: string): VaultDocument {
    let parsed: unknown;
    try {
        parsed = JSON.parse(serialized);
    } catch {
        throw new Error('Vault file is not valid JSON.');
    }

    if (!isRecord(parsed) || parsed.version !== 1) {
        throw new Error('Vault file has an unsupported or invalid format.');
    }

    if (
        typeof parsed.salt !== 'string' ||
        !/^[0-9a-f]{32}$/i.test(parsed.salt) ||
        !isEncryptedValue(parsed.verifier) ||
        !isRecord(parsed.secrets)
    ) {
        throw new Error('Vault file has an unsupported or invalid format.');
    }

    const secretEntries: Array<[string, EncryptedValue]> = [];
    for (const [id, value] of Object.entries(parsed.secrets)) {
        if (!/^[a-zA-Z0-9._-]{1,128}$/.test(id) || !isEncryptedValue(value)) {
            throw new Error('Vault file has an unsupported or invalid format.');
        }
        secretEntries.push([id, value]);
    }

    return {
        version: 1,
        salt: parsed.salt,
        verifier: parsed.verifier,
        secrets: Object.fromEntries(secretEntries),
    };
}

async function deriveKey(passphrase: string, salt: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
        scrypt(passphrase, salt, KEY_LENGTH, SCRYPT_OPTIONS, (error, key) => {
            if (error) reject(error);
            else resolve(key);
        });
    });
}

function encrypt(key: Buffer, plaintext: Buffer): EncryptedValue {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {
        iv: iv.toString('hex'),
        tag: cipher.getAuthTag().toString('hex'),
        ciphertext: ciphertext.toString('hex'),
    };
}

function decrypt(key: Buffer, encrypted: EncryptedValue): Buffer {
    const decipher = createDecipheriv(
        'aes-256-gcm',
        key,
        Buffer.from(encrypted.iv, 'hex'),
    );
    decipher.setAuthTag(Buffer.from(encrypted.tag, 'hex'));
    return Buffer.concat([
        decipher.update(Buffer.from(encrypted.ciphertext, 'hex')),
        decipher.final(),
    ]);
}

export class SecretVault {
    private closed = false;

    private constructor(
        private readonly vaultPath: string,
        private readonly key: Buffer,
        private document: VaultDocument,
    ) {}

    static async open(options: SecretVaultOptions): Promise<SecretVault> {
        if (options.passphrase.length < 12) {
            throw new Error('Vault passphrase must be at least 12 characters.');
        }

        const vaultPath = options.path ?? getDefaultVaultPath();
        let serialized: string | undefined;
        try {
            serialized = await fs.readFile(vaultPath, 'utf8');
        } catch (error) {
            if (!isRecord(error) || error.code !== 'ENOENT') {
                throw error;
            }
        }

        if (serialized !== undefined) {
            const document = parseDocument(serialized);
            const key = await deriveKey(options.passphrase, Buffer.from(document.salt, 'hex'));
            let verifier: Buffer;
            try {
                verifier = decrypt(key, document.verifier);
            } catch {
                key.fill(0);
                throw new Error('Incorrect vault passphrase or corrupted vault file.');
            }

            if (
                verifier.length !== VERIFIER.length ||
                !timingSafeEqual(verifier, VERIFIER)
            ) {
                verifier.fill(0);
                key.fill(0);
                throw new Error('Incorrect vault passphrase or corrupted vault file.');
            }
            verifier.fill(0);
            return new SecretVault(vaultPath, key, document);
        }

        const salt = randomBytes(16);
        const key = await deriveKey(options.passphrase, salt);
        const document: VaultDocument = {
            version: 1,
            salt: salt.toString('hex'),
            verifier: encrypt(key, VERIFIER),
            secrets: {},
        };
        const vault = new SecretVault(vaultPath, key, document);
        try {
            await vault.persist(document);
        } catch (error) {
            key.fill(0);
            throw error;
        }
        return vault;
    }

    listSecrets(): string[] {
        this.ensureOpen();
        return Object.keys(this.document.secrets).sort();
    }

    async setSecret(id: string, value: string): Promise<void> {
        this.ensureOpen();
        this.validateId(id);
        if (value.length === 0) {
            throw new Error('Secret value cannot be empty.');
        }

        const plaintext = Buffer.from(value, 'utf8');
        let encrypted: EncryptedValue;
        try {
            encrypted = encrypt(this.key, plaintext);
        } finally {
            plaintext.fill(0);
        }
        const document: VaultDocument = {
            ...this.document,
            secrets: { ...this.document.secrets, [id]: encrypted },
        };
        await this.persist(document);
        this.document = document;
    }

    async deleteSecret(id: string): Promise<void> {
        this.ensureOpen();
        this.validateId(id);
        if (!Object.hasOwn(this.document.secrets, id)) {
            throw new Error(`Secret "${id}" was not found.`);
        }

        const secrets = { ...this.document.secrets };
        delete secrets[id];
        const document: VaultDocument = { ...this.document, secrets };
        await this.persist(document);
        this.document = document;
    }

    async withSecret<T>(
        id: string,
        use: (secret: Buffer) => T | Promise<T>,
    ): Promise<T> {
        this.ensureOpen();
        this.validateId(id);
        if (!Object.hasOwn(this.document.secrets, id)) {
            throw new Error(`Secret "${id}" was not found.`);
        }
        const encrypted = this.document.secrets[id];
        if (!encrypted) {
            throw new Error(`Secret "${id}" was not found.`);
        }

        let secret: Buffer;
        try {
            secret = decrypt(this.key, encrypted);
        } catch {
            throw new Error(`Secret "${id}" could not be decrypted.`);
        }
        try {
            return await use(secret);
        } finally {
            secret.fill(0);
        }
    }

    close(): void {
        if (!this.closed) {
            this.key.fill(0);
            this.closed = true;
        }
    }

    private async persist(document: VaultDocument): Promise<void> {
        const directory = dirname(this.vaultPath);
        await fs.mkdir(directory, { recursive: true, mode: 0o700 });
        const temporaryPath = `${this.vaultPath}.${randomBytes(8).toString('hex')}.tmp`;
        const handle = await fs.open(temporaryPath, 'wx', 0o600);
        try {
            await handle.writeFile(`${JSON.stringify(document, null, 2)}\n`, 'utf8');
        } finally {
            await handle.close();
        }
        await fs.rename(temporaryPath, this.vaultPath);
        if (process.platform !== 'win32') {
            await fs.chmod(this.vaultPath, 0o600);
        }
    }

    private validateId(id: string): void {
        if (!/^[a-zA-Z0-9._-]{1,128}$/.test(id)) {
            throw new Error(
                'Secret IDs must be 1-128 characters using letters, numbers, ".", "_" or "-".',
            );
        }
    }

    private ensureOpen(): void {
        if (this.closed) {
            throw new Error('Vault is closed.');
        }
    }
}

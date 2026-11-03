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
import { scanText } from './scanner';
import {
    generateSecret,
    generateBackupCodes,
    verifyBackupCode,
    verifyTOTP,
    provisioningUri,
    type TOTPOptions,
    type BackupCodeResult,
} from './otp';
const VERIFIER = Buffer.from('prompt-guard-vault-v1');
const KEY_LENGTH = 32;
const SCRYPT_OPTIONS = { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };

const TWO_FACTOR_MAX_ATTEMPTS = 5;
const TWO_FACTOR_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes

interface EncryptedValue {
    iv: string;
    tag: string;
    ciphertext: string;
}

export interface SecretMeta {
    name?: string | undefined;
    tag?: string | undefined;
}

export interface AgentSecretInfo {
    id: string;
    title: string;
    preview: string;
    usage: string;
}

export interface CapturedPrompt {
    prompt: string;
    secrets: AgentSecretInfo[];
    manualReviewRequired: true;
    warning: string;
}

export interface TwoFactorConfig {
    enabled: boolean;
    totpSecret: string;
    backupCodes: string[];
    failedAttempts: number;
    lockoutUntil: number;
}

export interface TwoFactorEnrollment {
    secret: string;
    uri: string;
    backupCodes: string[];
}

const CAPTURE_WARNING =
    'Secret detection is best-effort. Manually review the redacted prompt for unrecognized credentials or sensitive data before sending it to any model.';

export interface AgentCatalogTool {
    name: 'prompt_guard_vault_catalog';
    description: string;
    inputSchema: {
        type: 'object';
        properties: Record<string, never>;
        additionalProperties: false;
    };
    execute: () => Promise<AgentSecretInfo[]>;
}

const SECRET_TITLES: Record<string, string> = {
    apiKey: 'API credential',
    api: 'API credential',
    key: 'API credential',
    password: 'Password',
    token: 'Authentication token',
    secret: 'Stored credential',
    githubToken: 'GitHub credential',
    awsSecretKey: 'Cloud credential',
    databaseUrl: 'Database credential',
    jwtToken: 'Authentication token',
    stripeKey: 'Payment credential',
    sshPrivateKey: 'SSH credential',
    creditCard: 'Payment card',
    ssn: 'Identity number',
    email: 'Email address',
    phoneNumber: 'Phone number',
    ipAddress: 'IP address',
    socialHandle: 'Social handle',
};

const AGENT_PREVIEW = '[value hidden; available only to an approved local operation]';
const AGENT_USAGE =
    'Use this ID only in a host-configured, allow-listed local operation. Never request, print, log, or return the secret value.';

export function createVaultCatalogTool(vault: SecretVault): AgentCatalogTool {
    return {
        name: 'prompt_guard_vault_catalog',
        description:
            'Lists safe secret IDs, generic titles, and redacted previews. This tool never returns secret values.',
        inputSchema: {
            type: 'object',
            properties: {},
            additionalProperties: false,
        },
        execute: () => vault.getAgentCatalog(),
    };
}

interface VaultDocument {
    version: 2;
    salt: string;
    verifier: EncryptedValue;
    secrets: Record<string, EncryptedValue>;
    meta: Record<string, EncryptedValue>;
    twoFactor?: EncryptedValue;
}

interface LegacyVaultDocument {
    version: 1;
    salt: string;
    verifier: EncryptedValue;
    secrets: Record<string, EncryptedValue>;
    meta: Record<string, SecretMeta>;
}

interface VaultMetadata extends SecretMeta {
    id: string;
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

function parseDocument(serialized: string): VaultDocument | LegacyVaultDocument {
    let parsed: unknown;
    try {
        parsed = JSON.parse(serialized);
    } catch {
        throw new Error('Vault file is not valid JSON.');
    }

    if (!isRecord(parsed) || (parsed.version !== 1 && parsed.version !== 2)) {
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
    const secretIds = new Set(secretEntries.map(([id]) => id));

    if (parsed.version === 2) {
        if (!isRecord(parsed.meta)) {
            throw new Error('Vault file has an unsupported or invalid format.');
        }
        const meta: Record<string, EncryptedValue> = {};
        for (const [id, value] of Object.entries(parsed.meta)) {
            if (
                !/^[0-9a-f]{32}$/i.test(id) ||
                !secretIds.has(id) ||
                !isEncryptedValue(value)
            ) {
                throw new Error('Vault file has an unsupported or invalid format.');
            }
            meta[id] = value;
        }
        if (Object.keys(meta).length !== secretEntries.length) {
            throw new Error('Vault file has an unsupported or invalid format.');
        }

        let twoFactor: EncryptedValue | undefined;
        if (parsed.twoFactor !== undefined && parsed.twoFactor !== null) {
            if (!isEncryptedValue(parsed.twoFactor)) {
                throw new Error('Vault file has an unsupported or invalid format.');
            }
            twoFactor = parsed.twoFactor;
        }

        const result: VaultDocument = {
            version: 2,
            salt: parsed.salt,
            verifier: parsed.verifier,
            secrets: Object.fromEntries(secretEntries),
            meta,
        };
        if (twoFactor !== undefined) {
            result.twoFactor = twoFactor;
        }
        return result;
    }

    const meta: Record<string, SecretMeta> = {};
    if (isRecord(parsed.meta)) {
        for (const [id, value] of Object.entries(parsed.meta)) {
            if (
                !/^[a-zA-Z0-9._-]{1,128}$/.test(id) ||
                !secretIds.has(id) ||
                !isRecord(value)
            ) {
                throw new Error('Vault file has an unsupported or invalid format.');
            }
            const name = typeof value.name === 'string' ? value.name : undefined;
            const tag = typeof value.tag === 'string' ? value.tag : undefined;
            if (name !== undefined || tag !== undefined) {
                meta[id] = { name, tag };
            } else {
                meta[id] = {};
            }
        }
    }

    return {
        version: 1,
        salt: parsed.salt,
        verifier: parsed.verifier,
        secrets: Object.fromEntries(secretEntries),
        meta,
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

function encryptMeta(key: Buffer, meta: VaultMetadata): EncryptedValue {
    const plaintext = Buffer.from(JSON.stringify(meta), 'utf8');
    try {
        return encrypt(key, plaintext);
    } finally {
        plaintext.fill(0);
    }
}

function decryptMeta(key: Buffer, encrypted: EncryptedValue): VaultMetadata {
    const plaintext = decrypt(key, encrypted);
    try {
        const parsed: unknown = JSON.parse(plaintext.toString('utf8'));
        if (!isRecord(parsed)) {
            throw new Error('Vault metadata is corrupted.');
        }
        if (typeof parsed.id !== 'string') {
            throw new Error('Vault metadata is corrupted.');
        }
        const name = typeof parsed.name === 'string' ? parsed.name : undefined;
        const tag = typeof parsed.tag === 'string' ? parsed.tag : undefined;
        return { id: parsed.id, name, tag };
    } catch (error) {
        if (error instanceof SyntaxError) {
            throw new Error('Vault metadata is corrupted.');
        }
        throw error;
    } finally {
        plaintext.fill(0);
    }
}

export class SecretVault {
    private closed = false;
    private twoFactorVerified = false;
    private twoFactorConfig: TwoFactorConfig | null = null;
    private _pendingBackupCodes: string[] | undefined;

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

            if (document.version === 1) {
                const secrets: Record<string, EncryptedValue> = {};
                const meta: Record<string, EncryptedValue> = {};
                for (const [id, encryptedSecret] of Object.entries(document.secrets)) {
                    let storageId = randomBytes(16).toString('hex');
                    while (Object.hasOwn(secrets, storageId)) {
                        storageId = randomBytes(16).toString('hex');
                    }
                    secrets[storageId] = encryptedSecret;
                    meta[storageId] = encryptMeta(key, {
                        id,
                        ...(document.meta[id] ?? {}),
                    });
                }
                const migrated: VaultDocument = {
                    version: 2,
                    salt: document.salt,
                    verifier: document.verifier,
                    secrets,
                    meta,
                };
                const vault = new SecretVault(vaultPath, key, migrated);
                try {
                    await vault.persist(vault.document);
                } catch (error) {
                    key.fill(0);
                    throw error;
                }
                return vault;
            }
            const vault = new SecretVault(vaultPath, key, document);
            if (document.version === 2 && document.twoFactor) {
                const tfPlaintext = decrypt(key, document.twoFactor);
                try {
                    const parsed = JSON.parse(tfPlaintext.toString('utf8'));
                    if (
                        typeof parsed.enabled === 'boolean' &&
                        typeof parsed.totpSecret === 'string' &&
                        Array.isArray(parsed.backupCodes)
                    ) {
                        vault._setTwoFactorConfig({
                            enabled: parsed.enabled,
                            totpSecret: parsed.totpSecret,
                            backupCodes: parsed.backupCodes,
                            failedAttempts: typeof parsed.failedAttempts === 'number' ? parsed.failedAttempts : 0,
                            lockoutUntil: typeof parsed.lockoutUntil === 'number' ? parsed.lockoutUntil : 0,
                        });
                    } else {
                        throw new Error('Two-factor config is corrupted.');
                    }
                } finally {
                    tfPlaintext.fill(0);
                }
            }
            return vault;
        }

        const salt = randomBytes(16);
        const key = await deriveKey(options.passphrase, salt);
        const document: VaultDocument = {
            version: 2,
            salt: salt.toString('hex'),
            verifier: encrypt(key, VERIFIER),
            secrets: {},
            meta: {},
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
        return this.listSecretsWithMeta().map(({ id }) => id);
    }

    listSecretsWithMeta(): Array<{ id: string; meta: SecretMeta }> {
        this.ensureOpen();
        return Object.keys(this.document.secrets)
            .map((storageId) => {
                const metadata = this.readMetadata(storageId);
                return { id: metadata.id, meta: this.publicMeta(metadata) };
            })
            .sort((a, b) => a.id.localeCompare(b.id));
    }

    getSecretMeta(id: string): SecretMeta | undefined {
        this.ensureOpen();
        this.validateId(id);
        const storageId = this.findStorageId(id);
        const metadata = storageId ? this.readMetadata(storageId) : undefined;
        return metadata ? this.publicMeta(metadata) : undefined;
    }

    async setSecretMeta(id: string, meta: SecretMeta): Promise<void> {
        this.ensureOpen();
        this.validateId(id);
        const storageId = this.findStorageId(id);
        if (!storageId) {
            throw new Error(`Secret "${id}" was not found.`);
        }
        for (const [field, value] of Object.entries(meta)) {
            if (
                value !== undefined &&
                (value.length > 120 ||
                    /[\u0000-\u001f\u007f]/.test(value) ||
                    !/^[\p{L}\p{N} ._:/+-]*$/u.test(value))
            ) {
                throw new Error(`Secret metadata "${field}" contains unsupported characters.`);
            }
        }
        await this.withSecret(id, (secret) => {
            const value = secret.toString('utf8').toLocaleLowerCase();
            if (
                Object.values(meta).some(
                    (entry) => entry !== undefined && entry.toLocaleLowerCase().includes(value),
                )
            ) {
                throw new Error('Secret metadata must not contain the secret value.');
            }
        });
        const document: VaultDocument = {
            ...this.document,
            meta: { ...this.document.meta, [storageId]: encryptMeta(this.key, { id, ...meta }) },
        };
        await this.persist(document);
        this.document = document;
    }

    async setSecret(id: string, value: string): Promise<void> {
        this.ensureOpen();
        this.validateId(id);
        if (value.length === 0) {
            throw new Error('Secret value cannot be empty.');
        }
        if (value.toLocaleLowerCase().includes(id.toLocaleLowerCase())) {
            throw new Error('Secret ID must not appear inside the secret value.');
        }

        const plaintext = Buffer.from(value, 'utf8');
        let encrypted: EncryptedValue;
        try {
            encrypted = encrypt(this.key, plaintext);
        } finally {
            plaintext.fill(0);
        }
        const existingStorageId = this.findStorageId(id);
        let storageId = existingStorageId ?? randomBytes(16).toString('hex');
        while (!existingStorageId && Object.hasOwn(this.document.secrets, storageId)) {
            storageId = randomBytes(16).toString('hex');
        }
        const document: VaultDocument = {
            ...this.document,
            secrets: { ...this.document.secrets, [storageId]: encrypted },
            meta: {
                ...this.document.meta,
                [storageId]:
                    this.document.meta[storageId] ?? encryptMeta(this.key, { id }),
            },
        };
        await this.persist(document);
        this.document = document;
    }

    async deleteSecret(id: string): Promise<void> {
        this.ensureOpen();
        this.validateId(id);
        const storageId = this.findStorageId(id);
        if (!storageId) {
            throw new Error(`Secret "${id}" was not found.`);
        }

        const secrets = { ...this.document.secrets };
        delete secrets[storageId];
        const meta = { ...this.document.meta };
        delete meta[storageId];
        const document: VaultDocument = { ...this.document, secrets, meta };
        await this.persist(document);
        this.document = document;
    }

    async withSecret<T>(
        id: string,
        use: (secret: Buffer) => T | Promise<T>,
    ): Promise<T> {
        this.ensureOpen();
        this.validateId(id);
        const storageId = this.findStorageId(id);
        if (!storageId) {
            throw new Error(`Secret "${id}" was not found.`);
        }

        const encrypted = this.document.secrets[storageId];
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

    async getAgentCatalog(filter?: { tag?: string; name?: string }): Promise<AgentSecretInfo[]> {
        this.ensureOpen();
        const catalog: AgentSecretInfo[] = [];
        for (const { id, meta } of this.listSecretsWithMeta()) {
            if (filter?.tag && meta.tag !== filter.tag) continue;
            if (filter?.name && meta.name !== filter.name) continue;
            const tag = meta.tag ?? '';
            const title = SECRET_TITLES[tag] ?? SECRET_TITLES[tag.toLowerCase()] ?? 'Stored credential';
            catalog.push({ id, title, preview: AGENT_PREVIEW, usage: AGENT_USAGE });
        }
        return catalog;
    }

    async captureAndRedactPrompt(prompt: string): Promise<CapturedPrompt> {
        this.ensureOpen();
        const existingIds = new Map<string, string>();
        for (const { id } of this.listSecretsWithMeta()) {
            const value = await this.withSecret(id, (secret) => secret.toString('utf8'));
            if (value.length > 0) existingIds.set(value, id);
        }

        const candidates: Array<{
            start: number;
            end: number;
            value: string;
            id: string | undefined;
            type: string | undefined;
        }> = scanText(prompt).matches
            .filter((match) => match.type !== 'prompt_injection')
            .filter(
                (match): match is typeof match & { start: number; end: number } =>
                    typeof match.start === 'number' && typeof match.end === 'number',
            )
            .map((match) => ({
                start: match.start,
                end: match.end,
                value: match.value,
                id: existingIds.get(match.value),
                type: match.type,
            }));

        for (const [value, id] of existingIds) {
            let start = prompt.indexOf(value);
            while (start !== -1) {
                candidates.push({ start, end: start + value.length, value, id, type: undefined });
                start = prompt.indexOf(value, start + value.length);
            }
        }
        candidates.sort((a, b) => a.start - b.start || b.end - a.end);

        const replacements: Array<{ start: number; end: number; id: string }> = [];
        const captured = new Map<string, string>();
        const capturedIds = new Set<string>();
        let lastEnd = 0;
        for (const match of candidates) {
            if (match.start < lastEnd || prompt.slice(match.start, match.end) !== match.value) {
                continue;
            }

            let id = match.id ?? existingIds.get(match.value) ?? captured.get(match.value);
            if (!id) {
                id = `captured-${randomBytes(12).toString('hex')}`;
                await this.setSecret(id, match.value);
                await this.setSecretMeta(id, {
                    name: SECRET_TITLES[match.type ?? ''] ?? 'Stored credential',
                    tag: match.type ?? 'secret',
                });
                captured.set(match.value, id);
            }
            capturedIds.add(id);
            replacements.push({ start: match.start, end: match.end, id });
            lastEnd = match.end;
        }

        let redacted = '';
        let cursor = 0;
        for (const replacement of replacements) {
            redacted +=
                prompt.slice(cursor, replacement.start) +
                `[PROMPT_GUARD_SECRET:${replacement.id}]`;
            cursor = replacement.end;
        }
        redacted += prompt.slice(cursor);

        return {
            prompt: redacted,
            secrets: (await this.getAgentCatalog()).filter((secret) => capturedIds.has(secret.id)),
            manualReviewRequired: true,
            warning: CAPTURE_WARNING,
        };
    }

    private _setTwoFactorConfig(config: TwoFactorConfig | null): void {
        this.twoFactorConfig = config;
    }

    private validateId(id: string): void {
        if (!/^[a-zA-Z0-9._-]{1,128}$/.test(id)) {
            throw new Error(
                'Secret IDs must be 1-128 characters using letters, numbers, ".", "_" or "-".',
            );
        }
        if (scanText(id).matches.some((match) => match.value === id)) {
            throw new Error('Secret IDs must not contain a detected credential or personal value.');
        }
    }

    private findStorageId(id: string): string | undefined {
        for (const storageId of Object.keys(this.document.meta)) {
            if (this.readMetadata(storageId)?.id === id) return storageId;
        }
        return undefined;
    }

    private readMetadata(storageId: string): VaultMetadata {
        const encrypted = this.document.meta[storageId];
        if (!encrypted) {
            throw new Error('Vault metadata is missing or corrupted.');
        }
        const metadata = decryptMeta(this.key, encrypted);
        if (!/^[a-zA-Z0-9._-]{1,128}$/.test(metadata.id)) {
            throw new Error('Vault metadata is corrupted.');
        }
        return metadata;
    }

    private publicMeta(metadata: VaultMetadata): SecretMeta {
        return {
            ...(metadata.name === undefined ? {} : { name: metadata.name }),
            ...(metadata.tag === undefined ? {} : { tag: metadata.tag }),
        };
    }

    private ensureOpen(): void {
        if (this.closed) {
            throw new Error('Vault is closed.');
        }
        if (this.requireTwoFactor()) {
            throw new Error(
                'Two-factor authentication required. Provide a TOTP code or backup code before accessing secrets.',
            );
        }
    }

    /** Ensures the vault is open without checking 2FA state (for 2FA verification itself). */
    private ensureOpenUnlocked(): void {
        if (this.closed) {
            throw new Error('Vault is closed.');
        }
    }

    /** Returns true when 2FA is enabled but not yet verified for this session. */
    requireTwoFactor(): boolean {
        return !!(this.twoFactorConfig?.enabled && !this.twoFactorVerified);
    }

    /** Returns true when 2FA has been configured on this vault. */
    isTwoFactorConfigured(): boolean {
        return !!this.twoFactorConfig?.enabled;
    }

    /** Returns two-factor status for CLI/reporting. Never reveals the TOTP secret. */
    getTwoFactorStatus(): {
        configured: boolean;
        verified: boolean;
        failedAttempts: number;
        lockoutUntil: number;
    } {
        return {
            configured: !!this.twoFactorConfig?.enabled,
            verified: this.twoFactorVerified,
            failedAttempts: this.twoFactorConfig?.failedAttempts ?? 0,
            lockoutUntil: this.twoFactorConfig?.lockoutUntil ?? 0,
        };
    }

    close(): void {
        if (!this.closed) {
            this.key.fill(0);
            this.closed = true;
        }
    }

    private async persist(document: VaultDocument, targetPath?: string): Promise<void> {
        const writePath = targetPath ?? this.vaultPath;
        const directory = dirname(writePath);
        await fs.mkdir(directory, { recursive: true, mode: 0o700 });
        const temporaryPath = `${writePath}.${randomBytes(8).toString('hex')}.tmp`;
        const handle = await fs.open(temporaryPath, 'wx', 0o600);
        try {
            await handle.writeFile(`${JSON.stringify(document, null, 2)}\n`, 'utf8');
        } finally {
            await handle.close();
        }
        await fs.rename(temporaryPath, writePath);
        if (process.platform !== 'win32') {
            await fs.chmod(writePath, 0o600);
        }
    }

    /** Writes the current encrypted vault document to `exportPath` as a backup bundle. */
    async exportTo(exportPath: string): Promise<void> {
        this.ensureOpen();
        await this.persist(this.document, exportPath);
    }

    /**
     * Restores a vault from an encrypted backup bundle.
     * Validates that `passphrase` can decrypt the bundle, then writes it to
     * `targetPath` (default vault path). Returns the opened target vault.
     */
    static async importFrom(
        importPath: string,
        passphrase: string,
        targetPath?: string,
    ): Promise<SecretVault> {
        // Fail closed: the bundle must decrypt with the supplied passphrase.
        const source = await SecretVault.open({ passphrase, path: importPath });
        const writePath = targetPath ?? getDefaultVaultPath();
        try {
            await source.exportTo(writePath);
            return await SecretVault.open({ passphrase, path: writePath });
        } finally {
            source.close();
        }
    }

    /**
     * Verifies a TOTP code or backup code and unlocks two-factor access.
     * Records failed attempts and enforces lockout after repeated failures.
     */
    async verifyTwoFactor(code: string): Promise<void> {
        this.ensureOpenUnlocked();
        const config = this.twoFactorConfig;
        if (!config?.enabled) {
            throw new Error('Two-factor authentication is not configured on this vault.');
        }
        if (config.lockoutUntil > 0 && Date.now() < config.lockoutUntil) {
            const remaining = Math.ceil((config.lockoutUntil - Date.now()) / 1000);
            throw new Error(
                `Two-factor locked. Try again in ${remaining} seconds.`,
            );
        }

        let verified = false;

        // Try TOTP code first.
        if (verifyTOTP(code, config.totpSecret)) {
            verified = true;
        } else {
            // Try backup codes (single-use).
            const backupIndex = config.backupCodes.findIndex((hash) =>
                verifyBackupCode(code, hash),
            );
            if (backupIndex !== -1) {
                verified = true;
                config.backupCodes.splice(backupIndex, 1);
            }
        }

        if (verified) {
            config.failedAttempts = 0;
            config.lockoutUntil = 0;
            this.twoFactorVerified = true;
            await this.persistTwoFactor(config);
            return;
        }

        // Failed attempt.
        config.failedAttempts += 1;
        if (config.failedAttempts >= TWO_FACTOR_MAX_ATTEMPTS) {
            config.lockoutUntil = Date.now() + TWO_FACTOR_LOCKOUT_MS;
        }
        await this.persistTwoFactor(config);
        throw new Error('Invalid two-factor code.');
    }

    /**
     * Starts two-factor enrollment. Generates a TOTP secret and backup codes,
     * stores them pending verification, and returns the enrollment data for
     * display to the user. Call `completeTwoFactorEnrollment(code)` to finish.
     */
    async startTwoFactorEnrollment(): Promise<TwoFactorEnrollment> {
        this.ensureOpen();
        if (this.twoFactorConfig?.enabled) {
            throw new Error('Two-factor authentication is already configured.');
        }

        const secret = generateSecret();
        const { codes, hashes } = generateBackupCodes(8, 12);

        // Store pending enrollment in memory (not persisted yet).
        this.twoFactorConfig = {
            enabled: false, // not enabled until confirmed
            totpSecret: secret,
            backupCodes: hashes,
            failedAttempts: 0,
            lockoutUntil: 0,
        };
        this._pendingBackupCodes = codes;

        return {
            secret,
            uri: provisioningUri(secret, 'prompt-guard', 'Prompt Guard'),
            backupCodes: codes,
        };
    }

    /**
     * Completes two-factor enrollment by verifying a TOTP code against the
     * pending secret. Persists the config and unlocks 2FA access.
     */
    async completeTwoFactorEnrollment(verificationCode: string): Promise<void> {
        this.ensureOpen();
        const config = this.twoFactorConfig;
        if (!config || config.enabled) {
            throw new Error('No pending two-factor enrollment. Call startTwoFactorEnrollment first.');
        }
        if (!this._pendingBackupCodes) {
            throw new Error('Enrollment state is corrupted.');
        }

        if (!verifyTOTP(verificationCode, config.totpSecret)) {
            throw new Error('Invalid TOTP code. Scan the QR code and try again.');
        }

        config.enabled = true;
        this.twoFactorVerified = true;
        const document: VaultDocument = {
            ...this.document,
            twoFactor: this.encryptTwoFactor(config),
        };
        await this.persist(document);
        this.document = document;
        this._pendingBackupCodes = undefined;
    }

    /**
     * Disables two-factor authentication. Requires 2FA to be verified first.
     */
    async disableTwoFactor(): Promise<void> {
        this.ensureOpen();
        if (!this.twoFactorConfig?.enabled) {
            throw new Error('Two-factor authentication is not configured.');
        }
        if (!this.twoFactorVerified) {
            throw new Error('Two-factor authentication must be verified before disabling.');
        }
        this.twoFactorConfig = null;
        this.twoFactorVerified = false;
        const { twoFactor: _tf, ...documentWithout2FA } = this.document;
        const document: VaultDocument = documentWithout2FA;
        await this.persist(document);
        this.document = document;
    }

    /** Regenerates backup codes. Requires 2FA to be verified first. */
    async regenerateBackupCodes(): Promise<string[]> {
        this.ensureOpen();
        if (!this.twoFactorConfig?.enabled) {
            throw new Error('Two-factor authentication is not configured.');
        }
        if (!this.twoFactorVerified) {
            throw new Error('Two-factor authentication must be verified first.');
        }
        const { codes, hashes } = generateBackupCodes(8, 12);
        this.twoFactorConfig.backupCodes = hashes;
        this.twoFactorConfig.failedAttempts = 0;
        this.twoFactorConfig.lockoutUntil = 0;
        await this.persistTwoFactor(this.twoFactorConfig);
        return codes;
    }

    /** Encrypts a TwoFactorConfig for storage in the vault document. */
    private encryptTwoFactor(config: TwoFactorConfig): EncryptedValue {
        const plaintext = Buffer.from(JSON.stringify(config), 'utf8');
        try {
            return encrypt(this.key, plaintext);
        } finally {
            plaintext.fill(0);
        }
    }

    /** Persists the current two-factor config to disk. */
    private async persistTwoFactor(config: TwoFactorConfig): Promise<void> {
        const document: VaultDocument = {
            ...this.document,
            twoFactor: this.encryptTwoFactor(config),
        };
        await this.persist(document);
        this.document = document;
    }
}

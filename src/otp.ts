import * as crypto from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export interface TOTPOptions {
    digits?: number;      // default 6
    period?: number;      // default 30 seconds
    algorithm?: 'SHA1' | 'SHA256' | 'SHA512'; // default SHA1 (Google Authenticator compatible)
    window?: number;      // default 1 (±1 period for clock drift)
}

export interface BackupCodeResult {
    codes: string[];      // plaintext codes — show to user once
    hashes: string[];     // SHA-256 hashes — stored in vault
}

/**
 * Generates a cryptographically random Base32-encoded TOTP secret key.
 * Default length 20 bytes → 32 Base32 characters (160 bits of entropy).
 */
export function generateSecret(length: number = 20): string {
    const bytes = crypto.randomBytes(length);
    let result = '';
    let buffer = 0;
    let bitsLeft = 0;
    for (const byte of bytes) {
        buffer = (buffer << 8) | byte;
        bitsLeft += 8;
        while (bitsLeft >= 5) {
            result += BASE32_ALPHABET[(buffer >> (bitsLeft - 5)) & 31];
            bitsLeft -= 5;
        }
    }
    if (bitsLeft > 0) {
        result += BASE32_ALPHABET[(buffer << (5 - bitsLeft)) & 31];
    }
    return result;
}

/**
 * Decodes a Base32 string (RFC 4648) to raw bytes.
 */
function decodeBase32(input: string): Uint8Array {
    const cleaned = input.toUpperCase().replace(/=+$/, '');
    let buffer = 0;
    let bitsLeft = 0;
    const result: number[] = [];
    for (const char of cleaned) {
        const val = BASE32_ALPHABET.indexOf(char);
        if (val === -1) {
            throw new Error('Invalid base32 character in TOTP secret.');
        }
        buffer = (buffer << 5) | val;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            result.push((buffer >> (bitsLeft - 8)) & 0xff);
            bitsLeft -= 8;
        }
    }
    return new Uint8Array(result);
}

/**
 * Converts a bigint counter to a big-endian byte buffer (RFC 4226 §5.2).
 */
function intToBytes(n: bigint, length: number): Buffer {
    const buf = Buffer.alloc(length);
    for (let i = length - 1; i >= 0; i--) {
        buf[i] = Number(n & 0xffn);
        n >>= 8n;
    }
    return buf;
}

/**
 * HMAC-based OTP (RFC 4226). Produces the OTP value for a given counter.
 */
function hotp(secret: Uint8Array, counter: bigint, opts: Required<TOTPOptions>): string {
    const counterBuf = intToBytes(counter, 8);
    const hmac = crypto.createHmac(opts.algorithm, secret).update(counterBuf).digest();
    const offset = hmac[19]! & 0x0f;
    const binary =
        ((hmac[offset]! & 0x7f) << 24) |
        ((hmac[offset + 1]! & 0xff) << 16) |
        ((hmac[offset + 2]! & 0xff) << 8) |
        (hmac[offset + 3]! & 0xff);
    const otp = BigInt(binary) % 10n ** BigInt(opts.digits);
    return otp.toString().padStart(opts.digits, '0');
}

/**
 * Generates the current TOTP code (RFC 6238).
 */
export function generateTOTP(secret: string, opts: TOTPOptions = {}): string {
    const options: Required<TOTPOptions> = {
        digits: opts.digits ?? 6,
        period: opts.period ?? 30,
        algorithm: opts.algorithm ?? 'SHA1',
        window: opts.window ?? 1,
    };
    const key = decodeBase32(secret);
    const counter = BigInt(Math.floor(Date.now() / 1000 / options.period));
    return hotp(key, counter, options);
}

/**
 * Verifies a TOTP code with time-window tolerance for clock drift.
 * Constant-time comparison to prevent timing attacks.
 */
export function verifyTOTP(token: string, secret: string, opts: TOTPOptions = {}): boolean {
    const options: Required<TOTPOptions> = {
        digits: opts.digits ?? 6,
        period: opts.period ?? 30,
        algorithm: opts.algorithm ?? 'SHA1',
        window: opts.window ?? 1,
    };
    if (!/^\d{6,10}$/.test(token)) return false;
    const currentTime = Math.floor(Date.now() / 1000);
    const currentCounter = BigInt(Math.floor(currentTime / options.period));
    const key = decodeBase32(secret);
    for (let i = -options.window; i <= options.window; i++) {
        const expected = hotp(key, currentCounter + BigInt(i), options);
        if (crypto.timingSafeEqual(Buffer.from(token, 'utf8'), Buffer.from(expected, 'utf8'))) {
            return true;
        }
    }
    return false;
}

/**
 * Builds an otpauth:// provisioning URI for authenticator app enrollment.
 * Scannable by Google Authenticator, Authy, Microsoft Authenticator, 1Password, etc.
 */
export function provisioningUri(secret: string, accountName: string, issuer: string): string {
    const encodedAccount = encodeURIComponent(accountName);
    const encodedIssuer = encodeURIComponent(issuer);
    return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${secret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}

/**
 * Generates single-use backup codes. Returns plaintext codes (show once) and
 * SHA-256 hashes (store in vault). Each code can verify exactly once.
 */
export function generateBackupCodes(count: number = 8, length: number = 12): BackupCodeResult {
    const codes: string[] = [];
    const hashes: string[] = [];
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    for (let i = 0; i < count; i++) {
        let code = '';
        for (let j = 0; j < length; j++) {
            code += chars[crypto.randomInt(0, chars.length)];
        }
        codes.push(code);
        hashes.push(crypto.createHash('sha256').update(code).digest('hex'));
    }
    return { codes, hashes };
}

/**
 * Verifies a backup code against its stored SHA-256 hash (constant-time).
 */
export function verifyBackupCode(code: string, hash: string): boolean {
    if (!code || !hash || typeof code !== 'string' || typeof hash !== 'string') {
        return false;
    }
    const expected = crypto.createHash('sha256').update(code).digest('hex');
    return crypto.timingSafeEqual(Buffer.from(expected, 'utf8'), Buffer.from(hash, 'utf8'));
}

import { readFileSync } from 'node:fs';
import { generateTOTP } from './otp';
import { appendSecurityLog } from './report';
import { scanText } from './scanner';
import type { SecretVault } from './vault';

/**
 * Secure account access for agent harnesses.
 *
 * The model only ever sees secret IDs. When a harness needs to log in to an
 * account (fill a password into a browser tab, send an API token, enter a 2FA
 * code), it asks the AccessBroker, which checks the request against an
 * explicit policy — which secret, on which origin, for which action — and
 * only then decrypts the value and hands it to the harness's own code. The
 * value is never returned to the caller, and everything the harness reads
 * back (page text, API responses) is redacted before the model sees it.
 */

/** How a secret may be used. */
export type AccessAction =
    /** Fill the value into a form field (browser). */
    | 'fill'
    /** Send the value in an HTTP header (Authorization: Bearer ..., or a named header). */
    | 'header'
    /** Treat the value as a TOTP seed and fill the current 6-digit code. */
    | 'totp';

export interface SecretGrant {
    /** Vault secret ID. */
    secretId: string;
    /**
     * Origins the secret may be sent to, e.g. "https://github.com" or
     * "https://*.example.com" (one subdomain label wildcard, not the apex).
     */
    origins: string[];
    /** Allowed actions. */
    actions: AccessAction[];
}

export interface AccessPolicy {
    grants: SecretGrant[];
    /**
     * Navigation allow-list (same pattern syntax as grant origins). When
     * omitted, any https origin (and http://localhost) may be opened.
     */
    allowedOrigins?: string[];
    /** Allow plain-http origins other than localhost. Defaults to false. */
    allowInsecureHttp?: boolean;
}

export interface AccessAuditEvent {
    event: 'secret_use' | 'secret_use_denied' | 'navigation_denied' | 'output_blocked';
    secretId?: string;
    origin?: string;
    action?: string;
    reason?: string;
}

export interface AccessBrokerOptions {
    /** Append audit events (metadata only, never values) to this JSON-lines file. */
    auditLogPath?: string;
    /** Called for every audit event. */
    onAudit?: (event: AccessAuditEvent) => void;
    /** Redact PII (emails, phone numbers, ...) from text returned to the model. Defaults to true. */
    redactPii?: boolean;
}

export interface AccessDecision {
    allowed: boolean;
    reason?: string;
}

export interface AuthorizedFetchOptions {
    secretId: string;
    /** "bearer" (default) → Authorization: Bearer <v>; "token" → Authorization: token <v>; or a header name. */
    scheme?: 'bearer' | 'token' | { header: string };
    method?: string;
    headers?: Record<string, string>;
    body?: string;
}

export interface AuthorizedFetchResult {
    status: number;
    ok: boolean;
    contentType: string | null;
    /** Response body with secrets/PII redacted. */
    body: string;
    /** Set when the server redirected; redirects are never followed with credentials. */
    redirectedTo?: string;
}

export const SECRET_PLACEHOLDER = /\[PROMPT_GUARD_SECRET:([a-zA-Z0-9._-]{1,128})\]/g;
const ACTIONS: readonly AccessAction[] = ['fill', 'header', 'totp'];
const ORIGIN_PATTERN = /^(https?):\/\/(\*\.)?([a-z0-9.-]+|\[[0-9a-f:]+\])(:\d{1,5})?$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Validates and normalises an untrusted policy object. Throws on anything unexpected. */
export function parseAccessPolicy(raw: unknown): AccessPolicy {
    if (!isRecord(raw)) throw new Error('Access policy must be a JSON object.');
    if (!Array.isArray(raw.grants)) throw new Error('Access policy "grants" must be an array.');
    const grants = raw.grants.map((grant, index): SecretGrant => {
        if (!isRecord(grant)) throw new Error(`grants[${index}] must be an object.`);
        const { secretId, origins, actions } = grant;
        if (typeof secretId !== 'string' || !/^[a-zA-Z0-9._-]{1,128}$/.test(secretId)) {
            throw new Error(`grants[${index}].secretId is not a valid secret ID.`);
        }
        if (!Array.isArray(origins) || origins.length === 0) {
            throw new Error(`grants[${index}].origins must be a non-empty array.`);
        }
        for (const origin of origins) assertOriginPattern(origin, `grants[${index}].origins`);
        if (!Array.isArray(actions) || actions.length === 0) {
            throw new Error(`grants[${index}].actions must be a non-empty array.`);
        }
        for (const action of actions) {
            if (!ACTIONS.includes(action as AccessAction)) {
                throw new Error(`grants[${index}].actions has unknown action "${String(action)}".`);
            }
        }
        return {
            secretId,
            origins: origins.map((o: string) => o.toLowerCase()),
            actions: actions as AccessAction[],
        };
    });
    const policy: AccessPolicy = { grants };
    if (raw.allowedOrigins !== undefined) {
        if (!Array.isArray(raw.allowedOrigins)) throw new Error('"allowedOrigins" must be an array.');
        for (const origin of raw.allowedOrigins) assertOriginPattern(origin, 'allowedOrigins');
        policy.allowedOrigins = raw.allowedOrigins.map((o: string) => o.toLowerCase());
    }
    if (raw.allowInsecureHttp !== undefined) {
        if (typeof raw.allowInsecureHttp !== 'boolean') throw new Error('"allowInsecureHttp" must be a boolean.');
        policy.allowInsecureHttp = raw.allowInsecureHttp;
    }
    return policy;
}

/** Loads an access policy from a JSON file. */
export function loadAccessPolicy(policyPath: string): AccessPolicy {
    return parseAccessPolicy(JSON.parse(readFileSync(policyPath, 'utf8')));
}

function assertOriginPattern(value: unknown, field: string): asserts value is string {
    if (typeof value !== 'string' || !ORIGIN_PATTERN.test(value)) {
        throw new Error(
            `${field}: "${String(value)}" is not an origin pattern (expected e.g. "https://example.com" or "https://*.example.com").`,
        );
    }
}

/** Returns the origin of a URL, or undefined if it is not an http(s) URL. */
export function originOf(url: string): string | undefined {
    try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return undefined;
        return parsed.origin.toLowerCase();
    } catch {
        return undefined;
    }
}

/** Matches an origin against "https://host[:port]" or "https://*.host[:port]". */
export function originMatches(pattern: string, origin: string): boolean {
    const p = pattern.toLowerCase();
    const o = origin.toLowerCase();
    if (!p.includes('*.')) return p === o;
    let target: URL;
    try {
        target = new URL(o);
    } catch {
        return false;
    }
    const match = ORIGIN_PATTERN.exec(p);
    if (!match) return false;
    const [, scheme, , baseHost, port] = match;
    if (`${scheme}:` !== target.protocol) return false;
    if ((port ?? '') !== (target.port ? `:${target.port}` : '')) return false;
    const host = target.hostname;
    // Exactly one extra label: "*.example.com" matches "a.example.com", not "example.com" or "a.b.example.com".
    if (!host.endsWith(`.${baseHost}`)) return false;
    const label = host.slice(0, -(baseHost!.length + 1));
    return label.length > 0 && !label.includes('.');
}

function isLocalhost(origin: string): boolean {
    try {
        const { hostname } = new URL(origin);
        // Loopback only: "localhost", the IPv4 127/8 block, or IPv6 ::1.
        return hostname === 'localhost' || /^127(?:\.\d{1,3}){3}$/.test(hostname) || hostname === '[::1]';
    } catch {
        return false;
    }
}

export class AccessBroker {
    readonly #vault: SecretVault;
    readonly #policy: AccessPolicy;
    readonly #options: AccessBrokerOptions;

    constructor(vault: SecretVault, policy: AccessPolicy, options: AccessBrokerOptions = {}) {
        this.#vault = vault;
        this.#policy = parseAccessPolicy(policy);
        this.#options = options;
    }

    /** The validated policy (a copy). */
    get policy(): AccessPolicy {
        return structuredClone(this.#policy);
    }

    private audit(event: AccessAuditEvent): void {
        this.#options.onAudit?.(event);
        if (this.#options.auditLogPath) {
            const detail: Record<string, string> = {};
            for (const [key, value] of Object.entries(event)) {
                if (key !== 'event' && typeof value === 'string') detail[key] = value;
            }
            appendSecurityLog(this.#options.auditLogPath, { event: event.event, detail });
        }
    }

    /** Whether a URL may be opened under the policy. */
    checkNavigation(url: string): AccessDecision {
        const origin = originOf(url);
        if (!origin) {
            return { allowed: false, reason: 'Only http(s) URLs can be opened.' };
        }
        if (origin.startsWith('http:') && !this.#policy.allowInsecureHttp && !isLocalhost(origin)) {
            return { allowed: false, reason: `Insecure http origin ${origin} is not allowed.` };
        }
        if (this.#policy.allowedOrigins && !this.#policy.allowedOrigins.some((p) => originMatches(p, origin))) {
            return { allowed: false, reason: `Origin ${origin} is not in the navigation allow-list.` };
        }
        const leak = this.findSecretLeak(url);
        if (leak) {
            return { allowed: false, reason: `The URL contains ${leak}; secrets must not be placed in URLs.` };
        }
        return { allowed: true };
    }

    /** Throws (and audits) if navigation is not allowed. */
    assertNavigation(url: string): void {
        const decision = this.checkNavigation(url);
        if (!decision.allowed) {
            const origin = originOf(url);
            this.audit({
                event: 'navigation_denied',
                ...(origin ? { origin } : {}),
                reason: decision.reason ?? 'denied',
            });
            throw new Error(`Prompt Guard blocked navigation: ${decision.reason}`);
        }
    }

    /** Whether a secret may be used on an origin for an action. */
    checkSecretUse(secretId: string, origin: string, action: AccessAction): AccessDecision {
        if (!this.#vault.listSecrets().includes(secretId)) {
            return { allowed: false, reason: `Secret "${secretId}" is not in the vault.` };
        }
        if (origin.startsWith('http:') && !isLocalhost(origin)) {
            return { allowed: false, reason: 'Secrets are never sent to plain-http origins.' };
        }
        const granted = this.#policy.grants.some(
            (grant) =>
                grant.secretId === secretId &&
                grant.actions.includes(action) &&
                grant.origins.some((pattern) => originMatches(pattern, origin)),
        );
        return granted
            ? { allowed: true }
            : { allowed: false, reason: `No grant allows "${secretId}" for ${action} on ${origin}.` };
    }

    /**
     * Decrypts a secret and passes it to `use` only if the policy allows it.
     * `use` runs in harness code; its return value must not contain the secret.
     */
    async useSecret<T>(
        secretId: string,
        origin: string,
        action: AccessAction,
        use: (value: string) => T | Promise<T>,
    ): Promise<T> {
        const decision = this.checkSecretUse(secretId, origin, action);
        if (!decision.allowed) {
            this.audit({ event: 'secret_use_denied', secretId, origin, action, reason: decision.reason ?? 'denied' });
            throw new Error(`Prompt Guard denied secret use: ${decision.reason}`);
        }
        this.audit({ event: 'secret_use', secretId, origin, action });
        return this.#vault.withSecret(secretId, (buffer) => {
            const raw = buffer.toString('utf8');
            const value = action === 'totp' ? generateTOTP(raw.replace(/\s+/g, '').toUpperCase()) : raw;
            return use(value);
        });
    }

    /**
     * Calls an API with a vault credential attached, without exposing it.
     * The URL's origin must be granted the "header" action for the secret.
     * Redirects are not followed, so credentials cannot be forwarded elsewhere.
     */
    async authorizedFetch(url: string, options: AuthorizedFetchOptions): Promise<AuthorizedFetchResult> {
        const origin = originOf(url);
        if (!origin) throw new Error('Prompt Guard: authorizedFetch needs an http(s) URL.');
        this.assertNavigation(url);
        await this.assertNoSecretValues(url, 'request URL');
        if (options.body !== undefined) await this.assertNoSecretValues(options.body, 'request body');
        const scheme = options.scheme ?? 'bearer';
        const response = await this.useSecret(options.secretId, origin, 'header', (value) => {
            const headers: Record<string, string> = { ...(options.headers ?? {}) };
            if (scheme === 'bearer') headers.Authorization = `Bearer ${value}`;
            else if (scheme === 'token') headers.Authorization = `token ${value}`;
            else headers[scheme.header] = value;
            const init: RequestInit = { method: options.method ?? 'GET', headers, redirect: 'manual' };
            if (options.body !== undefined) init.body = options.body;
            return fetch(url, init);
        });
        const result: AuthorizedFetchResult = {
            status: response.status,
            ok: response.ok,
            contentType: response.headers.get('content-type'),
            body: await this.redact(await response.text()),
        };
        const location = response.headers.get('location');
        if (location) result.redirectedTo = await this.redact(location);
        return result;
    }

    /**
     * Redacts text before it is returned to a model: any vault secret value
     * becomes its [PROMPT_GUARD_SECRET:id] placeholder, and detected
     * credentials (plus PII unless redactPii is false) become [REDACTED_TYPE].
     */
    async redact(text: string): Promise<string> {
        let output = text;
        for (const id of this.#vault.listSecrets()) {
            const value = await this.#vault.withSecret(id, (buffer) => buffer.toString('utf8'));
            if (value.length >= 4) output = output.split(value).join(`[PROMPT_GUARD_SECRET:${id}]`);
        }
        const piiTypes = new Set(['email', 'phoneNumber', 'ipAddress', 'socialHandle', 'ssn', 'creditCard', 'iban']);
        const matches = scanText(output, { ignore: ['prompt_injection'] })
            .matches.filter((m) => typeof m.start === 'number' && typeof m.end === 'number')
            .filter((m) => this.#options.redactPii !== false || !piiTypes.has(m.type))
            .sort((a, b) => (b.start ?? 0) - (a.start ?? 0));
        let lastStart = Number.POSITIVE_INFINITY;
        for (const match of matches) {
            const start = match.start ?? 0;
            const end = match.end ?? 0;
            if (end > lastStart) continue; // overlaps an already-redacted span
            output = `${output.slice(0, start)}[REDACTED_${match.type.toUpperCase()}]${output.slice(end)}`;
            lastStart = start;
        }
        return output;
    }

    /** Throws if text contains a raw vault secret value (e.g. the model trying to type one). */
    async assertNoSecretValues(text: string, where: string): Promise<void> {
        for (const id of this.#vault.listSecrets()) {
            const found = await this.#vault.withSecret(id, (buffer) => {
                const value = buffer.toString('utf8');
                return value.length >= 4 && text.includes(value);
            });
            if (found) {
                this.audit({ event: 'output_blocked', secretId: id, reason: `secret value in ${where}` });
                throw new Error(`Prompt Guard blocked the ${where}: it contains the value of vault secret "${id}".`);
            }
        }
    }

    /** Names the first credential-like finding in text (types only), or undefined. */
    private findSecretLeak(text: string): string | undefined {
        if (new RegExp(SECRET_PLACEHOLDER.source).test(text)) return 'a vault placeholder';
        const credentialTypes = new Set([
            'apiKey', 'githubToken', 'awsSecretKey', 'databaseUrl', 'jwtToken', 'stripeKey', 'sshPrivateKey',
            'pgpPrivateKey', 'ecPrivateKey', 'azureConnectionString', 'sendgridKey', 'gcpServiceAccount',
            'creditCard', 'ssn',
        ]);
        const hit = scanText(text, { ignore: ['prompt_injection'] }).matches.find((m) => credentialTypes.has(m.type));
        return hit ? `a ${hit.type}` : undefined;
    }
}

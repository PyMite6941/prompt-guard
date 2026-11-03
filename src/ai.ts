import { OpenAI } from 'openai';
import { config as dotenvConfig } from 'dotenv';
import { scanText, Severity } from './scanner';

dotenvConfig();

let sharedOpenai: OpenAI | null = null;

export interface SafePromptOptions {
    model?: string;
    autoSanitize?: boolean; // If true, replaces PII but still blocks prompt injection
    apiKey?: string; // Overrides OPENAI_API_KEY from environment
    baseURL?: string; // Base URL for the API (for OpenAI-compatible endpoints)
    maxInputTokens?: number; // Approximate maximum input tokens (will truncate prompt)
    maxOutputTokens?: number; // Maximum tokens in the model's response
}

/**
 * Call an AI model with prompt guarding.
 * userPrompt The raw prompt from the user.
 * options Configuration options.
 * returns The model's response text, or null if no response.
 */
export async function callAIGuarded(
    userPrompt: string,
    options: SafePromptOptions = {},
) {
    // Determine model and sanitize preference
    const model = options.model || 'gpt-4o-mini';
    const autoSanitize = options.autoSanitize ?? false;

    // Step 1: Run your local security scan
    const scanResult = scanText(userPrompt);

    let promptToSend = userPrompt;

    if (!scanResult.isSafe) {
        if (scanResult.matches.some((match) => match.type === 'prompt_injection')) {
            throw new Error('Security Violation Blocked: Prompt injection detected');
        }

        if (autoSanitize) {
            console.warn('⚠️ PII detected. Using sanitized text.');
            promptToSend = scanResult.sanitizedText;
        } else {
            throw new Error(
                `Security Violation Blocked: Found ${scanResult.matches.map((m) => m.type).join(', ')}`,
            );
        }
    }

    // Step 2: Optionally truncate the prompt to reduce input tokens
    if (options.maxInputTokens !== undefined) {
        // Rough approximation: 1 token ≈ 4 characters for English text.
        // Adjust if needed for other languages or tokenizers.
        const maxChars = options.maxInputTokens * 4;
        if (promptToSend.length > maxChars) {
            console.warn(`⚠️ Prompt truncated from ${promptToSend.length} to ${maxChars} characters to limit input tokens.`);
            promptToSend = promptToSend.slice(0, maxChars);
        }
    }

    // Step 3: Configure the OpenAI client
    let openaiInstance: OpenAI;
    if (options.apiKey || options.baseURL) {
        // If overriding API key or base URL, create a new instance
        openaiInstance = new OpenAI({
            apiKey: options.apiKey,
            baseURL: options.baseURL,
        });
    } else {
        // Use the shared instance (lazy initialization)
        if (!sharedOpenai) {
            sharedOpenai = new OpenAI();
        }
        openaiInstance = sharedOpenai;
    }

    // Step 4: Make the safe API call to the model
    const response = await openaiInstance.chat.completions.create({
        model: model,
        messages: [{ role: 'user', content: promptToSend }],
        ...(options.maxOutputTokens !== undefined && { max_tokens: options.maxOutputTokens }),
    });

    return response.choices[0]?.message.content ?? null;
}

/** Result of scanning a model's response for safety issues. */
export interface ModelResponseScanResult {
    isSafe: boolean;
    matches: ModelResponseMatch[];
    sanitizedText: string;
}

/** A single match found in a model's response. */
export interface ModelResponseMatch {
    type: string;     // e.g. 'apiKey', 'email', 'phishing_url', 'prompt_injection'
    severity: Severity;
    value: string;        // the matched text (never echoed to user in reports)
    start: number;
    end: number;
    description: string;  // human-readable explanation
}

/**
 * URL shortener domains commonly used in phishing to hide destination.
 */
const URL_SHORTENERS = new Set([
    'bit.ly', 'tinyurl.com', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly',
    'bit.do', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'cli.re',
]);

/** Detects IPv4 literals in URL host position (e.g. http://example.host/). */
const IP_URL_REGEX = /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?(\/\S*)?/gi;

/** Detects data URIs with base64 content (potential exfiltration channel). */
const DATA_URI_REGEX = /data:([^;,]*);base64,[A-Za-z0-9+/]{8,}={0,2}/gi;

/** Detects QR code data URIs or inline QR markers. */
const QR_CODE_REGEX = /(?:qr[-_]?code|data:image\/[^;]+;base64,)[A-Za-z0-9+/]{50,}={0,2}/gi;

/** Detects Markdown image tags that could be tracking pixels / auto-fetch beacons. */
const MARKDOWN_IMAGE_REGEX = /!\[([^\]]*)\]\(([^)]+)\)/gi;

/** Detects shortened URLs. */
const SHORT_URL_REGEX = /https?:\/\/(?:bit\.ly|tinyurl\.com|t\.co|ow\.ly|is\.gd|buff\.ly|adf\.ly|bit\.do|cutt\.ly|rebrand\.ly|shorturl\.at|tiny\.cc|cli\.re)(\/\S+)?/gi;

/** Detects http (not https) URLs in model output. */
const HTTP_URL_REGEX = /http:\/\/\S+/gi;

/** Collect all matches from a regex into ModelResponseMatch entries. */
function collectMatches(
    text: string,
    regex: RegExp,
    type: string,
    severity: Severity,
    description: string,
): ModelResponseMatch[] {
    const matches: ModelResponseMatch[] = [];
    for (const match of text.matchAll(regex)) {
        if (match[0].length === 0 || match.index === undefined) continue;
        matches.push({
            type,
            severity,
            value: match[0],
            start: match.index,
            end: match.index + match[0].length,
            description,
        });
    }
    return matches;
}

/**
 * Scans a model's response text for safety issues beyond PII and secrets:
 * - Phishing/suspicious URLs (shortened, IP-based, non-HTTPS)
 * - Data exfiltration via base64 data URIs
 * - QR code embeds that pivot attacks to mobile
 * - Tracking pixels / auto-fetch image beacons
 * - Prompt injection and PII (delegated to scanText)
 *
 * This defends against ChatGPhish (XPIA) and EchoLeak-style zero-click
 * data exfiltration where attacker-controlled content is rendered inside
 * a trusted AI chat interface.
 */
export function scanModelResponse(
    responseText: string,
): ModelResponseScanResult {
    const matches: ModelResponseMatch[] = [];

    // URL-based threats
    matches.push(...collectMatches(responseText, SHORT_URL_REGEX, 'phishing_url', 'critical', 'URL shortener used to hide destination'));
    matches.push(...collectMatches(responseText, IP_URL_REGEX, 'suspicious_url', 'high', 'IP-address URL used instead of domain name'));
    matches.push(...collectMatches(responseText, HTTP_URL_REGEX, 'suspicious_url', 'medium', 'Non-HTTPS HTTP URL'));
    matches.push(...collectMatches(responseText, DATA_URI_REGEX, 'data_exfiltration', 'critical', 'Base64 data URI may be used for data exfiltration'));
    matches.push(...collectMatches(responseText, QR_CODE_REGEX, 'qr_code', 'high', 'QR code embed may pivot attack to mobile device'));

    // Markdown images can be tracking pixels / auto-fetch beacons
    for (const match of responseText.matchAll(MARKDOWN_IMAGE_REGEX)) {
        if (match[0].length === 0 || match.index === undefined) continue;
        const url = match[2];
        // Data URI images are already caught by DATA_URI_REGEX; flag external image beacons
        if (url && !url.startsWith('data:')) {
            matches.push({
                type: 'tracking_pixel',
                severity: 'medium',
                value: match[0],
                start: match.index,
                end: match.index + match[0].length,
                description: 'External image may be a tracking pixel / auto-fetch beacon',
            });
        }
    }

    // Delegate PII and prompt injection detection to scanText,
    // preserving the original match type (e.g. 'apiKey', 'email', 'creditCard').
    const scanResult = scanText(responseText);
    for (const m of scanResult.matches) {
        matches.push({
            type: m.type,
            severity: m.severity,
            value: m.value,
            start: m.start ?? 0,
            end: m.end ?? m.value.length,
            description: `${m.type} detected in model response`,
        });
    }

    // Sort by position, stable
    matches.sort((a, b) => a.start - b.start || b.end - a.end);

    // Deduplicate overlapping matches: for identical (start, end) ranges,
    // keep only the highest-severity match. Prevents double-redaction bugs
    // when one text span matches multiple detectors (e.g. a base64 data URI
    // matches both DATA_URI_REGEX and QR_CODE_REGEX).
    const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
    const deduped: ModelResponseMatch[] = [];
    for (const m of matches) {
        const existing = deduped.find(
            (e) => e.start === m.start && e.end === m.end,
        );
        if (!existing) {
            deduped.push(m);
        } else if (
            severityRank[m.severity] ?? 0 > (severityRank[existing.severity] ?? 0)
        ) {
            deduped.splice(deduped.indexOf(existing), 1, m);
        }
    }

    // Build sanitized text by replacing dangerous matches with redactions
    let sanitized = responseText;
    // Process in reverse so positions stay valid
    for (const match of [...deduped].reverse()) {
        const redaction = `[REDACTED_${match.type.toUpperCase()}]`;
        sanitized = sanitized.slice(0, match.start) + redaction + sanitized.slice(match.end);
    }

    return {
        isSafe: deduped.length === 0,
        matches: deduped,
        sanitizedText: sanitized,
    };
}

/**
 * Sanitizes a model's response by redacting all detected unsafe content.
 * Returns the sanitized text safe to display to the user.
 */
export function sanitizeModelResponse(responseText: string): string {
    return scanModelResponse(responseText).sanitizedText;
}

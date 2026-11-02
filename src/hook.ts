import { scanText, ScanMatch, Severity } from './scanner';

/**
 * Claude Code hook integration.
 *
 * Claude Code runs a command hook with the event payload as JSON on stdin and
 * reads a JSON decision from stdout. This module turns that payload into a
 * decision without ever echoing the detected values back to the harness.
 */

export interface HookOptions {
    ignore?: string[];
    /** Findings below this severity are allowed through. Defaults to "medium". */
    minSeverity?: Severity;
    configPath?: string | undefined;
    /** What PreToolUse does on a finding: "deny" (default) or "ask" the user. */
    toolDecision?: 'deny' | 'ask';
}

export interface HookResult {
    exitCode: number;
    stdout?: string;
    stderr?: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Collects every string in a tool input (file contents, commands, URLs, ...). */
function collectStrings(value: unknown, out: string[], depth = 0): void {
    if (depth > 20) return;
    if (typeof value === 'string') {
        out.push(value);
    } else if (Array.isArray(value)) {
        for (const item of value) collectStrings(item, out, depth + 1);
    } else if (isRecord(value)) {
        for (const item of Object.values(value)) collectStrings(item, out, depth + 1);
    }
}

/** Summarises findings by type and severity only; values are never included. */
export function summarizeFindings(matches: ScanMatch[]): string {
    const counts = new Map<string, number>();
    for (const match of matches) {
        const key = `${match.type} (${match.severity})`;
        counts.set(key, (counts.get(key) ?? 0) + 1);
    }
    return [...counts].map(([key, count]) => (count > 1 ? `${key} x${count}` : key)).join(', ');
}

function scan(text: string, options: HookOptions): ScanMatch[] {
    return scanText(text, {
        ignore: options.ignore ?? [],
        minSeverity: options.minSeverity ?? 'medium',
        configPath: options.configPath,
    }).matches;
}

export function evaluateHookInput(raw: string, options: HookOptions = {}): HookResult {
    let payload: unknown;
    try {
        payload = JSON.parse(raw);
    } catch {
        // Fail closed: a security gate that cannot read its input must not allow it.
        return {
            exitCode: 2,
            stderr: 'Prompt Guard hook: stdin was not valid hook JSON; blocking to fail closed.',
        };
    }
    if (!isRecord(payload)) {
        return { exitCode: 2, stderr: 'Prompt Guard hook: hook input must be a JSON object.' };
    }

    const event = payload.hook_event_name;

    if (event === 'UserPromptSubmit') {
        const prompt = typeof payload.prompt === 'string' ? payload.prompt : '';
        const matches = scan(prompt, options);
        if (matches.length === 0) return { exitCode: 0 };
        return {
            exitCode: 0,
            stdout: JSON.stringify({
                decision: 'block',
                reason:
                    `Prompt Guard blocked this prompt before it reached the model: ${summarizeFindings(matches)}. ` +
                    'Remove or redact the sensitive values (or store them with "prompt-guard vault") and resend.',
            }),
        };
    }

    if (event === 'PreToolUse') {
        const strings: string[] = [];
        collectStrings(payload.tool_input, strings);
        const matches = strings.flatMap((text) => scan(text, options));
        if (matches.length === 0) return { exitCode: 0 };
        const toolName = typeof payload.tool_name === 'string' ? payload.tool_name : 'tool';
        return {
            exitCode: 0,
            stdout: JSON.stringify({
                hookSpecificOutput: {
                    hookEventName: 'PreToolUse',
                    permissionDecision: options.toolDecision ?? 'deny',
                    permissionDecisionReason:
                        `Prompt Guard found sensitive data in the ${toolName} input: ${summarizeFindings(matches)}. ` +
                        'Do not write, send, or log credentials or personal data; use a placeholder or a vault secret ID instead.',
                },
            }),
        };
    }

    // Other events carry nothing to scan; allow them unchanged.
    return { exitCode: 0 };
}

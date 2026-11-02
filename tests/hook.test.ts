import { describe, expect, it } from 'vitest';
import { evaluateHookInput } from '../src/hook';

const TOKEN = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890';
const payload = (value: unknown) => JSON.stringify(value);

describe('Claude Code hook', () => {
    it('allows a clean prompt with no output', () => {
        expect(
            evaluateHookInput(payload({ hook_event_name: 'UserPromptSubmit', prompt: 'refactor the scanner' })),
        ).toEqual({ exitCode: 0 });
    });

    it('blocks a prompt containing a credential without echoing it', () => {
        const result = evaluateHookInput(
            payload({ hook_event_name: 'UserPromptSubmit', prompt: `push with ${TOKEN}` }),
        );
        const output = JSON.parse(result.stdout!);
        expect(result.exitCode).toBe(0);
        expect(output.decision).toBe('block');
        expect(output.reason).toContain('githubToken (critical)');
        expect(result.stdout).not.toContain(TOKEN);
    });

    it('denies a tool call whose nested input contains a secret', () => {
        const result = evaluateHookInput(
            payload({
                hook_event_name: 'PreToolUse',
                tool_name: 'Write',
                tool_input: { file_path: 'a.env', edits: [{ new_string: `TOKEN=${TOKEN}` }] },
            }),
        );
        const output = JSON.parse(result.stdout!).hookSpecificOutput;
        expect(output.hookEventName).toBe('PreToolUse');
        expect(output.permissionDecision).toBe('deny');
        expect(output.permissionDecisionReason).toContain('Write');
        expect(result.stdout).not.toContain(TOKEN);
    });

    it('can ask instead of deny for tool calls', () => {
        const result = evaluateHookInput(
            payload({ hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: `echo ${TOKEN}` } }),
            { toolDecision: 'ask' },
        );
        expect(JSON.parse(result.stdout!).hookSpecificOutput.permissionDecision).toBe('ask');
    });

    it('ignores low-severity findings by default and respects --ignore', () => {
        expect(
            evaluateHookInput(payload({ hook_event_name: 'UserPromptSubmit', prompt: 'ping @johndoe' })).stdout,
        ).toBeUndefined();
        expect(
            evaluateHookInput(payload({ hook_event_name: 'UserPromptSubmit', prompt: `use ${TOKEN}` }), {
                ignore: ['githubToken'],
            }).stdout,
        ).toBeUndefined();
    });

    it('allows events it does not inspect', () => {
        expect(evaluateHookInput(payload({ hook_event_name: 'Stop' }))).toEqual({ exitCode: 0 });
    });

    it('fails closed on malformed input', () => {
        expect(evaluateHookInput('not json').exitCode).toBe(2);
        expect(evaluateHookInput('[]').exitCode).toBe(2);
    });
});

import { describe, expect, it, beforeAll } from 'vitest';
import { execSync } from 'child_process';

const CLI = 'dist/cli.js';

beforeAll(() => {
    // Ensure dist/ is built so the CLI integration test runs against
    // compiled output (CI runs `npm run build` before `npm test`).
    execSync('npm run build', { stdio: 'pipe' });
});

function runCli(args: string[]) {
    const result = require('child_process').spawnSync('node', [CLI, ...args], {
        encoding: 'utf8',
    });
    return {
        code: result.status ?? -1,
        output: (result.stdout ?? '') + (result.stderr ?? ''),
    };
}

describe('Prompt Guard CLI', () => {
    it('exits 0 and reports clean input', () => {
        const { code, output } = runCli(['examples/clean.txt']);
        expect(code).toBe(0);
        expect(output).toContain('clean and safe');
    });

    it('exits 1 and reports unsafe input', () => {
        const { code, output } = runCli(['examples/leak.txt']);
        expect(code).toBe(1);
        expect(output).toContain('Security risk detected');
        expect(output).toContain('email');
        expect(output).toContain('creditCard');
        expect(output).toContain('prompt_injection');
        expect(output).toContain('[REDACTED_EMAIL]');
        expect(output).toContain('[REDACTED_CREDITCARD]');
    });

    it('scans a directory of files', () => {
        const { code, output } = runCli(['examples/']);
        expect(code).toBe(1);
        expect(output).toContain('examples');
        expect(output).toContain('clean and safe');
        expect(output).toContain('Security risk detected');
    });

    it('honors --ignore for a category', () => {
        const { code, output } = runCli(['examples/leak.txt', '--ignore=email']);
        expect(code).toBe(1);
        expect(output).not.toContain("'email'");
        expect(output).toContain('creditCard');
        expect(output).toContain('prompt_injection');
    });

    it('errors with no path argument', () => {
        const { code, output } = runCli([]);
        expect(code).toBe(1);
        expect(output).toContain('Usage');
    });
});

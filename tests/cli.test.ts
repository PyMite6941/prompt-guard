import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { execSync } from 'child_process';
import * as fs from 'node:fs';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { join } from 'node:path';

const CLI = 'dist/cli.js';

let tempDir: string;

beforeAll(async () => {
    // Ensure dist/ is built so the CLI integration test runs against
    // compiled output (CI runs `npm run build` before `npm test`).
    execSync('npm run build', { stdio: 'pipe' });
    tempDir = await mkdtemp(join(process.cwd(), '.prompt-guard-cli-'));
});

afterAll(async () => {
    if (tempDir) await rm(tempDir, { recursive: true, force: true });
});

function runCli(args: string[], input?: string, env: NodeJS.ProcessEnv = process.env) {
    const result = require('child_process').spawnSync('node', [CLI, ...args], {
        encoding: 'utf8',
        input,
        env,
    });
    return {
        code: result.status ?? -1,
        output: (result.stdout ?? '') + (result.stderr ?? ''),
    };
}

describe('Prompt Guard CLI', () => {
    it('prints usage and exits successfully for --help', () => {
        const { code, output } = runCli(['--help']);
        expect(code).toBe(0);
        expect(output).toContain('Usage: prompt-guard');
        expect(output).toContain('vault <set|list|delete');
    });

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

    it('excludes a path relative to the scanned directory', async () => {
        const directory = join(tempDir, 'exclude-test');
        await fs.promises.mkdir(directory);
        await writeFile(join(directory, 'clean.txt'), 'This file is safe.');
        await writeFile(join(directory, 'excluded.txt'), 'test@example.com');

        const { code, output } = runCli([directory, '--exclude=excluded.txt']);
        expect(code).toBe(0);
        expect(output).toContain('clean.txt');
        expect(output).not.toContain('excluded.txt');
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

    it('does not accept vault secret value input from a non-interactive terminal', () => {
        const { code, output } = runCli(['vault', 'set', 'test-token']);
        expect(code).toBe(1);
        expect(output).toContain('interactive terminal');
    });

    it('does not read the vault passphrase from the environment', () => {
        const { code, output } = runCli(
            ['vault', 'set', 'dummy-secret'],
            undefined,
            { ...process.env, PROMPT_GUARD_VAULT_PASSPHRASE: 'dummy-test-passphrase' },
        );
        expect(code).toBe(1);
        expect(output).toContain('interactive terminal');
        expect(output).not.toContain('dummy-test-passphrase');
    });

    it('does not provide a CLI command that prints decrypted secrets', () => {
        const { code, output } = runCli(['vault', 'get', 'test-token']);
        expect(code).toBe(1);
        expect(output).toContain('Usage: prompt-guard vault');
        expect(output).not.toContain('private');
    });

    it('acts as a Claude Code hook reading the event from stdin', () => {
        const token = 'ghp_abcdefghijklmnopqrstuvwxyz1234567890';
        const { code, output } = runCli(
            ['hook'],
            JSON.stringify({ hook_event_name: 'UserPromptSubmit', prompt: `use ${token}` }),
        );
        expect(code).toBe(0);
        expect(JSON.parse(output).decision).toBe('block');
        expect(output).not.toContain(token);
    });

    it('blocks (exit 2) when the hook is misconfigured', () => {
        const { code, output } = runCli(['hook', '--tool-decision=allow'], '{}');
        expect(code).toBe(2);
        expect(output).toContain('Usage: prompt-guard hook');
    });

    it('config --check accepts a valid config file', async () => {
        const configPath = join(tempDir, 'valid.json');
        await writeFile(
            configPath,
            JSON.stringify({ ignore: [], minSeverity: 'high', partialRedaction: true }),
            'utf8',
        );
        const { code, output } = runCli(['config', '--check', '--config=' + configPath]);
        expect(code).toBe(0);
        expect(output).toContain('is valid');
    });

    it('config --check rejects an invalid config file', async () => {
        const configPath = join(tempDir, 'invalid.json');
        await writeFile(
            configPath,
            JSON.stringify({ ignore: 'not-an-array', minSeverity: 'nope' }),
            'utf8',
        );
        const { code, output } = runCli(['config', '--check', '--config=' + configPath]);
        expect(code).toBe(1);
        expect(output).toContain('invalid');
    });

    it('config --check rejects a missing config file', () => {
        const { code } = runCli(['config', '--check', '--config=' + join(tempDir, 'missing.json')]);
        expect(code).toBe(1);
    });

    it('--html writes a report file', () => {
        const outPath = join(tempDir, 'report.html');
        const { code } = runCli(['examples/leak.txt', '--html=' + outPath]);
        expect(code).toBe(1);
        expect(fs.existsSync(outPath)).toBe(true);
        const content = fs.readFileSync(outPath, 'utf8');
        expect(content).toContain('Prompt Guard - Scan Report');
        expect(content).not.toContain('alex.taylor@example.com');
    });

    it('--junit writes a report file', () => {
        const outPath = join(tempDir, 'report.xml');
        const { code } = runCli(['examples/leak.txt', '--junit=' + outPath]);
        expect(code).toBe(1);
        expect(fs.existsSync(outPath)).toBe(true);
        const content = fs.readFileSync(outPath, 'utf8');
        expect(content).toContain('<testsuites');
        expect(content).not.toContain('alex.taylor@example.com');
    });

    it('--audit-log appends an entry', () => {
        const outPath = join(tempDir, 'audit.log');
        const { code } = runCli(['examples/clean.txt', '--audit-log=' + outPath]);
        expect(code).toBe(0);
        expect(fs.existsSync(outPath)).toBe(true);
        const content = fs.readFileSync(outPath, 'utf8');
        const entry = JSON.parse(content.trim().split('\n').pop()!);
        expect(entry.filePath).toContain('clean.txt');
        expect(entry.isSafe).toBe(true);
    });

    it('--html rejects path traversal with .. segments', () => {
        const { code } = runCli(['examples/clean.txt', '--html=../../../etc/passwd']);
        expect(code).toBe(1);
    });

    it('--junit rejects path traversal with .. segments', () => {
        const { code } = runCli(['examples/clean.txt', '--junit=../../../tmp/evil.xml']);
        expect(code).toBe(1);
    });

    it('--audit-log rejects path traversal with .. segments', () => {
        const { code } = runCli(['examples/clean.txt', '--audit-log=../../../tmp/evil.log']);
        expect(code).toBe(1);
    });

    it('--html rejects absolute path outside cwd', () => {
        const { code } = runCli(['examples/clean.txt', '--html=/tmp/evil.html']);
        expect(code).toBe(1);
    });

    it('--html accepts a relative path within cwd', () => {
        const outPath = join(tempDir, 'report.html');
        const { code } = runCli(['examples/clean.txt', '--html=' + outPath]);
        expect(code).toBe(0);
        expect(fs.existsSync(outPath)).toBe(true);
    });
});

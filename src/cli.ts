#!/usr/bin/env node
import { scanText, generateSarif, ScanResult, Severity, TOOL_VERSION } from './scanner';
import * as fs from 'fs';
import * as path from 'path';
import { getDefaultVaultPath, SecretVault } from './vault';
import {
    generateHtmlReport,
    generateJunitXml,
    appendAuditLog,
    type ReportFile,
} from './report';

function readHidden(prompt: string): Promise<string> {
    const input = process.stdin;
    if (!input.isTTY || !process.stdout.isTTY || typeof input.setRawMode !== 'function') {
        return Promise.resolve('');
    }

    return new Promise((resolve, reject) => {
        const wasRaw = input.isRaw;
        let value = '';
        let finished = false;
        const finish = (error?: Error) => {
            if (finished) return;
            finished = true;
            input.removeListener('data', onData);
            input.pause();
            input.setRawMode(wasRaw);
            process.stdout.write('\n');
            if (error) reject(error);
            else resolve(value);
        };
        const onData = (chunk: Buffer | string) => {
            for (const character of chunk.toString()) {
                if (character === '\u0003') {
                    finish(new Error('Input cancelled.'));
                    return;
                }
                if (character === '\r' || character === '\n') {
                    finish();
                    return;
                }
                if (character === '\u007f' || character === '\b') {
                    value = Array.from(value).slice(0, -1).join('');
                } else if (character >= ' ') {
                    value += character;
                }
            }
        };

        process.stdout.write(prompt);
        input.setEncoding('utf8');
        input.setRawMode(true);
        input.resume();
        input.on('data', onData);
    });
}

async function runVaultCommand(args: string[]): Promise<void> {
    const [operation, id] = args;
    if (
        ![
            'set',
            'list',
            'delete',
            'popup',
            'catalog',
            'capture',
            'export',
            'import',
            'setup-2fa',
            '2fa',
            '2fa-status',
            'backup-codes',
            'disable-2fa',
        ].includes(operation ?? '')
    ) {
        console.error(
            'Usage: prompt-guard vault <set <id>|list|delete <id>|catalog|capture <file>|export <file>|import <file>|popup|setup-2fa|2fa <code>|2fa-status|backup-codes|disable-2fa>\\nSecret values and passphrases are entered without terminal echo.',
        );
        process.exitCode = 1;
        return;
    }
    if ((operation === 'set' || operation === 'delete') && !id) {
        throw new Error(`Usage: prompt-guard vault ${operation} <id>.`);
    }
    if (operation === '2fa' && !id) {
        throw new Error('Usage: prompt-guard vault 2fa <code>.');
    }
    if (operation === 'capture' && !id) {
        throw new Error('Usage: prompt-guard vault capture <file>.');
    }
    if ((operation === 'export' || operation === 'import') && !id) {
        throw new Error(`Usage: prompt-guard vault ${operation} <file>.`);
    }
    if (
        args.length > (operation === 'list' || operation === 'popup' || operation === 'catalog' || operation === '2fa-status' ? 1 : 2)
    ) {
        throw new Error('Too many arguments for vault command.');
    }
    if (id && !/^[a-zA-Z0-9._-]{1,128}$/.test(id)) {
        if (operation !== 'capture' && operation !== 'export' && operation !== 'import') {
            throw new Error('Secret IDs must be 1-128 characters using letters, numbers, ".", "_" or "-".');
        }
    }

    const vaultPath = getDefaultVaultPath();
    if (
        operation !== 'set' &&
        operation !== 'popup' &&
        operation !== 'import' &&
        operation !== 'setup-2fa' &&
        !fs.existsSync(vaultPath)
    ) {
        throw new Error('No vault exists yet; create one with "prompt-guard vault set <id>".');
    }
    let passphrase: string | undefined = undefined;
    if (operation !== 'popup') {
        passphrase = await readHidden('Vault passphrase: ');
        if (!passphrase) {
            throw new Error(
                'Vault commands require an interactive terminal for passphrase input. Use SecretVault from trusted host code for harness integration.',
            );
        }
        if (operation === 'set' && !fs.existsSync(vaultPath)) {
            const confirmation = await readHidden('Confirm new vault passphrase: ');
            if (passphrase !== confirmation) {
                throw new Error('Passphrases did not match.');
            }
        }
    }

    if (operation === 'popup') {
        const { launchVaultPopup } = await import('./vault-popup.js');
        await launchVaultPopup({ passphrase, path: vaultPath });
        console.log('Vault popup closed.');
        return;
    }

    if (operation === 'import') {
        const importedVault = await SecretVault.importFrom(id!, passphrase!, vaultPath);
        importedVault.close();
        console.log('Imported vault from ' + id!);
        return;
    }

    const vault = await SecretVault.open({ passphrase: passphrase!, path: vaultPath });
    passphrase = '';

    // If 2FA is required and the operation isn't providing the code, prompt for it.
    if (
        vault.requireTwoFactor() &&
        operation !== '2fa' &&
        operation !== 'setup-2fa'
    ) {
        const code = await readHidden('Two-factor code: ');
        if (!code) {
            throw new Error('Two-factor code is required.');
        }
        await vault.verifyTwoFactor(code);
        console.log('Two-factor verified.');
    }

    try {
        if (operation === 'setup-2fa') {
            if (vault.isTwoFactorConfigured()) {
                throw new Error('Two-factor authentication is already configured.');
            }
            const enrollment = await vault.startTwoFactorEnrollment();
            console.log('\n=== Two-Factor Enrollment ===');
            console.log('Scan this QR code with your authenticator app:');
            console.log(enrollment.uri);
            console.log(`\nSecret key: ${enrollment.secret}`);
            console.log('\nEnter a code from your authenticator app to verify:');
            const verificationCode = await readHidden('TOTP code: ');
            if (!verificationCode) {
                throw new Error('TOTP code is required.');
            }
            await vault.completeTwoFactorEnrollment(verificationCode);
            console.log('\n=== Two-Factor Enabled ===');
            console.log('Save these backup codes somewhere safe (each can be used once):');
            enrollment.backupCodes.forEach((c, i) => console.log(`  ${i + 1}. ${c}`));
            console.log('\nWithout these codes, loss of your authenticator app means lockout.');
            return;
        }
        if (operation === '2fa') {
            await vault.verifyTwoFactor(id!);
            console.log('Two-factor verified. Vault unlocked.');
            return;
        }
        if (operation === '2fa-status') {
            const status = vault.getTwoFactorStatus();
            console.log(`Configured: ${status.configured}`);
            console.log(`Verified: ${status.verified}`);
            console.log(`Failed attempts: ${status.failedAttempts}`);
            if (status.lockoutUntil > 0) {
                const remaining = Math.ceil((status.lockoutUntil - Date.now()) / 1000);
                console.log(`Locked until: ${remaining} seconds from now`);
            }
            return;
        }
        if (operation === 'backup-codes') {
            const codes = await vault.regenerateBackupCodes();
            console.log('=== New Backup Codes ===');
            codes.forEach((c, i) => console.log(`  ${i + 1}. ${c}`));
            console.log('Previous backup codes are now invalid.');
            return;
        }
        if (operation === 'disable-2fa') {
            await vault.disableTwoFactor();
            console.log('Two-factor authentication disabled.');
            return;
        }
        if (operation === 'capture') {
            const prompt = fs.readFileSync(id!, 'utf8');
            const protectedPrompt = await vault.captureAndRedactPrompt(prompt);
            console.log(JSON.stringify(protectedPrompt, null, 2));
        } else if (operation === 'catalog') {
            console.log(JSON.stringify(await vault.getAgentCatalog(), null, 2));
        } else if (operation === 'set') {
            const value = await readHidden(`Secret value for "${id}": `);
            await vault.setSecret(id!, value);
            console.log(`Stored secret "${id}".`);
        } else if (operation === 'list') {
            const ids = vault.listSecrets();
            console.log(ids.length ? ids.join('\n') : '(no secrets stored)');
        } else if (operation === 'export') {
            validateOutputPath(id!);
            await vault.exportTo(id!);
            console.log('Exported vault to ' + id!);
        } else {
            await vault.deleteSecret(id!);
            console.log(`Deleted secret "${id}".`);
        }
    } finally {
        vault.close();
    }
}

async function readStdin(): Promise<string> {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
        chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
    }
    return Buffer.concat(chunks).toString('utf8');
}

const SEVERITIES: Severity[] = ['low', 'medium', 'high', 'critical'];

async function runHookCommand(args: string[]): Promise<void> {
    const value = (name: string) =>
        args.find((arg) => arg.startsWith(`--${name}=`))?.slice(name.length + 3);
    const minSeverity = value('min-severity');
    const toolDecision = value('tool-decision');
    const unknown = args.filter(
        (arg) => !/^--(ignore|min-severity|config|tool-decision)=/.test(arg),
    );
    if (
        unknown.length > 0 ||
        (minSeverity !== undefined && !SEVERITIES.includes(minSeverity as Severity)) ||
        (toolDecision !== undefined && toolDecision !== 'deny' && toolDecision !== 'ask')
    ) {
        // Exit 2 so a misconfigured hook blocks instead of silently allowing everything.
        process.stderr.write(
            'Usage: prompt-guard hook [--ignore=a,b] [--min-severity=low|medium|high|critical] [--config=path] [--tool-decision=deny|ask]\n',
        );
        process.exitCode = 2;
        return;
    }

    const { evaluateHookInput } = await import('./hook.js');
    const result = evaluateHookInput(await readStdin(), {
        ignore: value('ignore')?.split(',').filter(Boolean) ?? [],
        ...(minSeverity ? { minSeverity: minSeverity as Severity } : {}),
        ...(toolDecision ? { toolDecision: toolDecision as 'deny' | 'ask' } : {}),
        configPath: value('config'),
    });
    if (result.stdout) process.stdout.write(`${result.stdout}\n`);
    if (result.stderr) process.stderr.write(`${result.stderr}\n`);
    process.exitCode = result.exitCode;
}

async function runConfigCommand(args: string[]): Promise<void> {
    const subcommand = (args[0] ?? '').replace(/^--/, '');
    if (subcommand === 'check') {
        const configPathArg = args.find((arg) => arg.startsWith('--config='));
        const configPath = configPathArg ? configPathArg.replace('--config=', '') : '.promptguardrc';
        let config: unknown;
        try {
            const raw = fs.readFileSync(configPath, 'utf8');
            config = JSON.parse(raw);
        } catch {
            console.error('Error: Cannot read config file "' + configPath + '".');
            process.exitCode = 1;
            return;
        }

        let valid = true;
        const errors: string[] = [];
        const validSeverities = new Set(['low', 'medium', 'high', 'critical']);

        const ignore = (config as { ignore?: unknown }).ignore;
        if (ignore !== undefined && !Array.isArray(ignore)) {
            errors.push('"ignore" must be an array of strings.');
            valid = false;
        }

        const minSeverity = (config as { minSeverity?: unknown }).minSeverity;
        if (minSeverity !== undefined && minSeverity !== null && !validSeverities.has(minSeverity as string)) {
            errors.push('"minSeverity" must be one of: ' + [...validSeverities].join(', ') + '.');
            valid = false;
        }

        if (typeof (config as { partialRedaction?: unknown }).partialRedaction !== 'undefined' &&
            typeof (config as { partialRedaction?: boolean }).partialRedaction !== 'boolean') {
            errors.push('"partialRedaction" must be a boolean.');
            valid = false;
        }

        const customPatterns = (config as { customPatterns?: unknown }).customPatterns;
        if (customPatterns !== undefined) {
            if (typeof customPatterns !== 'object' || Array.isArray(customPatterns) || customPatterns === null) {
                errors.push('"customPatterns" must be an object.');
                valid = false;
            } else {
                for (const [name, def] of Object.entries(customPatterns as Record<string, unknown>)) {
                    const d = def as { pattern?: unknown; severity?: unknown };
                    if (typeof d !== 'object' || d === null || Array.isArray(d)) {
                        errors.push('custom pattern "' + name + '" must be an object.');
                        valid = false;
                        continue;
                    }
                    if (typeof d.pattern !== 'string') {
                        errors.push('custom pattern "' + name + '" must have a string "pattern".');
                        valid = false;
                    } else {
                        try {
                            new RegExp(d.pattern, 'g');
                        } catch {
                            errors.push('custom pattern "' + name + '" has an invalid regex: ' + d.pattern);
                            valid = false;
                        }
                    }
                    if (d.severity !== undefined && !validSeverities.has(d.severity as string)) {
                        errors.push('custom pattern "' + name + '" has an invalid severity: ' + d.severity + '.');
                        valid = false;
                    }
                }
            }
        }

        if (valid) {
            console.log('Config "' + configPath + '" is valid.');
            process.exitCode = 0;
        } else {
            console.error('Config "' + configPath + '" is invalid:');
            for (const error of errors) {
                console.error('  - ' + error);
            }
            process.exitCode = 1;
        }
        return;
    }

    console.error('Usage: prompt-guard config --check [--config=path]');
    process.exitCode = 1;
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    if (args.includes('--help') || args.includes('-h')) {
        console.log(
            'Usage: prompt-guard <file|directory> [--ignore=type,...] [--json|--sarif] [--html[=file]] [--junit[=file]] [--audit-log[=file]]\n' +
                '       [--exclude=path,...] excludes paths relative to the scan root\n' +
                '       prompt-guard vault <set|list|delete|catalog|capture|export|import|popup> ...\n' +
                '       prompt-guard hook [--ignore=type,...] [--min-severity=level]\n' +
                '       prompt-guard config --check [--config=file]',
        );
        return;
    }
    if (args[0] === 'vault') {
        await runVaultCommand(args.slice(1));
        return;
    }
    if (args[0] === 'hook') {
        await runHookCommand(args.slice(1));
        return;
    }
    if (args[0] === 'config') {
        await runConfigCommand(args.slice(1));
        return;
    }

    const tuiFlag = args.includes('--tui') || args.includes('-t');

    if (tuiFlag) {
        import('./tui.js').catch((err) => {
            console.error('Failed to launch TUI:', err.message);
            process.exit(1);
        });
        return;
    }

    const target = args.find((arg) => !arg.startsWith('--'));

    const ignoreArg = args.find((arg) => arg.startsWith('--ignore='));
    const ignoreList = ignoreArg
        ? ignoreArg.replace('--ignore=', '').split(',')
        : [];
    const excludeArg = args.find((arg) => arg.startsWith('--exclude='));
    const excludeList = excludeArg
        ? excludeArg
              .slice('--exclude='.length)
              .split(',')
              .map((item) => item.replace(/\\/g, '/').replace(/^\.\/+|\/+$/g, ''))
              .filter(Boolean)
        : [];

    function isExcluded(filePath: string): boolean {
        const relative = path.relative(target!, filePath).split(path.sep).join('/');
        return excludeList.some(
            (excluded) => relative === excluded || relative.startsWith(`${excluded}/`),
        );
    }

    const jsonArg = args.includes('--json');
    const sarifArg = args.includes('--sarif');
    const htmlArg = args.some((arg) => arg === '--html' || arg.startsWith('--html='));
    const junitArg = args.some((arg) => arg === '--junit' || arg.startsWith('--junit='));
    const auditLogArg = args.some(
        (arg) => arg === '--audit-log' || arg.startsWith('--audit-log='),
    );

    /** Resolves a flag value from either "--flag=value" or "--flag value". */
    function flagValue(flag: string): string | undefined {
        const equals = args.find((arg) => arg.startsWith(flag + '='));
        if (equals) return equals.replace(flag + '=', '');
        const index = args.indexOf(flag);
        if (index >= 0 && index + 1 < args.length) {
            const next = args[index + 1];
            if (next !== undefined && !next.startsWith('--')) return next;
        }
        return undefined;
    }

    const auditLogPath = flagValue('--audit-log') ?? 'prompt-guard-audit.log';
    validateOutputPath(auditLogPath);
    const partialRedactionArg = args.includes('--partial-redaction');
    const configArg = args.find((arg) => arg.startsWith('--config='));
    const configPath = configArg ? configArg.replace('--config=', '') : undefined;

    function scanFile(filePath: string): void {
        const content = fs.readFileSync(filePath, 'utf8');
        const result = scanText(content, {
            ignore: ignoreList,
            minSeverity: undefined,
            partialRedaction: partialRedactionArg,
            configPath,
        });

        if (htmlArg || junitArg || auditLogArg) {
            reportFiles.push({ filePath, result, text: content });
        }

        if (!result.isSafe) {
            if (jsonArg) {
                results.push({ file: filePath, result });
            } else if (sarifArg) {
                sarifResults.push({ file: filePath, result, content });
            } else {
                if (exitCode === 0) {
                    console.log('🚨 Security risk detected!');
                }
                // Print matches WITHOUT the detected values (values withheld).
                console.table(
                    result.matches.map(({ type, severity, start, end }) => ({
                        type,
                        severity,
                        start: start ?? 0,
                        end: end ?? 0,
                    })),
                );
                console.log(`\n--- ${filePath} ---`);
                console.log(result.sanitizedText);
            }
            exitCode = 1;
        } else {
            if (jsonArg) {
                results.push({ file: filePath, result });
            } else if (sarifArg) {
                sarifResults.push({ file: filePath, result, content });
            } else {
                console.log(`✅ ${filePath} is clean and safe.`);
            }
        }
    }

    function walkDir(dir: string): void {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const full = path.join(dir, entry.name);
            if (isExcluded(full)) continue;
            if (entry.isDirectory()) {
                walkDir(full);
            } else if (entry.isFile()) {
                scanFile(full);
            }
        }
    }

    let exitCode = 0;
    const results: Array<{ file: string; result: ScanResult }> = [];
    const sarifResults: Array<{ file: string; result: ScanResult; content: string }> = [];
    const reportFiles: Array<{ filePath: string; result: ScanResult; text: string }> = [];

    if (!target) {
        console.error('Error: Please provide a file or directory path to scan.');
        console.error('Usage: prompt-guard <path> [--ignore=email,apiKey] [--json] [--sarif] [--partial-redaction] [--config=path]');
        process.exit(1);
    }

    if (!fs.existsSync(target)) {
        console.error(`Error: Path not found: ${target}`);
        process.exit(1);
    }

    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
        walkDir(target);
    } else if (!isExcluded(target)) {
        scanFile(target);
    }

    if (jsonArg) {
        console.log(
            JSON.stringify(
                results.map((r) => ({
                    file: r.file,
                    isSafe: r.result.isSafe,
                    matches: r.result.matches.map(({ type, severity, start, end }) => ({
                        type,
                        severity,
                        start,
                        end,
                    })),
                    sanitizedText: r.result.sanitizedText,
                })),
                null,
                2,
            ),
        );
    }

    if (sarifArg) {
        const sarifLogs = sarifResults.map((r) => generateSarif(r.file, r.result, r.content));
        // Rule indexes are per-file in each log; re-map them onto the merged rule list.
        const ruleIndexById = new Map<string, number>();
        const mergedResults: any[] = [];
        const mergedRules: any[] = [];

        for (const log of sarifLogs) {
            for (const rule of log.runs[0]?.tool.driver.rules ?? []) {
                if (!ruleIndexById.has(rule.id)) {
                    ruleIndexById.set(rule.id, mergedRules.length);
                    mergedRules.push(rule);
                }
            }
            for (const result of log.runs[0]?.results ?? []) {
                mergedResults.push({ ...result, ruleIndex: ruleIndexById.get(result.ruleId) });
            }
        }

        const mergedSarif = {
            version: '2.1.0',
            $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            runs: [
                {
                    tool: {
                        driver: {
                            name: 'Prompt Guard',
                            version: TOOL_VERSION,
                            rules: mergedRules,
                        },
                    },
                    results: mergedResults,
                },
            ],
        };

        console.log(JSON.stringify(mergedSarif, null, 2));
    }

    if (htmlArg) {
        const report = generateHtmlReport(reportFiles, {
            title: 'Prompt Guard - Scan Report',
            generatedBy: 'prompt-guard CLI',
        });
        const outPath = flagValue('--html');
        if (outPath) {
            validateOutputPath(outPath);
            fs.writeFileSync(outPath, report, 'utf8');
            console.log('HTML report written to ' + outPath);
        } else {
            console.log(report);
        }
    }

    if (junitArg) {
        const xml = generateJunitXml(reportFiles, {
            generatedBy: 'prompt-guard CLI',
        });
        const outPath = flagValue('--junit');
        if (outPath) {
            validateOutputPath(outPath);
            fs.writeFileSync(outPath, xml, 'utf8');
            console.log('JUnit report written to ' + outPath);
        } else {
            console.log(xml);
        }
    }

    if (auditLogArg) {
        for (const rf of reportFiles) {
            const counts = severityCountsFromMatches(rf.result.matches);
            appendAuditLog(auditLogPath, {
                filePath: rf.filePath,
                isSafe: rf.result.isSafe,
                matchCount: rf.result.matches.length,
                severityCounts: counts,
                types: rf.result.matches.map((m) => m.type),
            });
        }
        console.log('Audit log appended to ' + auditLogPath);
    }

    process.exit(exitCode);
}

function severityCountsFromMatches(matches: { severity: Severity }[]): Record<Severity, number> {
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const match of matches) {
        counts[match.severity] = (counts[match.severity] ?? 0) + 1;
    }
    return counts;
}

/**
 * Validates a user-supplied output path to prevent path traversal.
 * Rejects '..' segments and absolute paths that escape the cwd.
 */
export function validateOutputPath(filePath: string): void {
    const segments = filePath.split(/[/\\]/);
    for (const segment of segments) {
        if (segment === '..') {
            throw new Error('Unsafe path: ".." segments are not allowed.');
        }
    }
    if (path.isAbsolute(filePath)) {
        const resolved = path.resolve(filePath);
        const cwd = path.resolve(process.cwd());
        const relative = path.relative(cwd, resolved);
        if (relative.startsWith('..') || path.isAbsolute(relative)) {
            throw new Error(
                'Unsafe path: absolute paths must be within the current working directory.',
            );
        }
    }
}

main().catch((error: unknown) => {
    console.error(`Error: ${error instanceof Error ? error.message : 'Vault operation failed.'}`);
    process.exitCode = 1;
});

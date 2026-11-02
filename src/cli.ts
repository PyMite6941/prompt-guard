#!/usr/bin/env node
import { scanText, generateSarif, ScanResult } from './scanner';
import * as fs from 'fs';
import * as path from 'path';
import { getDefaultVaultPath, SecretVault } from './vault';

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
    if (!['set', 'list', 'delete', 'popup', 'catalog', 'capture'].includes(operation ?? '')) {
        console.error(
            'Usage: prompt-guard vault <set <id>|list|delete <id>|catalog|capture <file>|popup>\nSecret values and passphrases are entered without terminal echo.',
        );
        process.exitCode = 1;
        return;
    }
    if ((operation === 'set' || operation === 'delete') && !id) {
        throw new Error(`Usage: prompt-guard vault ${operation} <id>.`);
    }
    if (operation === 'capture' && !id) {
        throw new Error('Usage: prompt-guard vault capture <file>.');
    }
    if (
        args.length > (operation === 'list' || operation === 'popup' || operation === 'catalog' ? 1 : 2)
    ) {
        throw new Error('Too many arguments for vault command.');
    }
    if (id && !/^[a-zA-Z0-9._-]{1,128}$/.test(id)) {
        if (operation !== 'capture') {
            throw new Error('Secret IDs must be 1-128 characters using letters, numbers, ".", "_" or "-".');
        }
    }

    const vaultPath = getDefaultVaultPath();
    if (operation !== 'set' && operation !== 'popup' && !fs.existsSync(vaultPath)) {
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

    const vault = await SecretVault.open({ passphrase: passphrase!, path: vaultPath });
    passphrase = '';
    try {
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
        } else {
            await vault.deleteSecret(id!);
            console.log(`Deleted secret "${id}".`);
        }
    } finally {
        vault.close();
    }
}

async function main(): Promise<void> {
    const args = process.argv.slice(2);
    if (args[0] === 'vault') {
        await runVaultCommand(args.slice(1));
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

    const jsonArg = args.includes('--json');
    const sarifArg = args.includes('--sarif');
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

        if (!result.isSafe) {
            if (jsonArg) {
                results.push({ file: filePath, result });
            } else if (sarifArg) {
                sarifResults.push({ file: filePath, result });
            } else {
                if (exitCode === 0) {
                    console.log('🚨 Security risk detected!');
                }
                console.table(result.matches);
                console.log(`\n--- ${filePath} ---`);
                console.log(result.sanitizedText);
            }
            exitCode = 1;
        } else {
            if (jsonArg) {
                results.push({ file: filePath, result });
            } else if (sarifArg) {
                sarifResults.push({ file: filePath, result });
            } else {
                console.log(`✅ ${filePath} is clean and safe.`);
            }
        }
    }

    function walkDir(dir: string): void {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                walkDir(full);
            } else if (entry.isFile()) {
                scanFile(full);
            }
        }
    }

    let exitCode = 0;
    const results: Array<{ file: string; result: ScanResult }> = [];
    const sarifResults: Array<{ file: string; result: ScanResult }> = [];

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
    } else {
        scanFile(target);
    }

    if (jsonArg) {
        console.log(
            JSON.stringify(
                results.map((r) => ({
                    file: r.file,
                    isSafe: r.result.isSafe,
                    matches: r.result.matches,
                    sanitizedText: r.result.sanitizedText,
                })),
                null,
                2,
            ),
        );
    }

    if (sarifArg) {
        const sarifLogs = sarifResults.map((r) =>
            generateSarif(r.file, r.result),
        );
        const allRules: Record<string, number> = {};
        let ruleCounter = 0;
        const mergedResults: any[] = [];
        const mergedRules: any[] = [];

        sarifLogs.forEach((log) => {
            const rules = log.runs[0]?.tool.driver.rules || [];
            const res = log.runs[0]?.results || [];
            rules.forEach((rule: any) => {
                if (!allRules[rule.id]) {
                    allRules[rule.id] = ruleCounter;
                    mergedRules.push(rule);
                    ruleCounter++;
                }
            });
            res.forEach((result: any) => {
                mergedResults.push(result);
            });
        });

        const mergedSarif = {
            version: '2.1.0',
            schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
            runs: [
                {
                    tool: {
                        driver: {
                            name: 'Prompt Guard',
                            version: '2.0.0',
                            rules: mergedRules,
                        },
                    },
                    results: mergedResults,
                },
            ],
        };

        console.log(JSON.stringify(mergedSarif, null, 2));
    }

    process.exit(exitCode);
}

main().catch((error: unknown) => {
    console.error(`Error: ${error instanceof Error ? error.message : 'Vault operation failed.'}`);
    process.exitCode = 1;
});

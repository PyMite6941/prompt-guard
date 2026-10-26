#!/usr/bin/env node
import { scanText, generateSarif, ScanResult } from './scanner';
import * as fs from 'fs';
import * as path from 'path';

function main(): void {
    const args = process.argv.slice(2);
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

main();

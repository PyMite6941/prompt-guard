#!/usr/bin/env node
const { execFileSync, spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const excludedPaths = new Set([
    'README.md',
    'package-lock.json',
    'src/patterns.ts',
]);
const textExtensions = new Set([
    '.md',
    '.txt',
    '.ts',
    '.js',
    '.json',
    '.html',
    '.yaml',
    '.yml',
    '.env',
]);

function isTextFile(file) {
    const name = path.basename(file);
    return (
        textExtensions.has(path.extname(file)) ||
        name === '.env' ||
        name.startsWith('.env.')
    );
}

function isOutOfScope(file) {
    return (
        file.startsWith('examples/') ||
        file.startsWith('tests/') ||
        file.startsWith('docs/') ||
        excludedPaths.has(file)
    );
}

function main() {
    if (!fs.existsSync(path.join(process.cwd(), 'dist', 'cli.js'))) {
        throw new Error('dist/cli.js not found; run "npm run build" before committing.');
    }

    const staged = execFileSync(
        'git',
        ['diff', '--cached', '--name-only', '--diff-filter=ACM', '-z'],
        { encoding: 'utf8' },
    )
        .split('\0')
        .filter(Boolean);

    let scanned = 0;
    let failed = false;
    for (const file of staged) {
        if (isOutOfScope(file) || !isTextFile(file)) continue;
        if (!fs.existsSync(file)) continue;

        scanned += 1;
        const result = spawnSync(
            process.execPath,
            ['dist/cli.js', file, '--ignore=socialHandle'],
            { encoding: 'utf8', windowsHide: true },
        );
        if (result.error) {
            throw new Error(`Could not scan ${file}: ${result.error.message}`);
        }
        if (result.status !== 0) {
            console.error(`Prompt Guard blocked ${file}; inspect it with "node dist/cli.js ${file}".`);
            failed = true;
        }
    }

    if (failed) {
        process.exitCode = 1;
        console.error('Pre-commit scan failed.');
        return;
    }
    console.log(`Prompt Guard scanned ${scanned} staged file(s); no findings.`);
}

try {
    main();
} catch (error) {
    console.error(error instanceof Error ? error.message : 'Pre-commit scan failed.');
    process.exitCode = 1;
}

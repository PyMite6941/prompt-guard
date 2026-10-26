#!/usr/bin/env node
import { scanText } from './scanner';
import * as fs from 'fs';
import * as path from 'path';

const args = process.argv.slice(2);
const target = args.find((arg) => !arg.startsWith('--'));

const ignoreArg = args.find((arg) => arg.startsWith('--ignore='));
const ignoreList = ignoreArg
	? ignoreArg.replace('--ignore=', '').split(',')
	: [];

const jsonArg = args.includes('--json');

if (!target) {
	console.error('Error: Please provide a file or directory path to scan.');
	console.error('Usage: prompt-guard <path> [--ignore=email,apiKey] [--json]');
	process.exit(1);
}

if (!fs.existsSync(target)) {
	console.error(`Error: Path not found: ${target}`);
	process.exit(1);
}

let exitCode = 0;
const results: Array<{ file: string; result: ReturnType<typeof scanText> }> = [];

function scanFile(filePath: string): void {
	const content = fs.readFileSync(filePath, 'utf8');
	const result = scanText(content, { ignore: ignoreList });

	if (!result.isSafe) {
		if (jsonArg) {
			results.push({ file: filePath, result });
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

const stat = fs.statSync(target);
if (stat.isDirectory()) {
	walkDir(target);
} else {
	scanFile(target);
}

if (jsonArg) {
	console.log(JSON.stringify(
		results.map(r => ({
			file: r.file,
			isSafe: r.result.isSafe,
			matches: r.result.matches,
			sanitizedText: r.result.sanitizedText,
		})),
		null,
		2,
	));
}

process.exit(exitCode);

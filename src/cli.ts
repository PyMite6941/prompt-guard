#!/usr/bin/env node
import { scanText } from './scanner';
import * as fs from 'fs';

const args = process.argv.slice(2);
const filePath = args.find((arg) => !arg.startsWith('--'));

// Look for a flag like --ignore=email,creditCard
const ignoreArg = args.find((arg) => arg.startsWith('--ignore='));
const ignoreList = ignoreArg
	? ignoreArg.replace('--ignore=', '').split(',')
	: [];

if (!filePath) {
	console.error('Error: Please provide a file path to scan.');
	console.error('Usage: prompt-guard <file-path> [--ignore=email,apiKey]');
	process.exit(1);
}

const content = fs.readFileSync(filePath, 'utf8');
const result = scanText(content, { ignore: ignoreList });

if (!result.isSafe) {
	console.log('🚨 Security risk detected!');
	console.table(result.matches);
	console.log('\n--- Sanitized Preview ---');
	console.log(result.sanitizedText);
	process.exit(1);
} else {
	console.log('✅ Text is clean and safe.');
}

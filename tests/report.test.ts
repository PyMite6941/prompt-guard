import { afterEach, describe, expect, it } from 'vitest';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
	generateHtmlReport,
	generateJunitXml,
	appendAuditLog,
	readAuditLog,
} from '../src/report';
import { scanText } from '../src/scanner';

const directories: string[] = [];

async function makeDir(): Promise<string> {
	const directory = await mkdtemp(join(tmpdir(), 'prompt-guard-report-'));
	directories.push(directory);
	return directory;
}

afterEach(async () => {
	for (const directory of directories.splice(0)) {
		await rm(directory, { recursive: true, force: true });
	}
});

function scanFixture(text: string) {
	return scanText(text);
}

describe('generateHtmlReport', () => {
	it('renders a safe file report with no matches', () => {
		const result = scanFixture('Hello world, nothing sensitive here.');
		const html = generateHtmlReport([{ filePath: 'safe.txt', result }]);
		expect(html).toContain('safe.txt');
		expect(html).toContain('safe');
		expect(html).not.toContain('Hello world');
		expect(html).not.toContain('[REDACTED_');
	});

	it('renders unsafe files with counts and withholds values', () => {
		const result = scanFixture('Contact test@example.com and sk-proj-abcdefghijklmnopqrstuv.');
		const html = generateHtmlReport([{ filePath: 'leak.txt', result }]);
		expect(html).toContain('leak.txt');
		expect(html).toContain('unsafe');
		expect(html).toContain('email');
		expect(html).toContain('apiKey');
		// Detected values must not appear in the report.
		expect(html).not.toContain('test@example.com');
		expect(html).not.toContain('sk-proj-');
	});

	it('aggregates severity counts across multiple files', () => {
		const a = scanFixture('test@example.com');
		const b = scanFixture('sk-proj-abcdefghijklmnopqrstuv.');
		const html = generateHtmlReport([
			{ filePath: 'a.txt', result: a },
			{ filePath: 'b.txt', result: b },
		]);
		expect(html).toContain('2');
		expect(html).toContain('Critical');
	});

	it('includes optional title and generated-by', () => {
		const result = scanFixture('test@example.com');
		const html = generateHtmlReport([{ filePath: 'x.txt', result }], {
			title: 'My Scan',
			generatedBy: 'ci-runner',
		});
		expect(html).toContain('My Scan');
		expect(html).toContain('ci-runner');
	});
});

describe('generateJunitXml', () => {
	it('produces valid JUnit XML with failures for unsafe files', () => {
		const result = scanFixture('test@example.com');
		const xml = generateJunitXml([{ filePath: 'leak.txt', result }]);
		expect(xml).toContain('<?xml');
		expect(xml).toContain('<testsuites');
		expect(xml).toContain('<testsuite');
		expect(xml).toContain('<testcase');
		expect(xml).toContain('<failure');
		expect(xml).toContain('email');
		// Values withheld.
		expect(xml).not.toContain('test@example.com');
	});

	it('produces no failures for safe files', () => {
		const result = scanFixture('Hello world');
		const xml = generateJunitXml([{ filePath: 'safe.txt', result }]);
		expect(xml).not.toContain('<failure');
		expect(xml).toContain('testcase name="scan"');
	});

	it('escapes special characters in file paths and types', () => {
		const result = scanFixture('test@example.com');
		const xml = generateJunitXml([{ filePath: 'weird & "path".txt', result }]);
		expect(xml).toContain('weird &amp; &quot;path&quot;.txt');
	});
});

describe('audit log', () => {
	it('appends and reads JSON-lines entries without values', async () => {
		const directory = await makeDir();
		const logPath = join(directory, 'audit.log');
		const result = scanFixture('test@example.com');

		appendAuditLog(logPath, {
			filePath: 'leak.txt',
			isSafe: false,
			matchCount: result.matches.length,
			severityCounts: { critical: 0, high: 0, medium: 1, low: 0 },
			types: ['email'],
		});
		appendAuditLog(logPath, {
			filePath: 'safe.txt',
			isSafe: true,
			matchCount: 0,
			severityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
			types: [],
		});

		const entries = readAuditLog(logPath);
		expect(entries).toHaveLength(2);
		expect(entries[0].filePath).toBe('leak.txt');
		expect(entries[0].isSafe).toBe(false);
		expect(entries[0].matchCount).toBe(1);
		expect(entries[0].types).toEqual(['email']);
		expect(entries[1].isSafe).toBe(true);
		// Every entry has a timestamp.
		expect(entries[0].timestamp).toMatch(/\d{4}-\d{2}-\d{2}T/);
		expect(entries[1].timestamp).toMatch(/\d{4}-\d{2}-\d{2}T/);
	});

	it('returns empty array for missing log', async () => {
		const directory = await makeDir();
		const entries = readAuditLog(join(directory, 'does-not-exist.log'));
		expect(entries).toEqual([]);
	});

	it('skips corrupt lines but keeps valid ones', async () => {
		const directory = await makeDir();
		const logPath = join(directory, 'audit.log');
		await writeFile(logPath, '{not valid json\n', 'utf8');
		appendAuditLog(logPath, {
			filePath: 'ok.txt',
			isSafe: true,
			matchCount: 0,
			severityCounts: { critical: 0, high: 0, medium: 0, low: 0 },
			types: [],
		});
		const entries = readAuditLog(logPath);
		expect(entries).toHaveLength(1);
		expect(entries[0].filePath).toBe('ok.txt');
	});
});

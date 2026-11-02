import { PII_PATTERNS, INJECTION_PATTERNS } from './patterns';
import * as fs from 'fs';
import * as path from 'path';

/** Package version, reported as the SARIF tool version (works from src/ and dist/). */
export const TOOL_VERSION: string = (() => {
	try {
		const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
		return typeof pkg.version === 'string' ? pkg.version : '0.0.0';
	} catch {
		return '0.0.0';
	}
})();

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface ScanMatch {
	type: string;
	value: string;
	severity: Severity;
	start?: number;
	end?: number;
}

export interface ScanResult {
	isSafe: boolean;
	matches: ScanMatch[];
	sanitizedText: string;
}

export interface ScanOptions {
	ignore?: string[];
	minSeverity?: Severity | undefined;
	partialRedaction?: boolean;
	configPath?: string | undefined;
}

export interface PromptGuardConfig {
	ignore?: string[];
	minSeverity?: Severity | undefined;
	partialRedaction?: boolean;
	customPatterns?: Record<string, { pattern: string; severity: Severity }>;
}

export interface SarifRun {
	tool: {
		driver: {
			name: string;
			version: string;
			rules: SarifRule[];
		};
	};
	results: SarifResult[];
}

export interface SarifRule {
	id: string;
	name: string;
	shortDescription: { text: string };
	fullDescription: { text: string };
	help: { text: string };
	defaultConfiguration: { level: string };
}

export interface SarifResult {
	ruleId: string;
	ruleIndex: number;
	level: 'error' | 'warning' | 'note' | 'none';
	message: { text: string };
	locations: SarifLocation[];
}

export interface SarifLocation {
	physicalLocation: {
		artifactLocation: { uri: string };
		region: { startLine: number; startColumn: number; endLine: number; endColumn: number };
	};
}

export interface SarifLog {
	version: '2.1.0';
	$schema: string;
	runs: SarifRun[];
}

const DEFAULT_CONFIG: PromptGuardConfig = {
	ignore: [],
	minSeverity: undefined as Severity | undefined,
	partialRedaction: false,
	customPatterns: {},
};

export function loadConfig(configPath?: string): PromptGuardConfig {
	if (!configPath) {
		return { ...DEFAULT_CONFIG };
	}

	try {
		const raw = fs.readFileSync(configPath, 'utf8');
		const parsed = JSON.parse(raw) as PromptGuardConfig;
		return { ...DEFAULT_CONFIG, ...parsed };
	} catch {
		return { ...DEFAULT_CONFIG };
	}
}

function severityRank(sev: Severity): number {
	const rank: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
	return rank[sev];
}

function partialRedact(value: string, type: string): string {
	if (value.length <= 4) {
		return '[REDACTED_' + type.toUpperCase() + ']';
	}
	const last4 = value.slice(-4);
	const masked = '*'.repeat(value.length - 4);
	return masked + last4;
}

export function scanText(text: string, options: ScanOptions = {}): ScanResult {
	let config: PromptGuardConfig;
	if (options.configPath) {
		config = loadConfig(options.configPath);
	} else {
		config = loadConfig();
	}

	const ignoreList = options.ignore ?? config.ignore ?? [];
	const minSeverity = options.minSeverity ?? config.minSeverity ?? undefined;
	const partialRedaction = options.partialRedaction ?? config.partialRedaction ?? false;

	const minRank = minSeverity ? severityRank(minSeverity) : 0;
	let sanitizedText = text;
	const matches: ScanMatch[] = [];
	const redact = (value: string, type: string) =>
		partialRedaction ? partialRedact(value, type) : `[REDACTED_${type.toUpperCase()}]`;

	// Record every match at its exact offset in the original text, then redact
	// each occurrence with its own value (not the first match's value).
	const collectMatches = (pattern: RegExp, type: string, severity: Severity): void => {
		const globalPattern = pattern.global ? pattern : new RegExp(pattern.source, `${pattern.flags}g`);
		for (const match of text.matchAll(globalPattern)) {
			if (match[0].length === 0 || match.index === undefined) continue;
			matches.push({
				type,
				value: match[0],
				severity,
				start: match.index,
				end: match.index + match[0].length,
			});
		}
		sanitizedText = sanitizedText.replace(globalPattern, (value: string) =>
			value.length === 0 ? value : redact(value, type),
		);
	};

	for (const [type, def] of Object.entries(PII_PATTERNS)) {
		if (ignoreList.includes(type)) {
			continue;
		}
		const { pattern, severity } = def;
		if (severityRank(severity) < minRank) {
			continue;
		}
		collectMatches(pattern, type, severity);
	}

	if (!ignoreList.includes('prompt_injection')) {
		for (const def of INJECTION_PATTERNS) {
			const { pattern, severity } = def;
			if (severityRank(severity) < minRank) {
				continue;
			}
			if (pattern.test(text)) {
				const match = text.match(pattern);
				const val = match ? match[0] : pattern.source;
				const idx = text.indexOf(val);
				matches.push({
					type: 'prompt_injection',
					value: val,
					severity,
					start: idx >= 0 ? idx : 0,
					end: idx >= 0 ? idx + val.length : pattern.source.length,
				});
			}
		}
	}

	if (config.customPatterns) {
		for (const [type, def] of Object.entries(config.customPatterns)) {
			if (ignoreList.includes(type)) {
				continue;
			}
			try {
				const pattern = new RegExp(def.pattern, 'g');
				if (severityRank(def.severity) < minRank) {
					continue;
				}
				collectMatches(pattern, type, def.severity);
			} catch {
				// Skip invalid custom patterns
			}
		}
	}

	return {
		isSafe: matches.length === 0,
		matches,
		sanitizedText,
	};
}

/** Converts a character offset into a 1-based SARIF line/column position. */
function toPosition(text: string, offset: number): { line: number; column: number } {
	let line = 1;
	let lineStart = 0;
	for (let i = 0; i < offset && i < text.length; i++) {
		if (text[i] === '\n') {
			line++;
			lineStart = i + 1;
		}
	}
	return { line, column: offset - lineStart + 1 };
}

/**
 * Builds a SARIF log for one file. Pass the scanned `text` to get accurate
 * line/column regions; without it every region points at line 1.
 * Matched values are never copied into the report.
 */
export function generateSarif(filePath: string, result: ScanResult, text?: string): SarifLog {
	const rules: SarifRule[] = [];
	const results: SarifResult[] = [];
	const ruleMap: Record<string, number> = {};

	const severityToLevel: Record<Severity, 'error' | 'warning' | 'note' | 'none'> = {
		critical: 'error',
		high: 'warning',
		medium: 'note',
		low: 'note',
	};

	let ruleIndex = 0;
	result.matches.forEach((m) => {
		if (!Object.hasOwn(ruleMap, m.type)) {
			ruleMap[m.type] = ruleIndex;
			rules.push({
				id: m.type,
				name: m.type.replace(/_/g, ' ').toUpperCase(),
				shortDescription: { text: `${m.type} detected` },
				fullDescription: { text: `Prompt Guard detected a ${m.type} pattern with ${m.severity} severity.` },
				help: { text: 'Review and redact the detected pattern before sending to an AI model.' },
				defaultConfiguration: { level: severityToLevel[m.severity] },
			});
			ruleIndex++;
		}

		const hasOffsets = text !== undefined && m.start !== undefined && m.end !== undefined;
		const start = hasOffsets ? toPosition(text, m.start!) : { line: 1, column: 1 };
		const end = hasOffsets ? toPosition(text, m.end!) : { line: 1, column: m.value.length + 1 };

		results.push({
			ruleId: m.type,
			ruleIndex: ruleMap[m.type]!,
			level: severityToLevel[m.severity],
			message: { text: `${m.type} (${m.severity}) detected; value withheld from report.` },
			locations: [
				{
					physicalLocation: {
						artifactLocation: { uri: filePath },
						region: {
							startLine: start.line,
							startColumn: start.column,
							endLine: end.line,
							endColumn: end.column,
						},
					},
				},
			],
		});
	});

	return {
		version: '2.1.0',
		$schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
		runs: [
			{
				tool: {
					driver: {
						name: 'Prompt Guard',
						version: TOOL_VERSION,
						rules,
					},
				},
				results,
			},
		],
	};
}

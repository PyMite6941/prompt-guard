import { PII_PATTERNS, INJECTION_PATTERNS } from './patterns';
import * as fs from 'fs';
import * as path from 'path';

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
	schema: string;
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

	for (const [type, def] of Object.entries(PII_PATTERNS)) {
		if (ignoreList.includes(type)) {
			continue;
		}
		const { pattern, severity } = def;
		if (severityRank(severity) < minRank) {
			continue;
		}
		const found = text.match(pattern);
		if (found) {
			let offset = 0;
			for (const val of found) {
				const idx = text.indexOf(val, offset);
				if (idx >= 0) {
					matches.push({
						type,
						value: val,
						severity,
						start: idx,
						end: idx + val.length,
					});
					offset = idx + val.length;
				}
				const replacement = partialRedaction ? partialRedact(val, type) : `[REDACTED_${type.toUpperCase()}]`;
				sanitizedText = sanitizedText.replace(pattern, replacement);
			}
		}
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
				const found = text.match(pattern);
				if (found) {
					for (const val of found) {
						matches.push({
							type,
							value: val,
							severity: def.severity,
						});
						const replacement = partialRedaction ? partialRedact(val, type) : `[REDACTED_${type.toUpperCase()}]`;
						sanitizedText = sanitizedText.replace(pattern, replacement);
					}
				}
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

export function generateSarif(filePath: string, result: ScanResult): SarifLog {
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
		if (!ruleMap[m.type]) {
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

		results.push({
			ruleId: m.type,
			ruleIndex: ruleMap[m.type]!,
			level: severityToLevel[m.severity],
			message: { text: `${m.type} (${m.severity}): ${m.value}` },
			locations: [
				{
					physicalLocation: {
						artifactLocation: { uri: filePath },
						region: {
							startLine: 1,
							startColumn: 1,
							endLine: 1,
							endColumn: m.value.length + 1,
						},
					},
				},
			],
		});
	});

	return {
		version: '2.1.0',
		schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
		runs: [
			{
				tool: {
					driver: {
						name: 'Prompt Guard',
						version: '2.0.0',
						rules,
					},
				},
				results,
			},
		],
	};
}

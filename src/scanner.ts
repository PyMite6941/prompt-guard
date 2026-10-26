import { PII_PATTERNS, INJECTION_PATTERNS } from './patterns';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface ScanMatch {
	type: string;
	value: string;
	severity: Severity;
}

export interface ScanResult {
	isSafe: boolean;
	matches: ScanMatch[];
	sanitizedText: string;
}

export interface ScanOptions {
	ignore?: string[];
	minSeverity?: Severity | undefined;
}

export function scanText(text: string, options: ScanOptions = {}): ScanResult {
	let sanitizedText = text;
	const matches: ScanMatch[] = [];
	const ignoreList = options.ignore || [];
	const minSeverity = options.minSeverity;
	const severityRank: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
	const minRank = minSeverity ? severityRank[minSeverity] : 0;

	// Check PII
	for (const [type, def] of Object.entries(PII_PATTERNS)) {
		if (ignoreList.includes(type)) {
			continue;
		}
		const { pattern, severity } = def;
		if (severityRank[severity] < minRank) {
			continue;
		}
		const found = text.match(pattern);
		if (found) {
			found.forEach((val) => matches.push({ type, value: val, severity }));
			sanitizedText = sanitizedText.replace(
				pattern,
				`[REDACTED_${type.toUpperCase()}]`,
			);
		}
	}

	if (!ignoreList.includes('prompt_injection')) {
		// Check Prompt Injections
		for (const def of INJECTION_PATTERNS) {
			const { pattern, severity } = def;
			if (severityRank[severity] < minRank) {
				continue;
			}
			if (pattern.test(text)) {
				matches.push({ type: 'prompt_injection', value: pattern.source, severity });
			}
		}
	}

	return {
		isSafe: matches.length === 0,
		matches,
		sanitizedText,
	};
}

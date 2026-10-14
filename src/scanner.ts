import { PII_PATTERNS, INJECTION_PATTERNS } from './patterns';

export interface ScanResult {
	isSafe: boolean;
	matches: { type: string; value: string }[];
	sanitizedText: string;
}

export interface ScanOptions {
	ignore?: string[];
}

export function scanText(text: string, options: ScanOptions = {}): ScanResult {
	let sanitizedText = text;
	const matches: { type: string; value: string }[] = [];
	const ignoreList = options.ignore || [];

	// Check PII
	for (const [type, pattern] of Object.entries(PII_PATTERNS)) {
		if (ignoreList.includes(type)) {
			continue;
		}

		const found = text.match(pattern);
		if (found) {
			found.forEach((val) => matches.push({ type, value: val }));
			sanitizedText = sanitizedText.replace(
				pattern,
				`[REDACTED_${type.toUpperCase()}]`,
			);
		}
	}

	if (!ignoreList.includes('prompt_injection')) {
		// Check Prompt Injections
		for (const pattern of INJECTION_PATTERNS) {
			if (pattern.test(text)) {
				matches.push({ type: 'prompt_injection', value: pattern.source });
			}
		}
	}

	return {
		isSafe: matches.length === 0,
		matches,
		sanitizedText,
	};
}

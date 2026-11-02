export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface Piipattern {
	pattern: RegExp;
	severity: Severity;
}

export const PII_PATTERNS: Record<string, Piipattern> = {
	email: {
		pattern: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
		severity: 'medium',
	},
	socialHandle: {
		// The lookahead also rejects "/" and "-" so npm scopes like @types/node are not handles.
		pattern: /(?<![\w@])@[A-Za-z0-9_]{1,30}(?![\w./-])/g,
		severity: 'low',
	},
	creditCard: {
		pattern: /\b(?:\d[ -]?){12,18}\d\b/g,
		severity: 'critical',
	},
	apiKey: {
		pattern: /\b(sk-(?:proj-)?[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b/g,
		severity: 'critical',
	},
	githubToken: {
		pattern: /\b(ghp_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{80,})\b/g,
		severity: 'critical',
	},
	awsSecretKey: {
		pattern: /\b[A-Za-z0-9/+=]{40}\b/g,
		severity: 'critical',
	},
	databaseUrl: {
		pattern: /\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[^\s:@]+:[^\s:@]+@[^\s]+\b/g,
		severity: 'critical',
	},
	jwtToken: {
		// JWT headers are base64url-encoded JSON, so they always start with "eyJ" ('{"').
		pattern: /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
		severity: 'high',
	},
	stripeKey: {
		pattern: /\b(sk_(?:live|test)_[A-Za-z0-9]{24,})\b/g,
		severity: 'critical',
	},
	sshPrivateKey: {
		pattern: /-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g,
		severity: 'critical',
	},
	ipAddress: {
		pattern: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
		severity: 'low',
	},
	phoneNumber: {
		pattern: /(?<!\w)\+?(?:\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)/g,
		severity: 'medium',
	},
	ssn: {
		pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
		severity: 'high',
	},
	pgpPrivateKey: {
		pattern: /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
		severity: 'critical',
	},
	ecPrivateKey: {
		pattern: /-----BEGIN EC PRIVATE KEY-----/g,
		severity: 'critical',
	},
	pkcs8PrivateKey: {
		pattern: /-----BEGIN PRIVATE KEY-----/g,
		severity: 'critical',
	},
	azureConnectionString: {
		pattern: /DefaultEndpointsProtocol=https;[^;\s]+;AccountKey=[^;\s]+/g,
		severity: 'critical',
	},
	sendgridKey: {
		pattern: /\bSG\.[A-Za-z0-9_-]{22,}\.[A-Za-z0-9_-]{22,}\b/g,
		severity: 'critical',
	},
	gcpServiceAccount: {
		pattern: /"type"\s*:\s*"service_account"/g,
		severity: 'critical',
	},
	ethereumAddress: {
		pattern: /\b0x[a-fA-F0-9]{40}\b/g,
		severity: 'low',
	},
	bitcoinAddress: {
		pattern: /\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g,
		severity: 'low',
	},
	iban: {
		pattern: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b/g,
		severity: 'medium',
	},
};

export const INJECTION_PATTERNS: Array<{ pattern: RegExp; severity: Severity }> = [
	{ pattern: /ignore previous instructions/i, severity: 'critical' },
	{ pattern: /disregard previous instructions/i, severity: 'critical' },
	{ pattern: /system prompt/i, severity: 'high' },
	{ pattern: /you are now unbound/i, severity: 'high' },
	{ pattern: /you are now (in developer mode|DAN|do anything now)/i, severity: 'high' },
];

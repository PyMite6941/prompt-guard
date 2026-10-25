export const PII_PATTERNS = {
	email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
	socialHandle:
		/(?<![\w@])@[A-Za-z0-9_]{1,30}(?!\.)/g,
	creditCard: /\b(?:\d[ -]?){12,18}\d\b/g,
	apiKey: /\b(sk-(?:proj-)?[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b/g,
	ipAddress: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
	phoneNumber:
		/(?<!\w)\+?(?:\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)/g,
	ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
};

export const INJECTION_PATTERNS = [
	/ignore previous instructions/i,
	/system prompt/i,
	/you are now unbound/i,
];

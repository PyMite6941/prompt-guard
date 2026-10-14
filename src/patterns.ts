export const PII_PATTERNS = {
	email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
	creditCard: /\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b/g,
	apiKey: /\b(sk-[a-zA-Z0-9]{20,}|AKIA[0-9A-Z]{16})\b/g,
	ipAddress: /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
	phoneNumber: /\b(?:\?(\d{1,3}))?[-. (]*(\d{3})[-. ]*(\d{4})\b/g,
};

export const INJECTION_PATTERNS = [
	/ignore previous instructions/i,
	/system prompt/i,
	/you are now unbound/i,
];

import { OpenAI } from 'openai';
import { scanText } from './scanner';

// Initialize the OpenAI client (picks up OPENAI_API_KEY from environment variables)
const openai = new OpenAI();

export interface SafePromptOptions {
	model?: string;
	autoSanitize?: boolean; // If true, replaces PII but still blocks prompt injection
}

export async function callAIGuarded(
	userPrompt: string,
	options: SafePromptOptions = {},
) {
	const model = options.model || 'gpt-4o-mini';
	const autoSanitize = options.autoSanitize ?? false;

	// Step 1: Run your local security scan
	const scanResult = scanText(userPrompt);

	let promptToSend = userPrompt;

	if (!scanResult.isSafe) {
		if (scanResult.matches.some((match) => match.type === 'prompt_injection')) {
			throw new Error('Security Violation Blocked: Prompt injection detected');
		}

		if (autoSanitize) {
			console.warn('⚠️ PII detected. Using sanitized text.');
			promptToSend = scanResult.sanitizedText;
		} else {
			throw new Error(
				`Security Violation Blocked: Found ${scanResult.matches.map((m) => m.type).join(', ')}`,
			);
		}
	}

	// Step 2: Make the safe API call to OpenAI
	const response = await openai.chat.completions.create({
		model: model,
		messages: [{ role: 'user', content: promptToSend }],
	});

	return response.choices[0]?.message.content ?? null;
}

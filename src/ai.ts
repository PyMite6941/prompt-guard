import { OpenAI } from 'openai';
import { scanText } from './scanner';

// Initialize the OpenAI client (picks up OPENAI_API_KEY from environment variables)
const openai = new OpenAI();

export interface SafePromptOptions {
	model?: string;
	autoSanitize?: boolean; // If true, replaces PII instead of throwing an error
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
		if (autoSanitize) {
			console.warn('⚠️ PII or injection detected. Using sanitized text.');
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

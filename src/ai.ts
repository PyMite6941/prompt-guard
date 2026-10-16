import { OpenAI } from 'openai';
import { scanText } from './scanner';

let sharedOpenai: OpenAI | null = null;

export interface SafePromptOptions {
    model?: string;
    autoSanitize?: boolean; // If true, replaces PII but still blocks prompt injection
    apiKey?: string; // Overrides OPENAI_API_KEY from environment
    baseURL?: string; // Base URL for the API (for OpenAI-compatible endpoints)
    maxInputTokens?: number; // Approximate maximum input tokens (will truncate prompt)
    maxOutputTokens?: number; // Maximum tokens in the model's response
}

/**
 * Call an AI model with prompt guarding.
 * @param userPrompt The raw prompt from the user.
 * @param options Configuration options.
 * @returns The model's response text, or null if no response.
 */
export async function callAIGuarded(
    userPrompt: string,
    options: SafePromptOptions = {},
) {
    // Determine model and sanitize preference
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

    // Step 2: Optionally truncate the prompt to reduce input tokens
    if (options.maxInputTokens !== undefined) {
        // Rough approximation: 1 token ≈ 4 characters for English text.
        // Adjust if needed for other languages or tokenizers.
        const maxChars = options.maxInputTokens * 4;
        if (promptToSend.length > maxChars) {
            console.warn(`⚠️ Prompt truncated from ${promptToSend.length} to ${maxChars} characters to limit input tokens.`);
            promptToSend = promptToSend.slice(0, maxChars);
        }
    }

    // Step 3: Configure the OpenAI client
    let openaiInstance: OpenAI;
    if (options.apiKey || options.baseURL) {
        // If overriding API key or base URL, create a new instance
        openaiInstance = new OpenAI({
            apiKey: options.apiKey,
            baseURL: options.baseURL,
        });
    } else {
        // Use the shared instance (lazy initialization)
        if (!sharedOpenai) {
            sharedOpenai = new OpenAI();
        }
        openaiInstance = sharedOpenai;
    }

    // Step 4: Make the safe API call to the model
    const response = await openaiInstance.chat.completions.create({
        model: model,
        messages: [{ role: 'user', content: promptToSend }],
        ...(options.maxOutputTokens !== undefined && { max_tokens: options.maxOutputTokens }),
    });

    return response.choices[0]?.message.content ?? null;
}

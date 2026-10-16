# Prompt Guard

Project site: [Prompt Guard](https://pymite6941.is-a.dev/prompt-guard/)

Detailed guides: [Setup](docs/setup.html) · [Usage](docs/usage.html)

Prompt Guard is a lightweight TypeScript scanner for identifying common
personally identifiable information (PII) and prompt-injection phrases in
prompts before you pass them to an AI model. It can also redact detected PII
from a sanitized preview.

The `scanText` scanner runs locally and does not send text to an external
service. The optional `callAIGuarded` helper sends accepted prompts to OpenAI.

## What it detects

- Email addresses
- 13–19 digit credit-card-shaped numbers
- API keys matching common OpenAI (`sk-...`, including `sk-proj-...`) and AWS
  (`AKIA...`) formats
- IPv4-shaped addresses
- Phone-number-shaped strings
- Prompt-injection phrases such as “ignore previous instructions”

This is a best-effort pattern-based check, not a substitute for a complete
security review or validation of payment-card numbers. A detected injection
phrase is reported but is not removed from `sanitizedText`.

## Requirements

- Node.js
- npm

## Setup

From a clone of this repository, build and link the CLI globally:

```sh
npm install
npm run build
npm link
```

Alternatively, install the package globally from the repository directory:

```sh
npm install -g .
```

To install the published package from npm, use:

```sh
npm install -g @ai-clyde/promptguard
```

The scoped package has not been published yet. Until it is available, install
from this repository with the local steps above.

## CLI usage

After linking or installing, scan a text file:

```sh
prompt-guard examples/clean.txt
prompt-guard examples/leak.txt
```

After the package is published to npm, the same command can be run with npx:

```sh
npx @ai-clyde/promptguard examples/clean.txt
```

The CLI prints a sanitized preview when it detects issues and exits with status
`1`; clean input exits with status `0`. To skip a category, pass a comma-separated
list of match types:

```sh
prompt-guard examples/leak.txt --ignore=email,creditCard
```

Supported ignore names include `email`, `creditCard`, `apiKey`, `ipAddress`,
`phoneNumber`, and `prompt_injection`. Ignored categories are neither reported
nor redacted.

## Programmatic usage
Import \`scanText\` and \`callAIGuarded\` from the package:

\`\`\`ts
import { scanText, callAIGuarded } from '@ai-clyde/promptguard';

const result = scanText(userPrompt);

if (!result.isSafe) {
  console.warn('Prompt checks found:', result.matches.map(({ type }) => type));
  // Decide whether to block the request or use result.sanitizedText.
} else {
  // Safe to continue according to the configured pattern checks.
}
\`\`\`

\`scanText\` returns:

- \`isSafe\`: \`true\` when no configured pattern matched.
- \`matches\`: detected match types and values.
- \`sanitizedText\`: input with detected PII replaced by redaction markers.

Injection phrases are included in \`matches\` but are not redacted from
\`sanitizedText\`. Handle them according to your application's policy. The
\`callAIGuarded\` helper blocks prompts with detected injection phrases even when
\`autoSanitize\` is enabled; that option only redacts PII.

## Guarded OpenAI calls
The optional `callAIGuarded` helper checks and sends a prompt to an AI model (default: OpenAI). Set `OPENAI_API_KEY` in the environment before importing or calling it. You can also override the API key and base URL via options to use OpenAI-compatible endpoints.

```ts
import { callAIGuarded } from '@ai-clyde/promptguard';

const answer = await callAIGuarded(userPrompt, { 
    autoSanitize: true,
    maxInputTokens: 100,   //约束输入令牌数（约字符数）
    maxOutputTokens: 50,   //限制输出令牌数
    apiKey: process.env.CUSTOM_API_KEY, // 可选
    baseURL: process.env.CUSTOM_BASE_URL, // 可选
});
```

With `autoSanitize: true`, detected PII is redacted before sending. Prompt injection detections always block the request; they are not safe to auto-remove with the current pattern-based scanner.

### Environment Variables

Create a `.env` file (see `.env.example`) to configure:

- `OPENAI_API_KEY`: Your OpenAI API key (or compatible service)
- `OPENAI_BASE_URL`: Base URL for the API (default: `https://api.openai.com/v1`)
- `OPENAI_ORG_ID`: Optional OpenAI organization ID

### Options

The `callAIGuarded` function accepts an options object with:

- `model`: Model name (default: `gpt-4o-mini`)
- `autoSanitize`: Redact PII before sending (default: `false`)
- `apiKey`: Override the API key from environment
- `baseURL`: Override the base URL from environment
- `maxInputTokens`: Approximate maximum input tokens (truncates prompt if exceeded)
- `maxOutputTokens`: Maximum tokens in the model's response

### Token Compression

To reduce input tokens, set `maxInputTokens`. The prompt will be truncated to approximately `maxInputTokens * 4` characters (a rough estimate for English). For more precise token counting, preprocess your prompt with a tokenizer before calling.

### End-to-End Protection (Future Work)

For true end-to-end encryption, consider using a trusted proxy that decrypts the prompt before forwarding to the model. This library does not currently implement encryption because the model requires plaintext input.

## Development

```sh
npm install
npm test
npm run build
```

## Data Handling

Prompt Guard does not cache or store your prompts. The `scanText` function operates entirely in memory and does not send data to any external service. The `callAIGuarded` function only sends the sanitized prompt (after optional truncation) to the configured AI model. No additional metadata, cache files, or conversation history is transmitted unless you include it in the prompt yourself.

The `examples/` directory contains harmless sample input for trying the CLI.

# Prompt Guard

Project site: [Prompt Guard](https://pymite6941.is-a.dev/prompt-guard/)

Prompt Guard is a lightweight TypeScript scanner for identifying common
personally identifiable information (PII) and prompt-injection phrases in
prompts before you pass them to an AI model. It can also redact detected PII
from a sanitized preview.

The scanner runs locally and does not send text to an external service.

## What it detects

- Email addresses
- Credit-card-shaped numbers
- API keys matching common OpenAI (`sk-...`) and AWS (`AKIA...`) formats
- IPv4-shaped addresses
- Phone-number-shaped strings
- Prompt-injection phrases such as “ignore previous instructions”

This is a best-effort pattern-based check, not a substitute for a complete
security review or validation of payment-card numbers. A detected injection
phrase is reported but is not removed from `sanitizedText`.

## Requirements

- Node.js
- npm

## Install locally

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

## CLI usage

After linking or installing, scan a text file:

```sh
prompt-guard examples/clean.txt
prompt-guard examples/leak.txt
```

When the package is published to npm, the same command can be run with npx:

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

Import `scanText` from the package in a TypeScript service, Express backend, or
AI application:

```ts
import { scanText } from '@ai-clyde/promptguard';

const result = scanText(userPrompt);

if (!result.isSafe) {
  console.warn('Prompt checks found:', result.matches.map(({ type }) => type));
  // Decide whether to block the request or use result.sanitizedText.
} else {
  // Safe to continue according to the configured pattern checks.
}
```

`scanText` returns:

- `isSafe`: `true` when no configured pattern matched.
- `matches`: detected match types and values.
- `sanitizedText`: input with detected PII replaced by redaction markers.

Injection phrases are included in `matches` but are not redacted from
`sanitizedText`. Handle them according to your application's policy.

## Development

```sh
npm install
npm test
npm run build
```

The `examples/` directory contains harmless sample input for trying the CLI.

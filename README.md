# Prompt Guard

Project site: [Prompt Guard](https://pymite6941.is-a.dev/prompt-guard/)

Detailed guides: [Setup](docs/setup.html) · [Usage](docs/usage.html)

Prompt Guard is a lightweight TypeScript scanner that flags personally identifiable information (PII) and prompt-injection phrases **before** a prompt reaches an AI model. The `scanText` scanner runs entirely in memory — no network calls. The optional `callAIGuarded` helper runs the scan, then forwards accepted prompts to OpenAI or any OpenAI-compatible endpoint (including a local Ollama model for **zero API cost**).

## Table of contents

- [What it detects](#what-it-detects)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [CLI usage](#cli-usage)
- [Programmatic usage](#programmatic-usage)
- [Guarded AI calls (`callAIGuarded`)](#guarded-ai-calls-callaguarded)
- [Local models — zero API cost](#local-models---zero-api-cost)
- [Environment variables](#environment-variables)
- [Options reference](#options-reference)
- [CI integration](#ci-integration)
- [Pre-commit hook](#pre-commit-hook)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Data handling](#data-handling)
- [License](#license)

---

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
    maxInputTokens: 100,   // cap input tokens (~chars / 4)
    maxOutputTokens: 50,   // cap output tokens
    apiKey: process.env.OPENAI_API_KEY,   // optional override
    baseURL: process.env.CUSTOM_BASE_URL, // optional OpenAI-compatible endpoint
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

### Local Models (zero API cost)

You are not locked into OpenAI. Set `baseURL` to any OpenAI-compatible endpoint (e.g. a locally running Ollama at `http://localhost:11434/v1`) and pass any non-empty `apiKey` (Ollama ignores it). This keeps all prompt data on your machine with zero OpenAI API cost.

```ts
const answer = await callAIGuarded(userPrompt, {
    model: 'llama3:latest',
    baseURL: 'http://localhost:11434/v1',
    apiKey: 'ollama',   // required by the client; ignored by Ollama
    autoSanitize: true,
});
```

Start Ollama (`ollama serve`) and pull a model (`ollama pull llama3`) before calling. `callAIGuarded` still scans and blocks prompt injection locally before anything reaches the model.

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

---

## Environment variables

Create a `.env` file (copy from `.env.example`):

```sh
cp .env.example .env
# edit .env with your values
```

| Variable | Purpose | Required for |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI (or compatible) API key | OpenAI calls |
| `OPENAI_BASE_URL` | API base URL (default `https://api.openai.com/v1`) | Local/proxy endpoints |
| `OPENAI_ORG_ID` | Optional OpenAI organization ID | OpenAI calls |

`callAIGuarded` loads `.env` automatically via `dotenv` — no manual `export` needed. Options passed to `callAIGuarded` take precedence over environment variables.

---

## Options reference

| Option | Type | Default | Description |
|---|---|---|---|
| `model` | `string` | `'gpt-4o-mini'` | Model name |
| `autoSanitize` | `boolean` | `false` | Redact PII before sending |
| `apiKey` | `string` | `OPENAI_API_KEY` env | API key override |
| `baseURL` | `string` | `OPENAI_BASE_URL` env | OpenAI-compatible endpoint |
| `maxInputTokens` | `number` | `undefined` | Approx. max input tokens (truncates) |
| `maxOutputTokens` | `number` | `undefined` | Max output tokens |

`ScanOptions` for `scanText`:
- `ignore` (`string[]`) — categories to skip (`email`, `creditCard`, `apiKey`, `ipAddress`, `phoneNumber`, `prompt_injection`)

---

## CI integration

A GitHub Actions gate runs on every push/PR to `master`. It installs, builds, tests, then:

1. Scans `examples/clean.txt` — must pass (exit 0)
2. Scans `examples/leak.txt` as a **negative control** — the step fails only if the unsafe file slips through (exit 1)

Workflow: `.github/workflows/scan.yml`. No API key required — the scanner is fully local.

```yaml
name: Scan prompts with Prompt Guard
on:
  push:
    branches: [master]
  pull_request:
    branches: [master]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
      - run: npm ci
      - run: npm run build
      - run: npm test
      - run: node dist/cli.js examples/clean.txt            # must pass
      - run: |
          if node dist/cli.js examples/leak.txt; then
            echo "ERROR: leak.txt was not flagged" >&2
            exit 1
          fi                                              # negative control
```

---

## Pre-commit hook

A committed hook script scans staged text files on every commit and blocks the commit if anything is unsafe.

`scripts/pre-commit.sh` is in the repository. Git hooks cannot be tracked directly, so install it once per clone:

```sh
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit scripts/pre-commit.sh
```

Or run it manually anytime:

```sh
npm run pre-commit
```

Scanned extensions: `.md`, `.txt`, `.ts`, `.js`, `.json`, `.html`, `.yaml`, `.yml`, `.env.example`. Non-text files are skipped automatically.

---

## Troubleshooting

### `tsc` reports `TS18003: No inputs found` despite `src/` existing

**Cause:** This machine's `tsc` version fails to expand `include: ["src/**/*.ts"]` globs under non-ASCII paths (e.g. `OneDrive/ドキュメント/…`). It silently returns an empty input set.

**Fix (already applied in this repo):** `tsconfig.json` uses a `files:` array listing every source file explicitly instead of an `include:` glob. `files:` matches reliably where globs do not.

```json
"files": ["src/index.ts", "src/scanner.ts", "src/patterns.ts", "src/ai.ts", "src/cli.ts"]
```

Do not rename the project directory or patch source to work around this — the defect is in `tsc` path resolution, not the source.

### `npm test` passes but `npm run build` fails

Vitest transforms TypeScript directly and does not use `tsc`/`include`. A green test suite does **not** prove the build works — always verify `npm run build` separately and confirm `dist/` timestamps are newer than `src/`.

### `callAIGuarded` throws "Cannot find module 'openai'"

Run `npm install` first. The `openai` package is a runtime dependency.

### Local Ollama returns connection refused

Start the server: `ollama serve`. Then pull a model: `ollama pull llama3`. Confirm it's reachable:

```sh
curl http://localhost:11434/api/tags
```

---

## Development

```sh
npm install
npm test      # vitest — 17 tests across scanner, ai, and CLI integration
npm run build # tsc — outputs to dist/
```

### Adding a check
1. Add a pattern to `src/patterns.ts` (`PII_PATTERNS` or `INJECTION_PATTERNS`)
2. Add a test to `tests/scanner.test.ts`
3. Run `npm test && npm run build`

---

## Data handling

Prompt Guard does not cache or store your prompts. `scanText` operates entirely in memory and sends nothing externally. `callAIGuarded` sends only the accepted (optionally sanitized and truncated) prompt to the configured model. No metadata, cache files, or conversation history is transmitted unless you include it in the prompt itself.

---

## License

MIT. See [LICENSE](LICENSE).

# Prompt Guard

Project site: [Prompt Guard](https://pymite6941.is-a.dev/prompt-guard/)

Detailed guides: [Setup](docs/setup.html) · [Usage](docs/usage.html)

Prompt Guard is a lightweight TypeScript scanner that flags personally identifiable information (PII) and prompt-injection phrases **before** a prompt reaches an AI model. The `scanText` scanner runs entirely in memory — no network calls. The optional `callAIGuarded` helper runs the scan, then forwards accepted prompts to OpenAI or any OpenAI-compatible endpoint (including a local Ollama model for **zero API cost**).

## Table of contents

- [What it detects](#what-it-detects)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [CLI usage](#cli-usage)
- [Claude Code hook](#claude-code-hook)
- [Programmatic usage](#programmatic-usage)
- [Local secret vault](#local-secret-vault)
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

### PII Detection

- Email addresses
- Social media handles (@username on X, Instagram, TikTok)
- 13–19 digit credit-card-shaped numbers
- Social Security Numbers (XXX-XX-XXXX)
- Phone-number-shaped strings
- IPv4-shaped addresses

### Secret Detection

- API keys (OpenAI `sk-...`, `sk-proj-...`, AWS `AKIA...`)
- GitHub tokens (`ghp_*`, `github_pat_*`)
- AWS secret access keys (40-char base64)
- Stripe keys (`sk_live_*`, `sk_test_*`)
- Database connection strings (`postgres://user:pass@host`, etc.)
- JWT tokens
- SSH private keys (`-----BEGIN ... PRIVATE KEY-----`)

### Prompt Injection

- Phrases such as “ignore previous instructions”, “system prompt”, “you are now unbound”

These are the details you would not want posted publicly — they make content **social-safe** before sharing.

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

Supported ignore names: `email`, `socialHandle`, `creditCard`, `apiKey`,
`githubToken`, `awsSecretKey`, `databaseUrl`, `jwtToken`, `stripeKey`,
`sshPrivateKey`, `ipAddress`, `phoneNumber`, `ssn`, `prompt_injection`.
Ignored categories are neither reported nor redacted.

### CLI flags

| Flag | Description |
|------|-------------|
| `--ignore=cat1,cat2` | Skip comma-separated categories |
| `--json` | Output machine-readable JSON results |
| `--sarif` | Output SARIF 2.1.0 log (for code scanning tools) |
| `--partial-redaction` | Show last 4 chars instead of full redaction |
| `--config=path` | Load configuration from a `.promptguardrc` file |
| `--tui` / `-t` | Launch the terminal user interface |

### Terminal UI (TUI)

Launch a full-screen terminal interface with navigation:

```sh
prompt-guard --tui
# or
prompt-guard -t
```

The TUI provides:
- **Dashboard** — scan statistics with severity breakdown
- **Scan File / Scan Directory** — scan individual files or recursive directories
- **View Results** — detailed match listing with type and severity
- **Sanitized Text** — view PII-redacted output
- **Configuration** — edit ignore list, set minimum severity, reset defaults
- **Export JSON** — machine-readable JSON output
- **About** — version and license info

Navigate with arrow keys, select with Enter, press `q` to quit.

## Local secret vault

The local vault keeps credentials encrypted on disk and lets a trusted
application use a secret by ID without making the secret itself a model-facing
tool result. Secret IDs may appear in prompts; values must not. The CLI asks for
passphrases and secret values without echoing them, and never accepts secret
values as command-line arguments:

```sh
prompt-guard vault set deployment-token        # interactive: enter passphrase + value
prompt-guard vault list                        # print IDs only
prompt-guard vault delete deployment-token
prompt-guard vault catalog                     # safe agent-visible metadata only
prompt-guard vault capture prompt.txt          # store detections and print redacted prompt
prompt-guard vault export vault-backup.json    # encrypted backup
prompt-guard vault import vault-backup.json    # restore backup
prompt-guard vault popup                       # interactive terminal GUI
```

`vault export` writes an encrypted backup. `vault import` verifies the backup
with the vault passphrase and replaces the default vault; back up the current
vault first if you need to keep it. Import paths may refer to files outside the
current directory, while export paths are restricted to the current directory
to prevent accidental path traversal.

### Interactive popup GUI (`vault popup`)

`prompt-guard vault popup` opens a `blessed` terminal GUI for managing secrets
without typing commands:

- **Name** — e.g. `NVIDIA NIM API` (typed manually)
- **Tag** — pick from `password | API | key | token | secret | other`
- **Secret ID** — auto-derived from the name (slugified, de-duplicated); visible
  in the list but **read-only**, not editable
- **Value** — hidden input, encrypted at rest with AES-256-GCM

Keys: `a` add, `v` show a safe metadata preview, `d` delete (confirm), `r`
refresh, `h` help, `q`/Esc quit, `Tab` switches focus. Esc inside a prompt
cancels that prompt without storing anything. The popup never reveals secret
values. It requires an interactive terminal.

### Capture and redact prompts locally

Before a prompt reaches a model, pass it through the already-unlocked vault.
Known stored values are replaced, and scanner-detected PII/credentials are
encrypted into the vault and replaced with opaque IDs:

```ts
const protectedPrompt = await vault.captureAndRedactPrompt(incomingPrompt);
// Detection is best-effort. Require a human to review the prompt locally;
// do not send it to a model until that review explicitly approves it.
const approvedPrompt = await reviewPromptLocally(protectedPrompt);
const answer = await callAIGuarded(approvedPrompt, { autoSanitize: true });
```

`reviewPromptLocally` above represents a human-review step that your application
must implement; the vault does not approve or forward prompts. `manualReviewRequired`
is always true because detection is best-effort and cannot identify every
possible secret. The `capture` CLI command prints the capture result for local
review; do not pipe its output directly to a model. It prompts for the vault
passphrase without echo and never reads it from an environment variable or
command-line argument. `PROMPT_GUARD_VAULT_PATH` selects another vault file.

The first `set` creates an encrypted vault and asks you to confirm its
passphrase. CLI management commands require an interactive terminal. There is
deliberately no `vault get` command or passphrase environment variable, so
automation cannot accidentally print a resolved value into model-visible
stdout.

### Name and tag metadata

Each secret can carry a human-readable `name` and a `tag` (e.g. `API`,
`password`, `token`). IDs, names, and tags are encrypted at rest; the popup and
trusted package API can display local labels. Version 1 vaults are migrated to
the encrypted-metadata format when opened:

```ts
import { SecretVault } from '@ai-clyde/promptguard';

const vault = await SecretVault.open({ passphrase, path });
await vault.setSecret('nvidia-nim-api', '<api-key>');
await vault.setSecretMeta('nvidia-nim-api', { name: 'NVIDIA NIM API', tag: 'API' });
const listed = vault.listSecretsWithMeta(); // local metadata for trusted UI
vault.close();
```

For an agent, use only `getAgentCatalog()` or the output of `vault catalog`.
The catalog contains an ID, a generic title, a fixed redacted preview, and
host-operation guidance—never the stored value, a suffix, or arbitrary
user-supplied labels. `createVaultCatalogTool(vault)` provides a
zero-argument, model-facing catalog tool that can be adapted to a harness's
tool-registration API:

```ts
import { createVaultCatalogTool } from '@ai-clyde/promptguard';

const catalogTool = createVaultCatalogTool(vault);
registerHarnessTool({
  name: catalogTool.name,
  description: catalogTool.description,
  inputSchema: catalogTool.inputSchema,
  execute: catalogTool.execute,
});
```

Do not register a model-facing tool that calls `withSecret`. Bind IDs inside
host-controlled local operations instead.

### Trusted host code usage

```ts
import { SecretVault } from '@ai-clyde/promptguard';

async function runApprovedDeployment() {
  const vault = await SecretVault.open({
    passphrase: await readPassphraseFromYourOSKeychain(),
  });
  try {
    // Keep the ID fixed by host policy; do not expose a generic "get secret" tool.
    return await vault.withSecret('deployment-token', (token) =>
      deployApprovedArtifact({ token }),
    );
  } finally {
    vault.close();
  }
}
```

`withSecret` supplies a temporary `Buffer` to trusted local host code and
zeroes that buffer after the callback completes; do not retain or copy it.
Bind a fixed ID to a host-controlled, allow-listed local operation; do not make
a generic model-facing “get secret” tool. Return only non-secret outcomes.
Ensure the handler does not put credentials in prompts, tool results, logs,
traces, or telemetry. A
model-controlled shell or unrestricted local process with the same OS account
can bypass application-level restrictions; use your harness's tool allowlists
and process isolation for that threat model. Prompt Guard cannot guarantee
that a secret stays local if a host deliberately sends it to a cloud API.

Vault files use scrypt-derived keys and AES-256-GCM authenticated encryption.
Use a unique, strong passphrase and keep a recoverable copy outside the vault;
losing it means the encrypted secrets cannot be recovered. The vault is local
to the current machine and does not sync or call a network service.

## Claude Code hook

`prompt-guard hook` plugs into Claude Code (and other harnesses that use the
same hook protocol). Claude Code sends each event as JSON on stdin and
reads a decision back on stdout:

| Event | What is scanned | On a finding |
|---|---|---|
| `UserPromptSubmit` | the prompt text | `{"decision":"block"}`: the prompt never reaches the model |
| `PreToolUse` | every string in `tool_input` (commands, file contents, URLs) | `permissionDecision: "deny"` (or `"ask"`) |
| anything else | nothing | allowed |

Reasons list only the detection type and severity, such as `githubToken (critical)`,
and never the matched value. Malformed input or an invalid flag exits with code
2, which Claude Code treats as a block, so a broken hook does not silently
allow everything.

Install the CLI globally (`npm i -g @ai-clyde/promptguard`), then add this to
`.claude/settings.json` (project) or `~/.claude/settings.json` (all projects):

```json
{
  "hooks": {
    "UserPromptSubmit": [
      { "hooks": [{ "type": "command", "command": "prompt-guard hook", "timeout": 10 }] }
    ],
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|WebFetch",
        "hooks": [{ "type": "command", "command": "prompt-guard hook --tool-decision=ask", "timeout": 10 }]
      }
    ]
  }
}
```

Flags: `--min-severity=low|medium|high|critical` (default `medium`, so
low-severity social handles and IP addresses pass), `--ignore=email,ssn`,
`--config=path`, and `--tool-decision=deny|ask` (default `deny`). Use `ask` in
repositories whose test fixtures intentionally contain fake credentials, so
you can approve those edits. Hooks cannot rewrite a prompt. To keep a value
out of the conversation, store it with `prompt-guard vault` and refer to its
secret ID.

The same logic is available as `evaluateHookInput(rawJson, options)` from
the package API.

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

The optional secret vault stores encrypted credentials locally. Its passphrase
and secret values are not sent to a service by the vault API. Harness
integrations are responsible for keeping values out of model requests and
model-visible tool results. The npm package includes only the clean and leak
CLI examples; other files in the repository's `examples/` directory are
excluded from the published package.

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
- `ignore` (`string[]`) — categories to skip (`email`, `socialHandle`, `creditCard`, `apiKey`, `githubToken`, `awsSecretKey`, `databaseUrl`, `jwtToken`, `stripeKey`, `sshPrivateKey`, `ipAddress`, `phoneNumber`, `ssn`, `prompt_injection`)
- `minSeverity` (`'low' | 'medium' | 'high' | 'critical'`) — only report matches at or above this severity
- `partialRedaction` (`boolean`) — show last 4 characters instead of full replacement
- `configPath` (`string`) — path to a `.promptguardrc` configuration file

---

## Configuration File (`.promptguardrc`)

Create a `.promptguardrc` file in your project root (copy from `.promptguardrc.example`):

```sh
cp .promptguardrc.example .promptguardrc
# edit .promptguardrc with your values
```

| Setting | Type | Description |
|---------|------|-------------|
| `ignore` | `string[]` | Categories to skip |
| `minSeverity` | `'low' \| 'medium' \| 'high' \| 'critical'` | Minimum severity to report |
| `partialRedaction` | `boolean` | Show last 4 chars instead of full redaction |
| `customPatterns` | `object` | Custom regex patterns with severity |

Example `.promptguardrc`:

```json
{
  "ignore": ["ipAddress", "phoneNumber"],
  "minSeverity": "high",
  "partialRedaction": true,
  "customPatterns": {
    "internalTicket": {
      "pattern": "\\bTKT-\\d{6}\\b",
      "severity": "low"
    }
  }
}
```

Options passed directly to `scanText()` or CLI flags take precedence over the config file.

---

## Severity Levels

Every match is assigned a severity level:

| Severity | Examples |
|----------|----------|
| `critical` | Credit cards, API keys, GitHub tokens, AWS keys, DB URLs, Stripe keys, SSH keys, prompt injection |
| `high` | SSNs, JWT tokens, system prompt phrases |
| `medium` | Emails, phone numbers |
| `low` | Social handles, IP addresses |

Use `minSeverity` to filter out noise — e.g. `minSeverity: 'high'` only reports high and critical issues.

---

## Partial Redaction

Instead of replacing the entire matched value with `[REDACTED_TYPE]`, partial redaction shows the last 4 characters:

```
Before:  Contact alice@example.com or SSN 123-45-6789
After:   Contact *************.com or SSN *******6789
```

Enable with `--partial-redaction` on the CLI or `partialRedaction: true` in config/options.

---

## SARIF Output

For integration with code scanning tools (GitHub Code Scanning, Azure DevOps, etc.), output results in SARIF 2.1.0 format:

```sh
prompt-guard examples/leak.txt --sarif > results.sarif
```

The SARIF output includes:
- Rule definitions for each detection type with severity levels
- Result locations with file URIs and the line/column of each match
- Messages naming the detection type and severity; matched values are never
  copied into the report, so it is safe to upload to code-scanning services

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

## Publishing to npm

The npm release workflow publishes `@ai-clyde/promptguard` from a version tag. It installs dependencies, builds, runs the test suite, verifies the tag matches `package.json`, checks npm credentials, then publishes with public access. `npm pack --dry-run` previews package contents; the allowlist excludes local vault files and unlisted examples.

### Set up the npm token

1. Create an npm granular access token with **Read and write** package permissions for `@ai-clyde/promptguard`. Its owner must be allowed to publish under the `@ai-clyde` scope.
2. Add the token to the GitHub repository as the Actions secret `NPM_TOKEN` (Settings → Secrets and variables → Actions → New repository secret). The workflow checks the token with `npm whoami` before publishing.
3. Keep the token secret; never add it to `.env`, source, or workflow files.

### Release a new version

Review the tarball before release:

```sh
npm pack --dry-run
npm test
npm run build
```

Commit and push all intended release changes, then push a tag matching the version in both `package.json` and `package-lock.json`:

```sh
git add <intended-release-files>
git commit -m "chore: release v1.0.3"
git push origin master
git tag v1.0.3
git push origin v1.0.3
```

Version `1.0.2` is already published to npm, so do not reuse its version number. The next prepared version is `1.0.3`. Pushing its matching tag triggers the workflow; publishing fails before upload if the tag, package version, or npm credentials do not match.

---

## Pre-commit hook

A committed hook script scans staged text files on every commit and blocks the commit if anything is unsafe. It needs a built CLI (`npm run build`).

`scripts/pre-commit.sh` is a cross-platform wrapper around the Node hook. Git hooks cannot be tracked directly, so install it once per clone:

```sh
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit scripts/pre-commit.sh
```

Or run it manually anytime:

```sh
npm run pre-commit
```

Scanned extensions: `.md`, `.txt`, `.ts`, `.js`, `.json`, `.html`, `.yaml`, `.yml`, `.env`, `.env.*`. Non-text files are skipped automatically.
Use `--exclude=path,...` when scanning a directory to exclude comma-separated paths relative to the scan root.

Paths that intentionally contain sample PII or credentials are skipped: `examples/`, `tests/`, `docs/`, `README.md`, and `src/patterns.ts`, plus the generated `package-lock.json` (its integrity hashes resemble AWS secret keys). Low-severity social handles are ignored because JSDoc tags such as `@param` look like handles.

---

## Troubleshooting

### `tsc` reports `TS18003: No inputs found` despite `src/` existing

**Cause:** This machine's `tsc` version fails to expand `include: ["src/**/*.ts"]` globs under non-ASCII paths (e.g. `OneDrive/ドキュメント/…`). It silently returns an empty input set.

**Fix (already applied in this repo):** `tsconfig.json` uses a `files:` array listing every source file explicitly instead of an `include:` glob. `files:` matches reliably where globs do not.

```json
"files": ["src/index.ts", "src/scanner.ts", "src/patterns.ts", "src/ai.ts", "src/cli.ts", "src/tui.ts"]
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
npm test      # vitest — 24 tests across scanner, ai, and CLI integration
npm run build # tsc — outputs to dist/
```

### Adding a check
1. Add a pattern to `src/patterns.ts` (`PII_PATTERNS` or `INJECTION_PATTERNS`)
2. Add a test to `tests/scanner.test.ts`
3. Add custom patterns to `.promptguardrc` if project-specific
4. Run `npm test && npm run build`

### Adding a TUI view
1. Add a new method to `PromptGuardTUI` class in `src/tui.ts`
2. Add a menu item to the navigation list in `buildLayout()`
3. Add a case to `handleNavSelect()`
4. Run `npm test && npm run build`

---

## Data handling

Prompt Guard does not cache or store your prompts. `scanText` operates entirely in memory and sends nothing externally. `callAIGuarded` sends only the accepted (optionally sanitized and truncated) prompt to the configured model. No metadata, cache files, or conversation history is transmitted unless you include it in the prompt itself.

---

## License

MIT. See [LICENSE](LICENSE).

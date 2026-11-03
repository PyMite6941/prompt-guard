# Security Policy

## Supported versions

Only the latest release of `@ai-clyde/promptguard` on npm receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Report them privately via
[GitHub private vulnerability reporting](https://github.com/PyMite6941/prompt-guard/security/advisories/new).

Useful details:

- affected version and how you're using it (CLI, library, Claude Code hook, vault)
- steps or a synthetic input that reproduces the issue
- impact (e.g. secret leaked to output/logs, detection bypass, vault key exposure)

You can expect an acknowledgement within 7 days. Once a fix ships, the advisory is
published and you'll be credited unless you'd prefer not to be.

## Scope

Prompt Guard is a best-effort, pattern-based scanner. A prompt that evades detection is
worth reporting as a detection gap, but it is not by itself a vulnerability unless it
defeats a guarantee the docs make. Vault key handling, secret redaction in output or
audit logs, and path validation are in scope.

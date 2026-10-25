# Contributing to Prompt Guard

Thanks for wanting to improve Prompt Guard! This document explains how to get
started.

---

## Table of contents

- [Code of conduct](#code-of-conduct)
- [Getting started](#getting-started)
- [Making changes](#making-changes)
- [Adding a detection pattern](#adding-a-detection-pattern)
- [Submitting a pull request](#submitting-a-pull-request)

---

## Code of conduct

This project follows a simple standard: be respectful, keep discussions
on-topic, and assume good faith.

---

## Getting started

```sh
git clone https://github.com/PyMite6941/prompt-guard.git
cd prompt-guard
npm install
npm run build
npm test
```

The pre-commit hook is installed locally (not tracked in git):

```sh
cp scripts/pre-commit.sh .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit scripts/pre-commit.sh
```

It scans staged files under `examples/` and blocks commits that contain unsafe
content.

---

## Making changes

1. Create a branch from `master`.
2. Make your change.
3. Run `npm test && npm run build` — both must pass.
4. If you changed `src/`, add or update tests in `tests/`.
5. Update `README.md` if behavior or docs change.
6. Commit and open a pull request against `master`.

---

## Adding a detection pattern

Patterns live in `src/patterns.ts`:

- `PII_PATTERNS` — keyed object of name → regex (with `g` flag).
- `INJECTION_PATTERNS` — array of regexes.

Example:

```ts
export const PII_PATTERNS = {
	// ...
	myType: /regex-here/g,
};
```

Then:

1. Add a test case to `tests/scanner.test.ts`.
2. Add the type name to the `ignore` list documentation in `README.md`.
3. Add the type name to the scanned-extensions/ignore list in `README.md` if needed.
4. Run `npm test && npm run build`.

---

## Submitting a pull request

- Keep PRs focused on one change.
- Include tests for new behavior.
- Update the README if user-facing behavior changes.
- Ensure CI passes (`scan.yml` runs build, test, and the negative-control scan).

---

## License

By contributing, you agree your contributions are licensed under the MIT License.

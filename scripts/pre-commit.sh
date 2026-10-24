#!/usr/bin/env bash
# Pre-commit hook: scan staged example/prompt files with Prompt Guard.
# Exits non-zero (blocking the commit) if any staged file under examples/
# contains PII or prompt-injection patterns that are not ignored.
#
# Scope: only files under examples/ are scanned. Documentation, source code,
# and config files legitimately mention these patterns as explanatory text
# and should not be blocked by the scanner.

set -euo pipefail

# Location of the built CLI (relative to repo root).
CLI="node dist/cli.js"

# Only scan files that are staged, added, or modified (not deleted).
mapfile -t STAGED < <(git diff --cached --name-only --diff-filter=ACM | grep '^examples/' || true)

if [ ${#STAGED[@]} -eq 0 ]; then
    echo "No example files staged to scan."
    exit 0
fi

FAILED=0
for file in "${STAGED[@]}"; do
    # Skip non-text / generated files.
    case "$file" in
        *.md|*.txt|*.ts|*.js|*.json|*.html|*.yaml|*.yml|*.env.example) ;;
        *) continue ;;
    esac

    if [ ! -f "$file" ]; then
        continue
    fi

    echo "Scanning $file ..."
    if ! "$CLI" "$file" >/dev/null 2>&1; then
        echo "🚨 $file failed Prompt Guard scan — commit blocked."
        echo "   Fix the matches above, or use git restore --staged to unstage."
        FAILED=1
    fi
done

if [ "$FAILED" -ne 0 ]; then
    echo "Pre-commit scan failed. Commit blocked."
    exit 1
fi

echo "All staged example files passed Prompt Guard scan."

#!/usr/bin/env bash
set -euo pipefail

# OPA loads everything under policies/ by default.
# Backup/editor files can silently change policy behavior.
# This guardrail fails CI if any suspicious files exist.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bad="$(find "$ROOT/policies" -type f \( \
  -name "*~" -o -name "*.swp" -o -name "*.swo" -o -name "*.bak" -o -name "*.orig" -o -name "*.tmp" \
\) -print)"

if [[ -n "${bad}" ]]; then
  echo "ERROR: forbidden backup/editor files found under policies/:"
  echo "${bad}"
  exit 1
fi

echo "OK: no policy backup/editor files found."

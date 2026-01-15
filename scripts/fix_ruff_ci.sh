#!/usr/bin/env bash
set -euo pipefail
python scripts/fix_ruff_ci.py
ruff check .

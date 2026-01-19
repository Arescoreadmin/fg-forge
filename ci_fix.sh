#!/usr/bin/env bash
set -euo pipefail

echo "[1/7] Environment"
python -V
ruff --version

echo "[2/7] Fast fail: syntax check (tells you exactly where parsing breaks)"
python -m compileall -q services || true

echo "[3/7] Autofix what can be autofixed"
# Safe: removes unused vars/imports, fixes simple issues, sorts imports depending on config.
ruff check services --fix || true

echo "[4/7] Re-run syntax check (should now only fail on real syntax errors)"
python -m compileall -q services

echo "[5/7] Show remaining ruff errors (no fix)"
ruff check services

echo "[6/7] Run tests (quick)"
pytest -q

echo "[7/7] Done"

# Next P1 Plan

## Steps
1) Add offline verdict verification CLI script (scripts/verify_verdict.py) with hash recompute and signature verification logic plus unit tests in scripts/tests.
2) Implement artifact retention cleanup script with dry-run, investigation-flag protection, deterministic deletion logging, and operator auth guard plus unit tests (scripts/retention_cleanup.py, scripts/tests).
3) Tighten /readyz checks for orchestrator (OPA + scoreboard) and scoreboard (storage writable + signing key) without changing /healthz behavior (services/orchestrator/app/main.py, services/scoreboard/app/main.py) with tests.
4) Enforce operator-only access on completion endpoint and retention cleanup via OPERATOR_TOKEN header (services/orchestrator/app/main.py, scripts/retention_cleanup.py) with access control tests.
5) Update MVP_PROGRESS.md with completed P1 items and validation steps.

## Files to touch
- scripts/verify_verdict.py
- scripts/retention_cleanup.py
- scripts/tests/*
- services/orchestrator/app/main.py
- services/scoreboard/app/main.py
- services/orchestrator/tests/*
- services/scoreboard/tests/*
- MVP_PROGRESS.md

## Tests
- python -m unittest discover -s services/orchestrator/tests
- python -m unittest discover -s services/scoreboard/tests
- python -m unittest discover -s scripts/tests

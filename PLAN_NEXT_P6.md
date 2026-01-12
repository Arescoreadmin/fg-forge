# P6 Plan (Go-Live Readiness & Regression Prevention)

## Steps
1. Add a CI workflow to run unit tests, lint, OPA policy tests, and secret scanning.
2. Add startup config guardrails for required secrets and unsafe dev flags in non-dev modes.
3. Add OPA policy hash logging and optional mismatch enforcement on startup.
4. Add operator runbook documentation.
5. Update MVP_PROGRESS.md with completed P6 items.

## Files
- .github/workflows/ci.yml
- services/spawn_service/app/main.py
- services/orchestrator/app/main.py
- services/scoreboard/app/main.py
- docs/operator_runbook.md
- MVP_PROGRESS.md

## Tests
- python -m unittest discover -s services/spawn_service/tests
- python -m unittest discover -s services/orchestrator/tests
- python -m unittest discover -s services/scoreboard/tests
- python -m unittest discover -s scripts/tests

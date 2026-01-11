# Next P0 Plan

## Steps
1) Standardize SAT_HMAC_SECRET env var in spawn_service and orchestrator, with SAT_SECRET alias warning at startup, and update compose + docs/run instructions. (services/spawn_service/app/main.py, services/orchestrator/app/main.py, compose.yml, compose.staging.yml, README.md)
2) Implement minimal scoring artifacts generation (score.json, evidence bundle, verdict.sig) in the existing scoring path or a new service module, with deterministic schema and signing using ephemeral Ed25519 in staging. (services/scoreboard or services/overlay_sanitizer code, new scoring artifacts module)
3) Add tests covering SAT env var alias warning and scoring artifact generation/signing, including evidence bundle creation and signature verification. (relevant services/*/tests)
4) Update MVP_PROGRESS.md with completed P0 items and local run snippet with correct env vars.

## Files to touch
- services/spawn_service/app/main.py
- services/orchestrator/app/main.py
- services/scoreboard/** or services/overlay_sanitizer/** (as discovered)
- services/**/tests/**
- compose.yml
- compose.staging.yml
- README.md or docs/*
- MVP_PROGRESS.md

## Tests
- python -m unittest services/spawn_service/tests/test_spawn_service.py
- python -m unittest services/orchestrator/tests/test_orchestrator_sat.py
- python -m unittest services/scoreboard/tests/test_scoring_artifacts.py

# Next P0 Plan

## Steps
1) Implement SAT minting in spawn_service after billing, including required claims, TTL, and HMAC signing.
2) Implement SAT verification + replay protection in orchestrator with Redis when available and in-memory LRU fallback; enforce before scenario creation and deny on OPA errors/unreachable.
3) Add unit tests for SAT mint/verify and replay protection, plus minimal integration coverage for orchestrator gating.

## Files to touch
- services/spawn_service/app/main.py
- services/spawn_service/tests/test_spawn_service.py
- services/orchestrator/app/main.py
- services/orchestrator/tests/test_orchestrator_sat.py
- MVP_PROGRESS.md

## Tests
- python -m unittest services/spawn_service/tests/test_spawn_service.py
- python -m unittest services/orchestrator/tests/test_orchestrator_sat.py

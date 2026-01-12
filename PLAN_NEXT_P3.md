# Next P3 Plan

## Steps
1) Enforce Redis-backed rate limiting/quota in spawn_service with fail-closed behavior when Redis is configured, and add explicit dev fallback warnings plus staging compose REDIS_URL.
2) Add timeout/retry/jitter + circuit-breaker wrappers for inter-service HTTP calls in spawn_service and orchestrator, with unit tests for retry bounds/timeouts.
3) Add runtime isolation assertions to /readyz (read-only filesystem check, egress gateway deny-by-default check, OPA readiness where applicable) with tests updates.
4) Add one-command staging smoke test script for end-to-end spawn/complete/verify flow.
5) Update MVP_PROGRESS.md with P3 completion status and validation steps.

## Files to touch
- services/spawn_service/app/main.py
- services/spawn_service/tests/test_spawn_service.py
- services/orchestrator/app/main.py
- services/orchestrator/tests/test_orchestrator_readyz.py
- services/orchestrator/tests/test_orchestrator_sat.py
- services/scoreboard/app/main.py
- services/scoreboard/tests/test_scoreboard_readyz.py
- compose.staging.yml
- scripts/smoke_test.py
- scripts/tests/test_smoke_test.py
- PLAN_NEXT_P3.md
- MVP_PROGRESS.md

## Tests
- python -m unittest discover -s services/spawn_service/tests
- python -m unittest discover -s services/orchestrator/tests
- python -m unittest discover -s services/scoreboard/tests
- python -m unittest discover -s scripts/tests

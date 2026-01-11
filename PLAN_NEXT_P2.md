# Next P2 Plan

## Steps
1) Add subject-based rate limiting and concurrent quota enforcement in spawn_service using Redis when configured and in-memory TTL fallback, with stable client identifier fallback and request ID propagation.
2) Expand SAT claims to include tenant_id and enforce subject/tenant_id presence plus tier/track matching in orchestrator, and persist subject/tenant_id through scenario state and scoreboard scoring payloads.
3) Implement hash-chained audit log at storage/scenarios/<scenario_id>/results/audit.jsonl, include audit hash in evidence bundle, and add chain integrity verification helpers with tests for tamper detection.
4) Propagate X-Request-Id end-to-end (spawn_service to orchestrator, orchestrator to scoreboard) and include correlation_id in audit entries.
5) Update MVP_PROGRESS.md with completed P2 items and validation steps.

## Files to touch
- services/spawn_service/app/main.py
- services/spawn_service/tests/test_spawn_service.py
- services/orchestrator/app/main.py
- services/orchestrator/tests/test_orchestrator_sat.py
- services/scoreboard/app/main.py
- services/scoreboard/tests/test_scoring_artifacts.py
- services/scoreboard/tests/test_scoreboard_readyz.py
- PLAN_NEXT_P2.md
- MVP_PROGRESS.md

## Tests
- python -m unittest discover -s services/spawn_service/tests
- python -m unittest discover -s services/orchestrator/tests
- python -m unittest discover -s services/scoreboard/tests

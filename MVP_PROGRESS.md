# MVP Progress

## Completed (this run)
- Added `/healthz` and `/readyz` endpoints for all HTTP services.
- Implemented structured JSON logging with correlation IDs across services.
- Added `POST /api/spawn` with Spawn Authorization Token (SAT) scaffolding and basic tests.
- Implemented SAT minting/verification with expiry and replay protection, plus orchestrator SAT enforcement and OPA pre-launch gating tests.
- Standardized SAT_HMAC_SECRET with legacy SAT_SECRET warnings and updated compose/docs.
- Implemented scoring artifacts pipeline with deterministic score.json, evidence bundles, and verdict signatures plus tests.
- Added internal scenario completion endpoint in orchestrator with auth guard, scoreboard-triggered scoring, and completion status handling.
- Wrote scoring artifacts to storage/scenarios/<scenario_id>/results with verdict signatures and public keys.
- Added an end-to-end integration test covering SAT mint/verify, completion, scoring artifacts, and signature verification.

## How to run locally
```
python -m unittest discover -s services/spawn_service/tests
python -m unittest discover -s services/orchestrator/tests
python -m unittest discover -s services/scoreboard/tests
```

## Remaining
- Enable non-dry-run deny-all egress enforcement with NET_ADMIN capabilities in production compose.
- Introduce template versioning and immutability checks in spawn/orchestrator.
- Implement quota enforcement in orchestrator spawn flow and NATS admission gates.
- Integrate KMS-backed signing keys for verdict signatures.
- Add CI pipeline configuration to run tests and policy checks.

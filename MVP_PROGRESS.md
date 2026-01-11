# MVP Progress

## Completed (this run)
- Added `/healthz` and `/readyz` endpoints for all HTTP services.
- Implemented structured JSON logging with correlation IDs across services.
- Added `POST /api/spawn` with Spawn Authorization Token (SAT) scaffolding and basic tests.
- Implemented SAT minting/verification with expiry and replay protection, plus orchestrator SAT enforcement and OPA pre-launch gating tests.
- Standardized SAT_HMAC_SECRET with legacy SAT_SECRET warnings and updated compose/docs.
- Implemented scoring artifacts pipeline with deterministic score.json, evidence bundles, and verdict signatures plus tests.

## Remaining
- Enable non-dry-run deny-all egress enforcement with NET_ADMIN capabilities in production compose.
- Introduce template versioning and immutability checks in spawn/orchestrator.
- Implement quota enforcement in orchestrator spawn flow and NATS admission gates.
- Integrate KMS-backed signing keys for verdict signatures.
- Add CI pipeline configuration to run tests and policy checks.

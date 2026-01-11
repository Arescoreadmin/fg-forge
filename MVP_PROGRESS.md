# MVP Progress

## Completed (this run)
- Added `/healthz` and `/readyz` endpoints for all HTTP services.
- Implemented structured JSON logging with correlation IDs across services.
- Added `POST /api/spawn` with Spawn Authorization Token (SAT) scaffolding and basic tests.

## Remaining
- Enforce evidence bundle format (`evidence.tar.zst`) and integrate hash validation in scoring.
- Enable non-dry-run deny-all egress enforcement with NET_ADMIN capabilities in production compose.
- Introduce template versioning and immutability checks in spawn/orchestrator.
- Implement quota enforcement in orchestrator spawn flow and NATS admission gates.
- Integrate KMS-backed signing keys for verdict signatures.
- Add CI pipeline configuration to run tests and policy checks.


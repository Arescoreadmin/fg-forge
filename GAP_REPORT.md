# FrostGate Forge MVP Gap Report

This report assesses the repository against the Foundry blueprint contracts and MVP
security requirements. Reference: `docs/frostgate_forge_full_reference.md` and
`docs/blueprint.md`.

## Gaps

| Gap | Severity | Exploitability | User Impact | ROI | Fix Plan |
| --- | --- | --- | --- | --- | --- |
| Missing `/healthz` and `/readyz` endpoints across FastAPI services (only `/health` exists). | P0 | Medium (health checks bypassed) | High (orchestration can’t reliably gate rollouts) | High | Add `/healthz` + `/readyz` to every HTTP service with minimal JSON response. |
| Logs are not structured JSON and do not include correlation IDs. | P0 | Medium (audit trails incomplete) | High (can’t trace requests across services) | High | Add JSON log formatter + request ID middleware per service; emit `correlation_id` field. |
| Spawn API contract requires `POST /api/spawn` and SAT auth concept; only `/v1/spawn` exists and no SAT check. | P0 | Medium | High (contract mismatch, no auth scaffolding) | High | Add `/api/spawn` route alias, SAT verification stub with HMAC + expiration, configurable via env. |
| Evidence bundle format is `evidence.tar.gz`, not the required `evidence.tar.zst`. | P1 | Low | Medium | Medium | Switch worker evidence bundling to zstd-compressed tar (tar.zst) and update naming. |
| Egress enforcement is dry-run by default and the egress gateway lacks NET_ADMIN capability in compose. | P1 | Medium | High | Medium | Default DRY_RUN=false in production compose and add NET_ADMIN + drop others; document. |
| Templates are mounted read-only but not versioned/immutable metadata enforced. | P2 | Low | Low | Low | Add template version metadata and validation in spawn/orchestrator. |
| Multi-tenant quotas/blast radius controls exist as stubs only (metrics_tuner). | P2 | Medium | Medium | Medium | Implement quota enforcement in orchestrator spawn path and NATS admission. |
| Scoring contract uses ephemeral signing key; no key provenance (KMS/rotation). | P2 | Low | Medium | Medium | Integrate KMS-backed signing or inject key via sealed secrets. |


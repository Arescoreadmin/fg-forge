# FrostGate Forge Exec Summary

## Inventory (depth 4)
- Services under `services/`: `spawn_service`, `orchestrator`, `worker_agent`, `scoreboard`, `observer_hub`, `playbook_runner`, `metrics_tuner`, `egress_gateway`, `llm_analyzer`, `overlay_sanitizer`, plus placeholder docs for `aux_device1`, `aux_device2`, `attacker_agent`, `defender_agent`, `vector_db`.
- Compose files: `compose.yml`, `compose.staging.yml`.
- OPA policies: `policies/*.rego` (spawn, training, quota, action, llm).
- Templates: `templates/*.yaml` (netplus, ccna, cissp).
- Scripts: `scripts/setup_nats_streams.sh`, `services/egress_gateway/scripts/setup_nftables.sh`.
- Telemetry: `telemetry/prometheus.yml` + Grafana provisioning under `telemetry/grafana/`.
- Runtime entrypoints: `services/spawn_service/app/main.py`, `services/orchestrator/app/main.py`.

## Contract Mapping

| Contract | Files | Status | Risk |
| --- | --- | --- | --- |
| Spawn API: `POST /api/spawn` (track) | `services/spawn_service/app/main.py` | Missing (`/v1/spawn` only) | High |
| Billing stub (staging) + prod gateway placeholder | `services/spawn_service/app/main.py` (`record_billing`) | Partial | Medium |
| Spawn Authorization Token (SAT) concept | `services/spawn_service/app/main.py` | Missing | High |
| Orchestrator validation + network creation + launch | `services/orchestrator/app/main.py` | Implemented | Low |
| OPA training gate enforcement pre-spawn | `services/spawn_service/app/main.py`, `services/orchestrator/app/main.py`, `policies/training_gate.rego` | Partial (spawn/orchestrator gate; no failure audit) | Medium |
| Deny-all egress enforcement | `services/orchestrator/app/main.py` (internal networks), `services/egress_gateway/app/main.py` | Partial (egress gateway dry-run) | Medium |
| Templates immutable (read-only mounts) | `compose.yml`, `compose.staging.yml` | Partial (RO mounts, no version pinning) | Medium |
| Scoring contract (`score.json` + evidence bundle + `verdict.sig`) | `services/worker_agent/app/main.py`, `services/scoreboard/app/main.py` | Partial (evidence.tar.gz; ephemeral signing key) | Medium |
| Telemetry stack (Prometheus/Loki/Grafana) | `compose.yml`, `telemetry/*` | Implemented | Low |
| Multi-tenant quotas + blast radius controls | `services/metrics_tuner/app/main.py`, `policies/quota_gate.rego` | Partial (no enforcement in spawn) | Medium |
| `/healthz` + `/readyz` per service | `services/*/app/main.py` | Missing | High |
| Structured JSON logs with correlation IDs | `services/*/app/main.py` | Missing | High |


# FrostGate Forge Architecture

This repository bootstraps the core services and policies for the FrostGate Forge
platform. The focus is on high-isolation training scenarios, deterministic scoring,
and policy-gated operations.

The authoritative architecture requirements live in `docs/blueprint.md`.

## Services

- **forge_spawn_service**: Intake API for billing + spawn requests.
- **forge_orchestrator**: Validates templates, enforces OPA, and launches isolated scenario networks.
- **forge_worker_agent**: Executes scenario playbooks and collects evidence for scoring.
- **forge_observer_hub**: Aggregates scenario telemetry and audit streams.
- **forge_metrics_tuner**: Enforces usage quotas and fairness telemetry baselines.
- **forge_playbook_runner**: Executes deterministic success criteria playbooks.
- **forge_llm_analyzer**: Governed LLM proposal analysis + canary checks.
- **forge_vector_db**: Stores embeddings and scenario search metadata.
- **forge_attacker_agent / forge_defender_agent**: Controlled adversary/defender agents.
- **forge_aux_device1 / forge_aux_device2**: Auxiliary training devices.
- **forge_overlay_sanitizer**: PII scrubbing + audit trail sanitization.
- **forge_scoreboard**: Produces score.json, evidence.tar.zst, verdict.sig.
- **forge_egress_gateway**: nftables deny-all gateway with allowlist profiles.
- **forge_opa**: Policy engine enforcing training gates.
- **forge_nats**: Event bus for spawn and telemetry events.
- **forge_minio**: Object storage for evidence bundles.
- **forge_loki / forge_prometheus / forge_grafana**: Telemetry stack.

## Security Baseline

- Read-only filesystems by default
- Drop all Linux capabilities
- No-new-privileges enabled
- Deny-all egress enforced by policy
- Scenario networks isolated per-tenant

## Scoring & Evidence

Scoring outputs are expected to include:

- `score.json`
- `evidence.tar.zst`
- `verdict.sig`

These outputs are produced by scenario workers and stored in MinIO for audit.

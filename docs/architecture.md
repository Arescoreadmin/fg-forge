# FrostGate Forge Architecture

This repository bootstraps the core services and policies for the FrostGate Forge
platform. The focus is on high-isolation training scenarios, deterministic scoring,
and policy-gated operations.

## Services

- **forge_spawn_service**: Intake API for billing + spawn requests.
- **forge_opa**: Policy engine enforcing training gates.
- **forge_nats**: Event bus for spawn and telemetry events.
- **forge_minio**: Object storage for evidence bundles.
- **forge_loki / forge_prometheus / forge_grafana**: Telemetry stack.

## Security Baseline

- Read-only filesystems by default
- Drop all Linux capabilities
- No-new-privileges enabled
- Deny-all egress enforced by policy

## Scoring & Evidence

Scoring outputs are expected to include:

- `score.json`
- `evidence.tar.zst`
- `verdict.sig`

These outputs are produced by scenario workers and stored in MinIO for audit.

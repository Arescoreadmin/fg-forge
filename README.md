# FrostGate Forge

FrostGate Forge is a governed, sandboxed cyber-training platform for spawning
isolated training scenarios with deterministic scoring and audit-ready evidence.
This repository provides the baseline services, policies, and templates required
for the platform spine.

The canonical architecture and security requirements live in
`docs/blueprint.md`.

## Quickstart (Staging)

```bash
cp .env.example .env
docker compose -f compose.yml -f compose.staging.yml up -d --build
./scripts/setup_nats_streams.sh
```

Spawn test:

```bash
curl -s -X POST http://localhost:8082/v1/spawn \
  -H 'content-type: application/json' \
  -H 'x-request-id: demo-req-001' \
  -d '{"track":"netplus"}'
```

## Repository Layout

```
fg-forge/
  compose.yml
  compose.staging.yml
  templates/
  services/
    spawn_service/
    orchestrator/
    worker_agent/
    observer_hub/
    metrics_tuner/
    playbook_runner/
    llm_analyzer/
    vector_db/
    attacker_agent/
    defender_agent/
    aux_device1/
    aux_device2/
    overlay_sanitizer/
    scoreboard/
    egress_gateway/
  scenario_dsl/
  telemetry/
  storage/
  scripts/
  docs/
```

## Security Posture

- Read-only filesystems for containers
- Drop all Linux capabilities
- Policy gates enforced via OPA
- Deny-all egress default

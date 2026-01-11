# FrostGate Forge

FrostGate Forge is a governed, sandboxed cyber-training platform for spawning
isolated training scenarios with deterministic scoring and audit-ready evidence.
This repository provides the baseline services, policies, and templates required
for the platform spine.

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
  -d '{"track":"netplus"}'
```

## Repository Layout

```
fg-forge/
  compose.yml
  compose.staging.yml
  templates/
  services/
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

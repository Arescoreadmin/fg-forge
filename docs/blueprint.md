# FrostGate Forge — vNext Blueprint (Single Source of Truth)

## Summary
FrostGate Forge is a governed, sandboxed cyber-training platform with paid, isolated “spawned” training scenarios.
Security-by-default, deny-all egress, read-only containers, and policy-gated operations are non-negotiable.
Every scenario creation, agent action, and LLM proposal must be evidencable, scored, and auditable.

This document is the single reference for architecture, security posture, and forward milestones.

---

## Project Direction
Forge is training-as-a-service:
- learners pick a track via a minimal web form + billing
- Forge spawns an isolated scenario network
- learners interact via a short-lived access token
- system records telemetry, grades success criteria, and produces an audit bundle

Primary goals:
1. Monetizable training tracks (tiered templates + quotas)
2. Governed automation (OPA gating + signed actions)
3. Deterministic scoring (successCriteria -> evidence -> score -> signature)
4. High isolation (per-scenario networks, runtime isolation ready)
5. First-class telemetry (fairness, outcomes, usage)

Milestones (near-term):
1. Billing integration + short-lived token auth
2. Automated scoring for scenario successCriteria
3. Staging deployment of Forge Spawn Service (CI/CD ready)
4. Expand templates + OPA gates for advanced tiers

---

## Architecture Snapshot
Baseline components:
- Docker Compose hardened baseline (seccomp/AppArmor; drop caps; read-only FS)
- Egress Gateway: nftables deny-all with optional allowlist profiles
- OPA Policies: strict per-class gates, especially training gates
- Scenario Orchestrator: validates + launches isolated scenario networks
- Forge Spawn Service: onboarding + billing + spawn request submission
- Telemetry: Prometheus + Loki + Grafana dashboards (Red–Blue outcomes)
- Data Hygiene: PII scrubbing + signed audits + object lifecycle (MinIO)
- LLM Governance: analyzer + canary proposal pipeline + rollback safety

---

## Repository Layout (Current)
Recommended structure:

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

Branding convention:
- external product name: FrostGate Forge
- internal namespace: frostgate.forge
- service IDs: forge_<service>

---

## Forge Spawn Service
Purpose: Monetization choke point + safe intake.

API:
- POST /v1/spawn
  body: { "track": "netplus" | "ccna" | "cissp" }
  returns: { scenario_id, access_url }

Responsibilities:
- Billing: staging uses fake_charge; production uses gateway + receipts
- Scenario creation: selects read-only template + unique seed + submits spawn request
- Security: no secrets in image, templates mounted read-only, OPA enforced
- Output access_url is short-lived and must be bound to the user session

Hard requirement:
- spawn requests must be idempotent and traceable (request_id)

---

## Scenario Templates
Templates live in /templates and are immutable at runtime.
Each template includes:
- metadata.labels (track + tier)
- limits (resource + adversary constraints)
- network (including egress policy)
- assets (containers, services, datasets)
- successCriteria (grading contract)

---

## OPA Policy (Example Training Gate)
File: training_gate.rego

```
package frostgate.forge.training

default allow = false

allow {
  input.metadata.labels[_] == "class:netplus"
  input.limits.attacker_max_exploits <= 0
  input.network.egress == "deny"
}

allow {
  input.metadata.labels[_] == "class:ccna"
  input.limits.attacker_max_exploits <= 0
  input.network.egress == "deny"
}

allow {
  input.metadata.labels[_] == "class:cissp"
  input.limits.attacker_max_exploits <= 5
  input.network.egress == "deny"
}
```

Notes:
- deny-all egress is mandatory by default
- advanced tiers may allow curated allowlists via the egress gateway profile

---

## Deployment (Staging Quickstart)
```
cp .env.example .env
docker compose -f compose.yml -f compose.staging.yml up -d --build
./scripts/setup_nats_streams.sh
```

Spawn test:
```
curl -s -X POST http://localhost:8082/v1/spawn \
  -H 'content-type: application/json' \
  -d '{"track":"netplus"}'
```

Verify:
- Grafana and Loki reachable
- Spawn API returns scenario_id + access_url
- Egress gateway logs deny-all outbound
- OPA policies loaded and active

---

## Security & Ops Checklist
Runtime hardening:
- [ ] Read-only FS for all containers
- [ ] Drop Linux capabilities; no privileged containers
- [ ] seccomp + AppArmor profiles attached
- [ ] deny-all egress enforced; allowlist only via gateway profile
- [ ] per-scenario network isolation and no host network
- [ ] strict resource budgets and per-tenant quotas

Governance:
- [ ] OPA policy bundles versioned and validated
- [ ] Spawn requests signed and audited
- [ ] LLM proposals signed, canaried, and rollbackable

Data + audit:
- [ ] PII scrubber active with explicit allowlists
- [ ] Audit logs hashed and signed
- [ ] MinIO lifecycle configured for evidence retention

Telemetry:
- [ ] Grafana dashboards show spawns by track + completion rates
- [ ] Loki label cardinality controlled
- [ ] Alerts for spawn failure rate, policy denials, NATS lag, disk pressure

---

## Next-Level Requirement: Scoring & Evidence (Do Not Skip)
Automated grading must produce:
- score.json (normalized scores)
- evidence.tar.zst (artifacts + telemetry excerpts)
- verdict.sig (signature over hashes)

This is the core monetization primitive:
- proof of completion
- enterprise compliance exports
- anti-cheat and fairness analytics

---

## Future Path
- Runtime tokenization for student access via access broker
- Automated grading per successCriteria (standardized scoring contract)
- Expand template coverage and advanced network labs
- Transition orchestrator to k3s + Forge CRD for scale
- Vault/KMS for signing keys and API secrets
- Short-lived console auth via access broker (session-bound tokens)

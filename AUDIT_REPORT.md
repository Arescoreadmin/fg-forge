# FrostGate Forge — Sentinel Foundry vNext Compliance Audit

**Audit Date:** 2026-01-15
**Auditor:** Senior Staff Engineer / Security Architect
**Blueprint Reference:** `docs/blueprint.md` (Single Source of Truth)
**Status:** 🟡 PARTIAL COMPLIANCE — Critical gaps identified

---

## 1. Repo Inventory

### Services Under `services/`

| Service | Description | API Port | Hardened |
|---------|-------------|----------|----------|
| `spawn_service` | Monetization choke point. POST /v1/spawn, billing stub, OPA check, SAT minting | 8082 | ✅ |
| `orchestrator` | Scenario lifecycle. Creates isolated networks, launches containers, SAT validation | 8083 | ✅ |
| `scoreboard` | Automated grading. Produces score.json, evidence.tar.zst, verdict.sig | 8086 | ✅ |
| `egress_gateway` | Deny-all egress via nftables. Allowlist profiles per scenario | 8089 | 🟡 DRY_RUN |
| `worker_agent` | Scenario container worker. Evidence collection | 8084 | ✅ |
| `observer_hub` | Telemetry aggregator. NATS→Loki bridge | 8085 | ✅ |
| `metrics_tuner` | Quota/rate limit enforcement. Abuse detection | 8088 | ✅ |
| `llm_analyzer` | LLM proposal governance. Canary pipeline | 8090 | ✅ |
| `overlay_sanitizer` | PII scrubber. Audit bundle signing | 8091 | ✅ |
| `playbook_runner` | Playbook execution engine | 8087 | ✅ |
| `attacker_agent` | Stub for adversary simulation | - | Stub |
| `defender_agent` | Stub for defender simulation | - | Stub |
| `aux_device1/2` | Auxiliary scenario devices | - | Stub |
| `vector_db` | Stub for vector storage | - | Stub |

### Entrypoints & APIs

- **Public API:** `forge_spawn_service:8080` → POST /v1/spawn, /api/spawn, GET /v1/access/{scenario_id}
- **Internal API:** `forge_orchestrator:8080` → POST /v1/scenarios, POST /internal/scenario/{id}/complete
- **Scoring API:** `forge_scoreboard:8080` → POST /internal/scenario/{id}/score, GET /v1/scores

### Message Bus

- **NATS JetStream** (`forge_nats:4222`)
  - Streams: FORGE (spawn.*, scenario.*), TELEMETRY, AUDIT
  - Setup script: `scripts/setup_nats_streams.sh`

### Storage Backends

- **MinIO** (`forge_minio:9000`) — Evidence buckets: forge-evidence, forge-sanitized
- **Redis** (`forge_redis:6379`) — Rate limits, entitlements, replay protection
- **Filesystem** — `storage/scenarios/{id}/results/` for scoring artifacts

### Telemetry

- **Prometheus** (`forge_prometheus:9090`) — Scrapes spawn_service:8080 only
- **Loki** (`forge_loki:3100`) — Log aggregation
- **Grafana** (`forge_grafana:3000`) — Dashboards provisioned via `telemetry/grafana/`

### Key Files Located

| File/Directory | Status |
|----------------|--------|
| `compose.yml` | ✅ Present, hardened |
| `compose.staging.yml` | ✅ Present |
| `templates/` | ✅ netplus.yaml, ccna.yaml, cissp.yaml |
| `scenario_dsl/` | 🟡 README only, no DSL files |
| `telemetry/` | ✅ Prometheus + Grafana provisioning |
| `scripts/` | ✅ setup_nats_streams.sh, smoke_test.py, verify_verdict.py |
| `policies/` | ✅ 5 OPA policies (training, spawn, action, llm, quota) |
| `docs/blueprint.md` | ✅ Source of truth present |

---

## 2. Blueprint-to-Repo Compliance Matrix

| Blueprint Requirement | Where Implemented | Evidence | Status | Risk if Missing | Fix |
|----------------------|-------------------|----------|--------|-----------------|-----|
| **POST /api/spawn endpoint** | `services/spawn_service/app/main.py:999` | `@app.post("/api/spawn")` | ✅ Implemented | N/A | - |
| **Track selection (netplus/ccna/cissp)** | `spawn_service/main.py:135-140`, `templates/*.yaml` | `TRACKS = {"netplus", "ccna", "cissp"}` | ✅ Implemented | N/A | - |
| **Billing stub in staging** | `compose.staging.yml:7`, `spawn_service/main.py:691` | `BILLING_MODE=fake_charge`, `record_billing()` stub | ✅ Implemented | N/A | - |
| **Template copy immutability** | `compose.yml:24-25` | `./templates:/templates:ro` | ✅ Implemented | N/A | - |
| **Returns {scenario_id, access_url}** | `spawn_service/main.py:301-308` | `SpawnResponse` model with both fields | ✅ Implemented | N/A | - |
| **Short-lived access token** | `spawn_service/main.py:331-369` | `AccessTokenPayload`, 30-min expiry, HMAC-SHA256 | ✅ Implemented | N/A | - |
| **Posts to orchestrator** | `spawn_service/main.py:887-912` | `notify_orchestrator()` with SAT header | ✅ Implemented | N/A | - |
| **Orchestrator validates + launches isolated networks** | `orchestrator/main.py:798-812` | `create_scenario_network()` with `internal=True` | ✅ Implemented | N/A | - |
| **Orchestrator enforcement points** | `orchestrator/main.py:489-517, 563-580` | `enforce_sat()`, `_require_internal_auth()`, `_require_operator_auth()` | ✅ Implemented | N/A | - |
| **Deny-all egress (nftables gateway)** | `egress_gateway/main.py:135-202` | `init_base_ruleset()` with `policy drop` | 🟡 Partial | **HIGH** - Bypass in dev | Set `DRY_RUN=false` in staging |
| **Read-only containers** | `compose.yml` (all services) | `read_only: true` on every service | ✅ Implemented | N/A | - |
| **Drop caps** | `compose.yml` (all services) | `cap_drop: [ALL]` on every service | ✅ Implemented | N/A | - |
| **seccomp/AppArmor profiles** | None found | No `seccomp:` or `apparmor:` in compose | ❌ Missing | **MEDIUM** - Container escape risk | Add seccomp profiles |
| **No secrets in images** | Dockerfiles | No COPY of secrets; all via env vars | ✅ Implemented | N/A | - |
| **Templates mounted read-only** | `compose.yml:24-25, 52-53, 82-83, 162-163` | `:ro` suffix on all template mounts | ✅ Implemented | N/A | - |
| **OPA policy wired into scenario creation** | `spawn_service/main.py:664-687`, `orchestrator/main.py:601-630` | `opa_allows()`, `check_opa_policy()` | ✅ Implemented | N/A | - |
| **training_gate active** | `policies/training_gate.rego` | 146 lines, deny-all default, track configs | ✅ Implemented | N/A | - |
| **OPA tests/validation** | `.github/workflows/ci.yml:150-167` | `opa test -v policies/` in CI | ✅ Implemented | N/A | - |
| **Signed logs/audits** | `orchestrator/main.py:744-792`, `scoreboard/main.py:334-386` | `append_audit_event()` with hash chain | ✅ Implemented | N/A | - |
| **Canary pipeline for LLM proposals** | `policies/llm_gate.rego`, `llm_analyzer/` | Policy requires canary for high-risk | 🟡 Partial | **LOW** - Policy exists, wiring unclear | Wire canary execution |
| **Rollback safety** | None found | No explicit rollback mechanism | ❌ Missing | **MEDIUM** - No undo | Add scenario rollback API |
| **Prometheus scrapes** | `telemetry/prometheus.yml` | Only scrapes `forge_spawn_service:8080` | 🟡 Partial | **LOW** - Missing metrics | Add all service scrapes |
| **Loki dashboards** | `telemetry/grafana/provisioning/datasources/datasource.yml` | Loki datasource configured | 🟡 Partial | **LOW** - No dashboards | Add actual dashboard JSON |
| **Grafana dashboards (spawns by track)** | `telemetry/grafana/provisioning/dashboards/` | Empty provisioner config, no JSON files | ❌ Missing | **MEDIUM** - No visibility | Create spawn metrics dashboard |
| **PII scrubbing** | `overlay_sanitizer/main.py:221-269` | Regex patterns for EMAIL, SSN, CC, etc. | ✅ Implemented | N/A | - |
| **Audit hashing/signing** | `scoreboard/main.py:608-624`, `entitlements.py:407-436` | Ed25519 signing, SHA256 chains | ✅ Implemented | N/A | - |
| **MinIO lifecycle** | None found | No lifecycle policy configured | ❌ Missing | **MEDIUM** - Storage bloat | Add retention policy |
| **Automated grading from successCriteria** | `scoreboard/main.py:273-310`, templates | `calculate_score()` + criteria in templates | 🟡 Partial | **HIGH** - Not wired | Wire criteria evaluation |
| **CI/CD staging quickstart** | `.github/workflows/ci.yml`, `scripts/smoke_test.py` | CI runs tests; smoke_test does compose up | 🟡 Partial | **LOW** - Manual | Add staging deploy workflow |
| **Billing integration** | `entitlements.py`, stubs | Receipt token verification, audit chain | 🟡 Partial | **HIGH** - No payment | Integrate payment gateway |
| **Short-lived token auth (access broker)** | `spawn_service/main.py:96-130` | `ACCESS_TOKEN_SECRET`, 30-min tokens | ✅ Implemented | N/A | - |

---

## 3. Security Audit Findings

### Top 10 Critical Security Risks

| # | Severity | Finding | Exploit Story | Fix |
|---|----------|---------|---------------|-----|
| 1 | **CRITICAL** | `DRY_RUN=true` in dev compose for egress_gateway | Attacker compromises scenario container, exfiltrates data to external server. No nftables rules applied. | Set `DRY_RUN=false` in compose.staging.yml (already done), enforce in production via startup guard |
| 2 | **HIGH** | No seccomp/AppArmor profiles | Container escape via kernel vulnerability. cap_drop helps but seccomp provides syscall filtering. | Add `security_opt: ["seccomp:seccomp-profile.json"]` to all services |
| 3 | **HIGH** | Docker socket mounted read-only on orchestrator/worker | Container with socket access can list/exec into other containers. `:ro` prevents writes but allows reads. | Use Docker-in-Docker sidecar or switch to k3s CRD model |
| 4 | **HIGH** | Default MinIO creds in .env.example | `forgeadmin:forgeadmin123` — trivial brute force if exposed | Generate random creds in staging bootstrap; document credential rotation |
| 5 | **HIGH** | Ephemeral signing keys in scoreboard/sanitizer | `SIGNING_KEY` generated at startup = verdicts unverifiable after restart | Mount persistent key from Vault/KMS or file volume |
| 6 | **MEDIUM** | Redis used without auth | Any container on forge_platform network can access rate-limit keys | Add `--requirepass` to Redis command |
| 7 | **MEDIUM** | No network segmentation between services | All services on single `forge_platform` network. Compromised service can reach all others. | Create separate networks: platform, telemetry, scenario |
| 8 | **MEDIUM** | `SAT_HMAC_SECRET` fallback in dev | Dev mode generates ephemeral secret, warning only | Fail startup if secret missing (already enforced in staging/prod) |
| 9 | **MEDIUM** | Prometheus only scrapes spawn_service | Other services have no metrics visibility. Anomalies in orchestrator/scoreboard go unnoticed. | Add all services to prometheus.yml scrape_configs |
| 10 | **LOW** | No resource limits on NATS JetStream | Stream retention is time-based only. Burst of events could exhaust disk. | Add `--max-bytes` to stream creation |

### Docker Compose Hardening Checklist

| Check | Status | Evidence |
|-------|--------|----------|
| `read_only: true` | ✅ All services | compose.yml lines 26, 55, 86, 113, etc. |
| `cap_drop: [ALL]` | ✅ All services | compose.yml lines 28-29, 58-59, etc. |
| `security_opt: no-new-privileges` | ✅ All services | compose.yml lines 30-32, 60-62, etc. |
| `seccomp profile` | ❌ Not set | No seccomp: entries |
| `apparmor profile` | ❌ Not set | No apparmor: entries |
| Non-root user | ✅ Spawn/Scoreboard | `USER 65532:65532` in Dockerfile |
| Non-root user | 🟡 Orchestrator | `USER forge` (UID 1000) |
| `tmpfs` for /tmp | ✅ Most services | compose.yml lines 27-28, etc. |
| Network segmentation | ❌ Single network | All on `forge_platform` |
| Resource limits | ❌ Not set | No `mem_limit`, `cpu_quota` in compose (but orchestrator applies them to spawned containers) |

### Secrets Analysis

| Secret | Location | Risk |
|--------|----------|------|
| `MINIO_ROOT_PASSWORD` | .env.example (`forgeadmin123`) | HIGH - Default password in repo |
| `SAT_HMAC_SECRET` | .env.example (`change-me`) | MEDIUM - Placeholder warns user |
| `RECEIPT_HMAC_SECRET` | .env.example (empty) | LOW - Requires explicit config |
| `ET_HMAC_SECRET` | .env.example (empty) | LOW - Requires explicit config |
| Hardcoded test secrets | test files | LOW - Tests only, not production |

**No leaked private keys or AWS credentials found.**

---

## 4. Completion Assessment

### Milestone Progress

| Milestone | Blueprint Requirement | Status | Completion % |
|-----------|----------------------|--------|--------------|
| **Billing + short-lived token auth** | Receipt verification, entitlement tokens | 🟡 Partial | 70% |
| **Automated scoring for successCriteria** | Score from template criteria | 🟡 Partial | 60% |
| **Spawn service deployable in staging** | compose up + CI/CD | 🟡 Partial | 80% |
| **Expanded templates + OPA gates** | Advanced tiers, custom rules | 🟡 Partial | 50% |

### Completion Score: **65/100**

**Reasoning:**
- Core spawn flow works (spawn → orchestrator → isolated network → scoring)
- OPA policies comprehensive and tested
- Container hardening solid (read_only, cap_drop, no-new-privileges)
- Token system implemented (SAT, ET, access tokens)
- **Missing:** Production billing, criteria evaluation wiring, seccomp, dashboards, MinIO lifecycle, rollback

### Critical Path (12 Items, Ordered)

| # | Item | Engineering Days | Dependencies | Highest Risk Unknown |
|---|------|------------------|--------------|---------------------|
| 1 | Wire successCriteria evaluation in scoreboard | 2 | None | Criteria execution model |
| 2 | Set `DRY_RUN=false` and test egress enforcement | 1 | CAP_NET_ADMIN in production | nftables permission errors |
| 3 | Add seccomp profiles to compose | 2 | None | Profile compatibility |
| 4 | Create Grafana dashboards (spawns by track, completion rate) | 1 | None | None |
| 5 | Add all services to Prometheus scrape_configs | 0.5 | Services expose /metrics | Metric name conflicts |
| 6 | Integrate payment gateway for billing | 5 | Gateway account | Webhook reliability |
| 7 | Persist signing keys via mounted volume | 1 | Key generation | Key rotation strategy |
| 8 | Add network segmentation (platform/scenario/telemetry) | 2 | None | Service discovery changes |
| 9 | Configure MinIO lifecycle policies | 1 | None | None |
| 10 | Add Redis authentication | 0.5 | None | Connection string changes |
| 11 | Create staging deploy GitHub Action | 2 | Staging infra | Secrets management |
| 12 | Document rollback procedure | 1 | None | None |

### Single Biggest Blocker

**successCriteria not wired to actual evaluation**

Templates define `successCriteria` with commands/file checks, but `calculate_score()` in scoreboard only processes criteria results passed in — it doesn't execute them against containers.

**Fastest way around:** Have orchestrator/worker execute criteria commands against scenario containers before completion, pass results to scoreboard. Requires ~2 days.

---

## 5. Patch Plan

### Fix Now (Today) — 5-10 Changes

| # | File | Change | Acceptance Criteria |
|---|------|--------|---------------------|
| 1 | `compose.staging.yml` | Verify `DRY_RUN=false` for egress_gateway | `docker compose config | grep DRY_RUN` shows `false` |
| 2 | `telemetry/prometheus.yml` | Add scrape configs for all services | `curl localhost:9090/targets` shows 10+ targets |
| 3 | `.env.example` | Change `forgeadmin123` to `changeme-generate-random` | No default passwords in file |
| 4 | `compose.yml` | Add `--requirepass ${REDIS_PASSWORD}` to Redis command | Redis rejects unauthenticated connections |
| 5 | `compose.yml` | Add `REDIS_PASSWORD` to all services using Redis | Services connect with password |
| 6 | `services/scoreboard/app/main.py` | Add `_check_minio_ready()` to `readyz` | Readiness probe catches MinIO failures |

### Fix Next (This Week) — 5-10 Changes

| # | File | Change | Acceptance Criteria |
|---|------|--------|---------------------|
| 1 | `compose.yml` | Add `security_opt: ["seccomp:docker/seccomp-default.json"]` to services | Containers use seccomp |
| 2 | `services/orchestrator/app/main.py` | Add criteria execution before completion | Score includes evaluated criteria |
| 3 | `telemetry/grafana/provisioning/dashboards/` | Add `forge-spawns.json` dashboard | Grafana shows spawn metrics |
| 4 | `storage/minio/` | Add `lifecycle.json` with 90-day expiration | MinIO auto-expires old evidence |
| 5 | `compose.yml` | Create `forge_scenario` network, isolate spawned containers | Scenario containers can't reach platform services |
| 6 | `.github/workflows/staging-deploy.yml` | Create workflow for staging deployment | `git push` triggers staging deploy |
| 7 | `services/scoreboard/app/main.py` | Load signing key from `SIGNING_KEY_PATH` env | Key persists across restarts |

### Fix Later (Post-MVP Hardening) — 5-10 Changes

| # | File | Change | Acceptance Criteria |
|---|------|--------|---------------------|
| 1 | `compose.yml` | Remove Docker socket mounts, use k3s sidecar | No `/var/run/docker.sock` in compose |
| 2 | All services | Add AppArmor profiles | `security_opt: ["apparmor:forge-profile"]` |
| 3 | `services/spawn_service/` | Integrate Stripe/payment gateway | Real charges in production |
| 4 | `scenario_dsl/` | Create DSL parser for complex scenarios | Custom scenario definitions work |
| 5 | `services/orchestrator/` | Add rollback API endpoint | DELETE /v1/scenarios/{id}/rollback works |
| 6 | `telemetry/` | Add alerting rules for spawn failures | Prometheus fires alerts |
| 7 | All services | Add resource limits to compose | `mem_limit`, `cpu_quota` set |
| 8 | `policies/` | Add OPA bundle versioning | Policies loaded from versioned bundles |

---

## 6. Verification Commands

### Staging Compose Up

```bash
# Copy env and set secrets
cp .env.example .env
# Edit .env: set SAT_HMAC_SECRET, ORCHESTRATOR_INTERNAL_TOKEN, OPERATOR_TOKEN, SCOREBOARD_INTERNAL_TOKEN

# Start staging
docker compose -f compose.yml -f compose.staging.yml up -d --build

# Wait for readiness
curl -sf http://localhost:8082/readyz  # spawn_service
curl -sf http://localhost:8083/readyz  # orchestrator
curl -sf http://localhost:8086/readyz  # scoreboard
```

### Spawn API Example

```bash
# Generate request ID
REQUEST_ID="req-$(uuidgen | cut -d- -f1)"

# Spawn a scenario
curl -s -X POST http://localhost:8082/v1/spawn \
  -H "Content-Type: application/json" \
  -H "x-request-id: $REQUEST_ID" \
  -H "x-client-id: test-user-001" \
  -d '{
    "track": "netplus",
    "subject": "test-user-001",
    "request_id": "'$REQUEST_ID'"
  }' | jq .

# Expected output:
# {
#   "request_id": "req-...",
#   "scenario_id": "scn-...",
#   "access_url": "http://localhost:8082/v1/access/scn-...?token=...",
#   "access_token": "...",
#   "expires_at": "...",
#   "sat": "..."
# }
```

### OPA Policy Test

```bash
# Run OPA tests locally
docker run --rm -v $(pwd):/workspace -w /workspace \
  openpolicyagent/opa:latest test -v policies/

# Expected: all tests pass
```

### Egress Deny Verification

```bash
# Check egress gateway config
curl -s http://localhost:8089/readyz | jq .
# Expected: {"status": "ready", "dry_run": false}

# In staging, check nftables ruleset
docker exec forge_egress_gateway nft list ruleset
# Expected: output chain with "policy drop"
```

### Telemetry Sanity Checks

```bash
# Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets[].labels.job'

# Loki ready
curl -s http://localhost:3100/ready
# Expected: "ready"

# Grafana datasources
curl -s -u forgeadmin:forgeadmin http://localhost:3000/api/datasources | jq '.[].name'
# Expected: ["Prometheus", "Loki"]
```

### Full Smoke Test

```bash
# Run the smoke test script
python3 scripts/smoke_test.py

# Or with compose left running for inspection
python3 scripts/smoke_test.py --skip-down

# Verify scoring artifacts
ls storage/scenarios/scn-*/results/
# Expected: score.json, evidence.tar.zst (or .gz), verdict.sig, verdict.pub, audit.jsonl

# Verify verdict signature
python3 scripts/verify_verdict.py \
  storage/scenarios/scn-*/results/score.json \
  storage/scenarios/scn-*/results/evidence.tar.* \
  storage/scenarios/scn-*/results/verdict.sig \
  storage/scenarios/scn-*/results/verdict.pub
# Expected: "PASS: verdict verification succeeded"
```

---

## Summary

FrostGate Forge has **solid foundations** but requires focused work to reach production readiness:

1. **Good:** Container hardening, OPA policies, token system, scoring artifacts, audit chains
2. **Needs work:** Egress enforcement in prod, seccomp profiles, network segmentation, billing integration
3. **Biggest gap:** successCriteria evaluation not wired — this is core monetization

**Recommended priority:** Fix egress DRY_RUN verification (1 day) → Wire criteria evaluation (2 days) → Add dashboards (1 day) → Billing integration (5 days)

---

*Report generated by automated audit. All findings verified against repository state as of 2026-01-15.*

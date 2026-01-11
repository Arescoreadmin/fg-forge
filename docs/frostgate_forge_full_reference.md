# FrostGate Forge Full Reference

**Version**: 1.0
**Status**: Active Development
**Last Updated**: 2026-01-11

This document serves as the comprehensive technical reference for FrostGate Forge, a governed, sandboxed cyber-training platform. It consolidates architecture, API specifications, data models, security policies, and implementation details.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architecture Overview](#architecture-overview)
3. [Service Specifications](#service-specifications)
4. [API Reference](#api-reference)
5. [Data Models](#data-models)
6. [Security Framework](#security-framework)
7. [Scenario DSL](#scenario-dsl)
8. [Telemetry & Observability](#telemetry--observability)
9. [Deployment Guide](#deployment-guide)
10. [Operations Runbook](#operations-runbook)

---

## Executive Summary

FrostGate Forge delivers training-as-a-service with the following core capabilities:

- **Monetizable Training Tracks**: Tiered templates (netplus, ccna, cissp) with billing integration
- **Governed Automation**: OPA policy gates enforce security constraints at every decision point
- **Deterministic Scoring**: Success criteria produce verifiable evidence bundles
- **High Isolation**: Per-scenario networks with deny-all egress by default
- **First-Class Telemetry**: Fairness metrics, outcome tracking, usage analytics

### Core Principles

1. **Security by Default**: Deny-all egress, read-only containers, no privileged operations
2. **Evidence-First**: Every action produces auditable artifacts
3. **Policy-Gated**: OPA validates all scenario spawns and agent actions
4. **Idempotent Operations**: All spawn requests are traceable via request_id

---

## Architecture Overview

### System Topology

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           FrostGate Forge Platform                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐     │
│  │  Spawn Service  │───▶│   Orchestrator   │───▶│   Worker Agent     │     │
│  │   (Intake API)  │    │  (OPA + Launch)  │    │ (Exec + Evidence)  │     │
│  └────────┬────────┘    └────────┬─────────┘    └─────────┬──────────┘     │
│           │                      │                        │                │
│           │                      ▼                        ▼                │
│           │             ┌──────────────────┐    ┌────────────────────┐     │
│           │             │    OPA Engine    │    │  Playbook Runner   │     │
│           │             │ (Policy Gates)   │    │(Success Criteria)  │     │
│           │             └──────────────────┘    └─────────┬──────────┘     │
│           │                                               │                │
│           ▼                                               ▼                │
│  ┌─────────────────┐                           ┌────────────────────┐      │
│  │   NATS (Bus)    │◀─────────────────────────▶│    Scoreboard      │      │
│  │  spawn.request  │                           │ (Score + Evidence) │      │
│  │  telemetry.*    │                           └─────────┬──────────┘      │
│  └────────┬────────┘                                     │                │
│           │                                               ▼                │
│           ▼                                     ┌────────────────────┐     │
│  ┌─────────────────┐                           │      MinIO         │     │
│  │  Observer Hub   │                           │ (Evidence Store)   │     │
│  │ (Telemetry Agg) │                           └────────────────────┘     │
│  └────────┬────────┘                                                      │
│           │                                                               │
│           ▼                                                               │
│  ┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐    │
│  │   Prometheus    │───▶│      Loki        │◀───│     Grafana        │    │
│  │   (Metrics)     │    │     (Logs)       │    │   (Dashboards)     │    │
│  └─────────────────┘    └──────────────────┘    └────────────────────┘    │
│                                                                           │
├───────────────────────────────────────────────────────────────────────────┤
│                         Scenario Network (Isolated)                        │
├───────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐   │
│  │  Learner VM │  │  Attacker   │  │  Defender   │  │ Egress Gateway  │   │
│  │  (alpine)   │  │   Agent     │  │   Agent     │  │  (deny-all)     │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────┘   │
│  ┌─────────────┐  ┌─────────────┐                                         │
│  │ Aux Device1 │  │ Aux Device2 │                                         │
│  └─────────────┘  └─────────────┘                                         │
└───────────────────────────────────────────────────────────────────────────┘
```

### Service Registry

| Service | Port | Purpose |
|---------|------|---------|
| forge_spawn_service | 8082 | Intake API for billing + spawn requests |
| forge_orchestrator | 8083 | Template validation, OPA enforcement, scenario launch |
| forge_worker_agent | 8084 | Scenario execution and evidence collection |
| forge_observer_hub | 8085 | Telemetry aggregation and audit streams |
| forge_scoreboard | 8086 | Score calculation and evidence bundle generation |
| forge_playbook_runner | 8087 | Success criteria playbook execution |
| forge_egress_gateway | - | nftables deny-all gateway |
| forge_opa | 8181 | Policy engine |
| forge_nats | 4222/8222 | Event bus with JetStream |
| forge_minio | 9000/9001 | Object storage for evidence |
| forge_prometheus | 9090 | Metrics collection |
| forge_loki | 3100 | Log aggregation |
| forge_grafana | 3000 | Dashboards |

---

## Service Specifications

### forge_spawn_service

**Purpose**: Monetization choke point and safe intake for scenario requests.

**Responsibilities**:
- Validate incoming spawn requests
- Enforce idempotency via request_id
- Record billing events (stub/production modes)
- Forward validated requests to orchestrator

**Configuration**:
```yaml
environment:
  FORGE_ENV: dev|staging|production
  BILLING_MODE: stub|gateway
  SPAWN_BASE_URL: http://localhost:8082
  REQUEST_ID_HEADER: x-request-id
  TEMPLATE_DIR: /templates
  OPA_URL: http://forge_opa:8181
  NATS_URL: nats://forge_nats:4222
```

### forge_orchestrator

**Purpose**: Central coordinator for scenario lifecycle management.

**Responsibilities**:
- Load and validate scenario templates
- Enforce OPA policies before launch
- Create isolated scenario networks
- Dispatch work to worker agents
- Track scenario state via NATS

**Key Operations**:
1. Receive spawn request from NATS `spawn.request`
2. Load template from `/templates`
3. Query OPA for policy decision
4. Create scenario network (Docker network or k8s namespace)
5. Launch scenario containers
6. Publish `scenario.created` event
7. Monitor for completion/timeout

### forge_worker_agent

**Purpose**: Execute scenario playbooks and collect evidence.

**Responsibilities**:
- Subscribe to `scenario.execute` events
- Run learner environment setup
- Execute evidence collection commands
- Stream telemetry to observer_hub
- Report completion to scoreboard

**Evidence Collection**:
```python
evidence_types = [
    "command_output",    # stdout/stderr from commands
    "file_capture",      # file contents at checkpoints
    "network_capture",   # pcap excerpts
    "state_snapshot",    # container state dumps
]
```

### forge_scoreboard

**Purpose**: Calculate scores and generate evidence bundles.

**Outputs**:
- `score.json`: Normalized scores per success criterion
- `evidence.tar.zst`: Compressed evidence artifacts
- `verdict.sig`: Ed25519 signature over content hashes
  - **Generation**: Produced after `score.json` and `evidence.tar.zst` are finalized; the signer builds a manifest of SHA-256 hashes for each output plus scenario metadata (scenario_id, run_id, timestamp) and signs the manifest bytes.
  - **Rotation cadence**: Signing keys rotate every 90 days or on-demand for incident response; old keys remain valid for verification until the retention window expires.
  - **Storage backend**: Signatures are stored alongside evidence in the primary artifact store (S3-compatible bucket) with immutable object locking enabled when supported.
  - **Verification steps**: Consumers fetch `verdict.sig`, load the corresponding public key, rebuild the manifest from retrieved artifacts, and verify the Ed25519 signature before accepting scores.

**Scoring Algorithm**:
```python
def calculate_score(criteria_results: list[CriterionResult]) -> Score:
    passed = sum(1 for r in criteria_results if r.passed)
    total = len(criteria_results)
    return Score(
        value=passed / total if total > 0 else 0.0,
        passed=passed,
        total=total,
        criteria=criteria_results,
    )
```

### forge_observer_hub

**Purpose**: Aggregate telemetry from all scenario components.

**Streams**:
- `telemetry.metrics`: Prometheus-format metrics
- `telemetry.logs`: Structured log events
- `telemetry.traces`: Distributed traces (optional)

**Features**:
- PII detection and flagging
- Cardinality control for labels
- Fairness metric calculation

### forge_playbook_runner

**Purpose**: Execute success criteria playbooks deterministically.

**Playbook Format**:
```yaml
playbook:
  - step: execute_command
    container: learner_vm
    command: "ping -c 1 10.10.0.1"
    expect:
      exit_code: 0
      stdout_contains: "1 packets received"
  - step: check_file
    container: learner_vm
    path: /etc/hosts
    expect:
      contains: "gateway"
```

### forge_egress_gateway

**Purpose**: Enforce deny-all egress with optional allowlist profiles.

**nftables Rules**:
```nft
table inet forge_egress {
    chain output {
        type filter hook output priority 0;
        policy drop;

        # Allow established connections
        ct state established,related accept

        # Allow loopback
        oif lo accept

        # Allow internal network
        ip daddr 10.0.0.0/8 accept
        ip daddr 172.16.0.0/12 accept
        ip daddr 192.168.0.0/16 accept

        # Log and drop everything else
        log prefix "FORGE_EGRESS_DENY: " drop
    }
}
```

---

## API Reference

### Spawn Service API

#### POST /v1/spawn

Create a new training scenario.

**Authentication**:
- OAuth2/JWT bearer token (`Authorization: Bearer <token>`) is required for all non-health endpoints.
- Tokens must include tenant and role claims (see [Tenant Boundaries and Claims](#tenant-boundaries-and-claims)).

**Request**:
```json
{
  "track": "netplus|ccna|cissp",
  "request_id": "optional-idempotency-key"
}
```

**Headers**:
- `Content-Type: application/json`
- `x-request-id: <idempotency-key>` (alternative to body field)

**Response** (201 Created):
```json
{
  "request_id": "req-abc123",
  "scenario_id": "scn-def456789012",
  "access_url": "http://localhost:8082/access/scn-def456789012",
  "expires_at": "2026-01-11T13:30:00Z"
}
```

**Errors**:
- `400`: Missing request_id or unsupported track
- `401`: Missing/invalid bearer token
- `403`: OPA policy denied or insufficient role/tenant scope
- `429`: Rate limit exceeded (per-tenant quotas; retry with backoff)
- `502`: OPA unavailable
- `500`: Internal error

#### GET /health

Health check endpoint.

**Authentication**:
- None (public/internal readiness probe)

**Response**:
```json
{
  "status": "ok",
  "service": "forge_spawn_service"
}
```

### Orchestrator API

#### POST /v1/scenarios

Internal API for scenario creation.

**Authentication**:
- Mutual TLS (mTLS) between services for internal calls.
- OAuth2/JWT bearer token may be required when called from external control planes.
- Tokens must include tenant and role claims (see [Tenant Boundaries and Claims](#tenant-boundaries-and-claims)).

**Request**:
```json
{
  "scenario_id": "scn-def456789012",
  "template": "netplus",
  "request_id": "req-abc123"
}
```

**Response**:
```json
{
  "scenario_id": "scn-def456789012",
  "status": "creating",
  "network_id": "forge_scn_def456789012"
}
```

**Errors**:
- `401`: Missing/invalid bearer token (when token auth is enabled)
- `403`: mTLS identity or token claims not authorized for tenant or role
- `429`: Rate limit exceeded (per-tenant quotas; retry with backoff)

#### GET /v1/scenarios/{scenario_id}

Get scenario status.

**Authentication**:
- Mutual TLS (mTLS) between services for internal calls.
- OAuth2/JWT bearer token may be required when called from external control planes.
- Tokens must include tenant and role claims (see [Tenant Boundaries and Claims](#tenant-boundaries-and-claims)).

**Response**:
```json
{
  "scenario_id": "scn-def456789012",
  "status": "running|completed|failed|timeout",
  "created_at": "2026-01-11T13:00:00Z",
  "containers": ["learner_vm", "egress_gateway"],
  "network_id": "forge_scn_def456789012"
}
```

**Errors**:
- `401`: Missing/invalid bearer token (when token auth is enabled)
- `403`: mTLS identity or token claims not authorized for tenant or role
- `429`: Rate limit exceeded (per-tenant quotas; retry with backoff)

### Scoreboard API

#### GET /v1/scores/{scenario_id}

Retrieve scenario score.

**Authentication**:
- OAuth2/JWT bearer token (`Authorization: Bearer <token>`) is required.
- Tokens must include tenant and role claims (see [Tenant Boundaries and Claims](#tenant-boundaries-and-claims)).

**Response**:
```json
{
  "scenario_id": "scn-def456789012",
  "score": {
    "value": 0.85,
    "passed": 17,
    "total": 20
  },
  "evidence_url": "s3://forge-evidence/scn-def456789012/evidence.tar.zst",
  "verdict_url": "s3://forge-evidence/scn-def456789012/verdict.sig"
}
```

**Errors**:
- `401`: Missing/invalid bearer token
- `403`: Token claims not authorized for tenant or role
- `429`: Rate limit exceeded (per-tenant quotas; retry with backoff)

### Tenant Boundaries and Claims

All API calls are scoped to a tenant boundary. The caller must present identity claims that bind the request to a single tenant, and policies enforce that access is limited to that tenant's resources.

**Required claims**:
- `tenant_id`: Identifier for the tenant owning the scenario and data.
- `roles`: One or more roles (e.g., `forge.spawn`, `forge.orchestrator`, `forge.score.read`).

**Enforcement**:
- Spawn requests are authorized only when the caller's `tenant_id` matches the requested tenant context (or is resolved from the caller identity) and the `roles` claim includes `forge.spawn`.
- Orchestrator operations require `forge.orchestrator` and must operate only on scenarios tagged to the caller's `tenant_id`.
- Score retrieval requires `forge.score.read` and is limited to scores for scenarios under the same `tenant_id`.
- OPA policies enforce tenant isolation at request time and deny cross-tenant access with `403`.

### Rate Limiting and Abuse Protections

Rate limits and quotas are enforced per tenant to prevent noisy-neighbor and abuse scenarios.

**Per-tenant quotas**:
- Request budgets are applied to create, status, and score endpoints.
- Burst limits are enforced using token bucket or leaky bucket controls.

**Retry and backoff guidance**:
- When receiving `429 Too Many Requests`, clients should retry with exponential backoff and jitter.
- The service may return `Retry-After` to indicate a safe delay window.

**Error codes**:
- `401`: Authentication required or invalid token.
- `403`: Authorization failed (wrong tenant or missing roles).
- `429`: Rate limit exceeded (per-tenant quota).

---

## Data Models

### ScenarioTemplate

```yaml
metadata:
  name: string           # Template identifier
  labels:                # Classification labels
    - class:<track>      # Training track (netplus, ccna, cissp)
    - tier:<level>       # Difficulty tier (foundation, intermediate, advanced)

limits:
  cpu: int               # CPU cores allocated
  memory_mb: int         # Memory in MB
  attacker_max_exploits: int  # Exploit limit (0 for training tracks)
  timeout_minutes: int   # Scenario timeout

network:
  egress: deny|allowlist # Egress policy
  allowlist_profile: string|null  # Profile name if allowlist

assets:
  containers:
    - name: string       # Container identifier
      image: string      # Docker image
      read_only: bool    # Read-only filesystem
      environment: dict  # Environment variables
      networks: list     # Network attachments

successCriteria:
  - id: string           # Criterion identifier
    description: string  # Human-readable description
    weight: float        # Score weight (default 1.0)
    evidence:
      - type: command|file|network|state
        command: string  # For command type
        path: string     # For file type
        expect:
          exit_code: int
          stdout_contains: string
          file_exists: bool
```

### SpawnRequest

```python
class SpawnRequest(BaseModel):
    track: str           # Training track identifier
    request_id: str      # Idempotency key
    metadata: dict = {}  # Optional user metadata
```

### ScenarioState

```python
class ScenarioState(BaseModel):
    scenario_id: str
    status: Literal["pending", "creating", "running", "completed", "failed", "timeout"]
    created_at: datetime
    updated_at: datetime
    network_id: str
    containers: list[str]
    error: str | None = None
```

### EvidenceBundle

```python
class EvidenceBundle(BaseModel):
    scenario_id: str
    collected_at: datetime
    artifacts: list[Artifact]
    criteria_results: list[CriterionResult]

class Artifact(BaseModel):
    type: str            # command_output, file_capture, etc.
    name: str            # Artifact identifier
    content_hash: str    # SHA-256 of content
    size_bytes: int
    path: str            # Path in evidence archive

class CriterionResult(BaseModel):
    criterion_id: str
    passed: bool
    evidence_refs: list[str]  # Artifact names
    message: str | None
```

### ScoreResult

```python
class ScoreResult(BaseModel):
    scenario_id: str
    score: float         # 0.0 to 1.0
    passed: int          # Criteria passed
    total: int           # Total criteria
    criteria: list[CriterionResult]
    computed_at: datetime
```

---

## Security Framework

### Container Hardening

All containers MUST apply:

```yaml
security_opt:
  - no-new-privileges:true
  - seccomp:unconfined  # Replace with custom profile in production
cap_drop:
  - ALL
read_only: true
tmpfs:
  - /tmp:size=64M
```

### OPA Policy Structure

```
policies/
  training_gate.rego     # Training scenario validation
  spawn_gate.rego        # Spawn request authorization
  action_gate.rego       # Agent action authorization
  llm_gate.rego          # LLM proposal validation
```

**Training Gate Policy**:
```rego
package frostgate.forge.training

default allow = false

# Allow netplus foundation track
allow {
    input.metadata.labels[_] == "class:netplus"
    input.limits.attacker_max_exploits <= 0
    input.network.egress == "deny"
}

# Allow ccna track
allow {
    input.metadata.labels[_] == "class:ccna"
    input.limits.attacker_max_exploits <= 0
    input.network.egress == "deny"
}

# Allow cissp track (limited exploits permitted)
allow {
    input.metadata.labels[_] == "class:cissp"
    input.limits.attacker_max_exploits <= 5
    input.network.egress == "deny"
}

# Deny reasons for debugging
deny_reasons[msg] {
    not input.network.egress == "deny"
    msg := "egress must be deny"
}

deny_reasons[msg] {
    input.limits.attacker_max_exploits > 5
    msg := sprintf("attacker_max_exploits %d exceeds limit", [input.limits.attacker_max_exploits])
}
```

### Network Isolation

Each scenario runs in an isolated Docker network:

```python
def create_scenario_network(scenario_id: str) -> str:
    network_name = f"forge_scn_{scenario_id}"
    client.networks.create(
        name=network_name,
        driver="bridge",
        internal=True,  # No external access
        labels={
            "forge.scenario_id": scenario_id,
            "forge.created_at": datetime.utcnow().isoformat(),
        },
    )
    return network_name
```

### Audit Trail

All operations produce audit events:

```python
class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    event_type: str      # spawn.request, scenario.created, etc.
    actor: str           # Service or user identifier
    resource_id: str     # Affected resource
    action: str          # create, update, delete, execute
    outcome: str         # success, denied, error
    details: dict = {}
    signature: str | None = None  # Ed25519 signature
```

**Signing authority**: Audit events are signed by the forge_audit service using a dedicated Ed25519 keypair scoped to audit logs.

**Verification endpoints**:
- `GET /audit/keys/current`: Returns the active audit public key and key_id.
- `GET /audit/keys/{key_id}`: Returns a specific historical public key for verification.
- `GET /audit/events/{event_id}/signature`: Returns the detached signature for an audit event.

**Downstream validation**:
- Consumers fetch the public key from the verification endpoint, compute a canonical JSON representation of the audit event (sorted keys, RFC3339 timestamps), and verify the detached signature.
- Failed validation results in rejecting the event and alerting the audit pipeline.

**Operational runbook**:
1. **Key rotation**
   - Generate a new Ed25519 keypair in the HSM/KMS-backed key store.
   - Update forge_audit and forge_scoreboard configurations to reference the new key_id.
   - Publish the new public key via `GET /audit/keys/current` and keep the previous key available through `GET /audit/keys/{key_id}` for the retention window.
   - Verify rotation by validating a new audit event and a new `verdict.sig` in a staging environment before promoting to production.
2. **Incident response: suspected key compromise**
   - Immediately revoke the compromised key_id and remove it from `current` endpoints.
   - Rotate to a new keypair and re-sign any in-flight audit events or evidence bundles.
   - Invalidate cached public keys across downstream consumers and force a refresh from verification endpoints.
   - Run an integrity sweep on the artifact store to identify unsigned or unverifiable evidence and quarantine affected records.

---

## Scenario DSL

The scenario DSL defines training environments declaratively.

### Template Structure

```yaml
apiVersion: frostgate.forge/v1
kind: ScenarioTemplate
metadata:
  name: netplus-routing-lab
  labels:
    - class:netplus
    - tier:intermediate
    - topic:routing
  annotations:
    description: "Network+ routing fundamentals lab"
    duration: "30m"

spec:
  limits:
    cpu: 2
    memory_mb: 2048
    attacker_max_exploits: 0
    timeout_minutes: 30

  network:
    egress: deny
    subnets:
      - name: learner_net
        cidr: 10.10.0.0/24
      - name: target_net
        cidr: 10.20.0.0/24

  assets:
    containers:
      - name: learner_vm
        image: forge/learner-alpine:3.19
        read_only: true
        networks:
          - learner_net
        environment:
          LEARNER_MODE: "true"

      - name: router
        image: forge/vyos-mini:1.4
        read_only: true
        networks:
          - learner_net
          - target_net
        capabilities:
          - NET_ADMIN

      - name: target_server
        image: forge/nginx-test:1.0
        read_only: true
        networks:
          - target_net

  successCriteria:
    - id: route-add
      description: "Configure static route to target network"
      weight: 1.0
      evidence:
        - type: command
          container: learner_vm
          command: "ip route show"
          expect:
            stdout_contains: "10.20.0.0/24"

    - id: connectivity
      description: "Verify connectivity to target server"
      weight: 1.0
      evidence:
        - type: command
          container: learner_vm
          command: "curl -s http://10.20.0.10"
          expect:
            exit_code: 0
            stdout_contains: "nginx"
```

### DSL Validation Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["apiVersion", "kind", "metadata", "spec"],
  "properties": {
    "apiVersion": {
      "const": "frostgate.forge/v1"
    },
    "kind": {
      "const": "ScenarioTemplate"
    },
    "metadata": {
      "type": "object",
      "required": ["name", "labels"],
      "properties": {
        "name": {"type": "string", "pattern": "^[a-z0-9-]+$"},
        "labels": {"type": "array", "items": {"type": "string"}}
      }
    },
    "spec": {
      "type": "object",
      "required": ["limits", "network", "assets", "successCriteria"]
    }
  }
}
```

---

## Telemetry & Observability

### Prometheus Metrics

```yaml
# Spawn metrics
forge_spawn_requests_total{track, status}
forge_spawn_duration_seconds{track}
forge_active_scenarios{track}

# Scoring metrics
forge_score_distribution{track, bucket}
forge_criteria_pass_rate{track, criterion_id}
forge_evidence_size_bytes{track}

# System metrics
forge_opa_decisions_total{policy, result}
forge_nats_messages_total{subject}
forge_container_restarts_total{service}
```

### Grafana Dashboards

**Spawn Overview**:
- Spawns by track (time series)
- Spawn success rate (gauge)
- Average spawn latency (histogram)
- Active scenarios (gauge)

**Scoring Analytics**:
- Score distribution by track
- Pass rate per criterion
- Evidence bundle sizes
- Completion time distribution

**System Health**:
- Service health status
- OPA policy decision breakdown
- NATS message throughput
- Container resource utilization

### Loki Labels

```yaml
labels:
  service: forge_spawn_service|forge_orchestrator|...
  scenario_id: scn-xxx
  track: netplus|ccna|cissp
  level: debug|info|warn|error
```

**Cardinality Limits**:
- Max 10 label keys per stream
- Max 1000 unique label value combinations per service
- Use structured JSON for high-cardinality data

---

## Deployment Guide

### Prerequisites

- Docker 24.0+
- Docker Compose v2.20+
- 8GB RAM minimum
- 20GB disk space

### Staging Deployment

```bash
# Clone and configure
git clone https://github.com/org/fg-forge.git
cd fg-forge
cp .env.example .env

# Edit configuration
vim .env

# Launch stack
docker compose -f compose.yml -f compose.staging.yml up -d --build

# Initialize NATS streams
./scripts/setup_nats_streams.sh

# Verify deployment
curl http://localhost:8082/health
curl http://localhost:8181/health
```

### Environment Variables

```bash
# Core
FORGE_ENV=staging
LOG_LEVEL=info

# Billing
BILLING_MODE=stub

# Security
OPA_URL=http://forge_opa:8181
NATS_URL=nats://forge_nats:4222

# Storage
MINIO_ROOT_USER=forgeadmin
MINIO_ROOT_PASSWORD=<secure-password>
MINIO_BUCKET=forge-evidence

# Telemetry
GRAFANA_USER=forgeadmin
GRAFANA_PASSWORD=<secure-password>
```

### Production Checklist

- [ ] Replace default passwords
- [ ] Enable TLS for all services
- [ ] Configure seccomp profiles
- [ ] Enable AppArmor profiles
- [ ] Set resource limits
- [ ] Configure persistent volumes
- [ ] Enable audit logging
- [ ] Set up alerting
- [ ] Configure backup retention
- [ ] Document runbooks

---

## Operations Runbook

### Common Operations

**Spawn a Test Scenario**:
```bash
curl -X POST http://localhost:8082/v1/spawn \
  -H 'Content-Type: application/json' \
  -H 'x-request-id: test-001' \
  -d '{"track": "netplus"}'
```

**Check OPA Policy**:
```bash
curl -X POST http://localhost:8181/v1/data/frostgate/forge/training/allow \
  -H 'Content-Type: application/json' \
  -d '{"input": {"metadata": {"labels": ["class:netplus"]}, "limits": {"attacker_max_exploits": 0}, "network": {"egress": "deny"}}}'
```

**View Active Scenarios**:
```bash
docker ps --filter "label=forge.scenario_id"
```

**Cleanup Stale Scenarios**:
```bash
./scripts/cleanup_scenarios.sh --older-than 2h
```

### Troubleshooting

**Spawn Returns 403**:
1. Check OPA policy is loaded: `curl http://localhost:8181/v1/policies`
2. Verify template labels match policy rules
3. Check `network.egress == "deny"` in template

**Scenario Containers Not Starting**:
1. Check orchestrator logs: `docker logs forge_orchestrator`
2. Verify Docker socket is accessible
3. Check resource availability: `docker system df`

**Evidence Bundle Missing**:
1. Check worker_agent logs for errors
2. Verify MinIO is accessible: `curl http://localhost:9000/minio/health/live`
3. Check scoreboard processing queue

### Alerting Rules

```yaml
groups:
  - name: forge_alerts
    rules:
      - alert: SpawnFailureRateHigh
        expr: rate(forge_spawn_requests_total{status="error"}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High spawn failure rate"

      - alert: OPAUnhealthy
        expr: up{job="forge_opa"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "OPA policy engine is down"

      - alert: NATSBacklog
        expr: nats_jetstream_consumer_pending > 1000
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "NATS consumer backlog growing"
```

---

## Appendix

### NATS Subjects

| Subject | Purpose | Publisher | Consumer |
|---------|---------|-----------|----------|
| `spawn.request` | New spawn requests | spawn_service | orchestrator |
| `scenario.created` | Scenario ready | orchestrator | worker_agent |
| `scenario.execute` | Execute playbook | orchestrator | worker_agent |
| `scenario.completed` | Scenario finished | worker_agent | scoreboard |
| `telemetry.metrics` | Metrics stream | all services | observer_hub |
| `telemetry.logs` | Log events | all services | observer_hub |
| `audit.events` | Audit trail | all services | storage |

### Container Images

| Image | Purpose | Base |
|-------|---------|------|
| `forge/spawn-service` | Spawn API | python:3.12-slim |
| `forge/orchestrator` | Scenario coordination | python:3.12-slim |
| `forge/worker-agent` | Execution engine | python:3.12-slim |
| `forge/scoreboard` | Scoring service | python:3.12-slim |
| `forge/learner-alpine` | Learner environment | alpine:3.19 |
| `forge/egress-gateway` | Network gateway | alpine:3.19 |

### Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-11 | Initial comprehensive reference |

---

*This document is the authoritative reference for FrostGate Forge. For architecture decisions, see `docs/blueprint.md`. For quick start, see `README.md`.*

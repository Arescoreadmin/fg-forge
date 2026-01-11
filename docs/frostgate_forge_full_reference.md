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

### Egress Routing Model

- Scenario containers attach only to the isolated scenario network and use the egress gateway container as their default route for `0.0.0.0/0`.
- The egress gateway is the only container with a second interface on an upstream "egress" network; it performs NAT (masquerade) on outbound traffic so external destinations never see per-container IPs.
- By default, nftables applies a deny-all policy. Allowlisted destinations are the only paths that traverse the gateway; everything else is dropped and logged.
- If the gateway is absent or disabled, the scenario network remains internal and no external egress is possible.

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
3. Query OPA for training policy decision
4. Query OPA for capabilities policy decision (track/tier capability allowlist + privileged capability enforcement)
5. Create scenario network (Docker network or k8s namespace)
6. Launch scenario containers
7. Publish `scenario.created` event
8. Monitor for completion/timeout

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

**Routing & Attachment**:
- Each scenario network sets the egress gateway as the default route for containers that require outbound access.
- The gateway container attaches to the scenario network plus a dedicated upstream egress network, making it the single chokepoint for outbound traffic.
- Containers never get direct connectivity to the upstream network; they only reach it through the gateway.

**NAT Enforcement**:
- The gateway performs outbound NAT (masquerade) so external endpoints see only the gateway IP.
- Reply traffic is permitted for established/related flows; unsolicited inbound is dropped.

**Egress Blocking**:
- nftables uses a default drop policy on outbound paths.
- When no allowlist profile is applied, only internal RFC1918 traffic is permitted; all other destinations are logged and dropped.
- When a profile is applied, only explicitly allowed destinations and ports are permitted; everything else is logged and dropped.

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

**Allowlist Governance & Policy Checks**:
- **Source-of-truth**: Allowed destination sets are defined by the egress gateway profile catalog (see `services/egress_gateway/app/main.py` and `services/egress_gateway/scripts/setup_nftables.sh`), and are the only profiles that can be selected by `network.allowlist_profile`.
- **Approval workflow**: New profiles or changes require a policy/infra review with explicit approval in version control before deployment (change request + PR approval from the platform security owner).
- **OPA checks**: Training gate policy must validate that `network.egress == "allowlist"` only when `network.allowlist_profile` is present and matches an approved profile name; any missing or unknown profile is denied.

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
  - seccomp:default  # Use restrictive profile by default
cap_drop:
  - ALL
read_only: true
tmpfs:
  - /tmp:size=64M
```

**Deviation note**: Only relax seccomp in CI or test environments when required for tooling. Use a documented dev override (for example, `seccomp:unconfined`) and never ship this override to production.

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

**Capabilities Policy (example)**:
```rego
package frostgate.forge.capabilities

default allow = false

privileged_caps := {
    "SYS_ADMIN",
    "SYS_MODULE",
    "SYS_PTRACE",
    "SYS_TIME",
    "DAC_OVERRIDE",
}

track_tier_caps := {
    "netplus": {
        "foundation": [],
        "intermediate": ["NET_ADMIN"],
        "advanced": ["NET_ADMIN", "NET_RAW"],
    },
    "ccna": {
        "foundation": ["NET_ADMIN"],
        "intermediate": ["NET_ADMIN", "NET_RAW"],
        "advanced": ["NET_ADMIN", "NET_RAW"],
    },
    "cissp": {
        "foundation": ["NET_ADMIN"],
        "intermediate": ["NET_ADMIN", "NET_RAW"],
        "advanced": ["NET_ADMIN", "NET_RAW", "SYS_ADMIN", "SYS_PTRACE"],
    },
}

get_track(labels) = track {
    some label
    label := labels[_]
    startswith(label, "class:")
    track := substring(label, 6, -1)
}

get_tier(labels) = tier {
    some label
    label := labels[_]
    startswith(label, "tier:")
    tier := substring(label, 5, -1)
}

allow {
    track := get_track(input.metadata.labels)
    tier := get_tier(input.metadata.labels)
    allowed_caps := track_tier_caps[track][tier]
    containers_caps_allowed(input.spec.assets.containers, allowed_caps)
}

containers_caps_allowed(containers, allowed_caps) {
    count([c |
        c := containers[_]
        cap := object.get(c, "capabilities", [])[_]
        not cap_in_allowlist(cap, allowed_caps)
    ]) == 0
}

cap_in_allowlist(cap, allowed_caps) {
    allowed_caps[_] == cap
}

deny_reasons[msg] {
    track := get_track(input.metadata.labels)
    tier := get_tier(input.metadata.labels)
    allowed_caps := track_tier_caps[track][tier]
    container := input.spec.assets.containers[_]
    cap := object.get(container, "capabilities", [])[_]
    privileged_caps[cap]
    not cap_in_allowlist(cap, allowed_caps)
    msg := sprintf("privileged capability %s not allowed for %s/%s", [cap, track, tier])
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

### Capabilities by Track/Tier

The `spec.assets.containers[].capabilities` field is optional. When provided, each container's capability list **must** be a subset of the allowlist for its track and tier. Capabilities not listed below are rejected by policy. Privileged capabilities require explicit allowlist inclusion for that track/tier.

**Privileged capability set** (always denied unless explicitly allowed): `SYS_ADMIN`, `SYS_MODULE`, `SYS_PTRACE`, `SYS_TIME`, `DAC_OVERRIDE`.

| Track | Tier | Allowed Linux Capabilities |
| --- | --- | --- |
| netplus | foundation | *(none)* |
| netplus | intermediate | `NET_ADMIN` |
| netplus | advanced | `NET_ADMIN`, `NET_RAW` |
| ccna | foundation | `NET_ADMIN` |
| ccna | intermediate | `NET_ADMIN`, `NET_RAW` |
| ccna | advanced | `NET_ADMIN`, `NET_RAW` |
| cissp | foundation | `NET_ADMIN` |
| cissp | intermediate | `NET_ADMIN`, `NET_RAW` |
| cissp | advanced | `NET_ADMIN`, `NET_RAW`, `SYS_ADMIN`, `SYS_PTRACE` |

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

### Data Governance

**Retention** (configurable per environment):
- **Metrics** (Prometheus): 13 months for capacity planning and SLA reporting.
- **Logs** (Loki): 30 days for operational troubleshooting.
- **Traces** (distributed tracing backend): 14 days for performance analysis.
- **Evidence bundles** (MinIO `forge-evidence` bucket): 365 days unless contractually overridden.

**PII redaction rules**:
- Redact or hash direct identifiers before emission: emails, phone numbers, usernames, external account IDs.
- Truncate or tokenize IP addresses (retain /24 or /48 prefixes only).
- Strip secrets/tokens from headers, query parameters, and payloads (`Authorization`, `Cookie`, API keys).
- Evidence bundles must exclude raw learner submissions that contain PII unless explicitly required for assessment; when required, encrypt and restrict access to scoring/audit roles only.

**Storage locations & least-privilege access**:
- **Metrics**: Prometheus TSDB (PVC). Access limited to `telemetry-reader` (read) and `telemetry-admin` (admin/retention).
- **Logs**: Loki object store/PVC. Access limited to `log-reader` (read) and `log-admin` (retention/index).
- **Traces**: Tracing backend store. Access limited to `trace-reader` and `trace-admin`.
- **Evidence bundles**: MinIO `forge-evidence` bucket. Access limited to `evidence-reader` (read-only), `evidence-writer` (ingest), and `evidence-admin` (delete/export).
- All roles map to RBAC groups; default access is deny-all with explicit grants per tenant.

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
- [ ] Enforce restrictive seccomp profile (no unconfined overrides)
- [ ] Enable AppArmor profiles
- [ ] Set resource limits
- [ ] Configure persistent volumes
- [ ] Enable audit logging
- [ ] Set up alerting
- [ ] Configure backup retention
- [ ] Define RPO/RTO targets (for example: RPO ≤ 15 minutes, RTO ≤ 60 minutes)
- [ ] Schedule backup testing (for example: restore validation at least quarterly)
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

**Verify Egress Enforcement**:
```bash
# Confirm gateway ruleset is loaded
curl http://localhost:8089/v1/ruleset

# From a scenario container, verify external egress is blocked (should fail)
docker exec -it <scenario_container> curl -sS https://example.com --max-time 5

# If the scenario uses an allowlist profile, verify an allowed destination succeeds
docker exec -it <scenario_container> curl -sS https://repo.alpine.org --max-time 5

# Inspect gateway deny logs (should include blocked attempts)
curl http://localhost:8089/v1/logs | tail -n 20
```

**Cleanup Stale Scenarios**:
```bash
./scripts/cleanup_scenarios.sh --older-than 2h
```

**Evidence Deletion & Tenant Data Export**:
1. Verify request authorization (ticket ID + tenant ID) and log an audit event.
2. Export:
   - Generate a signed manifest of evidence objects for the tenant (`tenant_id`, `scenario_id`, `object_key`, `sha256`).
   - Copy objects from MinIO `forge-evidence` to a time-bound export bucket or encrypted archive.
   - Deliver export via pre-signed URL scoped to the tenant and expiry window.
3. Delete:
   - Delete evidence objects for the tenant from MinIO (`forge-evidence`).
   - Remove associated metadata from the scoreboard database and telemetry indices.
   - Emit audit events for export and deletion with `request_id` and `tenant_id`.
4. Confirm:
   - Run a post-delete inventory to validate no remaining objects for the tenant.
   - Record completion in the ticket and notify the requester.

### Backup & Restore Procedures

**MinIO Restore (Evidence Bucket)**:
1. Freeze writes:
   - Pause scenario creation and evidence uploads (scale orchestrator to 0 or enable maintenance mode).
2. Identify restore point:
   - Select the latest validated backup set for the `forge-evidence` bucket.
3. Restore objects:
   - If using `mc` + object storage snapshots, restore the bucket to the chosen snapshot.
   - If using filesystem backups, stop MinIO and restore the data directory (`/data`) from backup.
4. Validate:
   - List objects and compare against backup manifest.
   - Spot-check recent evidence objects and hashes.
5. Resume writes and notify stakeholders.

**NATS JetStream Recovery**:
1. Quiesce publishers:
   - Scale orchestrator and scenario services to stop new event writes.
2. Restore state:
   - Restore the JetStream storage directory from backup (commonly `/data/jetstream`).
   - If running clustered, restore all members consistently before restart.
3. Restart NATS and verify:
   - Confirm streams and consumers with `nats stream ls` and `nats consumer ls <stream>`.
   - Validate sequence continuity for key streams.
4. Resume publishers and monitor lag.

**Orchestrator Failover**:
1. Promote standby:
   - If using a hot standby, switch routing to the standby service or scale standby to active.
2. Validate dependencies:
   - Confirm OPA, NATS, and MinIO connectivity from the new primary.
3. Recover in-flight state:
   - Reconcile active scenarios by reconciling container labels and DB state.
4. Notify stakeholders and record incident timeline.

### Release Rollback Procedures

**Compose Rollback**:
1. Identify the last known good release tag or image digest.
2. Update `compose.yml` or override file to pin images to the prior version.
3. Run:
   ```bash
   docker compose -f compose.yml -f compose.staging.yml up -d --no-deps --force-recreate
   ```
4. Verify health endpoints and critical workflows (scenario spawn, policy check).

**Schema Compatibility Checks**:
1. Confirm database schema version matches application expectations.
2. If a migration ran, determine if it is reversible:
   - If reversible, run the down migration and re-verify application start.
   - If irreversible, keep schema at the newer version and deploy the app version that supports it.
3. Re-run smoke tests and monitor logs for schema errors.

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

#!/usr/bin/env bash
set -euo pipefail

# scripts/fix-training-gate-prod.sh
# - Writes a hardened, deterministic Rego v1 training_gate.rego (OPA 1.12+)
# - Validates compile with `opa check`
# - Restarts forge_opa + forge_opa_probe
# - Verifies /health + training/decision + training/allow explain (prints body even on non-200)

ROOT_DIR="${ROOT_DIR:-/home/jcosat/Projects/fg-forge}"
POLICY_REL="${POLICY_REL:-policies/training_gate.rego}"
ENV_FILE="${ENV_FILE:-.env.dev}"

OPA_IMAGE="${OPA_IMAGE:-openpolicyagent/opa:1.12.3}"
OPA_SERVICE="${OPA_SERVICE:-forge_opa}"
OPA_PROBE_SERVICE="${OPA_PROBE_SERVICE:-forge_opa_probe}"
OPA_NETWORK="${OPA_NETWORK:-forge_platform}"

COMPOSE_FILES_DEFAULT=("compose.yml" "compose.expose.yml" "compose.netfix.yml")
if [[ -n "${COMPOSE_FILES:-}" ]]; then
  # shellcheck disable=SC2206
  COMPOSE_FILES_ARR=(${COMPOSE_FILES})
else
  COMPOSE_FILES_ARR=("${COMPOSE_FILES_DEFAULT[@]}")
fi

log() { printf '[%s] %s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

cd "$ROOT_DIR"

dc() {
  local args=()
  args+=(--env-file "$ENV_FILE")
  for f in "${COMPOSE_FILES_ARR[@]}"; do
    args+=(-f "$f")
  done
  docker compose "${args[@]}" "$@"
}

POLICY_PATH="$ROOT_DIR/$POLICY_REL"
POLICY_DIR="$(dirname "$POLICY_PATH")"
mkdir -p "$POLICY_DIR"

log "Backing up existing policy (if present)"
ts="$(date -u +%Y%m%d_%H%M%S)"
if [[ -f "$POLICY_PATH" ]]; then
  cp -a "$POLICY_PATH" "${POLICY_PATH}.bak_${ts}"
  log "Backup: ${POLICY_PATH}.bak_${ts}"
fi

log "Writing deterministic Rego v1 production training_gate.rego -> $POLICY_REL"
cat >"$POLICY_PATH" <<'REGO'
package frostgate.forge.training
import rego.v1

# -----------------------------------------------------------------------------
# training_gate.rego (Rego v1, deterministic, hardened)
# -----------------------------------------------------------------------------
# Goals:
# - Never 500: all access is type-guarded.
# - Deterministic extraction: track/tier are single-valued via else-chains.
# - Accepts: template:"netplus" and/or metadata.labels=["class:netplus","tier:foundation"]
# - Baseline security: require network.egress == "deny"
# - Exposes: allow (bool) and decision (object) for orchestrator.
# -----------------------------------------------------------------------------

default allow := false
default decision := {"allow": false, "reason": "denied", "track": "unknown", "tier": "unknown"}

allowed_tracks := {"netplus"}

# NOTE: you currently have plan:"TEAM" + tier:foundation label in your example.
# If that pairing is intentionally allowed, keep "foundation".
allowed_tiers := {"team", "foundation"}

# -----------------------------------------------------------------------------
# Helpers (all type-safe)
# -----------------------------------------------------------------------------

safe_lower(x) := y if {
  is_string(x)
  y := lower(x)
} else := y if {
  y := "unknown"
}

trim_prefix(s, p) := out if {
  is_string(s)
  is_string(p)
  startswith(s, p)
  out := substring(s, count(p), -1)
} else := out if {
  out := s
}

# Deterministic label lookup: returns the FIRST (lowest index) match only.
label_value(labels, prefix) := val if {
  is_array(labels)
  is_string(prefix)

  idxs := [i |
    some i
    lbl := labels[i]
    is_string(lbl)
    startswith(lbl, prefix)
  ]

  count(idxs) > 0
  m := min(idxs)
  lbl := labels[m]
  val := trim_prefix(lbl, prefix)
}

egress := e if {
  is_object(input.network)
  is_string(input.network.egress)
  e := input.network.egress
} else := e if {
  e := "unknown"
}

# -----------------------------------------------------------------------------
# Deterministic track extraction (single-valued)
# -----------------------------------------------------------------------------

track := t if {
  is_string(input.track)
  t := input.track
} else := t if {
  is_string(input.template)
  t := input.template
} else := t if {
  is_string(input.template_id)
  t := input.template_id
} else := t if {
  is_object(input.details)
  is_string(input.details.track)
  t := input.details.track
} else := t if {
  is_object(input.metadata)
  is_object(input.metadata.labels)
  is_string(input.metadata.labels.track)
  t := input.metadata.labels.track
} else := t if {
  is_object(input.metadata)
  v := label_value(input.metadata.labels, "class:")
  is_string(v)
  t := v
} else := t if {
  is_object(input.metadata)
  v := label_value(input.metadata.labels, "track:")
  is_string(v)
  t := v
} else := t if {
  is_object(input.metadata)
  is_string(input.metadata.name)
  startswith(input.metadata.name, "netplus-")
  t := "netplus"
} else := t if {
  is_object(input.sat)
  is_string(input.sat.track)
  t := input.sat.track
} else := t if {
  is_object(input.claims)
  is_string(input.claims.track)
  t := input.claims.track
} else := t if {
  t := "unknown"
}

track_lc := safe_lower(track)

# -----------------------------------------------------------------------------
# Deterministic tier extraction (single-valued)
# -----------------------------------------------------------------------------

tier := x if {
  is_string(input.tier)
  x := lower(input.tier)
} else := x if {
  # orchestrator sends plan:"TEAM"
  is_string(input.plan)
  x := lower(input.plan)
} else := x if {
  is_object(input.sat)
  is_string(input.sat.tier)
  x := lower(input.sat.tier)
} else := x if {
  is_object(input.claims)
  is_string(input.claims.tier)
  x := lower(input.claims.tier)
} else := x if {
  is_object(input.metadata)
  v := label_value(input.metadata.labels, "tier:")
  is_string(v)
  x := lower(v)
} else := x if {
  x := "unknown"
}

# -----------------------------------------------------------------------------
# Policy
# -----------------------------------------------------------------------------

allow if {
  allowed_tracks[track_lc]
  allowed_tiers[tier]
  egress == "deny"
}

reason := "allowed" if { allow }
reason := "denied"  if { not allow }

decision := {
  "allow": allow,
  "reason": reason,
  "track": track_lc,
  "tier": tier
}
REGO

log "OPA policy compile check (local container)"
docker run --rm -v "$ROOT_DIR/policies:/policies:ro" "$OPA_IMAGE" check /policies

log "Restarting OPA + probe via docker compose"
dc up -d --force-recreate "$OPA_SERVICE" "$OPA_PROBE_SERVICE"

log "Waiting for probe to report healthy"
for _ in $(seq 1 120); do
  status="$(docker inspect -f '{{.State.Health.Status}}' "$OPA_PROBE_SERVICE" 2>/dev/null || true)"
  [[ "$status" == "healthy" ]] && break
  sleep 1
done
status="$(docker inspect -f '{{.State.Health.Status}}' "$OPA_PROBE_SERVICE" 2>/dev/null || true)"
[[ "$status" == "healthy" ]] || die "OPA probe not healthy (status=$status). Check: docker logs $OPA_SERVICE"

log "Quick verify: OPA /health"
docker run --rm --network "$OPA_NETWORK" curlimages/curl:8.5.0 \
  curl -sS "http://$OPA_SERVICE:8181/health" | sed 's/^/[health] /'
echo

# Print body even on non-200 (no curl -f nonsense)
opa_post() {
  local path="$1"
  docker run --rm --network "$OPA_NETWORK" curlimages/curl:8.5.0 sh -lc "
resp=\$(cat <<'JSON' | curl -sS -w '\n__HTTP__:%{http_code}\n' \
  -H 'content-type: application/json' \
  --data-binary @- \
  'http://$OPA_SERVICE:8181/v1/data/${path}'
{
  \"input\": {
    \"metadata\": {\"labels\": [\"class:netplus\", \"tier:foundation\"], \"name\": \"netplus-foundations\"},
    \"network\": {\"egress\": \"deny\"},
    \"plan\": \"TEAM\",
    \"tenant_id\": \"forge\",
    \"subject\": \"forge\",
    \"limits\": {\"cpu\": 2, \"memory_mb\": 2048, \"attacker_max_exploits\": 0},
    \"assets\": {\"containers\": [{\"name\":\"learner_vm\",\"image\":\"alpine:3.19\",\"read_only\": true}]}
  }
}
JSON
)
code=\$(printf '%s' \"\$resp\" | awk -F: '/__HTTP__/{print \$2}' | tail -n1)
body=\$(printf '%s' \"\$resp\" | sed '/__HTTP__/d')
printf '[opa] POST %s -> HTTP %s\n' '$path' \"\$code\"
printf '%s\n' \"\$body\"
exit 0
"
}

log "Quick verify: training/decision"
opa_post "frostgate/forge/training/decision?pretty=true"
echo

log "Explain: training/allow (why allow=true/false)"
opa_post "frostgate/forge/training/allow?pretty=true&explain=full"
echo

log "Done."

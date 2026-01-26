#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/jcosat/Projects/fg-forge}"
POLICY="${POLICY:-policies/training_gate.rego}"
ENV_FILE="${ENV_FILE:-.env.dev}"
COMPOSE="${COMPOSE:-compose.yml}"
EXPOSE_FILE="${EXPOSE_FILE:-compose.expose.yml}"
NETFIX_FILE="${NETFIX_FILE:-compose.netfix.yml}"

cd "$ROOT_DIR"

dc() { docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" -f "$NETFIX_FILE" "$@"; }

ts="$(date +%Y%m%d_%H%M%S)"
if [[ -f "$POLICY" ]]; then
  cp -a "$POLICY" "${POLICY}.bak_${ts}"
  echo "Backup: ${POLICY}.bak_${ts}"
fi

cat > "$POLICY" <<'REGO'
package frostgate.forge.training

# Orchestrator calls this:
default allow := false

# Optional for humans who enjoy pain:
default decision := {"allow": false, "reason": "denied", "track": track(input), "tier": tier(input)}

# ---- helpers (no unsafe vars) ----

tier(i) := t if { t := i.tier }
tier(i) := t if { t := i.sat.tier }
tier(i) := t if { t := i.claims.tier }

# "track" can come from many shapes:
track(i) := t if { t := i.track }
track(i) := t if { t := i.template }          # IMPORTANT: orchestrator body uses template:"netplus"
track(i) := t if { t := i.template_id }
track(i) := t if { t := i.details.track }
track(i) := t if { t := i.metadata.labels.track }
track(i) := t if { t := i.sat.track }
track(i) := t if { t := i.claims.track }

# Conservative: if missing, track(i) is undefined and allow stays false.

allowed_tracks := {"netplus"}
allowed_tiers  := {"TEAM"}  # keep dev strict-ish; expand if you want

allow {
  t := track(input)
  allowed_tracks[t]
  tr := tier(input)
  allowed_tiers[tr]
}

decision := {"allow": true, "reason": "allowed", "track": track(input), "tier": tier(input)} {
  allow
}
REGO

echo "Wrote policy: $POLICY"

echo "== Compile check via opa container (OPA image has no shell) =="
docker run --rm -v "$PWD/policies:/policies:ro" openpolicyagent/opa:1.12.3 check /policies
echo "OPA policy check OK"

echo "== Restart OPA + probe =="
dc up -d --force-recreate forge_opa forge_opa_probe >/dev/null

echo "== Wait for forge_opa_probe healthy =="
for i in $(seq 1 60); do
  st="$(docker inspect -f '{{.State.Health.Status}}' forge_opa_probe 2>/dev/null || true)"
  [[ "$st" == "healthy" ]] && { echo "forge_opa_probe healthy"; break; }
  sleep 1
done
[[ "$(docker inspect -f '{{.State.Health.Status}}' forge_opa_probe)" == "healthy" ]] || {
  echo "forge_opa_probe is not healthy. Recent logs:"
  docker logs --tail=120 forge_opa
  exit 1
}

echo "== Smoke test allow+decision inside network (no jq needed) =="
docker run --rm --network forge_platform curlimages/curl:8.5.0 sh -lc '
payload='\''{"input":{"template":"netplus","tier":"TEAM","metadata":{"labels":{"track":"netplus"}},"details":{"track":"netplus"},"limits":{"cpu":1,"memory_mb":512},"assets":{"containers":[]},"egress":"deny"}}'\''
echo "--- allow ---"
curl -sS http://forge_opa:8181/v1/data/frostgate/forge/training/allow -H "content-type: application/json" -d "$payload"; echo
echo "--- decision ---"
curl -sS http://forge_opa:8181/v1/data/frostgate/forge/training/decision -H "content-type: application/json" -d "$payload"; echo
'
echo "DONE"

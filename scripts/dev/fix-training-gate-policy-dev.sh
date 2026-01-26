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
cp -a "$POLICY" "${POLICY}.bak_${ts}" 2>/dev/null || true
echo "Backup: ${POLICY}.bak_${ts}"

cat > "$POLICY" <<'REGO'
package frostgate.forge.training

# What orchestrator calls:
default allow := false

# Optional: richer output for debugging
default decision := {"allow": false, "reason": "denied", "track": track(input), "tier": tier(input)}

# --- helpers (safe, no unsafe vars) ---

track(i) := t if { t := i.track }
track(i) := t if { t := i.details.track }
track(i) := t if { t := i.metadata.labels.track }

tier(i) := t if { t := i.tier }

# --- dev policy: allow netplus/TEAM with conservative defaults ---
allowed_tracks := {"netplus"}
allowed_tiers  := {"TEAM", "BASIC", "PRO"}  # loosen in dev; tighten in prod overlay

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

echo "== Quick compile check inside OPA container =="
dc up -d forge_opa >/dev/null
dc exec -T forge_opa sh -lc 'opa check /policies >/dev/null && echo "OPA check OK"'

echo "== Restart OPA + probe =="
dc up -d --force-recreate forge_opa forge_opa_probe >/dev/null

echo "== Wait for probe healthy =="
for i in $(seq 1 60); do
  st="$(docker inspect -f '{{.State.Health.Status}}' forge_opa_probe 2>/dev/null || true)"
  [[ "$st" == "healthy" ]] && { echo "forge_opa_probe healthy"; break; }
  sleep 1
done
[[ "$(docker inspect -f '{{.State.Health.Status}}' forge_opa_probe)" == "healthy" ]]

echo "== Smoke test allow endpoint =="
docker run --rm --network forge_platform curlimages/curl:8.5.0 sh -lc '
payload='\''{"input":{"track":"netplus","template":"netplus","tier":"TEAM","metadata":{"labels":{"track":"netplus"}},"details":{"track":"netplus"},"limits":{"cpu":1,"memory_mb":512},"assets":{"containers":[]},"egress":"deny"}}'\''
curl -sS http://forge_opa:8181/v1/data/frostgate/forge/training/allow -H "content-type: application/json" -d "$payload"
echo
'

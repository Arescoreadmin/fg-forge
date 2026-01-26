#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/jcosat/Projects/fg-forge}"
POLICY="${POLICY:-policies/training_gate.rego}"
ENV_FILE="${ENV_FILE:-.env.dev}"
COMPOSE="${COMPOSE:-compose.yml}"
EXPOSE_FILE="${EXPOSE_FILE:-compose.expose.yml}"
NETFIX_FILE="${NETFIX_FILE:-compose.netfix.yml}"
NETWORK_NAME="${NETWORK_NAME:-forge_platform}"

cd "$ROOT_DIR"

dc() {
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" -f "$NETFIX_FILE" "$@"
}

[[ -f "$POLICY" ]] || { echo "ERROR: missing $POLICY"; exit 1; }

ts="$(date +%Y%m%d_%H%M%S)"
bak="${POLICY}.bak_${ts}"
cp -a "$POLICY" "$bak"
echo "Backup: $bak"

cat > "$POLICY" <<'REGO'
package frostgate.forge.training

# ------------------------------------------------------------
# DEV SAFE POLICY (compiles, no unsafe vars)
# Tighten later. Right now you need a working system.
# ------------------------------------------------------------

default allow := false

# Canonical track extraction (supports a few shapes)
track := t if {
  t := input.track
  t != ""
}

track := t if {
  not input.track
  t := input.details.track
  t != ""
}

track := t if {
  not input.track
  not input.details.track
  labels := object.get(input.metadata, "labels", {})
  t := object.get(labels, "track", "")
  t != ""
}

# Basic allowlist for dev
allowed_tracks := {"netplus", "ccna", "cissp"}

allow if {
  track != ""
  allowed_tracks[track]
}

# Also allow explicitly if caller passes a dev flag (optional)
allow if {
  labels := object.get(input.metadata, "labels", {})
  object.get(labels, "env", "") == "dev"
}

# Decision object endpoint convenience (some callers prefer this shape)
decision := {
  "allow": allow,
  "track": track,
  "reason": reason,
}

reason := "allowed" if allow
reason := "denied"  if not allow
REGO

echo "Wrote safe policy: $POLICY"

echo "== Validate rego inside OPA container (fast compile check) =="
# OPA image has /opa; we can run a one-shot container to parse the policy mount
# using the same image tag you run in compose.
docker run --rm -v "$(pwd)/policies:/policies:ro" openpolicyagent/opa:1.12.3 \
  check /policies >/dev/null
echo "OPA policy check OK"

echo "== Restart OPA and probes =="
dc up -d forge_opa forge_opa_probe >/dev/null
dc restart forge_opa >/dev/null
dc up -d forge_opa_probe >/dev/null

echo "== Wait for forge_opa_probe healthy =="
for i in $(seq 1 90); do
  status="$(docker inspect -f '{{.State.Health.Status}}' forge_opa_probe 2>/dev/null || echo "unknown")"
  if [[ "$status" == "healthy" ]]; then
    echo "forge_opa_probe healthy"
    break
  fi
  if [[ "$i" -eq 90 ]]; then
    echo "ERROR: forge_opa_probe not healthy"
    docker logs --tail=200 forge_opa || true
    docker logs --tail=200 forge_opa_probe || true
    exit 1
  fi
  sleep 1
done

echo "== Verify OPA has IP and DNS works (inside network) =="
OPA_IP="$(docker inspect -f '{{(index .NetworkSettings.Networks "'"$NETWORK_NAME"'").IPAddress}}' forge_opa || true)"
OPA_EPID="$(docker inspect -f '{{(index .NetworkSettings.Networks "'"$NETWORK_NAME"'").EndpointID}}' forge_opa || true)"
echo "forge_opa ip=$OPA_IP endpoint=$OPA_EPID"

docker run --rm --network "$NETWORK_NAME" busybox:1.36 nslookup forge_opa
docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.5.0 \
  curl -fsS http://forge_opa:8181/health?plugins >/dev/null

echo "== Smoke test decision endpoint inside network =="
payload='{"input":{"track":"netplus","details":{"track":"netplus"},"metadata":{"labels":{"track":"netplus"}},"limits":{"cpu":1,"memory_mb":512},"assets":{"containers":[]},"egress":"deny"}}'
docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.5.0 sh -lc \
  "curl -fsS http://forge_opa:8181/v1/data/frostgate/forge/training/decision -H 'content-type: application/json' -d '$payload'"

echo "DONE"

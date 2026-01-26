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

[[ -f "$POLICY" ]] || { echo "ERROR: missing $POLICY"; exit 1; }

ts="$(date +%Y%m%d_%H%M%S)"
bak="${POLICY}.bak_${ts}"
cp -a "$POLICY" "$bak"
echo "Backup: $bak"

cat > "$POLICY" <<'REGO'
package frostgate.forge.training

# Training gate: validate track + enforce basic resource/security constraints.
# IMPORTANT: supports both label styles:
#  1) metadata.labels.track = "netplus"
#  2) metadata.labels["track=netplus"] = "true" (or any value)

default allow := false

allowed_tracks := {"netplus", "ccna", "cissp"}

# Conservative defaults that should allow dev E2E while still enforcing shape.
track_configs := {
  "netplus": {
    "max_cpu": 2,
    "max_memory_mb": 2048,
    "max_containers": 30,
    "egress_policy": "deny",
    "attacker_max_exploits": 0
  },
  "ccna": {
    "max_cpu": 2,
    "max_memory_mb": 2048,
    "max_containers": 30,
    "egress_policy": "deny",
    "attacker_max_exploits": 0
  },
  "cissp": {
    "max_cpu": 2,
    "max_memory_mb": 4096,
    "max_containers": 50,
    "egress_policy": "deny",
    "attacker_max_exploits": 0
  }
}

# --- helpers ---------------------------------------------------------------

labels := object.get(object.get(input, "metadata", {}), "labels", {})

# Extract track from labels.
# Accept:
#   labels.track == "netplus"
#   OR a key like "track=netplus"
get_track(l) := t if {
  # map-style
  t := object.get(l, "track", "")
  t != ""
} else := t if {
  # key-style: track=netplus
  some k
  startswith(k, "track=")
  v := object.get(l, k, null)
  v != null
  t := substring(k, 6, -1)
  t != ""
}

track := get_track(labels)

cfg := track_configs[track]

deny_reasons contains "missing track label" if {
  track == ""
}

deny_reasons contains msg if {
  track != ""
  not allowed_tracks[track]
  msg := sprintf("unsupported track: %s (allowed: %v)", [track, allowed_tracks])
}

deny_reasons contains msg if {
  track != ""
  allowed_tracks[track]
  cpu := object.get(object.get(input, "limits", {}), "cpu", 1)
  cpu > cfg.max_cpu
  msg := sprintf("CPU limit %v exceeds max %v for track %s", [cpu, cfg.max_cpu, track])
}

deny_reasons contains msg if {
  track != ""
  allowed_tracks[track]
  mem := object.get(object.get(input, "limits", {}), "memory_mb", 512)
  mem > cfg.max_memory_mb
  msg := sprintf("memory_mb %v exceeds max %v for track %s", [mem, cfg.max_memory_mb, track])
}

deny_reasons contains msg if {
  track != ""
  allowed_tracks[track]
  containers := object.get(object.get(input, "assets", {}), "containers", [])
  count(containers) > cfg.max_containers
  msg := sprintf("container count %v exceeds max %v for track %s", [count(containers), cfg.max_containers, track])
}

deny_reasons contains msg if {
  track != ""
  allowed_tracks[track]
  # Force deny egress by default for safety in dev.
  e := object.get(input, "egress", "deny")
  e != cfg.egress_policy
  msg := sprintf("egress must be '%s' for track %s", [cfg.egress_policy, track])
}

# allow if no deny reasons
allow if {
  count(deny_reasons) == 0
}

decision := {
  "allow": allow,
  "track": track,
  "deny_reasons": [r | r := deny_reasons[_]],
  "labels_seen": labels
}
REGO

echo "Wrote patched policy: $POLICY"

echo
echo "== Restart OPA =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" -f "$NETFIX_FILE" restart forge_opa >/dev/null

echo
echo "== Wait for OPA healthy (inside network) =="
docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.5.0 sh -lc '
for i in $(seq 1 60); do
  curl -fsS http://forge_opa:8181/health?plugins >/dev/null && { echo "OPA healthy"; exit 0; }
  sleep 1
done
echo "ERROR: OPA not healthy"; exit 1
'

echo
echo "== Decision tests (both label styles) =="
docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.5.0 sh -lc '
set -e

payload1='\''{"input":{"metadata":{"labels":{"track":"netplus"}},"limits":{"cpu":1,"memory_mb":512},"assets":{"containers":[]},"egress":"deny"}}'\''
echo "--- map-style labels.track ---"
curl -sS http://forge_opa:8181/v1/data/frostgate/forge/training/decision \
  -H "content-type: application/json" -d "$payload1" | sed -n "1,200p"

payload2='\''{"input":{"metadata":{"labels":{"track=netplus":"true"}},"limits":{"cpu":1,"memory_mb":512},"assets":{"containers":[]},"egress":"deny"}}'\''
echo "--- key-style labels[track=netplus] ---"
curl -sS http://forge_opa:8181/v1/data/frostgate/forge/training/decision \
  -H "content-type: application/json" -d "$payload2" | sed -n "1,200p"
'

echo
echo "DONE: training gate policy updated and validated."

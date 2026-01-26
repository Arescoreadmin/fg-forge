#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/jcosat/Projects/fg-forge}"
POLICY="${POLICY:-policies/training_gate.rego}"
ENV_FILE="${ENV_FILE:-.env.dev}"
COMPOSE="${COMPOSE:-compose.yml}"
EXPOSE_FILE="${EXPOSE_FILE:-compose.expose.yml}"

cd "$ROOT_DIR"

if [[ ! -f "$POLICY" ]]; then
  echo "ERROR: policy not found: $POLICY"
  exit 1
fi

ts="$(date +%Y%m%d_%H%M%S)"
bak="${POLICY}.bak_${ts}"
cp -a "$POLICY" "$bak"
echo "Backup: $bak"

# 1) Inject robust track derivation helpers (only if not already present)
if ! rg -q 'effective_track' "$POLICY"; then
  perl -0777 -i -pe '
s/(^#.*\n)+/sprintf("%s\n%s\n",
$&,
q{
# --- Track derivation (robust across input shapes) ---------------------------
# Prefer explicit fields; fall back to labels.
effective_track := t if {
  t := object.get(input, "track", "")
  t != ""
} else := t if {
  d := object.get(input, "details", {})
  t := object.get(d, "track", "")
  t != ""
} else := t if {
  md := object.get(input, "metadata", {})
  labels := object.get(md, "labels", {})
  t := track_from_labels(labels)
  t != ""
}

# labels can be an object/map OR a list/array. Support both.
track_from_labels(labels) := t if {
  is_object(labels)
  # common label keys
  some k
  k := {"track", "forge.track", "frostgate.track"}[_]
  t := object.get(labels, k, "")
  t != ""
} else := t if {
  is_array(labels)
  some i
  s := labels[i]
  startswith(s, "track=")
  t := substring(s, 6, -1)
  t != ""
} else := t if {
  is_array(labels)
  some i
  s := labels[i]
  startswith(s, "forge.track=")
  t := substring(s, 11, -1)
  t != ""
}
# ---------------------------------------------------------------------------
}
)/mse' "$POLICY"
  echo "Injected effective_track helpers into $POLICY"
else
  echo "effective_track already present, skipping inject"
fi

# 2) Replace fragile get_track(metadata.labels) usage with effective_track
# This is intentionally blunt: you *want* policy to use the robust method.
perl -i -pe 's/get_track\(input\.metadata\.labels\)/effective_track/g' "$POLICY"
perl -i -pe 's/get_track\(labels\)/track_from_labels(labels)/g' "$POLICY"

# 3) Quick sanity: ensure file still mentions track_configs and allow/deny rules
if ! rg -q 'track_configs' "$POLICY"; then
  echo "ERROR: patch looks wrong; track_configs missing after edit"
  exit 1
fi

echo "Patched: $POLICY"

echo
echo "== Restart OPA =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" restart forge_opa >/dev/null

echo "== Wait for OPA healthy =="
for i in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8181/health?plugins >/dev/null 2>&1; then
    echo "OPA healthy"
    exit 0
  fi
  sleep 1
done

echo "ERROR: OPA did not become healthy"
exit 1

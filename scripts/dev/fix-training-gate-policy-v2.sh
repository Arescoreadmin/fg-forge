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

# If you already have a backup from the failed run, restore the newest one
latest_bak="$(ls -1 "${POLICY}".bak_* 2>/dev/null | tail -n 1 || true)"
if [[ -n "$latest_bak" ]]; then
  echo "Restoring from latest backup: $latest_bak"
  cp -a "$latest_bak" "$POLICY"
fi

ts="$(date +%Y%m%d_%H%M%S)"
bak="${POLICY}.bak_${ts}"
cp -a "$POLICY" "$bak"
echo "Backup: $bak"

python - <<'PY'
from pathlib import Path
import re
policy_path = Path("policies/training_gate.rego")
s = policy_path.read_text(encoding="utf-8")

# If a previous botched inject left garbage, we already restored from backup above.
# Now patch safely.

TRACK_HELPERS = r'''
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
'''.strip() + "\n"

DECISION_RULE = r'''
# Structured decision output for debugging (don’t make humans guess).
decision := {"allow": allow, "deny_reasons": deny_reasons, "track": effective_track} {
  true
}
'''.strip() + "\n"

# 1) Ensure helpers are present near the top (after package/imports)
if "effective_track :=" not in s and "effective_track :=" not in s.replace(":= ", ":="):
  # place after package line (and any imports)
  m = re.search(r'(?m)^package\s+[^\n]+\n(?:\s*import\s+[^\n]+\n)*', s)
  if not m:
    raise SystemExit("Could not find package header in training_gate.rego")
  insert_at = m.end()
  s = s[:insert_at] + "\n" + TRACK_HELPERS + "\n" + s[insert_at:]

# 2) Replace any get_track(input.metadata.labels) occurrences with effective_track
s = re.sub(r'get_track\s*\(\s*input\.metadata\.labels\s*\)', "effective_track", s)

# 3) If there’s a helper get_track(labels) definition, rewrite calls to it
# (This doesn’t delete old helpers; it just makes references sane.)
s = re.sub(r'get_track\s*\(\s*labels\s*\)', "track_from_labels(labels)", s)

# 4) Ensure decision rule exists (helps you query OPA and see deny reasons)
if re.search(r'(?m)^\s*decision\s*:?=\s*', s) is None:
  # put near end
  s = s.rstrip() + "\n\n" + DECISION_RULE + "\n"

policy_path.write_text(s, encoding="utf-8")
print("Patched policies/training_gate.rego OK")
PY

echo
echo "== Restart OPA =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" restart forge_opa >/dev/null

echo "== Wait for OPA healthy (inside docker network) =="
docker run --rm --network forge_platform curlimages/curl:8.5.0 \
  sh -lc 'for i in $(seq 1 60); do curl -fsS http://forge_opa:8181/health?plugins >/dev/null && exit 0; sleep 1; done; exit 1' \
  && echo "OPA healthy" || (echo "ERROR: OPA not healthy" && exit 1)

echo
echo "== Quick policy sanity (query decision via docker network) =="
docker run --rm --network forge_platform curlimages/curl:8.5.0 sh -lc '
set -e
payload='\''{"input":{"track":"netplus","details":{"track":"netplus"},"metadata":{"labels":{"track":"netplus"}},"limits":{"cpu":1,"memory_mb":512},"assets":{"containers":[]},"egress":"deny"}}'\''
curl -sS http://forge_opa:8181/v1/data/frostgate/forge/training/decision \
  -H "content-type: application/json" \
  -d "$payload" | sed -n "1,200p"
'

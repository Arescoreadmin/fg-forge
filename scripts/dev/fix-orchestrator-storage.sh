#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/jcosat/Projects/fg-forge}"
COMPOSE="${COMPOSE:-compose.yml}"
EXPOSE_FILE="${EXPOSE_FILE:-compose.expose.yml}"
ENV_FILE="${ENV_FILE:-.env.dev}"

cd "$ROOT_DIR"

echo "== Working dir: $ROOT_DIR =="

# --- Step 0: pick newest backup if exists and restore it (your previous run already created one)
latest_bak="$(ls -1t "${COMPOSE}".bak_* 2>/dev/null | head -n 1 || true)"
if [[ -n "${latest_bak}" ]]; then
  echo "Restoring compose from backup: ${latest_bak}"
  cp -a "${latest_bak}" "${COMPOSE}"
else
  echo "No backup found; continuing with existing ${COMPOSE}"
fi

# --- Step 1: patch compose.yml safely (text-based, minimal changes)
python - <<'PY'
from pathlib import Path
import re

path = Path("compose.yml")
s = path.read_text(encoding="utf-8")

# 1) Ensure forge_orchestrator_storage volume exists at top-level volumes:
# If volumes: exists, inject entry if missing. If not, append volumes section.
if re.search(r"(?m)^volumes:\s*$", s):
    if not re.search(r"(?m)^\s{2}forge_orchestrator_storage:\s*$", s):
        # Insert right after "volumes:" line
        s = re.sub(r"(?m)^(volumes:\s*)$",
                   r"\1\n  forge_orchestrator_storage:",
                   s, count=1)
else:
    s += "\n\nvolumes:\n  forge_orchestrator_storage:\n"

# 2) Remove tmpfs entry for /app/storage under forge_orchestrator.
# You currently mount a named volume to /app/storage, so a tmpfs there is redundant and can cause weirdness.
# We remove ONLY the tmpfs stanza lines in that service, leaving other tmpfs uses alone.
lines = s.splitlines(True)
out = []
in_orch = False
orch_indent = None
skip_tmpfs_block = False

for i, line in enumerate(lines):
    # Detect service header
    m = re.match(r"^(\s*)forge_orchestrator:\s*$", line)
    if m:
        in_orch = True
        orch_indent = len(m.group(1))
        skip_tmpfs_block = False
        out.append(line)
        continue

    # Leave orchestrator when indentation drops back to service level (2 spaces typically)
    if in_orch:
        # if we hit another top-level service at same indent
        m2 = re.match(r"^(\s*)([a-zA-Z0-9_]+):\s*$", line)
        if m2 and len(m2.group(1)) == orch_indent and m2.group(2) != "forge_orchestrator":
            in_orch = False
            orch_indent = None
            skip_tmpfs_block = False

    if in_orch:
        # Start of tmpfs block
        if re.match(r"^\s{4}tmpfs:\s*$", line):
            skip_tmpfs_block = True
            continue
        if skip_tmpfs_block:
            # Skip tmpfs list items (and stop skipping when block ends)
            if re.match(r"^\s{6}-\s", line):
                continue
            else:
                skip_tmpfs_block = False
                # fallthrough to process this non-list line normally

    out.append(line)

s2 = "".join(out)
path.write_text(s2, encoding="utf-8")
print("compose.yml patched (volumes + orchestrator tmpfs cleanup).")
PY

echo
echo "== Compose config validation =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" config >/dev/null
echo "OK: compose config parses"

echo
echo "== Recreate orchestrator =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" up -d --force-recreate forge_orchestrator

echo
echo "== Verify STORAGE_ROOT env + write access inside orchestrator =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" exec -T forge_orchestrator sh -lc '
set -e
echo "STORAGE_ROOT=$STORAGE_ROOT"
python - <<PY
import os
from pathlib import Path
p = Path(os.getenv("STORAGE_ROOT","storage"))
print("storage_root:", p)
p.mkdir(parents=True, exist_ok=True)
t = p / ".__write_test__"
t.write_text("ok")
print("write ok:", t)
PY
ls -la "$STORAGE_ROOT" || true
'

echo
echo "== E2E: spawn -> create scenario (SAT captured, not empty) =="
REQ_ID="req-$(date +%s)"
SPAWN_JSON="$(curl -sS -X POST http://127.0.0.1:8082/v1/spawn \
  -H 'content-type: application/json' \
  -d "{\"track\":\"netplus\",\"subject\":\"forge\",\"request_id\":\"${REQ_ID}\",\"template_id\":\"netplus\"}")"

echo "$SPAWN_JSON" | jq .

SCENARIO_ID="$(echo "$SPAWN_JSON" | jq -r .scenario_id)"
SAT="$(echo "$SPAWN_JSON" | jq -r .sat)"

echo "scenario_id=$SCENARIO_ID"
echo "sat_len=${#SAT}"

if [[ "$SAT" == "null" || ${#SAT} -lt 50 ]]; then
  echo "ERROR: SAT not captured correctly."
  exit 1
fi

REQ_ID="orch-$(date +%s)"
RESP="$(curl -sS -i -X POST http://127.0.0.1:8083/v1/scenarios \
  -H 'content-type: application/json' \
  -H "X-SAT: ${SAT}" \
  -d "{\"scenario_id\":\"${SCENARIO_ID}\",\"template\":\"netplus\",\"request_id\":\"${REQ_ID}\",\"tier\":\"TEAM\"}")"

echo "$RESP"

code="$(printf "%s" "$RESP" | awk 'NR==1{print $2}')"
if [[ "$code" != "200" && "$code" != "201" ]]; then
  echo
  echo "== Orchestrator logs (tail) =="
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" logs --tail=200 forge_orchestrator
  exit 1
fi

echo
echo "SUCCESS: orchestrator scenario create returned HTTP $code"

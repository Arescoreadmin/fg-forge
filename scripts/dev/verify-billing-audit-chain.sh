#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env.prod}"
TENANT_ID="${TENANT_ID:-prod}"

docker compose --env-file "$ENV_FILE" -f compose.yml -f compose.prod.yml exec -T forge_spawn_service \
  python - <<PY
import json, hmac, hashlib
from pathlib import Path

path = Path("/var/lib/forge/billing_audit/tenants") / "$TENANT_ID" / "billing_audit.jsonl"
if not path.exists():
    raise SystemExit(f"missing audit file: {path}")

def canonical(d): 
    import json
    return json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

prev = ""
n = 0
for line in path.read_text(encoding="utf-8").splitlines():
    if not line.strip(): 
        continue
    entry = json.loads(line)
    data = entry.get("data")
    if entry.get("prev_hash") != prev:
        raise SystemExit(f"prev_hash mismatch at line {n+1}")
    expected = hashlib.sha256(prev.encode("utf-8") + canonical(data)).hexdigest()
    if not hmac.compare_digest(entry.get("hash",""), expected):
        raise SystemExit(f"hash mismatch at line {n+1}")
    prev = expected
    n += 1

print(f"OK: {n} entries verified")
PY

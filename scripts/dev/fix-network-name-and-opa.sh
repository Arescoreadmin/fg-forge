#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/jcosat/Projects/fg-forge}"
ENV_FILE="${ENV_FILE:-.env.dev}"
COMPOSE="${COMPOSE:-compose.yml}"
EXPOSE_FILE="${EXPOSE_FILE:-compose.expose.yml}"
NETWORK_NAME="${NETWORK_NAME:-forge_platform}"

cd "$ROOT_DIR"

for f in "$COMPOSE" "$EXPOSE_FILE"; do
  [[ -f "$f" ]] || { echo "ERROR: missing $f"; exit 1; }
done

ts="$(date +%Y%m%d_%H%M%S)"
cp -a "$COMPOSE" "${COMPOSE}.bak_${ts}"
cp -a "$EXPOSE_FILE" "${EXPOSE_FILE}.bak_${ts}"
echo "Backups: ${COMPOSE}.bak_${ts}  ${EXPOSE_FILE}.bak_${ts}"

python - <<'PY'
from pathlib import Path
import re

NETWORK_NAME = "forge_platform"

def ensure_network_named(path: Path):
  s = path.read_text(encoding="utf-8")

  # If file has a networks: section, ensure default has name: forge_platform.
  # If it does not, append a minimal networks section.
  if re.search(r'(?m)^\s*networks:\s*$', s):
    # Ensure a "default:" block exists under networks:
    if not re.search(r'(?m)^\s*networks:\s*\n(?:.*\n)*?\s*default:\s*$', s):
      # add default under networks:
      s = re.sub(r'(?m)^(networks:\s*)$',
                 r'\1\n  default:\n    name: %s\n    driver: bridge\n' % NETWORK_NAME,
                 s, count=1)
    else:
      # default exists. Ensure it has name: forge_platform
      # Find the default block and patch/insert name.
      lines = s.splitlines(True)
      out = []
      i = 0
      while i < len(lines):
        out.append(lines[i])
        if re.match(r'^\s*default:\s*$', lines[i]) and any(re.match(r'^\s*networks:\s*$', l) for l in lines[max(0,i-20):i+1]):
          # We are at default: under networks. Look ahead until next top-level key (non-indented) or next peer under networks.
          j = i + 1
          block = []
          while j < len(lines):
            # stop at next top-level (no leading spaces) OR next networks peer at 2 spaces indent
            if re.match(r'^[^\s#]', lines[j]):
              break
            if re.match(r'^\s{2}\S', lines[j]) and not re.match(r'^\s{4}\S', lines[j]):
              break
            block.append(lines[j])
            j += 1

          block_text = "".join(block)
          if re.search(r'(?m)^\s*name:\s*', block_text):
            block_text = re.sub(r'(?m)^\s*name:\s*.*$', f'    name: {NETWORK_NAME}', block_text, count=1)
          else:
            block_text = f'    name: {NETWORK_NAME}\n' + block_text

          # Normalize driver only in base compose; expose file doesn’t need driver.
          # We'll just leave driver alone if present.
          out.extend(block_text.splitlines(True))
          i = j
          continue
        i += 1
      s = "".join(out)
  else:
    s = s.rstrip() + f"\n\nnetworks:\n  default:\n    name: {NETWORK_NAME}\n    driver: bridge\n"

  path.write_text(s, encoding="utf-8")

ensure_network_named(Path("compose.yml"))
ensure_network_named(Path("compose.expose.yml"))
print("Patched network name to forge_platform in both compose.yml and compose.expose.yml")
PY

echo
echo "== Validate merged compose config =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" config >/dev/null
echo "OK: compose config parses"

echo
echo "== Bring up OPA (and probes) =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" up -d --force-recreate forge_opa forge_opa_probe >/dev/null

echo
echo "== Confirm docker network exists and is named $NETWORK_NAME =="
docker network ls | awk '{print $2}' | grep -Fx "$NETWORK_NAME" >/dev/null || {
  echo "ERROR: network $NETWORK_NAME not found"
  docker network ls
  exit 1
}
echo "OK: network exists"

echo
echo "== DNS check inside $NETWORK_NAME =="
docker run --rm --network "$NETWORK_NAME" busybox:1.36 sh -lc 'nslookup forge_opa >/dev/null && echo "OK: forge_opa resolves"'

echo
echo "== OPA health from inside network =="
docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.5.0 sh -lc '
for i in $(seq 1 60); do
  curl -fsS http://forge_opa:8181/health?plugins >/dev/null && { echo "OPA healthy"; exit 0; }
  sleep 1
done
echo "ERROR: OPA not healthy"; exit 1
'

echo
echo "== Query OPA decision from inside network (sanity) =="
docker run --rm --network "$NETWORK_NAME" curlimages/curl:8.5.0 sh -lc '
payload='\''{"input":{"track":"netplus","details":{"track":"netplus"},"metadata":{"labels":{"track":"netplus"}},"limits":{"cpu":1,"memory_mb":512},"assets":{"containers":[]},"egress":"deny"}}'\''
curl -sS http://forge_opa:8181/v1/data/frostgate/forge/training/decision \
  -H "content-type: application/json" \
  -d "$payload" | sed -n "1,200p"
'

echo
echo "DONE"

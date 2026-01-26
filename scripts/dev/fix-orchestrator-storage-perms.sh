#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-/home/jcosat/Projects/fg-forge}"
COMPOSE="${COMPOSE:-compose.yml}"
EXPOSE_FILE="${EXPOSE_FILE:-compose.expose.yml}"
ENV_FILE="${ENV_FILE:-.env.dev}"

cd "$ROOT_DIR"

echo "== Detect orchestrator UID/GID =="
# Ensure container exists
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" up -d forge_orchestrator >/dev/null

ORCH_UID="$(docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" exec -T forge_orchestrator sh -lc 'id -u')"
ORCH_GID="$(docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" exec -T forge_orchestrator sh -lc 'id -g')"

echo "orchestrator uid:gid = ${ORCH_UID}:${ORCH_GID}"

python - <<PY
from pathlib import Path
import re

compose = Path("compose.yml").read_text(encoding="utf-8")
uid = "${ORCH_UID}"
gid = "${ORCH_GID}"

# 1) Ensure init service exists (idempotent-ish)
init_service_name = "forge_orchestrator_storage_init:"
if init_service_name not in compose:
    # Insert init service near orchestrator for readability: right before forge_orchestrator:
    m = re.search(r"(?m)^  forge_orchestrator:\s*$", compose)
    if not m:
        raise SystemExit("Could not find forge_orchestrator service in compose.yml")

    insert_at = m.start()
    init_block = f"""  forge_orchestrator_storage_init:
    image: alpine:3.19
    container_name: forge_orchestrator_storage_init
    user: "0:0"
    command: ["sh","-lc","mkdir -p /app/storage && chown -R {uid}:{gid} /app/storage && chmod -R u+rwX,g+rwX /app/storage"]
    volumes:
      - forge_orchestrator_storage:/app/storage
    restart: "no"

"""
    compose = compose[:insert_at] + init_block + compose[insert_at:]

# 2) Add/replace user for forge_orchestrator service
# Find forge_orchestrator block and ensure 'user: "<uid>:<gid>"' present.
def patch_service_user(text: str) -> str:
    lines = text.splitlines(True)
    out = []
    in_orch = False
    orch_indent = None
    user_set = False
    for line in lines:
        m = re.match(r"^(\s*)forge_orchestrator:\s*$", line)
        if m:
            in_orch = True
            orch_indent = len(m.group(1))
            user_set = False
            out.append(line)
            continue

        if in_orch:
            m2 = re.match(r"^(\s*)([A-Za-z0-9_]+):\s*$", line)
            if m2 and len(m2.group(1)) == orch_indent and m2.group(2) != "forge_orchestrator":
                # leaving service: inject user if missing before leaving
                if not user_set:
                    out.append(f'    user: "{uid}:{gid}"\n')
                in_orch = False
                orch_indent = None

        if in_orch:
            if re.match(r'^\s{4}user:\s*', line):
                out.append(f'    user: "{uid}:{gid}"\n')
                user_set = True
                continue
            out.append(line)
        else:
            out.append(line)

    # EOF while still in service
    if in_orch and not user_set:
        out.append(f'    user: "{uid}:{gid}"\n')

    return "".join(out)

compose = patch_service_user(compose)

# 3) Ensure forge_orchestrator depends_on includes init completion
# Add a depends_on entry for init if not present
def ensure_depends_on_init(text: str) -> str:
    lines = text.splitlines(True)
    out = []
    in_orch = False
    saw_depends = False
    added = False

    for i, line in enumerate(lines):
        if re.match(r"^  forge_orchestrator:\s*$", line):
            in_orch = True
            saw_depends = False
            added = False
            out.append(line)
            continue

        if in_orch:
            # if next service begins, inject depends_on if needed
            if re.match(r"^  [A-Za-z0-9_]+:\s*$", line) and not line.startswith("  forge_orchestrator:"):
                if not saw_depends:
                    out.append("    depends_on:\n")
                    out.append("      forge_orchestrator_storage_init:\n")
                    out.append("        condition: service_completed_successfully\n")
                elif saw_depends and not added:
                    # depends_on existed but init not added; add it at end of depends_on block.
                    # If we get here, something went wrong with detection; keep it simple.
                    pass
                in_orch = False
                out.append(line)
                continue

            if re.match(r"^\s{4}depends_on:\s*$", line):
                saw_depends = True
                out.append(line)
                continue

            if saw_depends and not added:
                # If we see another top-level key under orch (4 spaces) and we haven't added init yet,
                # add it right before we leave depends_on section.
                if re.match(r"^\s{4}[A-Za-z0-9_]+:\s*$", line) and not line.strip().startswith("depends_on:"):
                    out.append("      forge_orchestrator_storage_init:\n")
                    out.append("        condition: service_completed_successfully\n")
                    added = True
                    out.append(line)
                    continue

            # If init already present, mark added
            if "forge_orchestrator_storage_init" in line:
                added = True

            out.append(line)
        else:
            out.append(line)

    # If file ended while inside orchestrator:
    if in_orch and not saw_depends:
        out.append("    depends_on:\n")
        out.append("      forge_orchestrator_storage_init:\n")
        out.append("        condition: service_completed_successfully\n")

    return "".join(out)

compose = ensure_depends_on_init(compose)

Path("compose.yml").write_text(compose, encoding="utf-8")
print("compose.yml patched: added storage init + set orchestrator user + depends_on")
PY

echo
echo "== Validate config =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" config >/dev/null
echo "OK"

echo
echo "== Run init + recreate orchestrator =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" up -d --force-recreate forge_orchestrator_storage_init
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" up -d --force-recreate forge_orchestrator

echo
echo "== Verify write access now =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE" -f "$EXPOSE_FILE" exec -T forge_orchestrator sh -lc '
set -e
echo "id=$(id)"
echo "STORAGE_ROOT=$STORAGE_ROOT"
python - <<PY
import os
from pathlib import Path
p = Path(os.getenv("STORAGE_ROOT","storage"))
p.mkdir(parents=True, exist_ok=True)
t = p / ".__write_test__"
t.write_text("ok")
print("write ok:", t)
PY
ls -la "$STORAGE_ROOT" || true
'
echo "DONE"

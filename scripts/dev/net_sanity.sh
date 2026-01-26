#!/usr/bin/env bash
export MINIO_ROOT_USER="${MINIO_ROOT_USER:-dummy}"
export MINIO_ROOT_PASSWORD="${MINIO_ROOT_PASSWORD:-dummy}"
export MINIO_BUCKET="${MINIO_BUCKET:-dummy}"
export SANITIZED_BUCKET="${SANITIZED_BUCKET:-dummy}"

set -euo pipefail

echo "== forge_nats networks =="
docker inspect -f '{{json .NetworkSettings.Networks}}' forge_nats | jq .

echo "== forge_scoreboard networks =="
docker inspect -f '{{json .NetworkSettings.Networks}}' forge_scoreboard | jq .

echo "== DNS from forge_scoreboard =="
docker compose exec -T forge_scoreboard getent hosts forge_nats

JQ="${JQ:-jq}"
if ! command -v "$JQ" >/dev/null 2>&1; then
  echo "jq not found, printing raw JSON"
  docker inspect -f '{{json .NetworkSettings.Networks}}' forge_nats
  docker inspect -f '{{json .NetworkSettings.Networks}}' forge_scoreboard
else
  docker inspect -f '{{json .NetworkSettings.Networks}}' forge_nats | jq .
  docker inspect -f '{{json .NetworkSettings.Networks}}' forge_scoreboard | jq .
fi
echo "== TCP connect to forge_nats:4222 from forge_scoreboard =="
docker compose --env-file .env.dev -f compose.yml -f compose.expose.yml exec -T forge_scoreboard sh -lc \
'python - <<PY
import socket, sys
host, port = "forge_nats", 4222
try:
    s = socket.create_connection((host, port), timeout=2)
    print("CONNECT_OK", s.getpeername())
    s.close()
except Exception as e:
    print("CONNECT_FAIL", repr(e))
    sys.exit(1)
PY'

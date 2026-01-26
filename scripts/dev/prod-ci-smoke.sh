#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="${ENV_FILE:-.env.prod}"
COMPOSE=(docker compose --env-file "${ENV_FILE}" -f compose.yml -f compose.prod.yml)

echo "ENV_FILE=${ENV_FILE}"
echo "== bring up deps =="

"${COMPOSE[@]}" up -d --force-recreate \
  forge_redis forge_opa forge_opa_probe forge_minio forge_minio_probe forge_nats forge_nats_probe forge_spawn_service

echo "== wait for spawn_service readyz =="
deadline=$((SECONDS+90))
while true; do
  if curl -fsS --max-time 2 http://127.0.0.1:8082/readyz >/dev/null 2>&1; then
    echo "spawn_service ready"
    break
  fi
  if (( SECONDS >= deadline )); then
    echo "ERROR: spawn_service never became ready"
    "${COMPOSE[@]}" ps forge_spawn_service || true
    "${COMPOSE[@]}" logs --tail=200 forge_spawn_service || true
    exit 1
  fi
  sleep 1
done

echo "== gate: billing_audit writable =="
"${COMPOSE[@]}" exec -T forge_spawn_service sh -lc 'test -w /var/lib/forge/billing_audit/tenants'

echo "== E2E: spawn + access =="
./scripts/prod-e2e-access.sh

echo "== verify billing audit chain =="
./scripts/verify-billing-audit-chain.sh

echo "OK: prod smoke passed"

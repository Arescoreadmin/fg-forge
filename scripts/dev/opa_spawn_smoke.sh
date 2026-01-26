#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE="${OPA_PROBE_SERVICE:-forge_opa_probe}"
OPA_URL="${OPA_URL:-http://forge_opa:8181}"
REQ_ID="${1:-bug-12345678}"

command -v docker >/dev/null 2>&1 || { echo "missing dependency: docker" >&2; exit 127; }

if ! docker compose config --services | grep -qx "${SERVICE}"; then
  echo "ERROR: compose service '${SERVICE}' not found." >&2
  docker compose config --services >&2
  exit 2
fi

if ! docker compose ps --services --status running | grep -qx "${SERVICE}"; then
  echo "ERROR: '${SERVICE}' is not running. Bring the stack up first." >&2
  docker compose ps >&2 || true
  exit 3
fi

docker compose exec -T "${SERVICE}" sh -lc "
set -eu
OPA_URL='${OPA_URL}'
REQ_ID='${REQ_ID}'

fail() { echo \"ERROR: \$*\" >&2; exit 1; }

echo '== OPA /health (code only) =='
code=\$(curl -sS -o /dev/null -w '%{http_code}' \"\$OPA_URL/health\" || true)
echo \"code=\$code\"
[ \"\$code\" = '200' ] || fail 'OPA health not 200'

echo
echo '== allow: valid payload (expect true) =='
cat >/tmp/in.json <<JSON
{
  \"input\": {
    \"request_id\": \"\$REQ_ID\",
    \"track\": \"netplus\",
    \"billing_ok\": true,
    \"tenant_blocked\": false,
    \"rate_limit_exceeded\": false,
    \"scenarios_used\": 0
  }
}
JSON

resp=\$(curl -sS -w '\nHTTP_CODE:%{http_code}\n' -H 'content-type: application/json' -d @/tmp/in.json \"\$OPA_URL/v1/data/frostgate/forge/spawn/allow\" || true)
echo \"\$resp\" | sed -n '1,/HTTP_CODE:/p'
echo \"\$resp\" | grep -q 'HTTP_CODE:200' || fail 'allow http != 200'
echo \"\$resp\" | grep -q '\"result\":true' || fail 'allow did not return true'

echo
echo '== deny_reasons: valid payload (expect []) =='
resp=\$(curl -sS -w '\nHTTP_CODE:%{http_code}\n' -H 'content-type: application/json' -d @/tmp/in.json \"\$OPA_URL/v1/data/frostgate/forge/spawn/deny_reasons\" || true)
echo \"\$resp\" | sed -n '1,/HTTP_CODE:/p'
echo \"\$resp\" | grep -q 'HTTP_CODE:200' || fail 'deny_reasons http != 200'
echo \"\$resp\" | grep -q '\"result\":\\[\\]' || fail 'deny_reasons not empty for valid payload'

echo
echo '== deny_reasons: bad track (expect unsupported track) =='
cat >/tmp/in_bad.json <<JSON
{
  \"input\": {
    \"request_id\": \"\$REQ_ID\",
    \"track\": \"lolnope\",
    \"billing_ok\": true,
    \"tenant_blocked\": false,
    \"rate_limit_exceeded\": false,
    \"scenarios_used\": 0
  }
}
JSON

resp=\$(curl -sS -w '\nHTTP_CODE:%{http_code}\n' -H 'content-type: application/json' -d @/tmp/in_bad.json \"\$OPA_URL/v1/data/frostgate/forge/spawn/deny_reasons\" || true)
echo \"\$resp\" | sed -n '1,/HTTP_CODE:/p'
echo \"\$resp\" | grep -q 'HTTP_CODE:200' || fail 'deny_reasons(bad track) http != 200'
echo \"\$resp\" | grep -q 'unsupported track' || fail 'missing unsupported track reason'

echo
echo 'OK'
"

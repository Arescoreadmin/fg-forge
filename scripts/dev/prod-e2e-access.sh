#!/usr/bin/env bash
set -euo pipefail

# End-to-end: spawn -> access
# Requires: python (std lib), curl
# Uses: ./scripts/mint-sat.py and ./scripts/mint-receipt.py

ENV_FILE="${ENV_FILE:-.env.prod}"
SPAWN_URL="${SPAWN_URL:-http://127.0.0.1:8082/v1/spawn}"
ACCESS_BASE="${ACCESS_BASE:-http://127.0.0.1:8082/v1/access}"

TRACK="${TRACK:-netplus}"
SUBJECT="${SUBJECT:-prod-e2e-user}"

fail() { echo "ERROR: $*" >&2; exit 2; }
need_file() { [[ -f "$1" ]] || fail "missing file: $1"; }

tmpdir="$(mktemp -d)"
cleanup() { rm -rf "$tmpdir"; }
trap cleanup EXIT

need_file "$ENV_FILE"
need_file "./scripts/mint-sat.py"
need_file "./scripts/mint-receipt.py"

SAT_HMAC_SECRET="$(grep -E '^SAT_HMAC_SECRET=' "$ENV_FILE" | cut -d= -f2- || true)"
RECEIPT_HMAC_SECRET="$(grep -E '^RECEIPT_HMAC_SECRET=' "$ENV_FILE" | cut -d= -f2- || true)"

[[ -n "${SAT_HMAC_SECRET// }" ]] || fail "SAT_HMAC_SECRET missing in $ENV_FILE"
[[ -n "${RECEIPT_HMAC_SECRET// }" ]] || fail "RECEIPT_HMAC_SECRET missing in $ENV_FILE"

SAT="$(SAT_HMAC_SECRET="$SAT_HMAC_SECRET" python ./scripts/mint-sat.py | tr -d '\n')"
RECEIPT="$(RECEIPT_HMAC_SECRET="$RECEIPT_HMAC_SECRET" python ./scripts/mint-receipt.py | tr -d '\n')"

[[ "$SAT" == *.*.* ]] || fail "SAT doesn't look like a token (len=${#SAT})"
[[ "$RECEIPT" == *.* ]] || fail "RECEIPT doesn't look like a token (len=${#RECEIPT})"

REQ_ID="prod-e2e-$(date +%s)"

echo "REQ_ID=$REQ_ID"
echo "SPAWN_URL=$SPAWN_URL"
echo "ACCESS_BASE=$ACCESS_BASE"
echo "TRACK=$TRACK SUBJECT=$SUBJECT"

spawn_hdr="$tmpdir/spawn.hdr"
spawn_body="$tmpdir/spawn.body"

# ---- spawn (retry) ----
echo
echo "== spawn =="

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

spawn_body="$tmpdir/spawn.body"
spawn_hdr="$tmpdir/spawn.hdr"

spawn_http="000"
attempts="${SPAWN_ATTEMPTS:-10}"

for i in $(seq 1 "$attempts"); do
  # IMPORTANT: don't let curl kill the script, we want to retry on connection resets
  spawn_http="$(
    curl -sS --max-time 5 \
      -D "$spawn_hdr" -o "$spawn_body" -w '%{http_code}\n' \
      -H "x-request-id: $REQ_ID" \
      -H "content-type: application/json" \
      -H "x-sat: $SAT" \
      -H "x-receipt-token: $RECEIPT" \
      -d "{\"track\":\"$TRACK\",\"subject\":\"$SUBJECT\"}" \
      "$SPAWN_URL" \
    || echo "000"
  )"

  if [[ "$spawn_http" == "200" ]]; then
    break
  fi

  echo "spawn attempt $i/$attempts failed (http=$spawn_http). waiting..."
  sleep 1
done

echo "spawn_http=$spawn_http"
if [[ "$spawn_http" != "200" ]]; then
  echo "---- spawn headers ----"
  [[ -f "$spawn_hdr" ]] && sed -n '1,120p' "$spawn_hdr" || true
  echo "---- spawn body ----"
  [[ -f "$spawn_body" ]] && head -c 2000 "$spawn_body" || true
  exit 1
fi


# Parse JSON safely (NOTE: args must be on same line as `python -`)
read -r SCENARIO_ID ACCESS_TOKEN ACCESS_URL EXPIRES_AT < <(
  python - "$spawn_body" <<'PY'
import json, sys

path = sys.argv[1]
raw = open(path, "rb").read()
d = json.loads(raw.decode("utf-8"))

sid = d.get("scenario_id","")
tok = d.get("access_token","")
url = d.get("access_url","")
exp = d.get("expires_at","")

# Print as 4 whitespace-separated fields
print(sid, tok, url, exp)
PY
)

[[ -n "${SCENARIO_ID}" ]] || fail "spawn JSON missing scenario_id"
[[ -n "${ACCESS_TOKEN}" ]] || fail "spawn JSON missing access_token"

echo "SCENARIO_ID=$SCENARIO_ID"
echo "ACCESS_TOKEN_LEN=${#ACCESS_TOKEN}"
echo "EXPIRES_AT=$EXPIRES_AT"
echo "ACCESS_URL=$ACCESS_URL"

# URL-encode token for query param
ENC_TOKEN="$(
  python - "$ACCESS_TOKEN" <<'PY'
import sys
from urllib.parse import quote
print(quote(sys.argv[1], safe=""))
PY
)"

access_hdr="$tmpdir/access.hdr"
access_body="$tmpdir/access.body"

echo
echo "== access =="
access_url="${ACCESS_BASE}/${SCENARIO_ID}?token=${ENC_TOKEN}"
echo "GET $access_url"

access_code="$(
  curl -sS -D "$access_hdr" -o "$access_body" -w '%{http_code}' \
    -H "content-type: application/json" \
    "$access_url" \
  || true
)"
echo "access_http=$access_code"

echo "---- access headers ----"
tail -n 80 "$access_hdr" || true
echo "---- access body (first 2000 bytes) ----"
head -c 2000 "$access_body" || true
echo

if [[ "$access_code" != "200" ]]; then
  echo "access failed (http=$access_code)" >&2
  exit 5
fi

echo "OK: spawn + access succeeded"

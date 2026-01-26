#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8082}"
SUBJECT="${SUBJECT:-dev-user}"
TIER="${TIER:-basic}"
TRACKS_JSON="${TRACKS_JSON:-[\"netplus\",\"ccna\",\"cissp\"]}"

echo "== Seed entitlement (best effort) =="
echo "BASE_URL=$BASE_URL SUBJECT=$SUBJECT TIER=$TIER TRACKS=$TRACKS_JSON"

openapi="$(mktemp)"
trap 'rm -f "$openapi"' EXIT

curl -fsS "$BASE_URL/openapi.json" -o "$openapi"

# Find likely entitlement endpoints
candidates=$(
  python - <<'PY' "$openapi"
import json,sys
spec=json.load(open(sys.argv[1]))
paths=spec.get("paths", {})
cand=[]
for p, methods in paths.items():
    pl=p.lower()
    if any(k in pl for k in ["entitle", "billing", "access", "admin", "seed"]):
        for m in methods.keys():
            if m.lower() in ["post", "put"]:
                cand.append((p, m.upper()))
for p,m in cand:
    print(f"{m} {p}")
PY
)

if [[ -z "${candidates}" ]]; then
  echo
  echo "No obvious entitlement endpoints in OpenAPI."
  echo "Implement dev fallback in spawn_service:"
  echo "  - BILLING_MODE=stub + ENTITLEMENT_ALLOW_ALL=true"
  echo "  - or ENTITLEMENTS_JSON env var and load it on startup"
  exit 2
fi

echo
echo "Candidate endpoints:"
echo "$candidates"
echo

# Try POST endpoints first, with a few common payload shapes.
payloads=(
  "{\"subject\":\"$SUBJECT\",\"tier\":\"$TIER\",\"tracks\":$TRACKS_JSON}"
  "{\"subject\":\"$SUBJECT\",\"tier\":\"$TIER\",\"allowed_tracks\":$TRACKS_JSON}"
  "{\"principal\":\"$SUBJECT\",\"tier\":\"$TIER\",\"tracks\":$TRACKS_JSON}"
  "{\"subject\":\"$SUBJECT\",\"plan\":\"$TIER\",\"tracks\":$TRACKS_JSON}"
)

ok=0
while read -r method path; do
  [[ -z "${method}" ]] && continue
  url="$BASE_URL$path"
  if [[ "$method" != "POST" ]]; then
    continue
  fi

  echo "Trying $method $url"
  for body in "${payloads[@]}"; do
    code=$(curl -sS -o /tmp/seed.out -w "%{http_code}" \
      -H "content-type: application/json" \
      -X POST "$url" \
      -d "$body" || true)
    if [[ "$code" =~ ^2 ]]; then
      echo "OK ($code): seeded via $path"
      cat /tmp/seed.out; echo
      ok=1
      break
    fi
  done
  [[ "$ok" -eq 1 ]] && break
done <<< "$candidates"

if [[ "$ok" -ne 1 ]]; then
  echo
  echo "Could not seed entitlement via any discovered endpoint."
  echo "Implement env-var based dev entitlements (fastest + deterministic):"
  echo "  ENTITLEMENT_ALLOW_ALL=true   # dev only"
  echo "  OR ENTITLEMENTS_JSON='[{\"subject\":\"dev-user\",\"tier\":\"basic\",\"tracks\":[\"netplus\"]}]'"
  exit 3
fi

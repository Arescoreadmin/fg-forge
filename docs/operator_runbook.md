# Operator Runbook

## Required environment variables (non-dev)

When `FORGE_ENV` is not `dev` or `development`, the following secrets **must** be set for all services:

- `SAT_HMAC_SECRET`
- `ET_HMAC_SECRET`
- `RECEIPT_HMAC_SECRET`
- `OPERATOR_TOKEN`

## Environment behavior

- **Dev (default)**: `FORGE_ENV=dev` or `development` allows startup without the required secrets. Feature flags may be enabled for local testing.
- **Staging/Prod**: `FORGE_ENV` in `staging`, `prod`, or `production` enforces required secrets and fails fast if `DEV_ALLOW_XPLAN=true` or `ALLOW_FREE_DEFAULT=true`.

## Offline verdict verification

Use the offline verification CLI against stored artifacts:

```
python scripts/verify_verdict.py \
  storage/scenarios/<scenario_id>/results/score.json \
  storage/scenarios/<scenario_id>/results/<evidence_bundle> \
  storage/scenarios/<scenario_id>/results/verdict.sig \
  storage/scenarios/<scenario_id>/results/verdict.pub
```

Artifacts are stored under `storage/scenarios/<scenario_id>/results/` with `score.json`, `verdict.sig`, `verdict.pub`, and an evidence bundle (e.g., `evidence.tar.gz` or `evidence.tar.zst`).

## Secret rotation & rollout order

1. **Pre-stage new secrets** in the secret manager (KMS/Vault/etc.).
2. **Update spawn_service first** (mints ET/SAT/receipts):
   - Roll out `SAT_HMAC_SECRET`, `ET_HMAC_SECRET`, `RECEIPT_HMAC_SECRET`.
3. **Update orchestrator second** (verifies SATs and OPA):
   - Roll out `SAT_HMAC_SECRET`, `ET_HMAC_SECRET`, `RECEIPT_HMAC_SECRET`, `OPERATOR_TOKEN`.
4. **Update scoreboard last** (verifies operator auth):
   - Roll out `OPERATOR_TOKEN` along with the shared HMAC secrets.
5. **Verify** with `/readyz` checks across services and run an end-to-end scenario.

## Failure recovery checklist

### spawn_service
- Confirm `FORGE_ENV` and required secrets are set (non-dev).
- Check `SAT_HMAC_SECRET`, `ET_HMAC_SECRET`, `RECEIPT_HMAC_SECRET` for mismatches.
- Validate entitlement sources (receipt/store) and retry `/readyz`.

### orchestrator
- Confirm `FORGE_ENV` and required secrets are set (non-dev).
- Check OPA connectivity and policy hash logs; validate `OPA_POLICY_HASH` if set.
- Restart NATS subscriber if disconnected.

### scoreboard
- Confirm `FORGE_ENV` and required secrets are set (non-dev).
- Validate signing key readiness and storage access.
- Re-run `/readyz` and reprocess any failed scenario completion events.

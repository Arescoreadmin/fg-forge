# Operator Runbook

## Required environment variables (non-dev)
Set these in staging/prod before starting any service:
- `SAT_HMAC_SECRET`
- `ET_HMAC_SECRET`
- `RECEIPT_HMAC_SECRET`
- `OPERATOR_TOKEN`

## Dev vs staging vs prod modes
- `FORGE_ENV=dev` (default): local iteration, dev-only fallbacks are permitted.
- `FORGE_ENV=staging|prod|production`: strict mode. Services fail fast if required secrets are missing or if unsafe dev flags are enabled.
- Do **not** set `DEV_ALLOW_XPLAN=true` or `ALLOW_FREE_DEFAULT=true` outside dev.

## Verify verdicts offline
Use the built-in verification CLI with stored artifacts:
```bash
python scripts/verify_verdict.py \
  storage/scenarios/<scenario_id>/results/score.json \
  storage/scenarios/<scenario_id>/results/evidence.tar.zst \
  storage/scenarios/<scenario_id>/results/verdict.sig \
  storage/scenarios/<scenario_id>/results/verdict.pub
```
A PASS confirms score/evidence hashes and the verdict signature.

## Rotate secrets safely
1. Generate new values for `SAT_HMAC_SECRET`, `ET_HMAC_SECRET`, `RECEIPT_HMAC_SECRET`, and `OPERATOR_TOKEN`.
2. Update the secret store (Vault/KMS/CI secrets) and deployment manifests.
3. Roll services in this order: spawn_service → orchestrator → scoreboard.
4. Validate `/readyz` for each service after rollout.
5. Invalidate any cached tokens/receipts issued with old secrets if your environment supports it.

## Recover from failed spawns or scoring
- **Spawn failures**: Check spawn_service logs and `/readyz` for dependency failures (OPA, egress gateway). Confirm orchestrator `/readyz` is healthy before retrying.
- **Orchestrator failures**: Verify NATS is reachable and OPA is healthy; rerun the spawn request once `/readyz` is green.
- **Scoring failures**: Check scoreboard `/readyz` (storage/signing key), then re-trigger scoring via the orchestrator completion flow.
- Always capture the correlation ID from logs when escalating incidents.

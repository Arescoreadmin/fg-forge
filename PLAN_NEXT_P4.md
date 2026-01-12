# Next P4 Plan

## Steps
1) Update orchestrator OPA input builder to include plan/tier, retention_days, subject, and tenant_id sourced from verified SAT claims.
2) Extend orchestrator scoring trigger payload to include entitlement context (subject, tenant_id, plan/tier, retention_days, scenario_id, correlation_id).
3) Update scoreboard scoring handler to require plan/tier, persist subject/tenant/plan/retention in score.json and evidence manifest.
4) Add/adjust orchestrator and scoreboard unit tests to cover OPA payload and scoring artifacts with entitlements.

## Files to touch
- services/orchestrator/app/main.py
- services/orchestrator/tests/*
- services/scoreboard/app/main.py
- services/scoreboard/tests/*
- PLAN_NEXT_P4.md

## Tests
- python -m unittest discover -s services/orchestrator/tests
- python -m unittest discover -s services/scoreboard/tests

# Next P5 Plan

## Steps
1) Add spawn_service entitlement resolver module to load verified receipt tokens and persistent entitlements (JSON/Redis) and return tier + retention_days.
2) Wire spawn_service request flow to use the resolver for tier/retention, update SAT claims, and remove reliance on request tier.
3) Extend spawn_service tests to cover entitlement resolution priority, denial on missing entitlements, and updated spawn flows.

## Files to touch
- services/spawn_service/app/entitlements.py
- services/spawn_service/app/main.py
- services/spawn_service/tests/test_spawn_service.py
- PLAN_NEXT_P5.md
- MVP_PROGRESS.md

## Tests
- python -m unittest discover -s services/spawn_service/tests

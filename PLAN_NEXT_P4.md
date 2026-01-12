# Next P4 Plan

## Steps
1) Define authoritative plan/entitlement catalog in spawn_service with defaults and validation helpers for tiers and tracks.
2) Enforce entitlements (rate limits, concurrent limits, allowed tracks) during spawn handling with fail-closed behavior on invalid tiers.
3) Extend spawn_service tests to cover plan lookup, track enforcement, and entitlement-driven limits.

## Files to touch
- services/spawn_service/app/main.py
- services/spawn_service/tests/test_spawn_service.py
- PLAN_NEXT_P4.md

## Tests
- python -m unittest discover -s services/spawn_service/tests

# Next P5 Plan

## Steps
1) Add Entitlement Token (ET) mint/verify helpers in `services/spawn_service/app/entitlements.py` and wire spawn flow in `services/spawn_service/app/main.py` to mint ET after entitlement resolution, then mint SAT strictly derived from ET.
2) Enforce guardrails in `services/spawn_service/app/main.py` to disable X-Plan and FREE defaults unless explicitly enabled via env flags.
3) Add billing audit chain append + verification utilities in `services/spawn_service/app/entitlements.py` and call from `services/spawn_service/app/main.py` when receipt-based plan changes occur.
4) Update `services/spawn_service/tests/test_spawn_service.py` with ET claim validation, SAT derived from ET, guardrail failure/allow tests, and audit chain integrity/tamper tests.
5) Update `.env.example` placeholders for new secrets/flags; update `MVP_PROGRESS.md` after implementation.

## Files to touch
- services/spawn_service/app/entitlements.py
- services/spawn_service/app/main.py
- services/spawn_service/tests/test_spawn_service.py
- .env.example
- PLAN_NEXT_P5.md
- MVP_PROGRESS.md

## Tests
- python -m unittest discover -s services/spawn_service/tests

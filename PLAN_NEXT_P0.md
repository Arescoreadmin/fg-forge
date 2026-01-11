# Next P0 Plan

## Steps
1) Add orchestrator internal completion endpoint with internal auth guard, completion logging, and wiring to scoring (services/orchestrator/app/main.py).
2) Implement scoring artifact generation in scoreboard on completion, writing score.json, evidence.tar.gz, verdict.sig (+pub key if available) under storage/scenarios/<id>/results (services/scoreboard/app/main.py).
3) Add integration test covering spawn SAT verification, completion, scoring artifacts, and signature verification using temp storage (services/orchestrator/tests/*, services/scoreboard/tests/*, services/spawn_service/tests/* as needed).
4) Update orchestrator readiness check to fail if scoreboard unreachable (services/orchestrator/app/main.py).
5) Update MVP_PROGRESS.md with completed items and local run snippet.

## Files to touch
- services/orchestrator/app/main.py
- services/scoreboard/app/main.py
- services/orchestrator/tests/*
- services/scoreboard/tests/*
- services/spawn_service/tests/*
- MVP_PROGRESS.md

## Tests
- python -m unittest discover -s services/spawn_service/tests
- python -m unittest discover -s services/orchestrator/tests
- python -m unittest discover -s services/scoreboard/tests

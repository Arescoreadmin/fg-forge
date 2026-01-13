# Next P6 Plan

## Status
Completed

## Completed steps
- Updated CI workflow to run linting, dependency installs, guardrail scans, and OPA v1 policy tests with a pinned Docker image.
- Enforced startup config guardrails in orchestrator and scoreboard services.
- Added OPA policy hash logging and optional enforcement in orchestrator.
- Added operator runbook documentation.
- Updated MVP progress tracking.

## Tests
- python -m unittest discover -s services/spawn_service/tests
- python -m unittest discover -s services/orchestrator/tests
- python -m unittest discover -s services/scoreboard/tests
- python -m unittest discover -s scripts/tests
- docker run --rm -v "$PWD:/workspace" -w /workspace openpolicyagent/opa@sha256:c0609fecc0924743f8648dc4a035d2f57ca163dc723ed1d13f3197ba5bd122b3 fmt --fail policies/
- docker run --rm -v "$PWD:/workspace" -w /workspace openpolicyagent/opa@sha256:c0609fecc0924743f8648dc4a035d2f57ca163dc723ed1d13f3197ba5bd122b3 test -v policies/

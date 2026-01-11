# Forge Services

This directory holds service scaffolding aligned to `docs/blueprint.md`.
Services marked as "stub" are placeholders awaiting implementation.

| Service | Purpose | Status |
| --- | --- | --- |
| spawn_service | Billing intake + spawn request submission | implemented |
| orchestrator | Validate templates, enforce OPA, create scenario networks | stub |
| worker_agent | Execute playbooks, collect evidence | stub |
| observer_hub | Aggregate telemetry and audit streams | stub |
| metrics_tuner | Usage quotas + fairness telemetry | stub |
| playbook_runner | Deterministic successCriteria execution | stub |
| llm_analyzer | LLM proposal governance + canary | stub |
| vector_db | Embedding search + scenario metadata | stub |
| attacker_agent | Controlled adversary agent | stub |
| defender_agent | Controlled defender agent | stub |
| aux_device1 | Auxiliary training device | stub |
| aux_device2 | Auxiliary training device | stub |
| overlay_sanitizer | PII scrubber + audit sanitizer | stub |
| scoreboard | Scoring outputs + signatures | stub |
| egress_gateway | nftables deny-all gateway + allowlist profiles | stub |

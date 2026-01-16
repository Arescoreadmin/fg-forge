SHELL := /bin/bash

# -----------------------------------------------------------------------------
# Repo basics
# -----------------------------------------------------------------------------
VENV ?= .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip

COMPOSE ?= docker compose
COMPOSE_FILE ?= compose.yml

# If you use compose.staging.yml sometimes, do:
# make itest-local COMPOSE_FILE=compose.staging.yml
COMPOSE_ARGS := -f $(COMPOSE_FILE)

# -----------------------------------------------------------------------------
# Python tooling (fg-forge keeps python deps under scripts/)
# -----------------------------------------------------------------------------
SCRIPTS_REQ := scripts/requirements.txt

.PHONY: venv
venv:
	@test -d "$(VENV)" || python3 -m venv "$(VENV)"
	@$(PIP) install --upgrade pip
	@test -f "$(SCRIPTS_REQ)" || (echo "❌ missing $(SCRIPTS_REQ)"; exit 2)
	@$(PIP) install -r "$(SCRIPTS_REQ)"

# -----------------------------------------------------------------------------
# Compose lifecycle
# -----------------------------------------------------------------------------
.PHONY: up down ps logs
up:
	$(COMPOSE) $(COMPOSE_ARGS) up -d --build

down:
	$(COMPOSE) $(COMPOSE_ARGS) down -v --remove-orphans

ps:
	$(COMPOSE) $(COMPOSE_ARGS) ps

logs:
	$(COMPOSE) $(COMPOSE_ARGS) logs --tail=200

# -----------------------------------------------------------------------------
# Integration / smoke lane
# -----------------------------------------------------------------------------
# Prefer the python smoke runner because it’s deterministic in CI.
SMOKE_PY := scripts/smoke_test.py
CI_LOCAL_SH := scripts/ci_local.sh

.PHONY: smoke itest-up itest-down itest-local ci-integration
smoke: venv
	@test -f "$(SMOKE_PY)" || (echo "❌ missing $(SMOKE_PY)"; exit 2)
	@$(PY) "$(SMOKE_PY)"

itest-up: up
itest-down: down

itest-local: itest-down itest-up
	@set -euo pipefail; \
	trap '$(MAKE) -s itest-down >/dev/null 2>&1 || true' EXIT; \
	$(MAKE) -s smoke

ci-integration: itest-local

# -----------------------------------------------------------------------------
# Evidence lane
# -----------------------------------------------------------------------------
# Don’t explode if env var isn’t set. Make already gives a default.
EVIDENCE_SCENARIO ?= default

.PHONY: evidence ci-evidence
evidence:
	@set -euo pipefail; \
	scenario="$${EVIDENCE_SCENARIO:-default}"; \
	echo "== evidence scenario: $$scenario =="; \
	case "$$scenario" in \
		default) \
			$(MAKE) -s itest-local ;; \
		ci_local) \
			test -x "$(CI_LOCAL_SH)" || (echo "❌ missing $(CI_LOCAL_SH)"; exit 2); \
			./"$(CI_LOCAL_SH)" ;; \
		*) \
			echo "❌ Unknown EVIDENCE_SCENARIO=$$scenario"; exit 2 ;; \
	esac; \
	echo "✅ evidence complete ($$scenario)"

ci-evidence: evidence

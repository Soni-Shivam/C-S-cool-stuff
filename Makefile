.DEFAULT_GOAL := help
SHELL := /bin/bash

# ─── Local development ───────────────────────────────────────────────────────
# Nothing in this section executes an APK. See CLAUDE.md — no sample ever runs
# on a developer machine.

.PHONY: install
install: ## Install core + dev dependencies (no lab extras — laptop never instruments)
	uv sync --group dev

.PHONY: install-lab
install-lab: ## Install lab extras (frida<17, mitmproxy). GCE detonator only.
	uv sync --group dev --extra lab

.PHONY: up
up: ## Run the API with reload on :8080
	uv run uvicorn drishti.api.main:app --reload --port 8080

.PHONY: ui
ui: ## Run the dashboard dev server
	cd ui && npm run dev

.PHONY: lint
lint: ## ruff check + format check
	uv run ruff check .
	uv run ruff format --check .

.PHONY: fmt
fmt: ## Apply ruff formatting
	# Scoped deliberately. A repo-wide `ruff format .` reformats the Python code
	# blocks inside docs/*.md, producing a 400-line diff in the spec that nobody
	# asked for. The docs are the contract; formatters do not get a vote.
	uv run ruff format drishti tests scripts
	uv run ruff check --fix drishti tests scripts

.PHONY: types
types: ## mypy
	uv run mypy drishti

.PHONY: test
test: ## Contract + unit tests. The gate for every PR.
	uv run pytest tests/contract tests/unit

.PHONY: e2e
e2e: ## Slow end-to-end tests on fixture APKs
	uv run pytest tests/e2e -s

.PHONY: check
check: lint test ## What CI runs

# ─── Evidence ledger ─────────────────────────────────────────────────────────
.PHONY: ledger
ledger: ## Verify a job's hash chain: make ledger JOB=job_xxx
	uv run python -m drishti.ledger.cli verify --job $(JOB)

# ─── GCP lab ─────────────────────────────────────────────────────────────────
# The ONLY place a real sample is ever executed. Targets are deliberately
# explicit: a nested-virt VM left running is the easiest way to burn the budget.

.PHONY: lab-status
lab-status: ## Show lab project, image version, VM state, bucket contents
	@bash infra/gcp/lab.sh status

.PHONY: lab-up
lab-up: ## Start the detonator VM
	@bash infra/gcp/lab.sh up

.PHONY: lab-down
lab-down: ## Stop the detonator VM. Run this when you finish a batch.
	@bash infra/gcp/lab.sh down

.PHONY: lab-verify
lab-verify: ## Run containment verification and emit a signed manifest
	@bash infra/gcp/lab.sh verify-containment

.PHONY: lab-test
lab-test: ## Tests that need a live lab (marked @pytest.mark.gcp)
	uv run pytest -m gcp

# ─── Demo ────────────────────────────────────────────────────────────────────
.PHONY: demo
demo: ## Reset demo state and bring the stack up
	uv run python scripts/demo_reset.py
	$(MAKE) up

.PHONY: freeze
freeze: ## Tag a code freeze
	git tag -a freeze-$$(date +%H%M) -m "code freeze"

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

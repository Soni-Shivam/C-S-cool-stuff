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

# The dashboard is a separate Vite app that proxies /api to :8080, so `make up`
# has to be running alongside it. Proxying rather than serving the built assets
# from FastAPI keeps the frozen route surface (T0.6) free of a UI mount.
.PHONY: ui-install
ui-install: ## Install dashboard dependencies
	cd ui && npm install

.PHONY: ui
ui: ## Run the dashboard dev server on :5173 (needs `make up` in another shell)
	cd ui && npm run dev

.PHONY: ui-build
ui-build: ## Typecheck and build the dashboard to ui/dist
	cd ui && npm run build

.PHONY: ui-preview
ui-preview: ui-build ## Serve the production build on :4173. Use this for the demo.
	cd ui && npm run preview

.PHONY: lint
lint: ## ruff check + format check
	uv run ruff check .
	uv run ruff format --check .

.PHONY: fmt
fmt: ## Apply ruff formatting
	uv run ruff format .
	uv run ruff check --fix .

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

# ─── Stage demos ─────────────────────────────────────────────────────────────
# Both run against a throwaway database and key, so they are safe to run live,
# repeatedly, in any order, without touching a real job.

.PHONY: demo-reject
demo-reject: ## Live: an AI claim citing no resolvable evidence is REFUSED
	uv run python scripts/demo_integrity.py reject

.PHONY: demo-tamper
demo-tamper: ## Live: an edited ledger is detected at an exact seq
	uv run python scripts/demo_integrity.py tamper

.PHONY: demo-integrity
demo-integrity: ## Both integrity demos, back to back
	uv run python scripts/demo_integrity.py both

.PHONY: demo-containment
demo-containment: ## The containment gate: accepts a sealed net, rejects the v1 nc -z probe
	uv run python scripts/demo_containment_gate.py

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

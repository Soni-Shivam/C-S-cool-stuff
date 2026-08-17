#!/usr/bin/env bash
# One-time project bootstrap: APIs, buckets, lifecycle, budget alerts.
#
# docs/superpowers/specs/2026-08-17-drishti-v2-build-design.md §4, CLAUDE.md "GCP layout".
#
# Creates NO compute. Empty buckets and a budget cost effectively nothing, so this is
# safe to run before any spending decision has been made. VMs are a separate, explicit
# step (`lab.sh`), because a nested-virt VM left running is the easiest way to burn the
# budget.
#
# Idempotent by construction: every create is guarded by an existence check, and every
# update is declarative. Re-running is a no-op that re-asserts the desired state.
#
# Deviation from CLAUDE.md, recorded in STATUS.md: region is us-east1, not asia-south1,
# to co-locate with the pre-existing extractor VM. Moving ~120GB cross-region would cost
# roughly $12 in egress, which buys nothing.
set -euo pipefail

PROJECT="${DRISHTI_GCP_PROJECT:-}"
REGION="${DRISHTI_GCP_REGION:-us-east1}"
BILLING_ACCOUNT="${DRISHTI_BILLING_ACCOUNT:-}"

# The trial account is closed, so there is no safety net behind these alerts.
# Amount is in the billing account's own currency (INR here); ~4200 INR ≈ the $50
# ceiling agreed in the build design. Thresholds fire at 60% and 90% of it.
BUDGET_AMOUNT="${DRISHTI_BUDGET_AMOUNT:-4200INR}"

#: Noncurrent object versions are deleted after this many days. Versioning is mandated
#: by CLAUDE.md; without this rule one accidental re-upload of the corpus silently
#: doubles 120GB of storage.
NONCURRENT_RETENTION_DAYS="${DRISHTI_NONCURRENT_RETENTION_DAYS:-7}"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; DIM=$'\033[2m'; RESET=$'\033[0m'
[[ -t 1 ]] || { RED=""; GREEN=""; YELLOW=""; DIM=""; RESET=""; }

die() { echo "${RED}error:${RESET} $*" >&2; exit 1; }
ok()   { echo "${GREEN}  ok${RESET}   $*"; }
skip() { echo "${DIM}  skip${RESET} $*"; }
warn() { echo "${YELLOW}  warn${RESET} $*" >&2; }

[[ -n "$PROJECT" ]] || die "DRISHTI_GCP_PROJECT is not set (see .env.example)"

# Retry wrapper. This laptop's network intermittently mangles TLS to *.googleapis.com
# (CLAUDE.md "Cost and lifecycle guardrails"), so a single failure must not abort a run.
gc() {
  local attempt
  for attempt in 1 2 3 4 5; do
    if gcloud "$@" 2>/tmp/drishti-bootstrap-err; then
      return 0
    fi
    echo "${DIM}  retry ${attempt}/5: gcloud $1 ${2:-}${RESET}" >&2
    sleep $(( attempt * 3 ))
  done
  cat /tmp/drishti-bootstrap-err >&2
  return 1
}

# ─── APIs ────────────────────────────────────────────────────────────────────
# IAP is how we reach VMs with no external IP. billingbudgets is what makes the
# spend alerts possible at all.
REQUIRED_APIS=(
  compute.googleapis.com
  storage.googleapis.com
  iap.googleapis.com
  oslogin.googleapis.com
  billingbudgets.googleapis.com
  cloudresourcemanager.googleapis.com
)

echo "── APIs ─────────────────────────────────────────────"
ENABLED="$(gc services list --enabled --project="$PROJECT" --format='value(config.name)')"
for api in "${REQUIRED_APIS[@]}"; do
  if grep -qx "$api" <<<"$ENABLED"; then
    skip "$api already enabled"
  else
    gc services enable "$api" --project="$PROJECT" && ok "enabled $api"
  fi
done

# ─── Buckets ─────────────────────────────────────────────────────────────────
# corpus    real APKs — private, versioned, never public, never leaves the project
# artifacts traces, screenshots, dropped dex, ledgers
# models    vocab_v1.json, the classifier, the calibrator
echo
echo "── Buckets (${REGION}) ───────────────────────────────"

LIFECYCLE_FILE="$(mktemp -t drishti-lifecycle-XXXXXX.json)"
trap 'rm -f "$LIFECYCLE_FILE"' EXIT
cat >"$LIFECYCLE_FILE" <<EOF
{
  "rule": [
    {
      "action": { "type": "Delete" },
      "condition": { "daysSinceNoncurrentTime": ${NONCURRENT_RETENTION_DAYS} }
    }
  ]
}
EOF

for suffix in corpus artifacts models; do
  bucket="gs://${PROJECT}-${suffix}"
  if gcloud storage buckets describe "$bucket" --project="$PROJECT" >/dev/null 2>&1; then
    skip "$bucket exists"
  else
    # public-access-prevention is not optional here: this bucket holds real malware.
    gc storage buckets create "$bucket" \
      --project="$PROJECT" \
      --location="$REGION" \
      --uniform-bucket-level-access \
      --public-access-prevention \
      && ok "created $bucket"
  fi

  # Declarative, so these are safe to re-apply on every run.
  gc storage buckets update "$bucket" --project="$PROJECT" --versioning >/dev/null \
    && ok "$bucket versioning on"
  gc storage buckets update "$bucket" --project="$PROJECT" \
    --lifecycle-file="$LIFECYCLE_FILE" >/dev/null \
    && ok "$bucket noncurrent versions deleted after ${NONCURRENT_RETENTION_DAYS}d"
done

# ─── Budget alerts ───────────────────────────────────────────────────────────
# Creating a budget needs billing.budgets.create on the *billing account*, which is a
# separate grant from project ownership. If it is missing we warn rather than abort:
# the buckets above are already correct, and a missing alert must not look like a
# failed bootstrap.
echo
echo "── Budget alerts ─────────────────────────────────────"

if [[ -z "$BILLING_ACCOUNT" ]]; then
  BILLING_ACCOUNT="$(gc billing projects describe "$PROJECT" \
    --format='value(billingAccountName)' | sed 's|billingAccounts/||')" || true
fi

if [[ -z "$BILLING_ACCOUNT" ]]; then
  warn "could not determine the billing account; skipping budget alerts"
  warn "set DRISHTI_BILLING_ACCOUNT and re-run"
else
  BUDGET_NAME="drishti-${PROJECT}"
  # --billing-project is load-bearing. The billing API is billed to gcloud's *quota*
  # project, which defaults to `gcloud config get project` — on this machine that is a
  # different, unrelated project, so without this flag the call fails with
  # "billingbudgets not enabled on <wrong project>" and reads exactly like a
  # permissions problem.
  EXISTING="$(gcloud billing budgets list --billing-account="$BILLING_ACCOUNT" \
    --billing-project="$PROJECT" \
    --filter="displayName=${BUDGET_NAME}" --format='value(name)' 2>/dev/null || true)"
  if [[ -n "$EXISTING" ]]; then
    skip "budget '${BUDGET_NAME}' exists"
  elif gcloud billing budgets create \
        --billing-account="$BILLING_ACCOUNT" \
        --billing-project="$PROJECT" \
        --display-name="$BUDGET_NAME" \
        --budget-amount="$BUDGET_AMOUNT" \
        --filter-projects="projects/$(gc projects describe "$PROJECT" \
           --format='value(projectNumber)')" \
        --threshold-rule=percent=0.6 \
        --threshold-rule=percent=0.9 \
        --threshold-rule=percent=1.0 >/dev/null 2>/tmp/drishti-budget-err; then
    ok "budget '${BUDGET_NAME}' at ${BUDGET_AMOUNT}, alerts at 60/90/100%"
  else
    warn "could not create the budget — needs billing.budgets.create on ${BILLING_ACCOUNT}"
    sed 's/^/       /' /tmp/drishti-budget-err >&2 || true
    warn "buckets and APIs are still correctly configured"
  fi
fi

# ─── What exists now ─────────────────────────────────────────────────────────
echo
echo "── State ─────────────────────────────────────────────"
echo "project  ${PROJECT}"
echo "region   ${REGION}"
echo "buckets"
gc storage ls --project="$PROJECT" | sed 's/^/         /'
echo "compute  $(gc compute instances list --project="$PROJECT" --format='value(name)' \
  | wc -l) instance(s) — bootstrap creates none"
echo
echo "${GREEN}bootstrap complete${RESET}"

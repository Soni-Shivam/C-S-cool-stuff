#!/usr/bin/env bash
set -euo pipefail

test "${DRISHTI_APPLY:-}" = "YES" || {
  echo "dry safety stop: set DRISHTI_APPLY=YES only after reviewing the M3 runbook" >&2; exit 2;
}
: "${GCP_PROJECT:?required}"
: "${GCP_NETWORK:?required}"
: "${GCP_ZONE:?required}"
: "${DRISHTI_FIXTURE_APK:?path to inert M3 fixture APK required}"
test -f "$DRISHTI_FIXTURE_APK"
case "$DRISHTI_FIXTURE_APK" in *canary.apk|*m3-inert-fixture*|*m3_fixture*) ;; *)
  echo "builder accepts only the authored canary or named inert fixture" >&2; exit 2;; esac

ALLOW_RULE="drishti-builder-https-${USER:-operator}"
DENY_RULE="drishti-builder-deny-${USER:-operator}"
IAP_RULE="drishti-builder-iap-${USER:-operator}"
cleanup() {
  gcloud compute firewall-rules delete "$ALLOW_RULE" "$DENY_RULE" "$IAP_RULE" --project "$GCP_PROJECT" --quiet 2>/dev/null || true
}
trap cleanup EXIT INT TERM

gcloud compute firewall-rules create "$ALLOW_RULE" --project "$GCP_PROJECT" \
  --network "$GCP_NETWORK" --direction EGRESS --priority 100 \
  --action ALLOW --rules tcp:443,udp:53,tcp:53 --destination-ranges 0.0.0.0/0 \
  --target-tags drishti-builder
gcloud compute firewall-rules create "$DENY_RULE" --project "$GCP_PROJECT" \
  --network "$GCP_NETWORK" --direction EGRESS --priority 200 \
  --action DENY --rules all --destination-ranges 0.0.0.0/0 --target-tags drishti-builder
gcloud compute firewall-rules create "$IAP_RULE" --project "$GCP_PROJECT" \
  --network "$GCP_NETWORK" --direction INGRESS --priority 100 \
  --action ALLOW --rules tcp:22 --source-ranges 35.235.240.0/20 --target-tags drishti-builder

export PKR_VAR_project="$GCP_PROJECT"
export PKR_VAR_zone="$GCP_ZONE"
export PKR_VAR_network="$GCP_NETWORK"
export PKR_VAR_fixture_apk="$DRISHTI_FIXTURE_APK"
packer init "$(dirname "$0")/packer"
packer build "$(dirname "$0")/packer/detonator.pkr.hcl"

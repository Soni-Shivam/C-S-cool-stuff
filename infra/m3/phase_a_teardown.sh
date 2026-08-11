#!/usr/bin/env bash
set -euo pipefail

test "${DRISHTI_APPLY:-}" = "YES" || { echo "set DRISHTI_APPLY=YES after review" >&2; exit 2; }
: "${GCP_PROJECT:?required}"
: "${GCP_REGION:?required}"
: "${FEATURE_BUCKET:?gs:// bucket required}"
: "${FEATURES_CSV:?local features.csv required}"
: "${EXTRACTOR_INSTANCE:?required}"
: "${CLOUD_ROUTER:?required}"
: "${CLOUD_NAT:?required}"

test "$(basename "$FEATURES_CSV")" = "features.csv"
test -f "$FEATURES_CSV"
gcloud storage cp "$FEATURES_CSV" "$FEATURE_BUCKET/features.csv"
gcloud compute instances delete "$EXTRACTOR_INSTANCE" --project "$GCP_PROJECT" --zone "${GCP_ZONE:?required}" --quiet
gcloud compute routers nats delete "$CLOUD_NAT" --router "$CLOUD_ROUTER" \
  --region "$GCP_REGION" --project "$GCP_PROJECT" --quiet

! gcloud compute instances describe "$EXTRACTOR_INSTANCE" --project "$GCP_PROJECT" --zone "$GCP_ZONE" >/dev/null 2>&1
! gcloud compute routers nats describe "$CLOUD_NAT" --router "$CLOUD_ROUTER" \
  --region "$GCP_REGION" --project "$GCP_PROJECT" >/dev/null 2>&1
echo "Phase A closed: features uploaded; extractor and Cloud NAT absent"

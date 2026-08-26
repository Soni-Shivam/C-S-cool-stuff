#!/usr/bin/env bash
# Pull observation artifacts off the sealed detonator and publish them. Laptop-side.
#
# The VM STAYS SEALED for this. IAP is an inbound tunnel and needs no egress from the
# instance, so traces come out over `gcloud compute scp --tunnel-through-iap` and the
# upload to GCS happens from here. Nothing about collecting results requires giving
# the detonator a route to the internet.
#
# What crosses this boundary is a JSON ObservationArtifact — redacted in the guest by
# the hook, and again by the ObservationEvent validator. An APK never does.
set -euo pipefail

VM="${DRISHTI_VM:-m3-detonator}"
ZONE="${DRISHTI_ZONE:-us-east1-c}"
PROJECT="${DRISHTI_PROJECT:-internship-505513}"
ARTIFACT_BUCKET="${DRISHTI_ARTIFACT_BUCKET:-gs://cybershield-505518-artifacts}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LOCAL="${REPO}/data/fixtures/observations"
RUN_ID="${DRISHTI_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"

retry() {
  local n=0
  until "$@"; do
    n=$((n + 1))
    [[ ${n} -ge 4 ]] && { echo "FAILED after ${n} attempts: $*" >&2; return 1; }
    echo "retry ${n}: $*" >&2
    sleep $((n * 5))
  done
}

STAGE=$(mktemp -d /tmp/drishti-results-XXXX)
trap 'rm -rf "${STAGE}"' EXIT

# The harness writes results as root with mode 600; make them readable for scp without
# changing what is in them.
retry gcloud compute ssh "${VM}" --zone="${ZONE}" --project="${PROJECT}" --tunnel-through-iap \
  --command='sudo chown -R $(id -un) /opt/drishti/results && sudo chmod 644 /opt/drishti/results/*.json && ls /opt/drishti/results/'

retry gcloud compute scp --recurse "${VM}:/opt/drishti/results/*.json" "${STAGE}/" \
  --zone="${ZONE}" --project="${PROJECT}" --tunnel-through-iap

# Refuse to publish anything that is not a well-formed artifact for the sample its
# filename claims. A mislabelled trace is worse than a missing one.
python3 - "${STAGE}" <<'PY'
import json, pathlib, sys
bad = []
for path in sorted(pathlib.Path(sys.argv[1]).glob("*.json")):
    data = json.loads(path.read_text())
    if data.get("sha256") != path.stem or data.get("simulated") is not False:
        bad.append(path.name)
    print(f"{path.stem[:12]}  outcome={data['outcome']:12s} obs={len(data['observations']):3d} "
          f"mitre={','.join(data.get('mitre_observed') or []) or '-'}")
if bad:
    sys.exit(f"refusing to publish mislabelled or simulated artifacts: {bad}")
PY

mkdir -p "${LOCAL}"
cp "${STAGE}"/*.json "${LOCAL}/"
# Two destinations on purpose: a run-stamped copy that is the record, and a `latest/`
# copy that the demo can point at without knowing the run id.
retry gsutil -m cp "${STAGE}"/*.json "${ARTIFACT_BUCKET}/observations/${RUN_ID}/"
retry gsutil -m cp "${STAGE}"/*.json "${ARTIFACT_BUCKET}/observations/latest/"

echo "published run ${RUN_ID}"
echo "  gcs:  ${ARTIFACT_BUCKET}/observations/${RUN_ID}/"
echo "  repo: ${LOCAL}/"

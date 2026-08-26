#!/usr/bin/env bash
# Ship the harness (drishti package + CLIs + Frida hooks) from the repo to the VM.
#
# Runs on the laptop. Code only — NEVER a sample. Idempotent: it overwrites what is
# already there, so re-run it after every edit to the harness.
set -euo pipefail

VM="${DRISHTI_VM:-m3-detonator}"
ZONE="${DRISHTI_ZONE:-us-east1-c}"
PROJECT="${DRISHTI_PROJECT:-internship-505513}"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Retry: calls to *.googleapis.com fail intermittently with SSL: WRONG_VERSION_NUMBER,
# and one transient failure must not abort a deploy.
retry() {
  local n=0
  until "$@"; do
    n=$((n + 1))
    [[ ${n} -ge 4 ]] && { echo "FAILED after ${n} attempts: $*" >&2; return 1; }
    echo "retry ${n}: $*" >&2
    sleep $((n * 5))
  done
}

TAR=$(mktemp /tmp/drishti-harness-XXXX.tar.gz)
trap 'rm -f "${TAR}"' EXIT
# --exclude __pycache__: stale .pyc for a different interpreter is a confusing failure.
# The two VM-side shell tools ship with the harness. They were previously copied by
# hand to /tmp, which is how detonator_stage.sh came to call a path that did not
# exist and silently staged nothing.
tar czf "${TAR}" -C "${REPO}" \
  --exclude='__pycache__' --exclude='*.pyc' \
  drishti scripts/dynamic_analyze.py scripts/verify_containment.py \
  infra/gcp/detonator_run.sh infra/gcp/detonator_lockdown.sh

retry gcloud compute scp "${TAR}" "${VM}:/tmp/drishti-harness.tar.gz" --zone="${ZONE}" --project="${PROJECT}" --tunnel-through-iap
retry gcloud compute ssh "${VM}" --zone="${ZONE}" --project="${PROJECT}" --tunnel-through-iap --command='
set -euo pipefail
mkdir -p /opt/drishti/lib /opt/drishti/harness /opt/drishti/bin
rm -rf /opt/drishti/lib/drishti /opt/drishti/lib/scripts /opt/drishti/lib/infra
tar xzf /tmp/drishti-harness.tar.gz -C /opt/drishti/lib
# The harness looks for its hooks at a fixed absolute path (HarnessConfig.hooks).
cp /opt/drishti/lib/drishti/m3_dynamic/scripts/hooks.js /opt/drishti/harness/frida_hooks.js
install -m 755 /opt/drishti/lib/infra/gcp/detonator_run.sh /opt/drishti/bin/detonator_run.sh
install -m 755 /opt/drishti/lib/infra/gcp/detonator_lockdown.sh /opt/drishti/bin/detonator_lockdown.sh
/opt/drishti/venv/bin/python -c "
import sys; sys.path.insert(0, \"/opt/drishti/lib\")
import drishti.m3_dynamic.harness as h, drishti.m3_dynamic.admission as a
print(\"harness\", h.HARNESS_VERSION, \"import OK\")
"
'
echo "deployed harness to ${VM}"

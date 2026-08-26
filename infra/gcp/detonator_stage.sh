#!/usr/bin/env bash
# Stage corpus samples onto the sealed detonator. Laptop-side.
#
#   detonator_stage.sh <file-of-sha256-lines>
#
# Staging needs GCS, and the detonator has no egress once sealed, so this opens the
# window, copies, and closes it again — in that order, with the close in a trap so an
# interrupted run cannot leave the VM reachable.
#
# Opening the window is safe ONLY while nothing is detonating: it refuses to run if a
# detonation holds the lock, and the emulator's guest is snapshot-clean between runs.
# Samples on disk are inert; it is `adb install` that makes them dangerous, and that
# only happens after `verify` re-signs a containment manifest.
set -euo pipefail

VM="${DRISHTI_VM:-m3-detonator}"
ZONE="${DRISHTI_ZONE:-us-east1-c}"
PROJECT="${DRISHTI_PROJECT:-internship-505513}"
CORPUS="${DRISHTI_CORPUS_BUCKET:-gs://cybershield-505518-corpus}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIST="${1:?usage: detonator_stage.sh <file-of-sha256-lines>}"

ssh_vm() { gcloud compute ssh "${VM}" --zone="${ZONE}" --project="${PROJECT}" --tunnel-through-iap --command="$1"; }

retry() {
  local n=0
  until "$@"; do
    n=$((n + 1))
    [[ ${n} -ge 4 ]] && { echo "FAILED after ${n} attempts: $*" >&2; return 1; }
    sleep $((n * 5))
  done
}

# Refuse to open the network while a sample is live.
if ssh_vm 'pgrep -f "venv/bin/pyth""on .*dynamic_analyze" >/dev/null && echo BUSY || echo IDLE' | grep -q BUSY; then
  echo "a detonation is in progress — refusing to open the network" >&2
  exit 1
fi

reseal() {
  echo "--- resealing ---"
  ssh_vm '/opt/drishti/bin/detonator_lockdown.sh lock' || true
  "${HERE}/detonator_seal.sh" seal
}
trap reseal EXIT

echo "--- opening the staging window ---"
"${HERE}/detonator_seal.sh" unseal-rules
"${HERE}/detonator_seal.sh" unseal
ssh_vm '/opt/drishti/bin/detonator_lockdown.sh unlock'

# Copy the sha list to the VM and pull the APKs there. The list is text; the APKs
# never touch the laptop.
retry gcloud compute scp "${LIST}" "${VM}:/tmp/stage_list.txt" --zone="${ZONE}" --project="${PROJECT}"
ssh_vm '
set -euo pipefail
mkdir -p /opt/drishti/scratch && chmod 700 /opt/drishti/scratch
# FD 3: keep the habit even where the loop body is a plain gsutil, so this loop stays
# correct if a stdin-consuming command is ever added to it.
while read -u 3 sha; do
  [ -z "$sha" ] && continue
  dest="/opt/drishti/scratch/$sha.apk"
  [ -f "$dest" ] && continue
  gsutil -q cp "gs://cybershield-505518-corpus/apks/${sha:0:2}/$sha.apk" "$dest" || echo "MISSING $sha"
done 3< /tmp/stage_list.txt
chmod 600 /opt/drishti/scratch/*.apk
ls /opt/drishti/scratch/*.apk | wc -l'

#!/usr/bin/env bash
# Detonation driver. Runs ON THE VM.
#
#   verify              run scripts/verify_containment.py and sign a manifest
#   detonate <sha> [s]  verify, then detonate one sample from scratch
#   batch <list> [s]    verify once, then detonate every sha in <list>
#
# The manifest is short-lived by contract (<=30 min), so `detonate` re-verifies
# every time rather than trusting a manifest signed earlier in the session.
set -euo pipefail

DRISHTI_ROOT=/opt/drishti
SERIAL=emulator-5554
export PATH="/opt/android-sdk/platform-tools:/opt/android-sdk/emulator:${PATH}"
export PYTHONPATH="${DRISHTI_ROOT}/lib"
# require_sealed_runtime() refuses to run without this, plus the RUNTIME_IMAGE marker
# and /dev/kvm. Three independent markers, so a stray copy of the harness on a laptop
# cannot execute a sample.
export DRISHTI_SEALED_RUNTIME=1
export DRISHTI_INSTANCE_ID="${DRISHTI_INSTANCE_ID:-$(cat ${DRISHTI_ROOT}/INSTANCE_ID 2>/dev/null || echo unknown)}"
PY="${DRISHTI_ROOT}/venv/bin/python"

verify() {
  # Root, because _iptables_default_drop() shells out to `iptables -C`, which a
  # non-root process cannot do — and a check that cannot run must not pass.
  sudo -E env \
    PATH="${PATH}" PYTHONPATH="${PYTHONPATH}" \
    DRISHTI_SEALED_RUNTIME=1 DRISHTI_INSTANCE_ID="${DRISHTI_INSTANCE_ID}" \
    "${PY}" "${DRISHTI_ROOT}/lib/scripts/verify_containment.py" \
    --serial "${SERIAL}" --ttl-minutes 30
}

detonate() {
  local sha=$1 duration=${2:-120}
  local apk="${DRISHTI_ROOT}/scratch/${sha}.apk"
  test -f "${apk}" || { echo "sample not staged: ${apk}"; return 3; }
  mkdir -p "${DRISHTI_ROOT}/results"
  # sample-kind=vetted_malware: these are corpus rows with a label and a VT count,
  # not an inert fixture. The value lands in the artifact's provenance metadata.
  sudo -E env \
    PATH="${PATH}" PYTHONPATH="${PYTHONPATH}" \
    DRISHTI_SEALED_RUNTIME=1 DRISHTI_INSTANCE_ID="${DRISHTI_INSTANCE_ID}" \
    "${PY}" "${DRISHTI_ROOT}/lib/scripts/dynamic_analyze.py" "${apk}" \
    --out "${DRISHTI_ROOT}/results/${sha}.json" \
    --duration "${duration}" --sample-kind vetted_malware
}

batch() {
  local list=$1 duration=${2:-120}
  # FD 3, deliberately: dynamic_analyze.py consumes stdin, so a naive
  # `while read sha; do ... done < list` silently stops after the first sample and
  # looks exactly like a data problem.
  while read -u 3 sha; do
    [[ -z "${sha}" || "${sha}" == \#* ]] && continue
    echo "=== ${sha} ==="
    # Re-verify per sample, not once per batch. ContainmentManifest caps its TTL at
    # 30 minutes and the harness re-checks the validity window on every run, so a
    # batch longer than that would start failing admission halfway through — and
    # per-sample verification is the stronger claim anyway: every artifact carries a
    # manifest signed minutes before its own detonation.
    if ! verify; then
      echo "CONTAINMENT VERIFICATION FAILED — aborting batch at ${sha}" >&2
      return 1
    fi
    # A failed sample must not abort the batch; the artifact records the failure.
    detonate "${sha}" "${duration}" || echo "sample ${sha} returned $?"
  done 3< "${list}"
}

case "${1:-verify}" in
  verify) verify ;;
  detonate) shift; verify; detonate "$@" ;;
  batch) shift; batch "$@" ;;
  *) echo "usage: $0 {verify|detonate <sha> [duration]|batch <list> [duration]}"; exit 2 ;;
esac

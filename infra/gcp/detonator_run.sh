#!/usr/bin/env bash
# Detonation driver. Runs ON THE VM.
#
#   verify              run scripts/verify_containment.py and sign a manifest
#   detonate <sha> [s]  verify, then detonate one sample from scratch
#   batch <list> [s]    verify once, then detonate every sha in <list>
#   morph <sha> <kinds> [s]
#                       pass 2 of the adversarial loop: verify, then detonate the same
#                       sample with the named morph scripts loaded ahead of the hooks.
#                       <kinds> is a comma-separated list of morph kinds, each of which
#                       must exist as /opt/drishti/lib/drishti/m3_dynamic/scripts/morph/
#                       <kind>.js. The result lands at results/<sha>.morph.json so the
#                       pass-1 artifact is never overwritten — the before/after pair is
#                       the artefact, and a pass 2 that clobbers pass 1 destroys it.
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

# ── The emulator console auth token, and why HOME is pinned here ──────────────
#
# MEASURED, 2026-08-26: a batch launched as `sudo detonator_run.sh batch …` failed
# ten samples in a row with `snapshot_restore_failed`, message
# "KO: bad sub-command". Nothing was wrong with the snapshot — `snapshot list` showed
# `clean` present and healthy the whole time.
#
# The emulator console gates its command set on `$HOME/.emulator_console_auth_token`,
# which exists only in the home of the user that started the emulator. An outer `sudo`
# sets HOME=/root; the inner `sudo -E` then faithfully preserves HOME=/root, root has
# no token, and the console silently degrades to the two commands it offers an
# unauthenticated client — so `avd snapshot load` comes back "bad sub-command" rather
# than "unauthenticated". It reads as a corrupt AVD and it is a permissions problem.
#
# So: derive HOME from the process that actually owns the emulator, and pass it
# explicitly into every privileged call. That makes the driver correct whether it is
# invoked as the operator or under sudo.
EMU_USER="$(ps -o user= -p "$(pgrep -f 'qemu-system-x86_64' | head -1)" 2>/dev/null | tr -d ' ')"
EMU_HOME="$(getent passwd "${EMU_USER:-nobody}" | cut -d: -f6)"
if [[ -z "${EMU_HOME}" || ! -r "${EMU_HOME}/.emulator_console_auth_token" ]]; then
  echo "cannot read the emulator console auth token (emulator user='${EMU_USER}')." >&2
  echo "snapshot restore would fail as 'KO: bad sub-command' — refusing to start." >&2
  exit 6
fi

# Every privileged call goes through this, so HOME can never be forgotten on one of them.
as_root() {
  sudo -E env \
    HOME="${EMU_HOME}" ANDROID_EMULATOR_HOME="${EMU_HOME}/.android" \
    PATH="${PATH}" PYTHONPATH="${PYTHONPATH}" \
    DRISHTI_SEALED_RUNTIME=1 DRISHTI_INSTANCE_ID="${DRISHTI_INSTANCE_ID}" \
    "$@"
}

verify() {
  # Root, because _iptables_default_drop() shells out to `iptables -C`, which a
  # non-root process cannot do — and a check that cannot run must not pass.
  as_root "${PY}" "${DRISHTI_ROOT}/lib/scripts/verify_containment.py" \
    --serial "${SERIAL}" --ttl-minutes 30
}

detonate() {
  local sha=$1 duration=${2:-120}
  local apk="${DRISHTI_ROOT}/scratch/${sha}.apk"
  test -f "${apk}" || { echo "sample not staged: ${apk}"; return 3; }
  mkdir -p "${DRISHTI_ROOT}/results"
  # sample-kind=vetted_malware: these are corpus rows with a label and a VT count,
  # not an inert fixture. The value lands in the artifact's provenance metadata.
  as_root "${PY}" "${DRISHTI_ROOT}/lib/scripts/dynamic_analyze.py" "${apk}" \
    --out "${DRISHTI_ROOT}/results/${sha}.json" \
    --duration "${duration}" --sample-kind vetted_malware
}

morph() {
  local sha=$1 kinds=$2 duration=${3:-120}
  local apk="${DRISHTI_ROOT}/scratch/${sha}.apk"
  local morphdir="${DRISHTI_ROOT}/lib/drishti/m3_dynamic/scripts/morph"
  test -f "${apk}" || { echo "sample not staged: ${apk}"; return 3; }
  test -f "${DRISHTI_ROOT}/results/${sha}.json" || {
    echo "no pass-1 artifact for ${sha}: run \`detonate\` first, because the loop's"
    echo "claim is a difference and there is nothing to difference against"
    return 4
  }
  local args=()
  local IFS=,
  for kind in ${kinds}; do
    unset IFS
    # Refuse a kind with no script rather than silently running an unmorphed pass 2 and
    # reporting it as morphed. A pass 2 that applied nothing is not a negative result.
    test -f "${morphdir}/${kind}.js" || { echo "no morph script for kind: ${kind}"; return 5; }
    args+=(--morph-script "${morphdir}/${kind}.js" --morph-label "${kind}")
  done
  unset IFS
  mkdir -p "${DRISHTI_ROOT}/results"
  as_root "${PY}" "${DRISHTI_ROOT}/lib/scripts/dynamic_analyze.py" "${apk}" \
    --out "${DRISHTI_ROOT}/results/${sha}.morph.json" \
    --duration "${duration}" --sample-kind vetted_malware \
    --pass-num 2 "${args[@]}"
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
  morph) shift; verify; morph "$@" ;;
  batch) shift; batch "$@" ;;
  *)
    echo "usage: $0 {verify|detonate <sha> [duration]|morph <sha> <kinds> [duration]|batch <list> [duration]}"
    exit 2
    ;;
esac

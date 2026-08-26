#!/usr/bin/env bash
# The consumer-facing beat: the breathing interstitial, then the warning a *person*
# sees. One command, one screen, no browser.
#
#   scripts/demo_consumer.sh                 # BLOCK   — the impersonation warning
#   scripts/demo_consumer.sh --review        # REVIEW  — softer, no hard block
#   scripts/demo_consumer.sh --monitor       # MONITOR — informational
#   scripts/demo_consumer.sh --verdict FILE  # push your own contract-A15 verdict JSON
#   scripts/demo_consumer.sh --live JOB_ID   # the real verdict for a real job
#   scripts/demo_consumer.sh --clear         # remove a pushed verdict
#   scripts/demo_consumer.sh --tap-on        # a TAP on an APK lands here, not on the
#   scripts/demo_consumer.sh --tap-off       #   analyst screen (off by default)
#
# WHAT IT SHOWS
#   1. The DRISHTI mark, breathing, on near-black, and one line: "Analysing… please
#      wait a moment. This is for your safety." Held for at least
#      ConsumerVerdictActivity.MIN_INTERSTITIAL_MS (3.4 s) so the answer never
#      arrives before the screen has finished drawing.
#   2. The verdict, painted entirely from `recommended_action` in the Verdict object
#      (contract A15, drishti/contracts/verdict.py). BLOCK is red and names the
#      impersonated brand. REVIEW is amber. MONITOR is quiet.
#
# HOW THE VERDICT IS CHOSEN, in the app's own order:
#   backend `/api/jobs/{id}/verdict`  →  the pushed file  →  the bundled fixture.
# Anything that is not the backend is labelled "REHEARSAL FIXTURE" on screen, by the
# app, automatically. That line is not a flag anyone can forget to set.
#
# SAFETY: this script installs nothing and touches no sample. It starts one activity
# and, with --verdict, pushes one JSON file.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="${DRISHTI_TOOLS:-$HOME/drishti-tools}"
ANDROID_HOME="${ANDROID_HOME:-$TOOLS/android-sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"

PKG="in.drishti.shield"
ACTIVITY="$PKG/.ui.ConsumerVerdictActivity"
# Must match ConsumerVerdictSource.OVERRIDE_PATH.
OVERRIDE="/sdcard/DrishtiStaging/verdict.json"
# Must match Config.CONSUMER_TAP_MARKER.
TAP_MARKER="/sdcard/DrishtiStaging/consumer_tap.on"

FIXTURE="block"
VERDICT_FILE=""
JOB_ID=""
CLEAR=0
TAP=""
while (( $# )); do
  case "$1" in
    --tap-on) TAP="on" ;;
    --tap-off) TAP="off" ;;
    --block) FIXTURE="block" ;;
    --review) FIXTURE="review" ;;
    --monitor) FIXTURE="monitor" ;;
    --verdict) VERDICT_FILE="${2:?--verdict needs a path}"; shift ;;
    --live) JOB_ID="${2:?--live needs a job id}"; shift ;;
    --clear) CLEAR=1 ;;
    -h|--help) sed -n "2,28p" "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

ok()   { printf '    \033[32m✓\033[0m %s\n' "$*"; }
step() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
die()  { printf '\n\033[1;31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

[[ -x "$ADB" ]] || die "adb not found at $ADB"
"$ADB" get-state >/dev/null 2>&1 || die "no device — run scripts/demo_up.sh first"
"$ADB" shell pm path "$PKG" >/dev/null 2>&1 || die "$PKG is not installed — run scripts/demo_up.sh"

if [[ -n "$TAP" ]]; then
  if [[ "$TAP" == "on" ]]; then
    "$ADB" shell mkdir -p "$(dirname "$TAP_MARKER")" >/dev/null 2>&1 || true
    "$ADB" shell touch "$TAP_MARKER" >/dev/null
    ok "a tap on an APK now opens the consumer screen"
    printf '      Note: until the backend exposes /api/jobs/{id}/verdict, a tapped\n'
    printf '      file with no A15 verdict lands on the "we could not check this app"\n'
    printf '      state. That is deliberate — a rehearsal fixture must never stand in\n'
    printf '      for a real file. Use --tap-off to restore the analyst screen.\n'
  else
    "$ADB" shell rm -f "$TAP_MARKER" >/dev/null 2>&1 || true
    ok "a tap on an APK opens the analyst verdict screen again"
  fi
  exit 0
fi

if (( CLEAR )); then
  "$ADB" shell rm -f "$OVERRIDE" >/dev/null 2>&1 || true
  ok "pushed verdict removed; the app falls back to its bundled fixtures"
  exit 0
fi

# A pushed verdict must be a real A15 Verdict before it reaches the stage. The
# contract validates it here rather than the screen discovering a bad field live.
if [[ -n "$VERDICT_FILE" ]]; then
  [[ -f "$VERDICT_FILE" ]] || die "no such file: $VERDICT_FILE"
  step "validating $VERDICT_FILE against contract A15"
  "$REPO/.venv/bin/python" - "$VERDICT_FILE" <<'PY' || die "that file is not a valid Verdict"
import sys
from drishti.contracts.verdict import Verdict
Verdict.model_validate_json(open(sys.argv[1]).read())
print("    ok — parses as drishti.contracts.verdict.Verdict")
PY
  "$ADB" shell mkdir -p "$(dirname "$OVERRIDE")" >/dev/null 2>&1 || true
  "$ADB" push "$VERDICT_FILE" "$OVERRIDE" >/dev/null
  ok "pushed to $OVERRIDE — the app will prefer it over its bundled fixture"
fi

step "showing the consumer screen"
# force-stop first: the activity is singleTask, and resuming an instance that has
# already settled would skip the interstitial the beat is built around.
"$ADB" shell am force-stop "$PKG" >/dev/null 2>&1 || true
"$ADB" logcat -c >/dev/null 2>&1 || true

ARGS=(--es fixture "$FIXTURE")
[[ -n "$JOB_ID" ]] && ARGS+=(--es job_id "$JOB_ID")
# -f 0x10008000 is NEW_TASK|CLEAR_TASK. force-stop kills the process but NOT the task
# record, and a plain `am start` against a surviving singleTask record reports "intent
# has been delivered to currently running top-most instance" and shows the previous
# screen. Same trick, same reason, as scripts/demo_up.sh.
"$ADB" shell am start -n "$ACTIVITY" -f 0x10008000 "${ARGS[@]}" >/dev/null

ok "interstitial up — it holds for ~3.4 s, then the verdict lands"
if [[ -n "$JOB_ID" ]]; then
  ok "asking the backend for job $JOB_ID; falls back to the '$FIXTURE' fixture if it has no verdict yet"
else
  ok "fixture: $FIXTURE"
fi

# Report the measured hold rather than the configured one, so the number anyone
# quotes on stage came from this run.
sleep 6
"$ADB" logcat -d -s DrishtiShield 2>/dev/null | grep -o 'consumer_screen settled after .*' | tail -1 || true

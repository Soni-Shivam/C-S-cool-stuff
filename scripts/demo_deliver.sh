#!/usr/bin/env bash
# The sender side of the demo theatre: deliver "RTO_Challan.apk" the way a real
# WhatsApp forward would.
#
#   scripts/demo_deliver.sh                 # notification, pause, then the file lands
#   scripts/demo_deliver.sh --no-notify     # just the file (for timing runs)
#   scripts/demo_deliver.sh --instant       # no dramatic pause
#
# Why a scripted notification and not a mock WhatsApp app: `cmd notification post`
# renders a real system notification from a real package, which is exactly what the
# audience needs to see, and it cannot crash mid-demo the way a second hand-written
# app can. The one thing a mock app would add — a chat UI — is not on screen during
# this beat anyway, because the whole point is that DRISHTI interrupts before the
# user goes looking.
#
# The file delivered is ALWAYS the inert decoy staged by demo_up.sh. This script
# cannot deliver anything else: it copies from the staging path on the device and
# refuses if the hash does not match the decoy built from this repo.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="${DRISHTI_TOOLS:-$HOME/drishti-tools}"
ANDROID_HOME="${ANDROID_HOME:-$TOOLS/android-sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"

STAGING="/sdcard/DrishtiStaging/RTO_Challan.apk"
TARGET="/sdcard/Download/RTO_Challan.apk"
DECOY_APK="$REPO/canary/decoy-challan/dist/RTO_Challan.apk"

NOTIFY=1
PAUSE=3
for arg in "$@"; do
  case "$arg" in
    --no-notify) NOTIFY=0 ;;
    --instant) PAUSE=0 ;;
    -h|--help) sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

die() { printf '\033[1;31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

"$ADB" get-state >/dev/null 2>&1 || die "no emulator. Run scripts/demo_up.sh first."
"$ADB" shell "[ -f $STAGING ]" 2>/dev/null || die "decoy not staged. Run scripts/demo_up.sh first."

# Refuse to deliver anything that is not the decoy this repo builds. This is the one
# guard that makes the script safe to run without reading it: whatever is at the
# staging path, if it is not our inert APK, nothing happens.
staged=$("$ADB" shell sha256sum "$STAGING" | awk '{print $1}' | tr -d '\r')
expected=$(sha256sum "$DECOY_APK" | awk '{print $1}')
[[ "$staged" == "$expected" ]] || die "staged file is not the repo's inert decoy (got ${staged:0:16}…, expected ${expected:0:16}…)"

# Clear any previous delivery so Layer 1 sees a genuinely new file.
"$ADB" shell "rm -f $TARGET" >/dev/null 2>&1 || true
sleep 1

if (( NOTIFY )); then
  printf '\033[1;36m==> Incoming message\033[0m\n'
  # A real system notification, posted under a tag we can cancel afterwards.
  #
  # The whole command goes as ONE string, single-quoted for the *device's* shell.
  # `adb shell a b c` joins its arguments and re-parses them with the device's sh, so
  # local quoting buys nothing: the first version of this used a title of
  # "Traffic Police (+91 98XXX XXXXX)" and the parentheses reached the device
  # unquoted, producing `sh: syntax error: unexpected '('` and no notification. Keep
  # the strings free of single quotes for the same reason.
  if ! "$ADB" shell "cmd notification post -S bigtext -t 'Traffic Police +91 98XXX XXXXX' drishti_demo_forward 'Your vehicle has a pending e-challan of Rs 1,500. Download the RTO app and pay before 6 PM to avoid court summons. RTO_Challan.apk'" >/dev/null 2>&1; then
    echo '    (could not post the notification on this image — continuing without it)'
  fi
  sleep "$PAUSE"
fi

printf '\033[1;36m==> Delivering RTO_Challan.apk to /sdcard/Download\033[0m\n'
landed_at=$(date +%s%3N)
# `cp` on-device rather than `adb push`: a push writes through adb's own file-sync
# service, while a copy is an ordinary write by an ordinary process — closer to what
# a messaging app actually does, and it exercises the same inotify path.
"$ADB" shell "cp $STAGING $TARGET"

printf '    file landed at %s (epoch ms)\n' "$landed_at"
printf '    watch the phone. The verdict screen should appear by itself.\n\n'

# Report the real measured latency once the verdict lands, read from Shield's own
# structured log rather than from a stopwatch.
deadline=$(( SECONDS + 90 ))
while (( SECONDS < deadline )); do
  line=$("$ADB" logcat -d -t 200 2>/dev/null | grep 'DrishtiShield: verdict scan=' | tail -1 || true)
  if [[ -n "$line" ]]; then
    printf '\033[1;32m%s\033[0m\n\n' "${line#*DrishtiShield: }"
    exit 0
  fi
  sleep 1
done
echo 'No verdict line in logcat within 90s. Check: adb logcat | grep DrishtiShield' >&2
exit 1

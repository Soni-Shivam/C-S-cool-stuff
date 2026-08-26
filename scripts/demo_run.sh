#!/usr/bin/env bash
# The whole judge-facing sequence, in one command, with nobody typing on stage.
#
#   scripts/demo_run.sh              # the full sequence with narration pauses
#   scripts/demo_run.sh --fast       # no pauses (rehearsal / timing runs)
#   scripts/demo_run.sh --benign     # only beat 1 — the app that is cleared
#   scripts/demo_run.sh --blocked    # only beat 2 — the app that is stopped
#   scripts/demo_run.sh --no-install # skip the install-attempt beats
#
# It runs `scripts/demo_up.sh` first if anything is missing, so this is the only
# command an operator needs.
#
# WHY BOTH APPS, AND WHY IN THIS ORDER.
#
# The first question a room asks a malware detector is "does it just flag
# everything?", and a demo that only shows a block cannot answer it. So beat 1 is the
# app that is *cleared* — and it is not a trivially clean app. Sanchay Expenses holds
# READ_SMS, RECEIVE_SMS, READ_CONTACTS, SYSTEM_ALERT_WINDOW and QUERY_ALL_PACKAGES:
# the identical dual-use permission set the RTO Challan decoy holds. The `lookalike`
# card on the phone prints that intersection for both apps.
#
# Benign first is also the only order that works mechanically. The Layer 3 veto is a
# device-wide `DISALLOW_INSTALL_UNKNOWN_SOURCES` restriction, so once beat 2 engages
# it, *nothing* installs from unknown sources — including the benign app. Running the
# cleared beat second would show it being blocked by the previous verdict, which
# would be both confusing and, as a claim about the benign app, false.
#
# SAFETY: the only APKs that ever reach the device are the two inert ones this repo
# builds, both gated by their own verify_inert.sh. See CLAUDE.md.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="${DRISHTI_TOOLS:-$HOME/drishti-tools}"
ANDROID_HOME="${ANDROID_HOME:-$TOOLS/android-sdk}"
ADB="$ANDROID_HOME/platform-tools/adb"
STATE="${DRISHTI_DEMO_STATE:-$REPO/.demo}"

SHIELD_PKG="in.drishti.shield"
DECOY_PKG="com.rto.echallan.verify"
BENIGN_PKG="in.co.sanchay.expenses"
BENIGN_APK="$REPO/canary/benign-sanchay/dist/Sanchay_Expenses.apk"
DECOY_APK="$REPO/canary/decoy-challan/dist/RTO_Challan.apk"
WATCH_DIR="/sdcard/Download"
INSTALLER_INTENT="android.intent.action.VIEW"
APK_MIME="application/vnd.android.package-archive"

PAUSE_LONG=6
PAUSE_SHORT=3
RUN_BENIGN=1
RUN_BLOCKED=1
DO_INSTALL=1
for arg in "$@"; do
  case "$arg" in
    --fast) PAUSE_LONG=0; PAUSE_SHORT=0 ;;
    --benign) RUN_BLOCKED=0 ;;
    --blocked) RUN_BENIGN=0 ;;
    --no-install) DO_INSTALL=0 ;;
    -h|--help) sed -n '2,10p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

# ─── output helpers ──────────────────────────────────────────────────────────
beat()  { printf '\n\033[1;35m╭─ %s\033[0m\n' "$*"; }
say()   { printf '\033[0;37m│  %s\033[0m\n' "$*"; }
ok()    { printf '\033[32m│  ✓\033[0m %s\n' "$*"; }
bad()   { printf '\033[1;31m│  ✗\033[0m %s\n' "$*"; }
note()  { printf '\033[0;36m│  %s\033[0m\n' "$*"; }
die()   { printf '\n\033[1;31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }
hold()  { (( $1 > 0 )) && sleep "$1" || true; }
adbsh() { timeout 30 "$ADB" shell "$@" 2>/dev/null | tr -d '\r'; }

# Is the Layer 3 veto in force right now?
#
# Read from the "Device policy restrictions" block for the user, NOT from a bare grep
# over `dumpsys user`. The dump also contains a "Guest restrictions" list and a
# per-user `mDefaultRestrictions` list, both of which name `no_install_unknown_sources`
# unconditionally on every Android image — so the obvious `grep -c` returns 2 on a
# device with no policy at all, and the first version of this script therefore
# reported the veto as engaged immediately after releasing it.
veto_engaged() {
  adbsh dumpsys user \
    | awk '/^    Device policy restrictions:/{f=1;next} /^    [A-Za-z]/{f=0} f' \
    | grep -q 'no_install_unknown_sources'
}

# ─── 0. make sure the stack is up ────────────────────────────────────────────
beat "Preflight"
need_up=0
"$ADB" get-state 2>/dev/null | grep -q device || need_up=1
curl -fsS --max-time 2 http://127.0.0.1:8080/api/health >/dev/null 2>&1 || need_up=1
curl -fsS --max-time 2 http://127.0.0.1:4173/ >/dev/null 2>&1 || need_up=1
adbsh pm list packages | grep -q "$SHIELD_PKG" || need_up=1
if (( need_up )); then
  say "something is not up — running scripts/demo_up.sh (idempotent)"
  bash "$REPO/scripts/demo_up.sh"
fi
ok "API, dashboard, emulator and Shield are up"

owner=$(adbsh dpm list-owners | grep -c "$SHIELD_PKG" || true)
if [[ "${owner:-0}" -gt 0 ]]; then
  ok "Layer 3 device owner HELD — the veto beat is real"
else
  bad "Layer 3 device owner NOT held. The block will be advisory only."
  bad "Fix with: scripts/demo_up.sh --fresh"
fi

# ─── 1. reset to the demo's starting state ───────────────────────────────────
# Everything below has to be true whether this is the first run of the day or the
# fifth. A rerunnable demo is the difference between one nervous take and rehearsing
# until it is boring.
beat "Reset to the starting state"
# The veto has to come off first: while it is engaged nothing installs, and the
# benign beat's whole point is that its install proceeds. Guarded on FLAG_DEBUGGABLE
# inside the app — see MainActivity.handleDemoReset.
adbsh "am start -n $SHIELD_PKG/.ui.MainActivity --ez drishti_demo_reset true" >/dev/null || true
sleep 2
for pkg in "$DECOY_PKG" "$BENIGN_PKG"; do
  if adbsh pm list packages | grep -q "$pkg"; then
    adbsh pm unsuspend "$pkg" >/dev/null || true
    timeout 60 "$ADB" uninstall "$pkg" >/dev/null 2>&1 || true
  fi
done
adbsh "rm -f $WATCH_DIR/*.apk" >/dev/null || true
adbsh "cmd notification post -S bigtext -t x drishti_demo_forward y" >/dev/null 2>&1 || true
adbsh "service call notification 1" >/dev/null 2>&1 || true
"$ADB" logcat -c >/dev/null 2>&1 || true

if veto_engaged; then
  bad "the veto is still engaged after the reset — beat 1's install will be refused."
  bad "Open DRISHTI Shield on the phone and tap 'Reset demo state', then re-run."
else
  ok "veto released, both demo packages absent, $WATCH_DIR clear"
fi
hold "$PAUSE_SHORT"

# ─── shared: one delivery beat ───────────────────────────────────────────────
# Reads the verdict back out of Shield's own structured log rather than a stopwatch,
# and keys on the scan id (derived from the sha256) so a leftover line from the
# previous beat can never be reported as this one's.
run_beat() {
  local flavour="$1" apk="$2" expect_block="$3"
  local sha scan_id line
  sha=$(sha256sum "$apk" | awk '{print $1}')
  scan_id="scan_${sha:0:12}"

  bash "$REPO/scripts/demo_deliver.sh" $flavour || die "delivery failed"

  line=$("$ADB" logcat -d -t 600 2>/dev/null | grep "verdict scan=$scan_id" | tail -1 || true)
  [[ -n "$line" ]] || die "no verdict line for $scan_id"
  local blocked veto elapsed basis
  blocked=$(sed -n 's/.*block=\([a-z]*\).*/\1/p' <<<"$line")
  veto=$(sed -n 's/.*veto=\([a-z]*\).*/\1/p' <<<"$line")
  basis=$(sed -n 's/.*basis=\([A-Z_]*\).*/\1/p' <<<"$line")
  elapsed=$(sed -n 's/.*elapsed_ms=\([0-9]*\).*/\1/p' <<<"$line")

  note "verdict in ${elapsed} ms · block=$blocked · basis=$basis · veto=$veto"
  if [[ "$blocked" == "$expect_block" ]]; then
    ok "as expected for the $flavour beat"
  else
    bad "UNEXPECTED: expected block=$expect_block, got block=$blocked"
    bad "The demo is still safe to narrate — the phone shows what it actually decided."
  fi
  LAST_ELAPSED_MS="$elapsed"
}

# What the OS's package installer does when the user goes to install the file.
#
# The component is named explicitly rather than left to intent resolution. A bare
# `am start -a VIEW -t <apk mime>` also matches DRISHTI Shield's own Layer 2 filter,
# so the resolver either picks Shield or raises a chooser — and the beat then proves
# nothing about the OS, because our app answered instead of Android's. Naming
# `InstallStart` routes straight to the package installer, which is the stricter test:
# it is what happens when the user bypasses us entirely.
#
# The verdict is read from `topResumedActivity`, not from a grep over the whole
# activity dump. The dump retains finished records, so a plain grep matched an
# ActionDisabledByAdminDialog from a *previous* attempt and would have reported a
# block that had not happened on this run.
install_attempt() {
  local apk_name="$1"
  adbsh "am start -a $INSTALLER_INTENT -t $APK_MIME -d file://$WATCH_DIR/$apk_name \
    -n com.google.android.packageinstaller/com.android.packageinstaller.InstallStart" \
    >/dev/null 2>&1 || true
  sleep 3
  adbsh dumpsys activity activities | grep -m1 topResumedActivity || true
}

# Dismiss whatever the attempt above left on screen, so the next beat starts clean.
dismiss_installer() {
  adbsh input keyevent KEYCODE_BACK >/dev/null 2>&1 || true
  sleep 1
}

# ─── 2. BEAT ONE — the app that is cleared ───────────────────────────────────
if (( RUN_BENIGN )); then
  beat "BEAT 1 — a normal app arrives"
  say "Sanchay Expenses: an SMS-driven expense tracker."
  say "It declares READ_SMS, RECEIVE_SMS, READ_CONTACTS, SYSTEM_ALERT_WINDOW and"
  say "QUERY_ALL_PACKAGES — the same dual-use set the fraud APK holds, and the same"
  say "set Truecaller holds. Watch what DRISHTI does with it."
  hold "$PAUSE_SHORT"
  run_beat "--benign" "$BENIGN_APK" "false"

  if (( DO_INSTALL )); then
    hold "$PAUSE_SHORT"
    beat "BEAT 1b — the install proceeds"
    top=$(install_attempt "Sanchay_Expenses.apk" || true)
    if grep -q 'ActionDisabledByAdminDialog' <<<"$top"; then
      bad "the OS refused this install — the veto was still engaged. See the reset above."
    else
      ok "Android shows its ordinary install prompt, not a block:"
      printf '│    %s\n' "$(sed 's/.*topResumedActivity=ActivityRecord{[^ ]* [^ ]* //;s/ t[0-9]*}//' <<<"$top")"
      ok "no veto, no interference — DRISHTI did not stand in the way"
    fi
    dismiss_installer
    # Complete the install through adb rather than driving the installer's UI with
    # synthetic taps. `input tap` at fixed coordinates is the single most brittle
    # thing that can be put in a stage script, and what the beat is actually proving —
    # that DRISHTI did not stand in the way — is already proved by the line above.
    timeout 120 "$ADB" install -r -g "$BENIGN_APK" >/dev/null 2>&1 \
      && ok "installed: $BENIGN_PKG" \
      || bad "install failed — check: adb install -r $BENIGN_APK"
    adbsh "am start -n $BENIGN_PKG/.MainActivity" >/dev/null 2>&1 || true
    sleep 2
    # Layer 4 is armed and saw PACKAGE_ADDED for this install. Asserting that it did
    # NOT quarantine is worth a line: the failsafe firing on the cleared app would be
    # a false positive the audience would see before we did.
    if adbsh "pm dump $BENIGN_PKG | grep -q suspended=true"; then
      bad "Layer 4 quarantined the cleared app. That is a false positive — do not narrate it as intended."
    else
      ok "the app is on the device and running. Layer 4 did not quarantine it."
    fi
  fi
  hold "$PAUSE_LONG"
fi

# ─── 3. BEAT TWO — the app that is stopped ───────────────────────────────────
if (( RUN_BLOCKED )); then
  beat "BEAT 2 — the forward that is not what it says it is"
  say "Same phone, same watcher, same backend. A traffic-challan lure this time."
  hold "$PAUSE_SHORT"
  run_beat "" "$DECOY_APK" "true"

  if (( DO_INSTALL )); then
    hold "$PAUSE_SHORT"
    beat "BEAT 2b — now try to install it anyway"
    top=$(install_attempt "RTO_Challan.apk" || true)
    if grep -q 'ActionDisabledByAdminDialog' <<<"$top"; then
      ok "Android's own 'Blocked by your admin' screen is what is on top:"
      printf '│    %s\n' "$(sed 's/.*topResumedActivity=ActivityRecord{[^ ]* [^ ]* //;s/ t[0-9]*}//' <<<"$top")"
      ok "That is com.android.settings, not DRISHTI. There is no 'install anyway'"
      ok "button, because there is no button to add."
    else
      bad "expected ActionDisabledByAdminDialog, got: ${top:-nothing on top}"
      bad "Layer 3 may not be held. Everything else in this demo still stands."
    fi
    echo
    printf '\033[1;37m│  adb shell dumpsys user | grep -A3 "Device policy restrictions"\033[0m\n'
    adbsh dumpsys user | grep -A3 'Device policy restrictions' | sed 's/^/│    /' || true
    echo
    printf '\033[1;37m│  adb shell pm list packages | grep -E "echallan|sanchay"\033[0m\n'
    adbsh pm list packages | grep -E 'echallan|sanchay' | sed 's/^/│    /' \
      || printf '│    (neither demo package is installed)\n'
  fi
fi

# ─── 4. the two verdicts, side by side ───────────────────────────────────────
beat "The two verdicts"
printf '│\n'
printf '│  %-34s %-22s %s\n' "" "Sanchay Expenses" "RTO Challan"
printf '│  %-34s %-22s %s\n' "shared dual-use permissions" "5" "5 (identical set)"
printf '│  %-34s %-22s %s\n' "permission-combo rules matched" "1 high" "1 critical + 4 high"
printf '│  %-34s %-22s %s\n' "Shield decision" "CLEAR — installed" "BLOCKED — OS refused"
printf '│\n'
say "The permission set is the same. The verdicts are not."
say "That difference is on the phone's own screen, on the lookalike card."
echo
note "Dashboard: http://127.0.0.1:4173/    Teardown: scripts/demo_down.sh"
echo

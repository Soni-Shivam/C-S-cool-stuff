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
# -f 0x10008000 = FLAG_ACTIVITY_NEW_TASK | FLAG_ACTIVITY_CLEAR_TASK. Without it, when
# MainActivity's task is already in front `am start` answers "its current task has been
# brought to the front" and NEVER DELIVERS THE EXTRA — the reset silently does nothing
# and the next run starts pre-blocked. See the same note in demo_up.sh §7b.
"$ADB" logcat -c >/dev/null 2>&1 || true
adbsh "am start -n $SHIELD_PKG/.ui.MainActivity -f 0x10008000 --ez drishti_demo_reset true" >/dev/null || true

# WAIT FOR THE RESET TO FINISH, do not sleep at it. handleDemoReset lifts every Layer 4
# quarantine, and releaseAllQuarantines makes one binder call per installed package —
# well over a hundred on a Google-APIs image. A flat `sleep 2` raced it, so the
# uninstalls below ran while the decoy was still uninstall-blocked, failed with
# DELETE_FAILED_OWNER_BLOCKED into `|| true`, and the run continued with the blocked
# app still on the device. Keying on the app's own completion line removes the race.
reset_deadline=$(( SECONDS + 30 ))
while (( SECONDS < reset_deadline )); do
  # An `if`, not `… && break`: under `set -e` a bare AND-list whose left side fails —
  # which is every poll before the line lands — aborts the whole script.
  if "$ADB" logcat -d -s DrishtiShield:I 2>/dev/null | grep -q 'DrishtiShield: demo_reset'; then
    break
  fi
  sleep 1
done

leftover=""
for pkg in "$DECOY_PKG" "$BENIGN_PKG"; do
  if adbsh pm list packages | grep -q "$pkg"; then
    adbsh pm unsuspend "$pkg" >/dev/null || true
    timeout 60 "$ADB" uninstall "$pkg" >/dev/null 2>&1 || true
  fi
  # Re-read rather than trust the uninstall's exit status: `adb uninstall` on a
  # device-owner-blocked package prints Failure and this loop used to swallow it.
  # Written as an `if`, not `grep -q … && leftover+=…`: under `set -e` that AND-list
  # returns non-zero in the ordinary case (package absent) and aborts the script.
  if adbsh pm list packages | grep -q "$pkg"; then
    leftover+=" $pkg"
  fi
done
adbsh "rm -f $WATCH_DIR/*.apk" >/dev/null || true
adbsh "cmd notification post -S bigtext -t x drishti_demo_forward y" >/dev/null 2>&1 || true
adbsh "service call notification 1" >/dev/null 2>&1 || true
"$ADB" logcat -c >/dev/null 2>&1 || true

if veto_engaged; then
  bad "the veto is still engaged after the reset — beat 1's install will be refused."
  bad "Open DRISHTI Shield on the phone and tap 'Reset demo state', then re-run."
elif [[ -n "$leftover" ]]; then
  # Loud, because the closing `pm list packages` will show it and a judge reading that
  # line sees the app we just said was blocked sitting on the device.
  bad "still installed after the reset:$leftover"
  bad "Beat 1's install is a no-op for anything listed, and the closing package list"
  bad "will show it. Recover with: scripts/demo_up.sh --fresh"
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

  line=$("$ADB" logcat -d -s DrishtiShield:I 2>/dev/null | grep "verdict scan=$scan_id" | tail -1 || true)
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
  # Shield's own verdict screen is very likely to be on top from the delivery beat that
  # just ran, and it will still be on top if the installer never starts. Push it out of
  # the way first so `topResumedActivity` afterwards means something.
  adbsh input keyevent KEYCODE_HOME >/dev/null 2>&1 || true
  sleep 1
  adbsh "am start -a $INSTALLER_INTENT -t $APK_MIME -d file://$WATCH_DIR/$apk_name \
    -n com.google.android.packageinstaller/com.android.packageinstaller.InstallStart" \
    >/dev/null 2>&1 || true

  # POLL, do not sample once. VerdictActivity is `singleTask` with `turnScreenOn`, and
  # it can come back to the front a second or two after the verdict lands — which is
  # exactly when a single `sleep 3` then reads it and reports that the admin dialog
  # never appeared. Return the moment the dialog is seen; otherwise return whatever was
  # on top at the end, so the caller can say what it actually found.
  local top="" deadline=$(( SECONDS + 12 ))
  while (( SECONDS < deadline )); do
    top=$(adbsh dumpsys activity activities | grep -m1 topResumedActivity || true)
    if grep -q 'ActionDisabledByAdminDialog' <<<"$top"; then break; fi
    sleep 1
  done
  printf '%s\n' "$top"
}

# What a victim actually does: tap the APK. This is the LAYER 2 route — no component
# named, so the intent resolves the way it would from a file manager or a chat app,
# and DRISHTI Shield's TapInterceptActivity is what answers. Used for the cleared beat,
# where the OS installer is not a usable probe (see below).
tap_attempt() {
  local apk_name="$1"
  adbsh input keyevent KEYCODE_HOME >/dev/null 2>&1 || true
  sleep 1
  adbsh "am start -a $INSTALLER_INTENT -t $APK_MIME -d file://$WATCH_DIR/$apk_name" >/dev/null 2>&1 || true
  sleep 3
  adbsh dumpsys activity activities | grep -m1 topResumedActivity || true
}

# Strip dumpsys's ActivityRecord noise down to just package/activity.
top_component() {
  sed 's/.*topResumedActivity=ActivityRecord{[^ ]* [^ ]* //;s/ t[0-9]*}//' <<<"$1"
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
    # The claim being proved here is "the OS is not standing in the way", and the
    # evidence for it is the ABSENCE of a device-policy restriction — read out of
    # dumpsys, in the same command that beat 2b uses to show the restriction present.
    # Two readings of one dial, which is what makes the pair legible.
    #
    # NOT proved by driving the package installer: with nothing to block,
    # `InstallStart` finishes silently on a file:// URI and never comes to the front,
    # so an earlier version of this beat printed a green "Android shows its ordinary
    # install prompt" while Shield's own screen sat on top. A check that passes when
    # the thing it checks never ran narrates a fiction on stage.
    if veto_engaged; then
      bad "a device-policy restriction IS in force — the veto was not released. See the reset above."
    else
      ok "no device-policy restriction is in force:"
      adbsh dumpsys user | grep -A2 'Device policy restrictions' | sed 's/^/│    /' || true
      ok "no veto, no interference — DRISHTI did not stand in the way"
    fi

    # And the tap route: the same gesture the victim makes on the fraud APK. Here it
    # opens Shield's verdict screen in its CLEAR state — green, install permitted.
    top=$(tap_attempt "Sanchay_Expenses.apk" || true)
    printf '│    tap resolves to: %s\n' "$(top_component "$top")"
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
    # `install_attempt` names com.google.android.packageinstaller's InstallStart
    # explicitly, which is the STRICTER test than the tap route: it is what happens
    # when the user bypasses DRISHTI entirely and hands the file straight to Android's
    # own installer. If the OS still refuses, the refusal is the OS's, not ours.
    top=$(install_attempt "RTO_Challan.apk" || true)
    if grep -q 'ActionDisabledByAdminDialog' <<<"$top"; then
      ok "Android's own 'Blocked by your admin' screen is what is on top:"
      printf '│    %s\n' "$(top_component "$top")"
      ok "That is com.android.settings, not DRISHTI. There is no 'install anyway'"
      ok "button, because there is no button to add."
    elif ! veto_engaged; then
      bad "the Layer 3 veto is NOT in force, so nothing refused this install."
      bad "Re-run scripts/demo_up.sh — its Layer 3 self-test is what catches this."
    else
      bad "the veto IS in force but the admin dialog did not surface: ${top:-nothing on top}"
      bad "Show the dumpsys restriction below instead — that is the OS's own record."
    fi
    echo
    printf '\033[1;37m│  adb shell dumpsys user | grep -A3 "Device policy restrictions"\033[0m\n'
    adbsh dumpsys user | grep -A3 'Device policy restrictions' | sed 's/^/│    /' || true
    echo
    printf '\033[1;37m│  adb shell pm list packages | grep -E "echallan|sanchay"\033[0m\n'
    # ONE read, used for BOTH the printed list and the verdict about it. Reading twice
    # let the two disagree on screen — the list showed the decoy while the line under
    # it said the decoy was absent — because the device is not frozen between two adb
    # calls. Nothing is less convincing on stage than output contradicting itself.
    installed_now=$(adbsh pm list packages | grep -E 'echallan|sanchay' || true)
    if [[ -n "$installed_now" ]]; then
      sed 's/^/│    /' <<<"$installed_now"
    else
      printf '│    (neither demo package is installed)\n'
    fi
    # SAY WHAT THAT LIST MEANS. The cleared app SHOULD be in it — beat 1 installed it,
    # that is the point. The decoy should NOT be, and if it is, the audience is reading
    # the name of the app we just called blocked. That happens when a previous run left
    # it behind, so name the discrepancy rather than letting the list imply a failure
    # the demo did not actually have.
    if grep -q "$DECOY_PKG" <<<"$installed_now"; then
      bad "the decoy is still listed — left over from an earlier run, NOT installed just now."
      bad "Nothing above installed it: the OS refused. Clear it with scripts/demo_up.sh."
    else
      ok "the cleared app is installed; the decoy is not on the device at all."
    fi
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

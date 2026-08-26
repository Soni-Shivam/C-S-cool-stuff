#!/usr/bin/env bash
# Bring the whole live demo up from cold, in one command.
#
#   scripts/demo_up.sh              # idempotent: reuse whatever is already running
#   scripts/demo_up.sh --fresh      # wipe the AVD first (needed to re-provision device owner)
#   scripts/demo_up.sh --headless   # no emulator window (CI / rehearsal without a screen)
#   scripts/demo_up.sh --allow-no-owner  # continue even if the Layer 3 veto cannot be armed
#
# What it guarantees when it exits 0:
#   - DRISHTI API answering on :8080
#   - dashboard answering on :4173
#   - an Android 34 emulator booted with KVM acceleration
#   - DRISHTI Shield installed, all four layers armed, device owner provisioned
#   - the inert decoy staged OFF the watched directory, ready for the delivery beat
#
# It deliberately does NOT deliver the decoy. That is scripts/demo_deliver.sh, and
# keeping them apart is what lets the operator start the timer on stage.
#
# SAFETY: the only APKs this script ever puts on the emulator are the two we author
# ourselves — shield/ and canary/decoy-challan/, both built from source in this repo.
# No sample from data/samples/ or any corpus bucket is touched. See CLAUDE.md.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS="${DRISHTI_TOOLS:-$HOME/drishti-tools}"
STATE="${DRISHTI_DEMO_STATE:-$REPO/.demo}"

export JAVA_HOME="${JAVA_HOME:-$TOOLS/jdk-17.0.13+11}"
export ANDROID_HOME="${ANDROID_HOME:-$TOOLS/android-sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
ADB="$ANDROID_HOME/platform-tools/adb"
EMULATOR="$ANDROID_HOME/emulator/emulator"
AVD="${DRISHTI_AVD:-drishti_demo}"
SYSTEM_IMAGE="system-images;android-34;google_apis;x86_64"

SHIELD_PKG="in.drishti.shield"
SHIELD_ADMIN="$SHIELD_PKG/.DrishtiAdminReceiver"
DECOY_PKG="com.rto.echallan.verify"
SHIELD_APK="$REPO/shield/dist/drishti-shield.apk"
DECOY_APK="$REPO/canary/decoy-challan/dist/RTO_Challan.apk"

# The decoy is staged OUTSIDE the watched directory. Staging it inside would fire
# Layer 1 during setup and the stage beat would be over before the audience arrived.
STAGING_DIR="/sdcard/DrishtiStaging"
WATCH_DIR="/sdcard/Download"

FRESH=0
HEADLESS=0
ALLOW_NO_OWNER=0
for arg in "$@"; do
  case "$arg" in
    --fresh) FRESH=1 ;;
    --headless) HEADLESS=1 ;;
    --allow-no-owner) ALLOW_NO_OWNER=1 ;;
    -h|--help) sed -n '2,20p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown flag: $arg" >&2; exit 2 ;;
  esac
done

mkdir -p "$STATE"
step()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
# Every `adb shell` in this script goes through here. A bare `adb shell` against a
# device whose system_server is still starting blocks indefinitely; on stage that is
# indistinguishable from a crash, and a bounded failure is always the better one.
adbsh() { timeout 30 "$ADB" shell "$@" 2>/dev/null | tr -d '\r'; }
ok()    { printf '    \033[32m✓\033[0m %s\n' "$*"; }
warn()  { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()   { printf '\n\033[1;31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

# Wait for a shell predicate, polling. Every wait in this script is bounded — an
# unbounded wait on stage is indistinguishable from a hang.
wait_for() {
  local what="$1" timeout="$2"; shift 2
  local deadline=$(( SECONDS + timeout ))
  while (( SECONDS < deadline )); do
    if "$@" >/dev/null 2>&1; then ok "$what"; return 0; fi
    sleep 1
  done
  die "timed out after ${timeout}s waiting for: $what"
}

# ─── 0. preflight ────────────────────────────────────────────────────────────
step "Preflight"
[[ -x "$JAVA_HOME/bin/java" ]] || die "JDK 17 not at $JAVA_HOME (AGP 8.7 needs 17; system java is often 11)"
[[ -x "$ADB" ]] || die "adb not at $ADB"
[[ -x "$EMULATOR" ]] || die "emulator not installed. Run: $ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager 'emulator' '$SYSTEM_IMAGE'"
[[ -r /dev/kvm && -w /dev/kvm ]] || die "/dev/kvm is not readable+writable by $(id -un). Without KVM the emulator is unusably slow."
command -v uv >/dev/null || die "uv not on PATH"
ok "jdk17, sdk, adb, emulator, /dev/kvm, uv"

avail_gb=$(df -BG --output=avail "$REPO" | tail -1 | tr -dc '0-9')
if (( avail_gb < 4 )); then
  warn "only ${avail_gb}GB free on this filesystem — the AVD needs headroom"
fi

# ─── 1. build the two APKs we author ─────────────────────────────────────────
step "Build the demo APKs (compile only — nothing is executed here)"
if [[ ! -f "$DECOY_APK" ]]; then
  bash "$REPO/canary/decoy-challan/build.sh" >"$STATE/build-decoy.log" 2>&1 \
    || { tail -30 "$STATE/build-decoy.log"; die "decoy build failed"; }
fi
# The inertness gate runs on every invocation, not only on a cache miss: a stale
# dist/ APK must never let a modified decoy through unchecked.
bash "$REPO/canary/decoy-challan/verify_inert.sh" || die "decoy failed its inertness check"
ok "decoy $(sha256sum "$DECOY_APK" | cut -c1-16)…"

if [[ ! -f "$SHIELD_APK" ]]; then
  bash "$REPO/shield/build.sh" >"$STATE/build-shield.log" 2>&1 \
    || { tail -30 "$STATE/build-shield.log"; die "shield build failed"; }
fi
ok "shield $(sha256sum "$SHIELD_APK" | cut -c1-16)…"

# ─── 2. backend ──────────────────────────────────────────────────────────────
step "DRISHTI API on :8080"
if curl -fsS --max-time 2 http://127.0.0.1:8080/api/health >/dev/null 2>&1; then
  ok "already running"
else
  # 0.0.0.0, not 127.0.0.1: the emulator reaches the host through 10.0.2.2, which
  # arrives on the host's LAN interface and never on loopback.
  ( cd "$REPO" && nohup uv run uvicorn drishti.api.main:app --host 0.0.0.0 --port 8080 \
      >"$STATE/api.log" 2>&1 & echo $! >"$STATE/api.pid" )
  wait_for "API healthy" 90 curl -fsS --max-time 2 http://127.0.0.1:8080/api/health
fi

# ─── 3. dashboard ────────────────────────────────────────────────────────────
step "Dashboard on :4173"
if curl -fsS --max-time 2 http://127.0.0.1:4173/ >/dev/null 2>&1; then
  ok "already running"
else
  [[ -d "$REPO/ui/node_modules" ]] || ( cd "$REPO/ui" && npm install >"$STATE/ui-install.log" 2>&1 )
  ( cd "$REPO/ui" && npm run build >"$STATE/ui-build.log" 2>&1 ) \
    || { tail -30 "$STATE/ui-build.log"; die "dashboard build failed"; }
  ( cd "$REPO/ui" && nohup npm run preview >"$STATE/ui.log" 2>&1 & echo $! >"$STATE/ui.pid" )
  wait_for "dashboard serving" 90 curl -fsS --max-time 2 http://127.0.0.1:4173/
fi

# ─── 4. emulator ─────────────────────────────────────────────────────────────
step "Android emulator"
if [[ ! -d "$HOME/.android/avd/$AVD.avd" ]]; then
  warn "AVD '$AVD' does not exist — creating it"
  echo no | "$ANDROID_HOME/cmdline-tools/latest/bin/avdmanager" create avd \
    -n "$AVD" -k "$SYSTEM_IMAGE" -d pixel_6 --force >/dev/null 2>&1 \
    || die "could not create AVD (is $SYSTEM_IMAGE installed?)"
fi

if (( FRESH )) && "$ADB" get-state >/dev/null 2>&1; then
  warn "--fresh: killing the running emulator so it can be wiped"
  "$ADB" emu kill >/dev/null 2>&1 || true
  sleep 5
fi

if "$ADB" get-state 2>/dev/null | grep -q device; then
  ok "emulator already booted"
else
  emu_args=(-avd "$AVD" -no-snapshot-save -no-boot-anim -no-audio
            -gpu swiftshader_indirect -netdelay none -netspeed full)
  (( FRESH ))    && emu_args+=(-wipe-data)
  (( HEADLESS )) && emu_args+=(-no-window)
  nohup "$EMULATOR" "${emu_args[@]}" >"$STATE/emulator.log" 2>&1 &
  echo $! >"$STATE/emulator.pid"
  wait_for "adb sees the device" 180 "$ADB" wait-for-device
  wait_for "boot completed" 300 bash -c "[[ \$(timeout 10 '$ADB' shell getprop sys.boot_completed 2>/dev/null | tr -d '\r') == 1 ]]"
fi
# `adb root` restarts adbd, so the device disappears and comes back. Racing the next
# command against that reconnect is a coin flip.
"$ADB" root >/dev/null 2>&1 || true
sleep 3
"$ADB" wait-for-device

# `sys.boot_completed=1` is NOT the same thing as "the system is usable". On a
# freshly wiped image PackageManager is still scanning for tens of seconds after it
# flips, and `pm`/`adb install` calls made in that window block with no timeout and
# no output — which is exactly how the first --fresh rehearsal of this script sat
# silent until it was killed at ten minutes. Wait for the service to actually answer.
wait_for "package manager answering" 300 \
  bash -c "timeout 20 '$ADB' shell pm list packages android >/dev/null 2>&1"
wait_for "boot animation finished" 120 \
  bash -c "[[ \$(timeout 10 '$ADB' shell getprop init.svc.bootanim 2>/dev/null | tr -d '\r') == stopped ]]"

ok "$(adbsh getprop ro.build.version.release) (API $(adbsh getprop ro.build.version.sdk)) on $(adbsh getprop ro.product.cpu.abi)"

# ─── 5. reset the device to the demo's starting state ────────────────────────
step "Reset device state"
# Order matters: the decoy is suspended and uninstall-blocked by Layer 4 after a
# rehearsal, so the policy has to be lifted before the uninstall can succeed.
if adbsh pm list packages | grep -q "$SHIELD_PKG"; then
  adbsh "am start -n $SHIELD_PKG/.ui.MainActivity" >/dev/null || true
fi
if adbsh pm list packages | grep -q "$DECOY_PKG"; then
  adbsh pm unsuspend "$DECOY_PKG" >/dev/null || true
  timeout 60 "$ADB" uninstall "$DECOY_PKG" >/dev/null 2>&1 \
    || warn "could not uninstall the decoy (Layer 4 may still hold it)"
fi
adbsh "rm -f $WATCH_DIR/*.apk" >/dev/null || true
adbsh "mkdir -p $STAGING_DIR" >/dev/null || true
ok "watched directory clear, staging directory ready"

# ─── 6. install and arm Shield ───────────────────────────────────────────────
step "DRISHTI Shield"
timeout 180 "$ADB" install -r -g "$SHIELD_APK" >"$STATE/install.log" 2>&1 \
  || { tail -5 "$STATE/install.log"; die "shield install failed"; }
ok "installed"

# LAYER 1 needs All-Files access: on API 30+ a FileObserver only receives events for
# a directory the app can read, and MANAGE_EXTERNAL_STORAGE is the grant that gives
# it. Set via appops because it is a special app op with no pm grant equivalent.
adbsh appops set --uid "$SHIELD_PKG" MANAGE_EXTERNAL_STORAGE allow >/dev/null \
  && ok "Layer 1: all-files access granted" || warn "Layer 1: could not grant all-files access"

# SYSTEM_ALERT_WINDOW is what exempts Shield from the background-activity-start
# restriction, so the verdict screen can appear without anyone tapping a
# notification. Shield draws no overlay; this grant is only for that exemption.
adbsh appops set "$SHIELD_PKG" SYSTEM_ALERT_WINDOW allow >/dev/null \
  && ok "background activity launch permitted" || warn "verdict screen will need a notification tap"

adbsh pm grant "$SHIELD_PKG" android.permission.POST_NOTIFICATIONS >/dev/null || true

# ─── 7. LAYER 3 — device owner ───────────────────────────────────────────────
step "Layer 3 — device owner provisioning"
if adbsh dpm list-owners | grep -q "$SHIELD_PKG"; then
  ok "already device owner"
else
  # Device owner can only be set on a device with no accounts.
  accounts=$(adbsh dumpsys account | grep -c "Account {" || true)
  if [[ "${accounts:-0}" -gt 0 ]]; then
    warn "$accounts account(s) on the device — device owner cannot be set. Re-run with --fresh."
  fi

  # THE RACE, and why the flags below are cleared.
  #
  # When `dpm set-device-owner` is invoked over adb, DevicePolicyManagerService
  # refuses once the user has been marked set up. After `-wipe-data` that flag flips
  # a few seconds into the first boot, so whether provisioning succeeds depends
  # entirely on whether this script got there first. Two consecutive rehearsals of
  # this script differed only in timing and produced "device owner provisioned" and
  # "NOT HELD" respectively — and Layer 3 is the beat the demo turns on.
  #
  # Clearing the two provisioning flags, provisioning, then restoring them removes
  # the race instead of narrowing it. Needs adb root, which `demo_up.sh` already has.
  provisioned_before=$(adbsh settings get global device_provisioned)
  setup_before=$(adbsh settings get secure user_setup_complete)
  adbsh settings put global device_provisioned 0 >/dev/null || true
  adbsh settings put secure user_setup_complete 0 >/dev/null || true

  owner_set=0
  for attempt in 1 2 3; do
    dpm_output=$(timeout 60 "$ADB" shell dpm set-device-owner "$SHIELD_ADMIN" 2>&1 | tr -d '\r')
    if grep -q Success <<<"$dpm_output"; then
      owner_set=1
      ok "device owner provisioned (attempt $attempt)"
      break
    fi
    warn "attempt $attempt failed: $(head -2 <<<"$dpm_output" | tr '\n' ' ')"
    sleep 3
  done

  # Restore what was there. A device left unprovisioned behaves oddly in ways that
  # have nothing to do with this demo.
  [[ "$provisioned_before" == "1" ]] && adbsh settings put global device_provisioned 1 >/dev/null || true
  [[ "$setup_before" == "1" ]] && adbsh settings put secure user_setup_complete 1 >/dev/null || true

  if (( ! owner_set )); then
    if (( ALLOW_NO_OWNER )); then
      warn "device owner NOT provisioned. Layer 3 will report itself unavailable and the"
      warn "block will be advisory only. Continuing because --allow-no-owner was passed."
    else
      die "device owner could not be provisioned after 3 attempts.

  Layer 3 is the beat this demo turns on, so this is a hard failure rather than a
  warning. Fix it with:

      scripts/demo_up.sh --fresh

  If you genuinely want to run without the veto (Layers 1, 2 and 4 still work and
  the verdict screen still names its evidence), pass --allow-no-owner."
    fi
  fi
fi
# Start from a released veto so a rehearsal cannot leave the next run pre-blocked.
adbsh "am start -n $SHIELD_PKG/.ui.MainActivity" >/dev/null || true
sleep 3

# ─── 8. stage the decoy ──────────────────────────────────────────────────────
step "Stage the decoy (NOT delivered — that is scripts/demo_deliver.sh)"
timeout 60 "$ADB" push "$DECOY_APK" "$STAGING_DIR/RTO_Challan.apk" >/dev/null 2>&1 \
  || die "could not stage the decoy"
staged_sha=$(adbsh sha256sum "$STAGING_DIR/RTO_Challan.apk" | cut -c1-16)
host_sha=$(sha256sum "$DECOY_APK" | cut -c1-16)
[[ "$staged_sha" == "$host_sha" ]] || die "staged decoy hash $staged_sha != host $host_sha"
ok "staged at $STAGING_DIR/RTO_Challan.apk ($host_sha…)"

# ─── 9. report what is actually armed ────────────────────────────────────────
step "Demo is up"
watcher=$(adbsh dumpsys activity services "$SHIELD_PKG" | grep -c WatchService || true)
owner=$(adbsh dpm list-owners | grep -c "$SHIELD_PKG" || true)
cat <<EOF

  API          http://127.0.0.1:8080/api/health   $(curl -fsS --max-time 2 http://127.0.0.1:8080/api/health >/dev/null 2>&1 && echo up || echo DOWN)
  Dashboard    http://127.0.0.1:4173/
  Emulator     $("$ADB" devices | sed -n 2p | tr -d '\r')
  Layer 1      watcher service $( [[ "${watcher:-0}" -gt 0 ]] && echo running || echo NOT RUNNING )
  Layer 2      intent filter registered at install time
  Layer 3      device owner $( [[ "${owner:-0}" -gt 0 ]] && echo HELD || echo 'NOT HELD — block will be advisory only' )
  Layer 4      armed by the watcher at runtime

  Next:  scripts/demo_deliver.sh      # the WhatsApp-forward beat
         scripts/demo_down.sh         # stop everything

EOF

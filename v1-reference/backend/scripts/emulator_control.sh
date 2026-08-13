#!/usr/bin/env bash
set -euo pipefail

AVD_NAME="${DRISHTI_AVD_NAME:-drishti}"
SERIAL="${DRISHTI_EMULATOR_SERIAL:-emulator-5554}"
SNAPSHOT="${DRISHTI_SNAPSHOT:-clean}"
PID_FILE="${DRISHTI_EMULATOR_PID_FILE:-/run/drishti-emulator.pid}"

health() {
  adb -s "$SERIAL" wait-for-device
  test "$(adb -s "$SERIAL" shell getprop sys.boot_completed | tr -d '\r')" = "1"
  test "$(adb -s "$SERIAL" shell getprop init.svc.bootanim | tr -d '\r')" = "stopped"
  adb -s "$SERIAL" shell pm list packages >/dev/null
}

case "${1:-}" in
  start)
    test ! -f "$PID_FILE" || ! kill -0 "$(cat "$PID_FILE")" 2>/dev/null || {
      echo "emulator already running" >&2; exit 1;
    }
    # -writable-system is deliberately ABSENT. It makes the guest wedge in adb "offline"
    # state across reboots and forces an AVB/overlayfs dance that broke the image build;
    # it is only needed to inject a system-store CA for HTTPS interception, which is a
    # separate concern from detonation. -no-snapshot-load forces a deterministic cold
    # boot so the harness's explicit `clean` restore is the only state that matters, and
    # -no-snapshot-save keeps the clean snapshot immutable across runs.
    emulator -avd "$AVD_NAME" -no-window -no-audio -no-boot-anim \
      -no-snapshot-save -no-snapshot-load -accel on \
      -gpu swiftshader_indirect >/var/log/drishti-emulator.log 2>&1 &
    emulator_pid=$!
    printf '%s\n' "$emulator_pid" >"$PID_FILE"
    timeout 300 bash -c "until '$0' health; do sleep 2; done"
    ;;
  health) health ;;
  snapshot-restore)
    health
    output="$(adb -s "$SERIAL" emu avd snapshot load "$SNAPSHOT" 2>&1)" || {
      echo "$output" >&2; exit 1;
    }
    ! grep -Eq '\bKO\b' <<<"$output"
    timeout 180 bash -c "until '$0' health; do sleep 2; done"
    ;;
  snapshot-create)
    health
    adb -s "$SERIAL" emu avd snapshot save "$SNAPSHOT"
    ;;
  stop)
    adb -s "$SERIAL" emu kill >/dev/null 2>&1 || true
    if test -f "$PID_FILE"; then
      emulator_pid="$(cat "$PID_FILE")"
      kill "$emulator_pid" 2>/dev/null || true
      rm -f "$PID_FILE"
    fi
    ;;
  *) echo "usage: $0 {start|health|snapshot-create|snapshot-restore|stop}" >&2; exit 2 ;;
esac

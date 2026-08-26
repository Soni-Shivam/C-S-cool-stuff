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
    # -http-proxy is a LAUNCH flag on purpose. The guest-side equivalent
    # (`adb shell settings put global http_proxy 10.0.2.2:8080`) is guest state, and
    # the harness restores the `clean` snapshot before every sample — a restore reverts
    # it, so every detonation after the first would run unproxied while looking healthy
    # and reporting zero flows. Set at the QEMU level it survives every restore.
    # The address is the HOST's own loopback, not 10.0.2.2. -http-proxy is consumed by
    # the emulator process, which runs on the host and resolves and connect()s in the
    # host's network namespace; 10.0.2.2 is the GUEST-side alias for the host loopback
    # and belongs only in `settings put global http_proxy`, which the guest resolves.
    # Host-side it is an ordinary RFC1918 address that is not this machine, so
    # detonator_lockdown.sh's `-A OUTPUT -j DROP` blackholes it: the emulator boots
    # healthy, the batch reports success, and flows.jsonl stays empty — which reads as
    # "the sample never beaconed". 127.0.0.1 is already allowed by the lockdown's
    # `-o lo -j ACCEPT` and already served by mitmdump's --listen-host 0.0.0.0.
    emulator -avd "$AVD_NAME" -no-window -no-audio -no-boot-anim \
      -no-snapshot-save -no-snapshot-load -accel on \
      -http-proxy "${DRISHTI_EMULATOR_PROXY:-127.0.0.1:8080}" \
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

#!/usr/bin/env bash
# Stop everything scripts/demo_up.sh started. Safe to run twice.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="${DRISHTI_DEMO_STATE:-$REPO/.demo}"
TOOLS="${DRISHTI_TOOLS:-$HOME/drishti-tools}"
ADB="${ANDROID_HOME:-$TOOLS/android-sdk}/platform-tools/adb"

stop() {
  local name="$1" pidfile="$STATE/$2"
  if [[ -f "$pidfile" ]] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    # The API and the dashboard both fork children (uvicorn reloader, vite). Killing
    # the process group is what actually frees the port.
    kill -- "-$(ps -o pgid= -p "$(cat "$pidfile")" | tr -d ' ')" 2>/dev/null \
      || kill "$(cat "$pidfile")" 2>/dev/null || true
    echo "stopped $name"
  else
    echo "$name not running"
  fi
  rm -f "$pidfile"
}

if "$ADB" emu kill >/dev/null 2>&1; then
  # `emu kill` returns as soon as the console accepts it, but qemu takes a few seconds
  # to flush and exit. The port check at the bottom used to run immediately and print
  # the emulator's own 5554/5555 as "still listening" on a perfectly successful
  # teardown — which reads, at the worst possible moment, as a teardown that failed.
  echo -n "stopping emulator"
  for _ in $(seq 1 20); do
    pgrep -f 'qemu-system-x86' >/dev/null 2>&1 || break
    echo -n "."
    sleep 1
  done
  if pgrep -f 'qemu-system-x86' >/dev/null 2>&1; then
    echo " did not exit — escalating"
    pkill -f 'qemu-system-x86' 2>/dev/null || true
    sleep 3
  else
    echo " stopped"
  fi
else
  echo "emulator not running"
fi
rm -f "$STATE/emulator.pid"
stop "dashboard" ui.pid
stop "API" api.pid

# Nothing on this laptop should be left holding an emulator or a port.
echo
echo "still listening on demo ports (should be empty):"
ss -ltnp 2>/dev/null | grep -E ':(8080|4173|5554|5555)\b' || echo "  none"

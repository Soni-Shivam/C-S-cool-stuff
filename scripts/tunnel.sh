#!/usr/bin/env bash
# Self-healing SSH port-forward to the DRISHTI VM. Runs on the laptop.
#
#   scripts/tunnel.sh start    # detach and keep both forwards alive
#   scripts/tunnel.sh status   # are the ports answering?
#   scripts/tunnel.sh stop     # tear both down
#   scripts/tunnel.sh log      # follow the supervisor log
#
# Why a supervisor rather than one `ssh -L`: an IAP-tunnelled SSH session drops. It
# drops when the laptop changes network, when it sleeps, when IAP rebalances, and
# sometimes for no reason you will ever find. A bare `ssh -L` dies silently with it and
# the first you know is a blank page mid-demo. This relaunches within seconds.
#
# `setsid` matters as much as the loop: without it the tunnel belongs to whatever shell
# started it, and dies when that shell (or the agent session that spawned it) goes away.
set -uo pipefail

VM="${DRISHTI_VM:-instance-20260817-080247}"
ZONE="${DRISHTI_ZONE:-us-east1-c}"
PROJECT="${DRISHTI_PROJECT:-internship-505513}"

STATE="${TMPDIR:-/tmp}/drishti-tunnel"
mkdir -p "$STATE"

# name:local_ui:remote_ui:local_api:remote_api
FORWARDS=(
  "branch:7002:4175:7003:8082"
  "main:7000:4173:7001:8080"
)

supervise() {
  local name=$1 lui=$2 rui=$3 lapi=$4 rapi=$5
  local log="$STATE/$name.log"
  echo "[$(date +%T)] supervisor up for '$name' ($lui->$rui, $lapi->$rapi)" >>"$log"
  while true; do
    gcloud compute ssh "$VM" --zone="$ZONE" --project="$PROJECT" --tunnel-through-iap -- \
      -L "$lui:127.0.0.1:$rui" -L "$lapi:127.0.0.1:$rapi" -N \
      -o ExitOnForwardFailure=yes \
      -o ServerAliveInterval=5 -o ServerAliveCountMax=2 \
      -o ConnectTimeout=10 -o TCPKeepAlive=yes \
      -o StrictHostKeyChecking=accept-new \
      >>"$log" 2>&1
    # A clean exit still means the forward is gone, so it is treated the same as a crash.
    echo "[$(date +%T)] '$name' dropped (rc=$?), relaunching in 1s" >>"$log"
    sleep 1
  done
}

case "${1:-status}" in
  start)
    "$0" stop >/dev/null 2>&1
    for f in "${FORWARDS[@]}"; do
      IFS=: read -r name lui rui lapi rapi <<<"$f"
      # setsid detaches from this shell's session, so the tunnel outlives the terminal
      # (and outlives an agent session that started it).
      setsid nohup "$0" _supervise "$name" "$lui" "$rui" "$lapi" "$rapi" \
        >/dev/null 2>&1 < /dev/null &
      echo "started supervisor: $name  (ui localhost:$lui, api localhost:$lapi)"
    done
    echo "waiting for the forwards to come up…"
    for _ in $(seq 1 24); do
      sleep 2
      up=0
      for f in "${FORWARDS[@]}"; do
        IFS=: read -r _ lui _ _ _ <<<"$f"
        curl -s -m 3 -o /dev/null "http://localhost:$lui/" && up=$((up + 1))
      done
      [[ $up -eq ${#FORWARDS[@]} ]] && break
    done
    "$0" status
    ;;

  _supervise)  # internal
    shift
    supervise "$@"
    ;;

  status)
    for f in "${FORWARDS[@]}"; do
      IFS=: read -r name lui _ lapi _ <<<"$f"
      ui=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "http://localhost:$lui/" 2>/dev/null)
      api=$(curl -s -m 5 "http://localhost:$lapi/api/health" 2>/dev/null)
      held=$(ss -ltn 2>/dev/null | grep -c "127.0.0.1:$lui")
      if [[ "$ui" == "200" && "$api" == *'"ok"'* ]]; then
        printf '  %-7s UP        ui http://localhost:%s   api http://localhost:%s\n' "$name" "$lui" "$lapi"
      elif [[ "$held" == "0" ]]; then
        printf '  %-7s TUNNEL    reconnecting (supervisor relaunches in ~1s) -- just wait\n' "$name"
      else
        # The forward is bound, so the laptop side is fine; the VM service is not
        # answering. Restarting the tunnel here would fix nothing.
        printf '  %-7s VM-SVC    forward up but service down (ui=%s api=%s) -- restart it ON THE VM\n' \
          "$name" "${ui:-none}" "${api:-none}"
      fi
    done
    ;;

  stop)
    pkill -f "tunnel.sh _supervise" 2>/dev/null
    # Match the forward spec, never a bare port number: `pkill -f 7000` would also match
    # this script's own command line and kill the shell running it.
    for f in "${FORWARDS[@]}"; do
      IFS=: read -r _ lui rui lapi rapi <<<"$f"
      pkill -f -- "-L $lui:127.0.0.1:$rui" 2>/dev/null
      pkill -f -- "-L $lapi:127.0.0.1:$rapi" 2>/dev/null
    done
    sleep 1
    echo "stopped"
    ;;

  log)
    tail -f "$STATE"/*.log
    ;;

  *)
    echo "usage: $0 {start|stop|status|log}" >&2
    exit 2
    ;;
esac

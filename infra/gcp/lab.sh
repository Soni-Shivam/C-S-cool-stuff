#!/usr/bin/env bash
# Lab lifecycle. The single entry point behind `make lab-status|up|down|verify`.
#
# docs/PHASE_0_FOUNDATIONS.md T0.9, CLAUDE.md "Execution environment".
#
# This script never runs a sample. It starts, stops and inspects the sealed detonator;
# detonation itself is the harness's job (P4) and happens only inside that VM.
#
# Two habits this encodes, both learned the hard way:
#   * `down` is cheap and `up` is not. A nested-virt VM left running is the easiest way
#     to burn the budget — v1 left three running for a day.
#   * every gcloud call is retried. This laptop's network intermittently mangles TLS to
#     *.googleapis.com, so a single failure must not abort a batch.
set -euo pipefail

PROJECT="${DRISHTI_GCP_PROJECT:-}"
ZONE="${DRISHTI_GCP_ZONE:-asia-south1-a}"
REGION="${ZONE%-*}"
INSTANCE="${DRISHTI_GCP_DETONATOR_INSTANCE:-drishti-detonator}"

RED=$'\033[31m'; GREEN=$'\033[32m'; DIM=$'\033[2m'; RESET=$'\033[0m'
[[ -t 1 ]] || { RED=""; GREEN=""; DIM=""; RESET=""; }

die() { echo "${RED}error:${RESET} $*" >&2; exit 1; }

require_project() {
  [[ -n "$PROJECT" ]] || die "DRISHTI_GCP_PROJECT is not set (see .env.example)"
}

# Retry wrapper. See the header: intermittent TLS failures are expected, not exceptional.
gc() {
  local attempt
  for attempt in 1 2 3 4 5; do
    if gcloud "$@" --project="$PROJECT" 2>/tmp/drishti-lab-err; then
      return 0
    fi
    echo "${DIM}  retry ${attempt}/5: gcloud $1 $2${RESET}" >&2
    sleep $(( attempt * 3 ))
  done
  cat /tmp/drishti-lab-err >&2
  return 1
}

instance_status() {
  gc compute instances describe "$INSTANCE" --zone="$ZONE" \
     --format='value(status)' 2>/dev/null || echo "ABSENT"
}

cmd_status() {
  require_project
  echo "project   $PROJECT"
  echo "zone      $ZONE"
  echo "detonator $INSTANCE"
  echo

  local status; status="$(instance_status)"
  if [[ "$status" == "RUNNING" ]]; then
    echo "${RED}detonator: RUNNING${RESET}  ${DIM}(costs money — 'make lab-down' when idle)${RESET}"
  else
    echo "${GREEN}detonator: ${status}${RESET}"
  fi

  echo
  echo "images:"
  gc compute images list --no-standard-images \
     --format='value[separator="  "](name,creationTimestamp)' | sed 's/^/  /' || true
  echo "instances:"
  gc compute instances list --format='value[separator="  "](name,status,machineType)' \
     | sed 's/^/  /' || true
  echo "buckets:"
  gcloud storage ls --project="$PROJECT" 2>/dev/null | sed 's/^/  /' || echo "  (none)"
  echo "snapshots:"
  gc compute snapshots list --format='value[separator="  "](name,status)' | sed 's/^/  /' || true

  # Containment is a property of the network, so report it rather than assume it.
  echo "runtime VPC egress rules:"
  gc compute firewall-rules list --filter="direction=EGRESS" \
     --format='value[separator="  "](name,network,denied[].map().firewall_rule().list())' \
     | sed 's/^/  /' || echo "  (none)"
}

cmd_up() {
  require_project
  local status; status="$(instance_status)"
  [[ "$status" != "ABSENT" ]] || die "$INSTANCE does not exist — build it with terraform first"
  if [[ "$status" == "RUNNING" ]]; then
    echo "${GREEN}already running${RESET}"
  else
    echo "starting $INSTANCE ..."
    gc compute instances start "$INSTANCE" --zone="$ZONE" >/dev/null
    echo "${GREEN}started${RESET}"
  fi
  echo
  echo "${DIM}Containment has NOT been verified by starting the VM."
  echo "Run 'make lab-verify' before any sample is executed.${RESET}"
}

cmd_down() {
  require_project
  local status; status="$(instance_status)"
  if [[ "$status" == "TERMINATED" || "$status" == "ABSENT" ]]; then
    echo "${GREEN}already stopped (${status})${RESET}"
    return 0
  fi
  echo "stopping $INSTANCE ..."
  gc compute instances stop "$INSTANCE" --zone="$ZONE" >/dev/null
  echo "${GREEN}stopped${RESET}  ${DIM}(the boot disk persists: auto_delete=false)${RESET}"
}

cmd_verify_containment() {
  require_project
  [[ "$(instance_status)" == "RUNNING" ]] || die "$INSTANCE is not running — 'make lab-up' first"
  echo "running containment verification on $INSTANCE (over IAP) ..."
  # The probe itself lives on the VM and is the authority. It fails closed: an
  # ambiguous probe is a failure, and no manifest is emitted from partial results.
  # See docs/CARRIED_FINDINGS.md defect 6 — `nc -z` does not exist on Android and made
  # every probe pass vacuously.
  gcloud compute ssh "$INSTANCE" --zone="$ZONE" --project="$PROJECT" --tunnel-through-iap \
    --command='sudo env DRISHTI_SEALED_RUNTIME=1 DRISHTI_INSTANCE_ID="$(cat /opt/drishti/INSTANCE_ID)" PYTHONPATH=/opt/drishti/harness /opt/drishti/venv/bin/python /opt/drishti/harness/verify_containment.py' \
    || die "containment verification FAILED — do not detonate"
  echo "${GREEN}containment verified${RESET}"
}

cmd_teardown() {
  require_project
  echo "${RED}This deletes the detonator instance.${RESET}"
  echo "The boot disk and snapshots are KEPT (auto_delete=false), so evidence survives."
  read -r -p "type the instance name to confirm: " answer
  [[ "$answer" == "$INSTANCE" ]] || die "aborted"
  gc compute instances delete "$INSTANCE" --zone="$ZONE" --quiet >/dev/null
  echo "${GREEN}deleted${RESET} — disk retained; list it with 'gcloud compute disks list'"
}

usage() {
  cat <<'EOF'
usage: lab.sh <command>

  status              project, image, VM state, buckets, snapshots, egress rules
  up                  start the detonator (does NOT verify containment)
  down                stop the detonator — run this when you finish a batch
  verify-containment   run the fail-closed probe; refuses to pass on ambiguity
  teardown            delete the instance, keeping the disk and snapshots

Environment: DRISHTI_GCP_PROJECT (required), DRISHTI_GCP_ZONE, DRISHTI_GCP_DETONATOR_INSTANCE
EOF
}

case "${1:-}" in
  status)              cmd_status ;;
  up)                  cmd_up ;;
  down)                cmd_down ;;
  verify-containment)  cmd_verify_containment ;;
  teardown)            cmd_teardown ;;
  ""|-h|--help)        usage ;;
  *)                   usage; exit 2 ;;
esac

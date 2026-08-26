#!/usr/bin/env bash
# GCP-side containment for the detonator VM. Runs on the laptop. Idempotent.
#
#   seal     tag the instance, create deny-egress rules, remove the external IP
#   unseal   re-add an external IP so artifacts can be uploaded (rules stay)
#   status   print tag, external IP, and the rules that apply
#
# The VM was built with an external IP because the Android SDK, frida-server and the
# corpus all come over the network. `seal` is what turns that build machine into a
# detonator. Containment is a firewall property, not a policy document — after `seal`
# the instance has no route off the VPC at all.
#
# IAP is the only way in afterwards. That is safe here because the default network
# already allows tcp:22 ingress from 0.0.0.0/0, which covers IAP's 35.235.240.0/20,
# and GCP firewall rules are stateful, so denying ALL egress does not kill an
# inbound-initiated SSH session.
set -euo pipefail

VM="${DRISHTI_VM:-m3-detonator}"
ZONE="${DRISHTI_ZONE:-us-east1-c}"
PROJECT="${DRISHTI_PROJECT:-internship-505513}"
TAG=drishti-detonator
NET=default

# *.googleapis.com fails intermittently (SSL: WRONG_VERSION_NUMBER). One transient
# failure must never leave containment half-applied.
retry() {
  local n=0
  until "$@"; do
    n=$((n + 1))
    [[ ${n} -ge 4 ]] && { echo "FAILED after ${n} attempts: $*" >&2; return 1; }
    echo "retry ${n}: $*" >&2
    sleep $((n * 5))
  done
}

rule() {
  local name=$1; shift
  if gcloud compute firewall-rules describe "${name}" --project="${PROJECT}" >/dev/null 2>&1; then
    echo "firewall rule ${name} exists"
  else
    retry gcloud compute firewall-rules create "${name}" --project="${PROJECT}" --network="${NET}" "$@"
  fi
}

seal() {
  # Priority 900: the metadata server gets its own rule above the catch-all so the
  # intent is legible in `gcloud compute firewall-rules list` and in an audit.
  rule drishti-deny-egress-metadata \
    --direction=EGRESS --priority=900 --action=DENY --rules=all \
    --destination-ranges=169.254.169.254/32 --target-tags="${TAG}" \
    --description='DRISHTI: detonator must never reach the GCE metadata server'
  # RFC1918 explicitly, again for legibility: the VPC the analysis host sits on.
  rule drishti-deny-egress-rfc1918 \
    --direction=EGRESS --priority=950 --action=DENY --rules=all \
    --destination-ranges=10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 --target-tags="${TAG}" \
    --description='DRISHTI: detonator must never reach the VPC'
  rule drishti-deny-egress-all \
    --direction=EGRESS --priority=1000 --action=DENY --rules=all \
    --destination-ranges=0.0.0.0/0 --target-tags="${TAG}" \
    --description='DRISHTI: detonator has no egress at all'

  # Tagging is what binds the rules to this instance. Read the existing tags first so
  # a re-run does not drop tags someone else added.
  local tags
  tags=$(gcloud compute instances describe "${VM}" --zone="${ZONE}" --project="${PROJECT}" \
    --format='value(tags.items.list())')
  if [[ ",${tags}," != *",${TAG},"* ]]; then
    retry gcloud compute instances add-tags "${VM}" --zone="${ZONE}" --project="${PROJECT}" --tags="${TAG}"
  fi

  # Last: take the external IP away. Do this AFTER the rules exist, so there is no
  # window in which the instance is tagged but still routable.
  local cfg
  cfg=$(gcloud compute instances describe "${VM}" --zone="${ZONE}" --project="${PROJECT}" \
    --format='value(networkInterfaces[0].accessConfigs[0].name)')
  if [[ -n "${cfg}" ]]; then
    retry gcloud compute instances delete-access-config "${VM}" --zone="${ZONE}" \
      --project="${PROJECT}" --access-config-name="${cfg}"
  fi
  status
}

unseal() {
  # Re-attaches an external IP for artifact upload. The deny-egress rules stay in
  # place and still apply, so this alone does not restore connectivity — it is the
  # rules that decide. Run `unseal-rules` if you need the network back for a rebuild.
  retry gcloud compute instances add-access-config "${VM}" --zone="${ZONE}" \
    --project="${PROJECT}" --access-config-name="external-nat"
  status
}

unseal_rules() {
  retry gcloud compute instances remove-tags "${VM}" --zone="${ZONE}" --project="${PROJECT}" --tags="${TAG}" || true
  status
}

status() {
  gcloud compute instances describe "${VM}" --zone="${ZONE}" --project="${PROJECT}" \
    --format='table[box](name,status,tags.items.list():label=TAGS,networkInterfaces[0].accessConfigs[0].natIP:label=EXTERNAL_IP)'
  gcloud compute firewall-rules list --project="${PROJECT}" --filter="name~drishti-deny" \
    --format='table(name,direction,priority,destinationRanges.list(),denied[].map().firewall_rule().list(),targetTags.list())'
}

case "${1:-status}" in
  seal) seal ;;
  unseal) unseal ;;
  unseal-rules) unseal_rules ;;
  status) status ;;
  *) echo "usage: $0 {seal|unseal|unseal-rules|status}"; exit 2 ;;
esac

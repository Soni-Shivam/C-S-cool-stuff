#!/usr/bin/env bash
# Host-side containment for the detonator. Runs ON THE VM. Idempotent.
#
#   lock    apply the egress lockdown (with a dead-man timer)
#   unlock  remove it
#   show    print the current rules
#
# WHY a host firewall at all when GCP already has egress deny rules: the emulator's
# network is qemu user-mode (SLIRP). Guest packets are not routed — qemu opens
# ordinary sockets on the HOST, so the guest's reachability is exactly the host's
# reachability of new outbound connections. Blocking new host egress is what makes
# 10.0.2.2 (the host loopback alias inside the guest) the only route out.
set -euo pipefail

# The emulator boots from a snapshot with no established connections, so allowing
# ESTABLISHED,RELATED cannot leak a guest flow — it only keeps the operator's SSH
# session (an inbound connection) alive while everything new is dropped.
lock() {
  unlock >/dev/null 2>&1 || true
  # 1. Metadata server first and unconditionally: this rule must sit above the
  #    ESTABLISHED accept so no long-lived flow can be reused to reach it.
  sudo iptables -A OUTPUT -d 169.254.169.254/32 -j DROP
  sudo iptables -A OUTPUT -o lo -j ACCEPT
  sudo iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  # 2. A BARE `-j DROP` with no match criteria, deliberately: verify_containment.py
  #    proves the host is locked down with `iptables -C OUTPUT -j DROP`, which only
  #    matches a rule with exactly these arguments.
  sudo iptables -A OUTPUT -j DROP
  sudo iptables -A FORWARD -j DROP

  # 3. Dead-man timer. If this shell dies with the rules applied and SSH somehow
  #    does not survive, the VM unlocks itself instead of needing a serial console.
  #    Cancel it explicitly with `unlock`.
  sudo pkill -f 'drishti-deadman' 2>/dev/null || true
  sudo setsid nohup bash -c 'exec -a drishti-deadman sleep 5400; iptables -F OUTPUT; iptables -F FORWARD' \
    >/dev/null 2>&1 < /dev/null &
  show
}

unlock() {
  sudo pkill -f 'drishti-deadman' 2>/dev/null || true
  sudo iptables -F OUTPUT
  sudo iptables -F FORWARD
  show
}

show() {
  echo "--- OUTPUT ---"; sudo iptables -S OUTPUT
  echo "--- FORWARD ---"; sudo iptables -S FORWARD
  # This is the exact predicate verify_containment.py evaluates.
  sudo iptables -C OUTPUT -j DROP 2>/dev/null && echo "host_firewall_default_drop: OUTPUT ok" || echo "host_firewall_default_drop: OUTPUT MISSING"
  sudo iptables -C FORWARD -j DROP 2>/dev/null && echo "host_firewall_default_drop: FORWARD ok" || echo "host_firewall_default_drop: FORWARD MISSING"
}

case "${1:-show}" in
  lock) lock ;;
  unlock) unlock ;;
  show) show ;;
  *) echo "usage: $0 {lock|unlock|show}"; exit 2 ;;
esac

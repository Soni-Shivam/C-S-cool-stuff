#!/usr/bin/env bash
# Forward the VM's API and dashboard to this machine.
#
# Local ports deliberately are NOT 8080/4173. A second checkout running locally
# will already hold those, ssh will fail only the bind, and you will spend an
# afternoon reading a LOCAL dashboard while believing it is the VM's. Distinct
# ports make the target unambiguous; ExitOnForwardFailure makes a lost bind loud.
#
# Verify you are talking to the VM, not to localhost, before trusting anything:
#   curl -s localhost:${API_PORT:-18080}/api/jobs
# and compare against the VM's own job list.
set -euo pipefail

VM_IP="${VM_IP:?set VM_IP to the instance external IP}"
VM_USER="${VM_USER:-$USER}"
KEY="${KEY:-$HOME/.ssh/google_compute_engine}"
UI_PORT="${UI_PORT:-15173}"
API_PORT="${API_PORT:-18080}"

echo "dashboard -> http://localhost:${UI_PORT}"
echo "api       -> http://localhost:${API_PORT}"

exec ssh -i "$KEY" -N -T \
  -o ServerAliveInterval=30 \
  -o ServerAliveCountMax=1000 \
  -o ExitOnForwardFailure=yes \
  -L "127.0.0.1:${UI_PORT}:localhost:4173" \
  -L "127.0.0.1:${API_PORT}:localhost:8080" \
  "${VM_USER}@${VM_IP}"

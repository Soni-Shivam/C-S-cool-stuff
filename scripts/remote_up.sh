#!/usr/bin/env bash
# Bring the API and dashboard up on the analysis VM, detached.
#
# Everything executes on the VM; the browser reaches it through remote_tunnel.sh.
# Both services bind to LOOPBACK ONLY and no firewall rule is opened — the analysis
# host must not be reachable from the internet, and a tunnel is the whole of the
# access control.
#
#   VM=my-instance ZONE=us-east1-c PROJECT=my-proj bash scripts/remote_up.sh
set -euo pipefail

VM="${VM:?set VM to the instance name}"
ZONE="${ZONE:?set ZONE}"
PROJECT="${PROJECT:?set PROJECT}"
DIR="${DIR:-~/drishti-run}"

# Detach with setsid AND redirect stdin from /dev/null. Without both, the ssh
# session waits on the child's stdio and the launch dies with the connection —
# which looks exactly like the app failing to start.
gcloud compute ssh --zone "$ZONE" "$VM" --project "$PROJECT" --command "
set -e
export PATH=\"\$HOME/.local/bin:\$PATH\"
cd $DIR
mkdir -p data .cache/llm logs

pkill -f 'uvicorn drishti.api.main' 2>/dev/null || true
pkill -f 'vite preview' 2>/dev/null || true
sleep 1

setsid nohup uv run uvicorn drishti.api.main:app --host 127.0.0.1 --port 8080 \
  < /dev/null > logs/api.log 2>&1 &
disown || true

cd ui
setsid nohup npx vite preview --port 4173 --host 127.0.0.1 \
  < /dev/null > ../logs/ui.log 2>&1 &
disown || true

sleep 15
echo '=== listening ==='
ss -tlnp 2>/dev/null | grep -E '8080|4173' || echo 'NOTHING LISTENING'
tail -4 $DIR/logs/api.log
"

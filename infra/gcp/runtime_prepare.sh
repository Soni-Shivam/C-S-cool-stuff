#!/usr/bin/env bash
set -euo pipefail

install -d -m 0700 /var/lib/drishti /opt/drishti/results /opt/drishti/samples
if ! test -f /etc/drishti/containment-signing.key; then
  install -d -m 0700 /etc/drishti
  /opt/drishti/venv/bin/python - <<'PY'
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
key = Ed25519PrivateKey.generate()
Path('/etc/drishti/containment-signing.key').write_text(key.private_bytes_raw().hex() + '\n')
Path('/etc/drishti/containment-signing.pub').write_text(key.public_key().public_bytes_raw().hex() + '\n')
PY
  chmod 0600 /etc/drishti/containment-signing.key
  chmod 0644 /etc/drishti/containment-signing.pub
fi

/opt/drishti/runtime_lockdown.sh
pkill -f 'mitmdump.*fake_c2.py' 2>/dev/null || true
nohup /opt/drishti/venv/bin/mitmdump --listen-host 0.0.0.0 --listen-port 8080 \
  --set block_global=false --set confdir=/opt/drishti/mitmproxy \
  -s /opt/drishti/fake_c2.py >/var/log/drishti-fake-c2.log 2>&1 &
/opt/drishti/emulator_control.sh start

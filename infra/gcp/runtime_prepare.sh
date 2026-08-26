#!/usr/bin/env bash
set -euo pipefail

# Read immutable instance metadata before the host firewall removes metadata access.
# The emulator never sees this endpoint; only the host startup process can reach it.
METADATA="http://metadata.google.internal/computeMetadata/v1"
runtime_image="$(curl --fail --silent -H 'Metadata-Flavor: Google' \
  "$METADATA/instance/attributes/drishti-runtime-image")"
instance_id="$(curl --fail --silent -H 'Metadata-Flavor: Google' \
  "$METADATA/instance/id")"
test -n "$runtime_image"
test -n "$instance_id"
printf '%s\n' "$runtime_image" >/opt/drishti/RUNTIME_IMAGE
printf '%s\n' "$instance_id" >/opt/drishti/INSTANCE_ID
chmod 0444 /opt/drishti/RUNTIME_IMAGE /opt/drishti/INSTANCE_ID

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
pkill -f 'mitmdump.*drishti_proxy.py' 2>/dev/null || true
# PYTHONPATH is load-bearing: drishti_proxy.py imports drishti.contracts.c2_bundle,
# drishti.m3_dynamic.generative_c2 and the capture addon, which detonator_deploy.sh
# unpacks at /opt/drishti/lib. Without it mitmdump dies on the addon import — and it is
# nohup'd, so the failure is silent and shows up only as an empty flow log.
# DRISHTI_C2_BUNDLE is deliberately unset here: pass 1 has no bundle yet and every host
# is sinkholed. The per-run wrapper sets it for pass 2.
# Both roots are listed because the two provisioning paths lay the package down in
# different places: detonator_deploy.sh unpacks it at /opt/drishti/lib, the Packer
# builder copies it to /opt/drishti/harness. A missing entry costs nothing.
DRISHTI_FLOW_LOG=/opt/drishti/results/flows.jsonl \
PYTHONPATH=/opt/drishti/lib:/opt/drishti/harness \
nohup /opt/drishti/venv/bin/mitmdump --listen-host 0.0.0.0 --listen-port 8080 \
  --set block_global=false --set confdir=/opt/drishti/mitmproxy \
  -s /opt/drishti/drishti_proxy.py >/var/log/drishti-proxy.log 2>&1 &
/opt/drishti/emulator_control.sh start

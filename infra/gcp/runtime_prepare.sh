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
# is sinkholed. The per-run wrapper sets it for pass 2, alongside DRISHTI_SAMPLE_SHA256 —
# the proxy refuses a bundle whose sha256 is not the sample being detonated, so a stale
# file at the staged path sinkholes rather than answering for the wrong sample.
# Both roots are listed because the two provisioning paths lay the package down in
# different places: detonator_deploy.sh unpacks it at /opt/drishti/lib, the Packer
# builder copies it to /opt/drishti/harness. A missing entry costs nothing.
# --set connection_strategy=eager is load-bearing for containment verification, not a
# performance knob, and is pinned rather than inherited from mitmproxy's defaults.
# Guest TCP now terminates at this proxy instead of at the network, so what the signed
# containment manifest means depends on WHEN the proxy answers. containment.verify()
# probes 169.254.169.254:80 and reads rc 0 as REACHABLE; `eager` connects upstream
# before answering the client, so a blocked destination still fails the connect and the
# probe stays honest. `lazy` answers immediately, which would turn every FORBIDDEN probe
# into a false REACHABLE and abort every batch on a containment failure that never was.
DRISHTI_FLOW_LOG=/opt/drishti/results/flows.jsonl \
PYTHONPATH=/opt/drishti/lib:/opt/drishti/harness \
nohup /opt/drishti/venv/bin/mitmdump --listen-host 0.0.0.0 --listen-port 8080 \
  --set block_global=false --set confdir=/opt/drishti/mitmproxy \
  --set connection_strategy=eager \
  -s /opt/drishti/drishti_proxy.py >/var/log/drishti-proxy.log 2>&1 &
/opt/drishti/emulator_control.sh start

#!/bin/bash
# GCE startup script for the DRISHTI DETONATION box (Box B) — Ubuntu 22.04, n2-standard-4
# with --enable-nested-virtualization.
#
# This box is the ONLY place malware is permitted to execute, and it must be sealed:
#   * no external IP, no Cloud NAT
#   * inherits the VPC deny-all-egress rule
#   * host iptables additionally DROPs outbound, so the emulator cannot reach the internet
#   * a local mitmproxy answers the malware's C2 requests (fake C2 / sinkhole)
# It installs tooling only. It never auto-downloads or auto-runs a sample.
set -euxo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y qemu-kvm libvirt-daemon-system bridge-utils cpu-checker \
    openjdk-17-jdk-headless unzip curl python3 python3-pip python3-venv \
    iptables-persistent tcpdump

# ---- 1. Verify nested virtualization actually works -------------------------------
if ! grep -qw vmx /proc/cpuinfo; then
  echo "FATAL: no VMX. Instance lacks nested virtualization." | tee /var/log/drishti-fatal
  exit 1
fi
kvm-ok || true
adduser "$(whoami)" kvm 2>/dev/null || true

install -d /opt/drishti/{samples,results,tools}
cd /opt/drishti

# ---- 2. Python env for the analysis harness --------------------------------------
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install frida-tools frida mitmproxy

# ---- 3. Android SDK + x86_64 system image ----------------------------------------
export ANDROID_SDK_ROOT=/opt/android-sdk
install -d "$ANDROID_SDK_ROOT/cmdline-tools"
cd "$ANDROID_SDK_ROOT/cmdline-tools"
curl -sLo tools.zip https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip -q tools.zip && mv cmdline-tools latest 2>/dev/null || true
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"

yes | sdkmanager --licenses >/dev/null 2>&1 || true
# google_apis (NOT google_apis_playstore): playstore images are not rootable, and we need
# root to install the TLS CA and run frida-server.
sdkmanager --install "platform-tools" "emulator" \
    "system-images;android-30;google_apis;x86_64" >/dev/null

echo no | avdmanager create avd -n drishti -k "system-images;android-30;google_apis;x86_64" \
    --device "pixel_4" --force

# ---- 4. Frida server matching the installed frida client -------------------------
FRIDA_VER="$(/opt/drishti/venv/bin/frida --version | tr -d '[:space:]')"
cd /opt/drishti/tools
curl -sLo frida-server.xz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VER}/frida-server-${FRIDA_VER}-android-x86_64.xz"
unxz -f frida-server.xz && chmod +x frida-server

# ---- 5. HOST-LEVEL EGRESS LOCKDOWN (defence in depth over the VPC rule) ----------
# Allow loopback (mitmproxy, adb) and the internal metadata/GCS path only.
cat >/opt/drishti/lockdown.sh <<'LOCK'
#!/bin/bash
set -eux
iptables -F OUTPUT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -d 169.254.169.254 -j ACCEPT          # GCE metadata
iptables -A OUTPUT -d 199.36.153.8/30 -j ACCEPT          # private.googleapis.com (GCS)
iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT               # internal VPC
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT           # keep IAP SSH alive
iptables -A OUTPUT -j DROP                               # everything else: black hole
netfilter-persistent save
echo "egress locked down"
LOCK
chmod +x /opt/drishti/lockdown.sh
/opt/drishti/lockdown.sh

# ---- 6. Containment self-test ----------------------------------------------------
cat >/opt/drishti/verify_containment.sh <<'VERIFY'
#!/bin/bash
# Fails loudly if the box can reach the internet. Run BEFORE staging any sample.
fail=0
echo "== nested virtualization =="
grep -cw vmx /proc/cpuinfo | grep -qv '^0$' && echo "  OK vmx present" || { echo "  FAIL no vmx"; fail=1; }
echo "== egress must be sealed =="
for target in https://example.com https://google.com http://1.1.1.1; do
  if curl -s -m 5 -o /dev/null "$target"; then echo "  FAIL reached $target"; fail=1;
  else echo "  OK blocked $target"; fi
done
echo "== external IP must be absent =="
if curl -s -m 3 -H 'Metadata-Flavor: Google' \
   'http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip' \
   | grep -q '[0-9]'; then echo "  FAIL has external IP"; fail=1; else echo "  OK no external IP"; fi
[ "$fail" -eq 0 ] && echo "CONTAINMENT OK — safe to stage samples" \
                  || { echo "CONTAINMENT FAILED — DO NOT STAGE MALWARE"; exit 1; }
VERIFY
chmod +x /opt/drishti/verify_containment.sh

cat >/etc/profile.d/drishti.sh <<'EOF'
export ANDROID_SDK_ROOT=/opt/android-sdk
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"
echo "DRISHTI DETONATOR — malware executes here. Nothing else runs on this box."
echo "  1. sudo /opt/drishti/verify_containment.sh     <-- ALWAYS run first"
echo "  2. stage a sample into /opt/drishti/samples/"
echo "  3. sudo /opt/drishti/venv/bin/python scripts/dynamic_analyze.py <apk> --out obs.json"
EOF

echo ready > /var/log/drishti-ready

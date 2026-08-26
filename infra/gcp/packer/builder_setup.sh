#!/usr/bin/env bash
# Immutable M3 tools image provisioner.
#
# Every step below was validated on a real n2-standard-4 GCE instance with nested
# virtualization. Notes marked FIX record a defect found during that validation, so the
# reasoning is not lost the next time this file is edited.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list
apt-get update

# FIX 1: the Android emulator's bundled qemu is dynamically linked against a large set
# of X11/xkb/GL/ALSA/PulseAudio/dbus libraries even with -no-window, because
# `-gpu swiftshader_indirect` still needs libGL/libEGL/libgbm. The previous list
# (qemu-kvm, jdk, unzip, curl, xz, python3-venv, pip, iptables-persistent,
# ca-certificates) left qemu-system-x86_64 unable to start at all:
#   qemu-system-x86_64: error while loading shared libraries: libxkbfile.so.1
apt-get install -y --no-install-recommends \
  qemu-kvm openjdk-17-jdk-headless unzip curl xz-utils \
  python3-venv python3-pip python3-dev build-essential \
  iptables-persistent ca-certificates openssl file \
  libpulse0 libnss3 libnspr4 libasound2 \
  libgl1 libglu1-mesa libegl1 libgbm1 libdrm2 \
  libx11-6 libx11-xcb1 libxcb1 libxcb-xkb1 libxcomposite1 libxcursor1 libxdamage1 \
  libxext6 libxfixes3 libxi6 libxrandr2 libxrender1 libxtst6 libxkbcommon0 \
  libxkbfile1 libxkbcommon-x11-0 libsm6 libice6 libxmu6 libxpm4 libxft2 \
  libxinerama1 libxss1 libxv1 \
  libdbus-1-3 libfontconfig1 libfreetype6 libglib2.0-0 \
  libatk1.0-0 libatk-bridge2.0-0 libcairo2 libpango-1.0-0 libcups2 \
  libgtk-3-0 libgdk-pixbuf-2.0-0 libopus0 libvpx7 libsnappy1v5 libwebp7

install -d -m 0755 /opt/android-sdk/cmdline-tools /opt/drishti/tools /opt/drishti/harness
curl --fail --location --proto '=https' --tlsv1.2 -o /tmp/tools.zip \
  https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip -q /tmp/tools.zip -d /opt/android-sdk/cmdline-tools
mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest

export ANDROID_SDK_ROOT=/opt/android-sdk
export ANDROID_HOME=/opt/android-sdk
export ANDROID_AVD_HOME=/root/.android/avd
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"

yes | sdkmanager --licenses >/dev/null
# FIX 2: platforms;android-30 added. avdmanager resolves the --device profile against an
# installed platform; without it AVD creation is brittle.
sdkmanager --install "platform-tools" "emulator" "build-tools;35.0.0" \
  "platforms;android-30" "system-images;android-30;google_apis;x86_64"

ln -sf /opt/android-sdk/platform-tools/adb /usr/local/bin/adb
ln -sf /opt/android-sdk/emulator/emulator /usr/local/bin/emulator
ln -sf /opt/android-sdk/build-tools/35.0.0/aapt /usr/local/bin/aapt

# FIX 3: verify by RUNNING the binary. `ldd` is useless here -- libQt6*AndroidEmu.so.6,
# libandroid-emu-*.so and libc++.so ship inside $SDK/emulator/lib64 and resolve through
# RPATH, so ldd reports them as "not found" on a perfectly good install.
/opt/android-sdk/emulator/emulator -version | head -3
# Root owns /dev/kvm (crw-rw---- root:kvm) so provisioning works, but the emulator's
# ProbeKVM also consults group membership for non-root operators.
getent group kvm >/dev/null || groupadd -r kvm
for u in ubuntu packer; do id "$u" >/dev/null 2>&1 && gpasswd -a "$u" kvm || true; done
emulator -accel-check

python3 -m venv /opt/drishti/venv
/opt/drishti/venv/bin/pip install --upgrade pip wheel
# FIX 4: frida must stay on the 16.x line. frida >= 17 imports typing.NotRequired
# (Python 3.11+) while Ubuntu 22.04 ships Python 3.10, so `import frida` raises
# ImportError -- which breaks collect_frida() inside dynamic_analyze.py, not merely a
# version probe. Revisit only when the base image moves to Python >= 3.11.
/opt/drishti/venv/bin/pip install "frida<17" "frida-tools<14" mitmproxy cryptography \
  pydantic pydantic-settings
/opt/drishti/venv/bin/python -c 'import frida; print("frida", frida.__version__)'

# FIX 5: read the version from the importable module, never from the `frida` CLI. The
# CLI crashed under FIX 4's conditions and produced an EMPTY version, so the old
# download URL 404'd and the image shipped with no frida-server whatsoever.
# --location is required because GitHub release assets redirect.
FRIDA_VERSION="$(/opt/drishti/venv/bin/python -c 'import frida; print(frida.__version__)' | tr -d '[:space:]')"
test -n "$FRIDA_VERSION"
curl --fail --location --proto '=https' --tlsv1.2 -o /tmp/frida-server.xz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz"
xz -df /tmp/frida-server.xz
install -m 0755 /tmp/frida-server /opt/drishti/tools/frida-server
file /opt/drishti/tools/frida-server | grep -q 'ELF 64-bit.*x86-64'
printf 'frida_client=%s\nfrida_server=%s\n' "$FRIDA_VERSION" "$FRIDA_VERSION" \
  > /opt/drishti/tools/frida-version.txt

install -m 0644 /tmp/frida_hooks.js /opt/drishti/harness/frida_hooks.js
cp -a /tmp/drishti /opt/drishti/harness/drishti
install -m 0755 /tmp/dynamic_analyze.py /opt/drishti/harness/dynamic_analyze.py
install -m 0755 /tmp/verify_containment.py /opt/drishti/harness/verify_containment.py
install -m 0755 /tmp/emulator_control.sh /opt/drishti/emulator_control.sh
install -m 0755 /tmp/runtime_lockdown.sh /opt/drishti/runtime_lockdown.sh
install -m 0755 /tmp/runtime_prepare.sh /opt/drishti/runtime_prepare.sh
install -m 0644 /tmp/drishti_proxy.py /opt/drishti/drishti_proxy.py
PYTHONPATH=/opt/drishti/harness /opt/drishti/venv/bin/python \
  -c 'import dynamic_analyze; print("harness import OK", dynamic_analyze.HARNESS_VERSION)'

echo no | avdmanager create avd -n drishti \
  -k "system-images;android-30;google_apis;x86_64" --device pixel_4 --force

EMU_ARGS="-no-window -no-audio -no-boot-anim -no-snapshot-load -gpu swiftshader_indirect -accel on"

hard_stop() {
  adb emu kill >/dev/null 2>&1 || true; sleep 3
  pkill -f qemu-system-x86_64 2>/dev/null || true
  adb kill-server >/dev/null 2>&1 || true; sleep 4
}
boot_up() {
  adb start-server >/dev/null 2>&1 || true
  nohup /opt/android-sdk/emulator/emulator -avd drishti $EMU_ARGS >>/tmp/emulator.log 2>&1 &
  sleep 5
  adb wait-for-device
  for _ in $(seq 1 120); do
    if [ "$(adb get-state 2>/dev/null | tr -d '\r')" = device ] &&
       [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; then return 0; fi
    sleep 5
  done
  return 1
}

# Generate the mitmproxy CA offline; the proxy itself runs only on the sealed runtime.
timeout 25 /opt/drishti/venv/bin/mitmdump --listen-host 127.0.0.1 --listen-port 8081 \
  --set confdir=/root/.mitmproxy >/tmp/mitm-genca.log 2>&1 || true
test -f /root/.mitmproxy/mitmproxy-ca-cert.pem

boot_up
# The proxy is NOT set here any more. `settings put global http_proxy` is guest state,
# and the harness restores the `clean` snapshot before every sample: a restore reverts
# it, so every run after the first would be unproxied and silently capture no flows —
# the same trap as the system CA (FIX 6 below). emulator_control.sh now passes
# -http-proxy at launch instead, which is a QEMU-level flag no restore can undo.

# Exercise the inert fixture once so the clean image is a booted, warmed state, then
# remove it. The validation fixture must not persist into the image.
adb install -r /tmp/m3-inert-fixture.apk
adb shell monkey -p in.drishti.fixture.m3 -c android.intent.category.LAUNCHER 1 || true
adb uninstall in.drishti.fixture.m3
test -z "$(adb shell pm path in.drishti.fixture.m3)"

# FIX 6: HTTPS system-CA injection is optional and intentionally absent. `Cipher.doFinal`
# observes plaintext before encryption, while `-writable-system` made clean boots brittle.
# The snapshot is cut only after the authored fixture is removed.
adb emu avd snapshot delete clean 2>&1 | tail -1 || true
sleep 3
adb emu avd snapshot save clean
sleep 20
adb emu avd snapshot list | grep -qi clean

# FIX 7: assert restore semantics. A snapshot that saves but restores wrongly would
# silently allow one sample to contaminate the next.
adb shell 'touch /data/local/tmp/dirty_marker'
adb emu avd snapshot load clean
sleep 25
adb wait-for-device
for _ in $(seq 1 60); do
  [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break; sleep 3
done
test -z "$(adb shell 'ls /data/local/tmp/dirty_marker 2>/dev/null' | tr -d '\r')"

mv /root/.mitmproxy /opt/drishti/mitmproxy
chmod -R go-rwx /opt/drishti/mitmproxy
rm -f /tmp/m3-inert-fixture.apk /tmp/tools.zip
hard_stop

# Image retains only tools, a clean AVD snapshot, and the local proxy CA. No validation
# fixture, malware sample, cloud key, or external-service credential is present.
sync

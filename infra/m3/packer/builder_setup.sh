#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list
apt-get update
apt-get install -y --no-install-recommends qemu-kvm openjdk-17-jdk-headless unzip curl xz-utils \
  python3-venv python3-pip iptables-persistent ca-certificates
install -d -m 0755 /opt/android-sdk/cmdline-tools /opt/drishti/{tools,harness}
curl --fail --proto '=https' --tlsv1.2 -o /tmp/tools.zip \
  https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
unzip -q /tmp/tools.zip -d /opt/android-sdk/cmdline-tools
mv /opt/android-sdk/cmdline-tools/cmdline-tools /opt/android-sdk/cmdline-tools/latest
export ANDROID_SDK_ROOT=/opt/android-sdk
export PATH="$ANDROID_SDK_ROOT/cmdline-tools/latest/bin:$ANDROID_SDK_ROOT/platform-tools:$ANDROID_SDK_ROOT/emulator:$PATH"
yes | sdkmanager --licenses >/dev/null
sdkmanager "platform-tools" "emulator" "build-tools;35.0.0" "system-images;android-30;google_apis;x86_64"
ln -sf /opt/android-sdk/platform-tools/adb /usr/local/bin/adb
ln -sf /opt/android-sdk/emulator/emulator /usr/local/bin/emulator
ln -sf /opt/android-sdk/build-tools/35.0.0/aapt /usr/local/bin/aapt
echo no | avdmanager create avd -n drishti -k "system-images;android-30;google_apis;x86_64" --device pixel_4 --force

python3 -m venv /opt/drishti/venv
/opt/drishti/venv/bin/pip install --upgrade pip
/opt/drishti/venv/bin/pip install frida frida-tools mitmproxy cryptography pydantic
FRIDA_VERSION="$(/opt/drishti/venv/bin/frida --version)"
curl --fail --proto '=https' --tlsv1.2 -o /tmp/frida-server.xz \
  "https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/frida-server-${FRIDA_VERSION}-android-x86_64.xz"
xz -d /tmp/frida-server.xz
install -m 0755 /tmp/frida-server /opt/drishti/tools/frida-server
install -m 0644 /tmp/frida_hooks.js /opt/drishti/harness/frida_hooks.js
cp -a /tmp/drishti /opt/drishti/harness/drishti
install -m 0755 /tmp/dynamic_analyze.py /opt/drishti/harness/dynamic_analyze.py
install -m 0755 /tmp/verify_containment.py /opt/drishti/harness/verify_containment.py
install -m 0755 /tmp/emulator_control.sh /opt/drishti/emulator_control.sh
install -m 0755 /tmp/runtime_lockdown.sh /opt/drishti/runtime_lockdown.sh
install -m 0755 /tmp/runtime_prepare.sh /opt/drishti/runtime_prepare.sh
install -m 0644 /tmp/fake_c2.py /opt/drishti/fake_c2.py
install -d -m 0755 /opt/drishti/inert-banking-fixtures
install -m 0644 /tmp/bank-one.apk /opt/drishti/inert-banking-fixtures/bank-one.apk
install -m 0644 /tmp/bank-two.apk /opt/drishti/inert-banking-fixtures/bank-two.apk

/opt/android-sdk/emulator/emulator -avd drishti -no-window -no-audio -no-boot-anim -writable-system -gpu swiftshader_indirect >/tmp/emulator.log 2>&1 &
emulator_pid=$!
trap 'kill "$emulator_pid" 2>/dev/null || true' EXIT
adb wait-for-device
timeout 300 bash -c 'until test "$(adb shell getprop sys.boot_completed | tr -d "\r")" = 1; do sleep 2; done'

/opt/drishti/venv/bin/mitmdump --listen-host 0.0.0.0 --listen-port 8080 --set block_global=false \
  -s /opt/drishti/fake_c2.py >/tmp/mitmproxy.log 2>&1 &
proxy_pid=$!
sleep 3
adb shell settings put global http_proxy 10.0.2.2:8080
# Builder-only CA installation. The CA and inert fixture are removed before imaging.
adb root
adb remount
ca_hash="$(openssl x509 -inform PEM -subject_hash_old -in /root/.mitmproxy/mitmproxy-ca-cert.pem | head -1)"
cp /root/.mitmproxy/mitmproxy-ca-cert.pem "/tmp/${ca_hash}.0"
adb push "/tmp/${ca_hash}.0" "/system/etc/security/cacerts/${ca_hash}.0"
adb shell chmod 644 "/system/etc/security/cacerts/${ca_hash}.0"
adb install -r /tmp/m3-inert-fixture.apk
adb shell monkey -p in.drishti.fixture.m3 -c android.intent.category.LAUNCHER 1
adb uninstall in.drishti.fixture.m3
test -z "$(adb shell pm path in.drishti.fixture.m3)"
adb emu avd snapshot save clean
kill "$proxy_pid"
mv /root/.mitmproxy /opt/drishti/mitmproxy
chmod -R go-rwx /opt/drishti/mitmproxy
rm -f /tmp/m3-inert-fixture.apk /tmp/bank-one.apk /tmp/bank-two.apk /tmp/*.0 /tmp/tools.zip
adb emu kill
wait "$emulator_pid" || true
trap - EXIT

# Image retains only tools, clean AVD, proxy CA, and explicitly inert banking fixtures.
# It contains no validation fixture, malware sample, cloud key, or external-service credential.
sync

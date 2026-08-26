#!/usr/bin/env bash
# Provision the m3-detonator VM in place: Android SDK, emulator, AVD, frida, harness.
#
# Runs ON THE VM, not on a laptop. Idempotent: every step writes a stamp under
# /opt/drishti/.provision and re-running skips completed steps. Run one step at a
# time while debugging:  ./detonator_provision.sh <step>   (default: all)
#
# This is a MANUAL provision, not a Packer image. That is a deliberate, recorded
# deviation (STATUS.md) taken to reach a first live detonation inside the deadline;
# the runtime marker below says "manual" so no artifact can claim an immutable image.
set -euo pipefail

SDK_ROOT=/opt/android-sdk
DRISHTI_ROOT=/opt/drishti
STAMPS="${DRISHTI_ROOT}/.provision"
AVD_NAME=drishti
SERIAL=emulator-5554
SYSIMG="system-images;android-33;google_apis;x86_64"   # google_apis, NOT playstore: playstore images refuse `adb root`
BUILD_TOOLS="build-tools;33.0.2"
# Pinned. Ubuntu 22.04's python3 is 3.10 but the drishti contracts need 3.11
# (`from datetime import UTC`), so the harness runs on a uv-managed 3.11.
PY_VERSION=3.11
# frida client and frida-server MUST be the same version; 16.7.19 is the pair
# verified against this emulator image (CLAUDE.md "Verified lab facts" #2/#3).
FRIDA_PIN=16.7.19
RUNTIME_IMAGE_ID="m3-detonator-manual-20260826"

export ANDROID_SDK_ROOT="${SDK_ROOT}"
export ANDROID_HOME="${SDK_ROOT}"
export ANDROID_AVD_HOME="${DRISHTI_ROOT}/avd"
export PATH="${SDK_ROOT}/cmdline-tools/latest/bin:${SDK_ROOT}/platform-tools:${SDK_ROOT}/emulator:${DRISHTI_ROOT}/bin:${PATH}"

log() { echo "[provision $(date -u +%H:%M:%S)] $*"; }
stamped() { [[ -f "${STAMPS}/$1" ]]; }
stamp() { mkdir -p "${STAMPS}"; touch "${STAMPS}/$1"; }

step_dirs() {
  sudo mkdir -p "${DRISHTI_ROOT}"/{bin,harness,results,scratch,avd} "${SDK_ROOT}" /etc/drishti /var/lib/drishti
  sudo chown -R "$(id -un):$(id -gn)" "${DRISHTI_ROOT}" "${SDK_ROOT}"
  sudo chmod 700 /var/lib/drishti
}

step_disk() {
  # The image was 10GB and the disk is 200GB. growpart/resize2fs are no-ops when
  # the partition already spans the disk, so this is safe to re-run.
  sudo growpart /dev/sda 1 || true
  sudo resize2fs /dev/sda1 || true
  df -h /
}

step_kvm() {
  test -e /dev/kvm || { echo "FATAL: /dev/kvm missing — nested virt is off"; exit 1; }
  sudo usermod -aG kvm "$(id -un)"
  # NOTE: `emulator -accel-check` fails for a non-root user because it tests kvm
  # group membership of the *current* process, which does not see a group added
  # after login. Do not chase it; `ls -l /dev/kvm` + a booting emulator is the test.
  ls -l /dev/kvm
}

step_apt() {
  stamped apt && { log "apt already done"; return; }
  sudo DEBIAN_FRONTEND=noninteractive apt-get update -y
  # libxkbfile1 is the non-obvious one: without it qemu-system-x86_64 refuses to
  # start even with -no-window, because swiftshader_indirect still initialises the
  # Qt/GL stack. The libGL/libEGL/libgbm trio is required for the same reason.
  sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
    openjdk-17-jdk-headless unzip curl xz-utils socat iptables \
    libxkbfile1 libgl1 libegl1 libgbm1 libglu1-mesa \
    libnss3 libxcomposite1 libxcursor1 libxi6 libxtst6 libxdamage1 libxrandr2 \
    libasound2 libpulse0 libdrm2 libxkbcommon0 libx11-xcb1 libxshmfence1 \
    libfontconfig1 libfreetype6 libdbus-1-3 libxrender1 libxext6
  stamp apt
}

step_sdk() {
  stamped sdk && { log "sdk already done"; return; }
  if [[ ! -x "${SDK_ROOT}/cmdline-tools/latest/bin/sdkmanager" ]]; then
    curl -fL --retry 5 --retry-delay 3 -o /tmp/cmdline-tools.zip \
      https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
    rm -rf /tmp/cmdline-tools && unzip -q /tmp/cmdline-tools.zip -d /tmp/cmdline-tools
    mkdir -p "${SDK_ROOT}/cmdline-tools"
    rm -rf "${SDK_ROOT}/cmdline-tools/latest"
    mv /tmp/cmdline-tools/cmdline-tools "${SDK_ROOT}/cmdline-tools/latest"
  fi
  yes | sdkmanager --licenses >/dev/null 2>&1 || true
  sdkmanager --install "platform-tools" "emulator" "platforms;android-33" "${BUILD_TOOLS}" "${SYSIMG}"
  # aapt is how the harness reads the package name out of an APK without executing it.
  sudo ln -sf "${SDK_ROOT}/${BUILD_TOOLS//;//}/aapt" /usr/local/bin/aapt
  # Verify with `emulator -version`. NEVER with ldd: Qt and android-emu resolve via
  # RPATH out of $SDK/emulator/lib64, so ldd reports false "not found".
  emulator -version | head -3
  adb version
  stamp sdk
}

step_avd() {
  stamped avd && { log "avd already done"; return; }
  mkdir -p "${ANDROID_AVD_HOME}"
  echo no | avdmanager create avd -n "${AVD_NAME}" -k "${SYSIMG}" --force
  cat >> "${ANDROID_AVD_HOME}/${AVD_NAME}.avd/config.ini" <<'EOF'
hw.ramSize=3072
disk.dataPartition.size=6G
hw.gpu.enabled=yes
hw.gpu.mode=swiftshader_indirect
hw.audioInput=no
hw.audioOutput=no
EOF
  stamp avd
}

step_python() {
  stamped python && { log "python already done"; return; }
  # uv gives an exact CPython 3.11 without a PPA. The distro python3.10 cannot
  # import the contracts (`from datetime import UTC` is 3.11+).
  if [[ ! -x "${HOME}/.local/bin/uv" ]]; then
    curl -fLsS --retry 5 https://astral.sh/uv/install.sh | sh
  fi
  export PATH="${HOME}/.local/bin:${PATH}"
  uv python install "${PY_VERSION}"
  uv venv --python "${PY_VERSION}" "${DRISHTI_ROOT}/venv"
  # Only what the detonation path imports: contracts (pydantic, cryptography),
  # logging (structlog), collector (frida). Nothing from the ML/static stack.
  VIRTUAL_ENV="${DRISHTI_ROOT}/venv" uv pip install \
    "pydantic>=2.9,<3" "cryptography>=43,<44" "structlog>=24.4,<25" "frida==${FRIDA_PIN}"
  "${DRISHTI_ROOT}/venv/bin/python" -c "import frida, sys; print('frida', frida.__version__, 'py', sys.version)"
  stamp python
}

step_proxy() {
  stamped proxy && { log "proxy already done"; return; }
  # mitmproxy goes into the SAME uv-managed 3.11 venv as the harness, not into the
  # system python: drishti_proxy.py imports drishti.contracts.*, which needs 3.11
  # (StrEnum, datetime.UTC). Ubuntu 22.04's 3.10 raises on the import and mitmdump
  # dies — silently, because runtime_prepare.sh nohups it.
  export PATH="${HOME}/.local/bin:${PATH}"
  VIRTUAL_ENV="${DRISHTI_ROOT}/venv" uv pip install "mitmproxy>=11,<12"
  "${DRISHTI_ROOT}/venv/bin/mitmdump" --version | head -2
  # Generate the CA into the confdir runtime_prepare.sh passes, now, while this host
  # can still write it. Nothing on the runtime network reaches a mirror or a CA, and
  # the emulator is pointed at this proxy at launch (see emulator_control.sh), so a
  # first-request CA generation would race the first sample.
  mkdir -p "${DRISHTI_ROOT}/mitmproxy"
  timeout 25 "${DRISHTI_ROOT}/venv/bin/mitmdump" --listen-host 127.0.0.1 --listen-port 8081 \
    --set confdir="${DRISHTI_ROOT}/mitmproxy" >/tmp/mitm-genca.log 2>&1 || true
  test -f "${DRISHTI_ROOT}/mitmproxy/mitmproxy-ca-cert.pem"
  # The addon itself is shipped by detonator_deploy.sh (code, from the repo, over IAP)
  # to /opt/drishti/drishti_proxy.py. Import it through the same PYTHONPATH mitmdump
  # will use, so a missing dependency fails HERE and not inside a nohup'd proxy.
  # No stamp unless that import succeeds: an unstamped step re-runs, and `uv pip
  # install` is a no-op the second time, so the cost of retrying is a few seconds.
  if [[ ! -f "${DRISHTI_ROOT}/drishti_proxy.py" ]]; then
    log "drishti_proxy.py absent — run detonator_deploy.sh, then re-run: $0 proxy"
    return 1
  fi
  DRISHTI_FLOW_LOG="${DRISHTI_ROOT}/results/flows.jsonl" \
  PYTHONPATH="${DRISHTI_ROOT}/lib" "${DRISHTI_ROOT}/venv/bin/python" - <<PY
import importlib.util as u, sys
spec = u.spec_from_file_location("drishti_proxy", "${DRISHTI_ROOT}/drishti_proxy.py")
module = u.module_from_spec(spec)
sys.modules["drishti_proxy"] = module   # @dataclass resolves through sys.modules
spec.loader.exec_module(module)
print("proxy addons OK:", [type(a).__name__ for a in module.addons])
PY
  stamp proxy
}

step_marker() {
  # Runtime admission markers. require_sealed_runtime() refuses to run without all
  # three: the env var, this marker file, and /dev/kvm.
  echo "${RUNTIME_IMAGE_ID}" | sudo tee "${DRISHTI_ROOT}/RUNTIME_IMAGE" >/dev/null
  if [[ ! -f /etc/drishti/containment-signing.key ]]; then
    # Ed25519 seed, 32 bytes hex. Generated on the VM and never leaves it.
    openssl rand -hex 32 | sudo tee /etc/drishti/containment-signing.key >/dev/null
    sudo chmod 600 /etc/drishti/containment-signing.key
  fi
  sudo chown "$(id -un)" /etc/drishti/containment-signing.key /etc/drishti
  cat "${DRISHTI_ROOT}/RUNTIME_IMAGE"
}

step_boot() {
  if adb -s "${SERIAL}" shell getprop sys.boot_completed 2>/dev/null | grep -q 1; then
    log "emulator already booted"; return
  fi
  adb start-server
  # No -writable-system: with it, `adb remount` claims success while /system stays
  # read-only and `adb reboot` can wedge the guest `offline` until the AVD is purged.
  # -http-proxy at LAUNCH, never `settings put global http_proxy` in the guest: a
  # snapshot restore reverts guest state, so the guest-side setting would vanish before
  # the second sample and every later run would capture nothing. On an already-provisioned
  # VM do NOT re-run this step to pick the flag up (it -wipe-data's the AVD and step_snapshot
  # would re-cut `clean`) — restart via emulator_control.sh instead.
  nohup emulator -avd "${AVD_NAME}" -no-window -no-audio -no-boot-anim \
    -gpu swiftshader_indirect -no-snapshot-load -wipe-data \
    -http-proxy "${DRISHTI_EMULATOR_PROXY:-10.0.2.2:8080}" \
    -netdelay none -netspeed full \
    > "${DRISHTI_ROOT}/emulator.log" 2>&1 &
  log "waiting for device"
  adb wait-for-device
  for _ in $(seq 1 120); do
    [[ "$(adb -s "${SERIAL}" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]] && break
    sleep 5
  done
  adb -s "${SERIAL}" shell getprop sys.boot_completed
}

step_frida() {
  # Version comes from the IMPORTABLE MODULE, never from `frida --version` on the
  # CLI: a mismatch here ships a VM with no working frida-server and a 404 that
  # nobody notices until detonation.
  local ver
  ver="$("${DRISHTI_ROOT}/venv/bin/python" -c 'import frida; print(frida.__version__)')"
  log "frida module version ${ver}"
  local xz="/tmp/frida-server-${ver}.xz"
  if [[ ! -f "/tmp/frida-server-${ver}" ]]; then
    # --location: GitHub release assets are a redirect to objects.githubusercontent.com
    curl -fL --retry 5 --retry-delay 3 -o "${xz}" \
      "https://github.com/frida/frida/releases/download/${ver}/frida-server-${ver}-android-x86_64.xz"
    unxz -f "${xz}"
  fi
  adb -s "${SERIAL}" root >/dev/null 2>&1 || true
  adb -s "${SERIAL}" wait-for-device
  adb -s "${SERIAL}" push "/tmp/frida-server-${ver}" /data/local/tmp/frida-server
  adb -s "${SERIAL}" shell chmod 755 /data/local/tmp/frida-server
  adb -s "${SERIAL}" shell 'su 0 sh -c "setenforce 0" 2>/dev/null || setenforce 0' || true
  adb -s "${SERIAL}" shell 'nohup /data/local/tmp/frida-server -D >/dev/null 2>&1 &' || true
  sleep 3
  "${DRISHTI_ROOT}/venv/bin/python" - <<'PY'
import frida
d = frida.get_usb_device(timeout=15)
print("frida device:", d.id, d.name)
print("processes:", len(d.enumerate_processes()))
PY
}

step_snapshot() {
  # Cut the clean snapshot only once the guest is fully booted AND frida-server is
  # in place, so a restore lands on a guest that is ready to instrument.
  adb -s "${SERIAL}" emu avd snapshot save clean
  adb -s "${SERIAL}" emu avd snapshot list || true
}

case "${1:-all}" in
  all)
    step_dirs; step_disk; step_kvm; step_apt; step_sdk; step_avd; step_python
    step_marker; step_boot; step_frida; step_snapshot
    # Last, and allowed to defer: the proxy verifies the addon it will actually load,
    # and that file arrives from the laptop via detonator_deploy.sh, which runs after
    # this script on a first provision. The step stays unstamped so the retry works.
    step_proxy || log "proxy step DEFERRED — run detonator_deploy.sh, then: $0 proxy"
    ;;
  *) "step_$1" ;;
esac
log "done: ${1:-all}"

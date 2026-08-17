#!/usr/bin/env bash
# Build the audited inert canary APK without changing the system toolchain.
#
# This script COMPILES source only. It deliberately contains no adb, emulator, install,
# monkey, or launch command: execution belongs exclusively to the sealed GCP runtime.
set -euo pipefail

TOOLS="${DRISHTI_TOOLS:-$HOME/drishti-tools}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JDK_VERSION="17.0.13+11"
GRADLE_VERSION="8.10.2"
ANDROID_PLATFORM="android-35"
BUILD_TOOLS="35.0.0"

step() { printf '==> %s\n' "$*"; }
have() { [[ -x "$1" ]]; }

mkdir -p "$TOOLS"

# AGP 8.7.3 requires JDK 17. Keep it user-local; the host JDK is intentionally
# untouched and the path is never committed.
export JAVA_HOME="$TOOLS/jdk-${JDK_VERSION}"
if ! have "$JAVA_HOME/bin/javac"; then
  step "downloading Temurin JDK ${JDK_VERSION}"
  archive="$TOOLS/temurin-jdk17.tar.gz"
  curl --fail --location --retry 5 --retry-all-errors --output "$archive" \
    "https://github.com/adoptium/temurin17-binaries/releases/download/jdk-17.0.13%2B11/OpenJDK17U-jdk_x64_linux_hotspot_17.0.13_11.tar.gz"
  tar -xzf "$archive" -C "$TOOLS"
  rm -f "$archive"
fi
export PATH="$JAVA_HOME/bin:$PATH"

GRADLE_HOME="$TOOLS/gradle-${GRADLE_VERSION}"
if ! have "$GRADLE_HOME/bin/gradle"; then
  step "downloading Gradle ${GRADLE_VERSION}"
  archive="$TOOLS/gradle-${GRADLE_VERSION}-bin.zip"
  curl --fail --location --retry 5 --retry-all-errors --output "$archive" \
    "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"
  unzip -q "$archive" -d "$TOOLS"
  rm -f "$archive"
fi
export PATH="$GRADLE_HOME/bin:$PATH"

export ANDROID_HOME="$TOOLS/android-sdk"
SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
if ! have "$SDKMANAGER"; then
  step "downloading Android command-line tools"
  archive="$TOOLS/android-commandline-tools.zip"
  mkdir -p "$ANDROID_HOME/cmdline-tools"
  curl --fail --location --retry 5 --retry-all-errors --output "$archive" \
    "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
  unzip -q "$archive" -d "$ANDROID_HOME/cmdline-tools"
  mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
  rm -f "$archive"
fi

accept_licenses() {
  # `yes` gets SIGPIPE (141) once sdkmanager has consumed all answers. With
  # `pipefail`, blindly piping it into sdkmanager turns successful acceptance into
  # a failed build. The authority is sdkmanager's second PIPESTATUS slot.
  local statuses
  set +e
  yes | "$SDKMANAGER" --licenses >/dev/null
  statuses=("${PIPESTATUS[@]}")
  set -e
  if [[ "${statuses[1]}" -ne 0 ]]; then
    printf 'sdkmanager license acceptance failed (sdkmanager rc=%s)\n' "${statuses[1]}" >&2
    return "${statuses[1]}"
  fi
}

if [[ ! -d "$ANDROID_HOME/platforms/$ANDROID_PLATFORM" ]]; then
  step "installing Android platform ${ANDROID_PLATFORM} and build-tools ${BUILD_TOOLS}"
  accept_licenses
  "$SDKMANAGER" "platforms;${ANDROID_PLATFORM}" "build-tools;${BUILD_TOOLS}" >/dev/null
fi

step "compiling the inert canary"
printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$HERE/local.properties"
(
  cd "$HERE"
  gradle --no-daemon --console=plain assembleDebug
)

mkdir -p "$HERE/dist"
cp "$HERE/app/build/outputs/apk/debug/app-debug.apk" "$HERE/dist/canary.apk"
step "artifact ready (not executed)"
sha256sum "$HERE/dist/canary.apk"

#!/usr/bin/env bash
# Build the inert canary APK, provisioning its toolchain if absent.
#
# docs/PHASE_0_FOUNDATIONS.md T0.9, CLAUDE.md §4.
#
# **Building an APK is not running one.** This compiles source we wrote ourselves and
# whose entire behaviour is enumerated in canary/README.md; no sample is involved and
# nothing is executed. Detonation happens only on the sealed GCE detonator.
#
# Everything installs under $DRISHTI_TOOLS (default ~/drishti-tools) and **needs no root**.
# The system JDK stays untouched — Ubuntu 22.04 ships JDK 11 and `apt`'s Gradle is 4.4.1,
# both far too old for AGP 8.7.3, and pinning our own versions is more reproducible than
# arguing with the distro.
set -euo pipefail

TOOLS="${DRISHTI_TOOLS:-$HOME/drishti-tools}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# AGP 8.7.3 requires JDK 17 and Gradle 8.9+; compileSdk 35 requires platform 35.
JDK_VERSION="17.0.13+11"
JDK_TARBALL="OpenJDK17U-jdk_x64_linux_hotspot_${JDK_VERSION/+/_}.tar.gz"
JDK_URL="https://github.com/adoptium/temurin17-binaries/releases/download/jdk-${JDK_VERSION//+/%2B}/${JDK_TARBALL}"
GRADLE_VERSION="8.10.2"
CMDLINE_TOOLS_URL="https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
ANDROID_PLATFORM="android-35"
BUILD_TOOLS="35.0.0"

GREEN=$'\033[32m'; DIM=$'\033[2m'; RESET=$'\033[0m'
[[ -t 1 ]] || { GREEN=""; DIM=""; RESET=""; }
step() { echo "${GREEN}==>${RESET} $*"; }
skip() { echo "${DIM}    already present: $*${RESET}"; }

mkdir -p "$TOOLS"

# ─── JDK 17 ──────────────────────────────────────────────────────────────────
export JAVA_HOME="$TOOLS/jdk-${JDK_VERSION}"
if [[ -x "$JAVA_HOME/bin/javac" ]]; then
  skip "JDK ${JDK_VERSION}"
else
  step "fetching JDK ${JDK_VERSION} (no root; system JDK untouched)"
  curl -fsSL --retry 5 -o "$TOOLS/jdk.tar.gz" "$JDK_URL"
  tar -xzf "$TOOLS/jdk.tar.gz" -C "$TOOLS"
  rm -f "$TOOLS/jdk.tar.gz"
fi
export PATH="$JAVA_HOME/bin:$PATH"

# ─── Gradle ──────────────────────────────────────────────────────────────────
GRADLE_HOME="$TOOLS/gradle-${GRADLE_VERSION}"
if [[ -x "$GRADLE_HOME/bin/gradle" ]]; then
  skip "Gradle ${GRADLE_VERSION}"
else
  step "fetching Gradle ${GRADLE_VERSION}"
  curl -fsSL --retry 5 -o "$TOOLS/gradle.zip" \
    "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip"
  unzip -q -o "$TOOLS/gradle.zip" -d "$TOOLS"
  rm -f "$TOOLS/gradle.zip"
fi
export PATH="$GRADLE_HOME/bin:$PATH"

# ─── Android SDK ─────────────────────────────────────────────────────────────
export ANDROID_HOME="$TOOLS/android-sdk"
SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
if [[ -x "$SDKMANAGER" ]]; then
  skip "Android cmdline-tools"
else
  step "fetching Android cmdline-tools"
  mkdir -p "$ANDROID_HOME/cmdline-tools"
  curl -fsSL --retry 5 -o "$TOOLS/cmdline-tools.zip" "$CMDLINE_TOOLS_URL"
  unzip -q -o "$TOOLS/cmdline-tools.zip" -d "$ANDROID_HOME/cmdline-tools"
  # The zip unpacks to `cmdline-tools/`; sdkmanager insists on being under `latest/`.
  rm -rf "$ANDROID_HOME/cmdline-tools/latest"
  mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
  rm -f "$TOOLS/cmdline-tools.zip"
fi

if [[ -d "$ANDROID_HOME/platforms/$ANDROID_PLATFORM" ]]; then
  skip "$ANDROID_PLATFORM + build-tools $BUILD_TOOLS"
else
  step "accepting SDK licences and installing $ANDROID_PLATFORM"
  yes 2>/dev/null | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
  "$SDKMANAGER" "platforms;$ANDROID_PLATFORM" "build-tools;$BUILD_TOOLS" "platform-tools" \
    >/dev/null
fi

# ─── Build ───────────────────────────────────────────────────────────────────
step "building the canary APK"
cd "$HERE"
echo "sdk.dir=$ANDROID_HOME" > local.properties   # gitignored; machine-specific
gradle --no-daemon --console=plain assembleDebug

# The artifact path is canary/dist/, NOT Gradle's build/outputs/. git cannot re-include a
# file whose parent directory is excluded, so a `!` allowlist inside an ignored build/
# directory can never fire — tests/contract/test_repo_invariants.py guards both directions.
mkdir -p "$HERE/dist"
cp "$HERE/app/build/outputs/apk/debug/app-debug.apk" "$HERE/dist/canary-debug.apk"

step "done"
ls -la "$HERE/dist/canary-debug.apk"
echo "sha256 $(sha256sum "$HERE/dist/canary-debug.apk" | cut -d' ' -f1)"

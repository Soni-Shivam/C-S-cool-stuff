#!/usr/bin/env bash
# Build the DRISHTI Shield guard app.
#
# COMPILE ONLY. Like canary/build.sh, this script deliberately contains no adb,
# emulator, or install command — installation is scripts/demo_up.sh's job, and
# keeping the two apart means "did we build it" and "did we put it on a device" are
# separate questions with separate answers.
set -euo pipefail

TOOLS="${DRISHTI_TOOLS:-$HOME/drishti-tools}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export JAVA_HOME="${JAVA_HOME:-$TOOLS/jdk-17.0.13+11}"   # AGP 8.7 requires JDK 17
export ANDROID_HOME="${ANDROID_HOME:-$TOOLS/android-sdk}"
export PATH="$JAVA_HOME/bin:$TOOLS/gradle-8.10.2/bin:$PATH"

printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$HERE/local.properties"
( cd "$HERE" && gradle --no-daemon --console=plain assembleDebug "$@" )

mkdir -p "$HERE/dist"
cp "$HERE/app/build/outputs/apk/debug/app-debug.apk" "$HERE/dist/drishti-shield.apk"
printf '==> built (not installed): %s\n' "$HERE/dist/drishti-shield.apk"
sha256sum "$HERE/dist/drishti-shield.apk"

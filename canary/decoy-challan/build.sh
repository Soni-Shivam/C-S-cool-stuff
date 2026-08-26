#!/usr/bin/env bash
# Build the inert RTO Challan decoy.
#
# COMPILE ONLY, and gated: verify_inert.sh runs first and a failure aborts the build.
# Like canary/build.sh this script contains no adb, emulator, install, or launch
# command.
set -euo pipefail

TOOLS="${DRISHTI_TOOLS:-$HOME/drishti-tools}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The gate. If the decoy ever grows a real capability, nothing downstream builds.
bash "$HERE/verify_inert.sh"

export JAVA_HOME="${JAVA_HOME:-$TOOLS/jdk-17.0.13+11}"
export ANDROID_HOME="${ANDROID_HOME:-$TOOLS/android-sdk}"
export PATH="$JAVA_HOME/bin:$TOOLS/gradle-8.10.2/bin:$PATH"

printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$HERE/local.properties"
( cd "$HERE" && gradle --no-daemon --console=plain assembleDebug "$@" )

mkdir -p "$HERE/dist"
# Named as the lure, because the demo's whole point is that the name is a lie the
# static surface cannot tell.
cp "$HERE/app/build/outputs/apk/debug/app-debug.apk" "$HERE/dist/RTO_Challan.apk"
printf '==> built (not executed): %s\n' "$HERE/dist/RTO_Challan.apk"
sha256sum "$HERE/dist/RTO_Challan.apk"

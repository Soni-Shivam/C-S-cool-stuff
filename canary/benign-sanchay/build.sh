#!/usr/bin/env bash
# Build the inert benign control sample, "Sanchay Expenses".
#
# COMPILE ONLY, and gated: verify_inert.sh runs first and a failure aborts the build.
# Like the decoy's build.sh this script contains no adb, emulator, install, or launch
# command — installation is scripts/demo_up.sh's and scripts/demo_run.sh's job.
set -euo pipefail

TOOLS="${DRISHTI_TOOLS:-$HOME/drishti-tools}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# The gate. If the control sample ever grows a real capability — or a banking roster,
# or a service component — nothing downstream builds.
bash "$HERE/verify_inert.sh"

export JAVA_HOME="${JAVA_HOME:-$TOOLS/jdk-17.0.13+11}"
export ANDROID_HOME="${ANDROID_HOME:-$TOOLS/android-sdk}"
export PATH="$JAVA_HOME/bin:$TOOLS/gradle-8.10.2/bin:$PATH"

printf 'sdk.dir=%s\n' "$ANDROID_HOME" > "$HERE/local.properties"
( cd "$HERE" && gradle --no-daemon --console=plain assembleDebug "$@" )

mkdir -p "$HERE/dist"
cp "$HERE/app/build/outputs/apk/debug/app-debug.apk" "$HERE/dist/Sanchay_Expenses.apk"
printf '==> built (not executed): %s\n' "$HERE/dist/Sanchay_Expenses.apk"
sha256sum "$HERE/dist/Sanchay_Expenses.apk"

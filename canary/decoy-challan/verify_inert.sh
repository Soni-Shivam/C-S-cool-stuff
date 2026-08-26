#!/usr/bin/env bash
# Prove the decoy is inert, by grep, before anyone builds or installs it.
#
# The README makes a claim. This script is what turns that claim into something a
# reviewer can check in two seconds — the same reason `verify_containment.py` exists
# rather than a paragraph asserting containment.
#
# It scans CODE ONLY. Comments are stripped first, because this file's own
# documentation names the forbidden APIs in order to say the decoy does not call
# them, and a scanner that cannot tell those apart flags its own prose. (That was the
# first result of running it: four hits, all of them sentences promising the opposite
# of what they matched.)
#
# Exit 0 = inert. Any hit below is a hard failure: the decoy has grown a payload and
# must not be built.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/app/src/main/java"
STRIPPED="$(mktemp -d)"
trap 'rm -rf "$STRIPPED"' EXIT

# Strip /* … */ blocks and // line comments, keeping line numbers intact so a hit is
# still locatable. Not a Kotlin parser — a string literal containing "//" would be
# over-stripped — but it errs toward LESS text to match, never more, so it cannot
# hide a real call.
strip_comments() {
  awk '
    BEGIN { inblock = 0 }
    {
      line = $0
      if (inblock) {
        if (match(line, /\*\//)) { line = substr(line, RSTART + 2); inblock = 0 }
        else { print ""; next }
      }
      while (match(line, /\/\*/)) {
        head = substr(line, 1, RSTART - 1)
        rest = substr(line, RSTART + 2)
        if (match(rest, /\*\//)) { line = head substr(rest, RSTART + 2) }
        else { line = head; inblock = 1; break }
      }
      sub(/\/\/.*$/, "", line)
      print line
    }
  ' "$1"
}

while IFS= read -r file; do
  rel="${file#"$SRC"/}"
  mkdir -p "$STRIPPED/$(dirname "$rel")"
  strip_comments "$file" > "$STRIPPED/$rel"
done < <(find "$SRC" -name '*.kt' -type f)

# Every API that would give the decoy a real capability. If one of these appears in
# the stripped source, the "no implementation body does anything" claim is false.
#
# `addView` is deliberately absent and `WindowManager` present instead: the decoy's
# own about-screen legitimately calls LinearLayout.addView, while the capability that
# actually matters is obtaining a WindowManager to draw over another app.
FORBIDDEN=(
  # network
  'java\.net\.' 'HttpURLConnection' 'URLConnection' 'okhttp' 'openConnection'
  'WebView' 'loadUrl' 'Socket\('
  # SMS
  'SmsManager' 'sendTextMessage' 'getMessagesFromIntent' 'Telephony\.' 'pdus'
  'content://sms' 'abortBroadcast'
  # overlay
  'WindowManager' 'TYPE_APPLICATION_OVERLAY' 'TYPE_SYSTEM_ALERT'
  # accessibility abuse
  'rootInActiveWindow' 'performGlobalAction' 'performAction' 'AccessibilityNodeInfo'
  'dispatchGesture' 'getSource\('
  # dropper / dynamic code
  'DexClassLoader' 'PathClassLoader' 'InMemoryDexClassLoader' 'PackageInstaller'
  'ACTION_INSTALL_PACKAGE' 'Runtime\.getRuntime' 'ProcessBuilder'
  # credential / data harvesting
  'ContentResolver' 'contentResolver' 'AccountManager' 'ClipboardManager'
  'getDeviceId' 'getSubscriberId' 'KeyguardManager'
  # crypto — a decoy needs the constant string, never the call
  'Cipher\.' 'javax\.crypto' 'MessageDigest'
  # reflection
  'java\.lang\.reflect' 'Class\.forName' 'getDeclaredMethod'
)

fail=0
for pattern in "${FORBIDDEN[@]}"; do
  if hits="$(grep -rnE "$pattern" "$STRIPPED" 2>/dev/null)"; then
    printf 'FORBIDDEN API in decoy code: %s\n%s\n\n' "$pattern" "$hits" >&2
    fail=1
  fi
done

# The two "C2" constants must stay unroutable by construction, not by intention.
MARKER="$SRC/in/drishti/decoy/rtochallan/InertMarker.kt"
grep -q 'C2_PRIMARY = "http://192\.0\.2\.' "$MARKER" || {
  echo 'C2_PRIMARY is no longer RFC 5737 TEST-NET-1 (192.0.2.0/24). Refusing.' >&2
  fail=1
}
grep -q 'C2_FALLBACK = "https://[^"]*\.invalid' "$MARKER" || {
  echo 'C2_FALLBACK is no longer an RFC 2606 .invalid host. Refusing.' >&2
  fail=1
}

if [[ "$fail" -ne 0 ]]; then
  echo 'DECOY IS NOT INERT. See canary/decoy-challan/README.md.' >&2
  exit 1
fi

echo "decoy verified inert: $(find "$SRC" -name '*.kt' | wc -l) source files scanned, no capability-granting API present"

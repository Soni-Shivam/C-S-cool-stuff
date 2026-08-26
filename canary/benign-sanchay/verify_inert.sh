#!/usr/bin/env bash
# Prove the benign control sample is inert, by grep, before anyone builds or installs it.
#
# This is the SAME gate as canary/decoy-challan/verify_inert.sh, and it matters more
# here, not less. The decoy is never installed; this app is — letting the install
# succeed is the whole point of the benign beat. An app that declares READ_SMS and
# READ_CONTACTS and then actually gets installed on a device must be provably unable
# to use them, and "provably" means a script, not a paragraph.
#
# It scans CODE ONLY. Comments are stripped first, because this file's own
# documentation names the forbidden APIs in order to say the app does not call them.
#
# Exit 0 = inert. Any hit below is a hard failure.
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
# `addView` is deliberately absent and `WindowManager` present instead: this app's
# own screen legitimately calls LinearLayout.addView, while the capability that
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

# The one endpoint constant must stay unresolvable by construction, not by intention.
# RFC 2606 reserves `.invalid`, so it can never resolve — and no code here passes it
# to anything anyway.
MARKER="$SRC/in/drishti/benign/sanchay/InertMarker.kt"
grep -q 'SYNC_ENDPOINT = "https://[^"]*\.invalid' "$MARKER" || {
  echo 'SYNC_ENDPOINT is no longer an RFC 2606 .invalid host. Refusing.' >&2
  fail=1
}

# The control sample must NOT carry a banking roster. If it ever did, the lookalike
# assessment would fire on it and the demo's negative control would stop being one —
# silently, and only visible as a surprising verdict on stage.
if grep -rniE 'com\.(sbi|icicibank|axis|hdfcbank|phonepe)|net\.one97\.paytm|in\.org\.npci' "$SRC" >/dev/null 2>&1; then
  echo 'Banking/UPI package identifiers found in the benign control sample. Refusing:' >&2
  grep -rniE 'com\.(sbi|icicibank|axis|hdfcbank|phonepe)|net\.one97\.paytm|in\.org\.npci' "$SRC" >&2
  fail=1
fi

# Nor a service component: OVERLAY_CREDENTIAL_THEFT, CLIPBOARD_MONITOR and
# SCREEN_CAPTURE all key on `plus_component_type: service`, and this sample holds
# SYSTEM_ALERT_WINDOW and INTERNET. Adding a service would push it over the block
# policy's two-high threshold and the negative control would start being blocked.
if grep -qE '<service' "$HERE/app/src/main/AndroidManifest.xml"; then
  echo 'The benign control sample declares a <service>. That would trip the overlay and' >&2
  echo 'screen-capture combinations and it would be blocked. Refusing.' >&2
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  echo 'CONTROL SAMPLE IS NOT INERT. See canary/benign-sanchay/README.md.' >&2
  exit 1
fi

echo "benign control verified inert: $(find "$SRC" -name '*.kt' | wc -l) source files scanned, no capability-granting API, no banking roster, no service component"

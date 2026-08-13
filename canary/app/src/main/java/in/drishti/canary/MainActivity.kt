package in.drishti.canary

import android.app.Activity
import android.os.Bundle
import android.provider.Telephony
import android.util.Log
import android.widget.TextView
import java.net.HttpURLConnection
import java.net.URL

/**
 * DRISHTI canary — a deliberately INERT test target.
 *
 * `docs/00_GUIDING_MAP.md` §4 defines this app's behaviour exhaustively, and this file
 * implements exactly that and nothing else:
 *
 *   1. query [android.content.pm.PackageManager] for a package name
 *   2. read an SMS inbox **count**
 *   3. attempt one HTTP GET to a configured local host
 *   4. write `Log.i("CANARY", ...)` lines
 *
 * It exists only to prove the JIT-morphing loop fires: step 1 asks for a package that is
 * not installed, the frontier synthesises it, and on re-detonation the same query
 * returns a hit. That transition is the demo's central beat, and this is the only sample
 * we can safely use to rehearse it.
 *
 * ## What this app must never do
 *
 * No overlay, no accessibility service, no SMS sending or forwarding, no credential
 * capture, no dynamic code loading, no clipboard access, no reading of message bodies or
 * contacts. It reads a **count**, never content. It has no capability to harm a device or
 * a user, and extending it beyond the four behaviours above requires changing §4 first
 * (`CLAUDE.md`: "If a task asks to extend `canary/` beyond that, stop and ask.")
 *
 * Note this is deliberately **narrower** than v1's `m3-inert-fixture`, which also
 * exercised the clipboard, a `Cipher`, and `DexClassLoader` on its own APK. Those are
 * harmless in isolation but they are not on §4's list, and the value of a narrow,
 * exhaustively-stated boundary is that it can be audited by reading one file.
 */
class MainActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val log = mutableListOf<String>()

        // (1) Environment probe. This is what the frontier responds to: the package is
        // absent on a clean emulator, so the probe MISSES and a morph plan installs it.
        val probed = PROBE_PACKAGE
        val installed = try {
            packageManager.getPackageInfo(probed, 0)
            true
        } catch (_: Exception) {
            false
        }
        Log.i(TAG, "probe package=$probed installed=$installed")
        log += "PackageManager('$probed') -> ${if (installed) "HIT" else "MISS"}"

        // (2) SMS inbox COUNT only. Never a body, never an address — the count is enough
        // to prove the query happened, and message content is the thing a real OTP
        // trojan is after.
        val smsCount = try {
            contentResolver.query(
                Telephony.Sms.Inbox.CONTENT_URI,
                arrayOf(Telephony.Sms._ID), // id column only: no body, no address
                null, null, null,
            )?.use { it.count } ?: -1
        } catch (_: Exception) {
            -1 // no permission granted, which is the expected default
        }
        Log.i(TAG, "sms inbox count=$smsCount")
        log += "SMS inbox count -> $smsCount"

        // (3) One HTTP GET to a LOCAL host. 10.0.2.2 is the emulator's alias for its own
        // host loopback, so this cannot reach the internet even if egress were open. The
        // request is expected to fail when nothing is listening; that is fine.
        Thread {
            val outcome = try {
                (URL(BEACON_URL).openConnection() as HttpURLConnection).run {
                    connectTimeout = 1500
                    readTimeout = 1500
                    requestMethod = "GET"
                    val code = responseCode
                    disconnect()
                    "http $code"
                }
            } catch (e: Exception) {
                "no upstream (${e.javaClass.simpleName})"
            }
            Log.i(TAG, "beacon url=$BEACON_URL outcome=$outcome")
        }.start()

        setContentView(
            TextView(this).apply {
                text = buildString {
                    append("DRISHTI CANARY — INERT TEST TARGET\n\n")
                    append(log.joinToString("\n"))
                    append("\n\nNo message content, contacts or credentials are read.\n")
                    append("No remote service is contacted.")
                }
                textSize = 18f
                setPadding(48, 48, 48, 48)
            },
        )
    }

    companion object {
        private const val TAG = "CANARY"

        /**
         * The package the canary asks about. Chosen to be absent from a clean emulator so
         * the probe misses; the frontier's `install_packages` morph then makes it appear.
         */
        const val PROBE_PACKAGE: String = "in.drishti.canary.absent.target"

        /** Emulator alias for the analysis host's loopback. Never a routable address. */
        const val BEACON_URL: String = "http://10.0.2.2:8080/canary"
    }
}

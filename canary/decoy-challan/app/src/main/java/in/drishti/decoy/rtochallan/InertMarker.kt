package `in`.drishti.decoy.rtochallan

import android.util.Log

/**
 * ============================================================================
 * DRISHTI DECOY — INERT BY CONSTRUCTION.
 * ============================================================================
 *
 * Every component in this package routes its entire behaviour through [noop]. There
 * is exactly one way for this app to do anything, and it writes a log line.
 *
 * The strings in [Surface] exist to populate the DEX string pool so the M2 static
 * engine has realistic constants to extract. They are **data, never arguments**:
 * nothing in this package opens a socket, decodes them, or reflects on them. Grep
 * the package for `java.net`, `HttpURLConnection`, `Socket`, `Cipher`, `SmsManager`,
 * `WindowManager`, `DexClassLoader` — there are no hits, and
 * `canary/decoy-challan/verify_inert.sh` asserts that.
 * ============================================================================
 */
internal object InertMarker {
    const val TAG = "DRISHTI_DECOY"

    /**
     * The only behaviour in this application.
     *
     * @param what the component and event being declined, for the logcat record
     */
    fun noop(what: String) {
        Log.i(TAG, "INERT DECOY: $what — no action taken. This APK has no payload.")
    }
}

/**
 * String constants that make the static surface realistic.
 *
 * None of these is ever used as an argument to anything. They are declared `const`
 * so they land in the DEX string pool, which is the only place the analysis engine
 * looks for them.
 */
internal object Surface {
    /**
     * The fake command-and-control endpoint.
     *
     * `192.0.2.0/24` is TEST-NET-1, reserved by RFC 5737 for documentation and
     * guaranteed never to be routed on the public internet. `.invalid` is reserved
     * by RFC 2606 and can never resolve. Both are chosen so that even a mistake
     * cannot produce a real connection — and no code here attempts one.
     */
    const val C2_PRIMARY = "http://192.0.2.87:8443/rto/v3/collect"
    const val C2_FALLBACK = "https://challan-verify.invalid/api/sync"

    /** Shaped like the family's obfuscated config blob. Never decoded. */
    const val CONFIG_BLOB = "eJx0aGlzIGlzIGFuIGluZXJ0IERSSVNIVEkgZGVjb3kgc3RyaW5n"
    const val CRYPTO_TRANSFORM = "AES/CBC/PKCS5Padding"
    const val CAMPAIGN_ID = "rto_mh_2026_q1"

    /** Bank package names the family checks for. Never queried by this APK. */
    val TARGET_PACKAGES = arrayOf(
        "com.sbi.lotusintouch",
        "com.icicibank.imobile",
        "net.one97.paytm",
        "com.phonepe.app",
    )
}

package `in`.drishti.benign.sanchay

import android.util.Log

/**
 * ============================================================================
 * DRISHTI CONTROL SAMPLE — INERT BY CONSTRUCTION.
 * ============================================================================
 *
 * Same discipline as `canary/decoy-challan`: every component routes its entire
 * behaviour through [noop], and the only thing this application can do is write a
 * log line.
 *
 * That matters more here than it does for the decoy. This app declares READ_SMS and
 * READ_CONTACTS, and it is installed on the demo device — an install the demo is
 * specifically there to let succeed. An app that actually read those on stage would
 * be the single worst thing in this repository, so it does not contain the code.
 *
 * `canary/benign-sanchay/verify_inert.sh` asserts that by grep and gates the build.
 * ============================================================================
 */
internal object InertMarker {
    const val TAG = "DRISHTI_BENIGN"

    /**
     * The only behaviour in this application.
     *
     * @param what the component and event being declined, for the logcat record
     */
    fun noop(what: String) {
        Log.i(TAG, "INERT CONTROL SAMPLE: $what — no action taken. This APK has no payload.")
    }
}

/**
 * String constants that make the static surface realistic.
 *
 * Deliberately *different in kind* from `decoy-challan`'s [Surface]. The decoy's
 * string pool carries a roster of Indian bank package names and an OTP lexicon,
 * because that is what the fraud family carries. This one carries spending
 * categories, because that is what an expense tracker carries.
 *
 * The difference is the demo. `drishti/m2_static/lookalike.py` reads the string pool
 * looking for a target roster; it finds one in the decoy and none here, and that is
 * the signal that separates two apps holding identical permissions.
 *
 * None of these is ever used as an argument to anything.
 */
internal object Surface {
    /** Categories the tracker would sort a transaction into. */
    val CATEGORIES = arrayOf(
        "Groceries", "Fuel", "Rent", "Utilities", "Transport",
        "Dining", "Healthcare", "Education", "Subscriptions",
    )

    /** Shapes of the bank alert lines an SMS-driven tracker parses. Data only. */
    val ALERT_TEMPLATES = arrayOf(
        "debited by Rs",
        "credited to your account",
        "UPI txn of Rs",
        "available balance",
    )

    /** Where a paid tier would sync to, if this app had a network stack. It does not. */
    const val SYNC_ENDPOINT = "https://sync.sanchay.invalid/v1/ledger"
}

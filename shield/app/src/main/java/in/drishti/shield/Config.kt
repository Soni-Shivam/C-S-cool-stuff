package `in`.drishti.shield

import android.content.Context

/** Everything that differs between the demo emulator and a real deployment. */
object Config {
    private const val PREFS = "drishti_shield"
    private const val KEY_BACKEND = "backend_base"

    /**
     * `10.0.2.2` is the Android emulator's alias for the host's own loopback, so this
     * default reaches `make up` on the demo laptop and nothing else. Overridable at
     * runtime from the main screen for a physical-device demo.
     */
    const val DEFAULT_BACKEND: String = "http://10.0.2.2:8080"

    /** The directory a WhatsApp-style forward lands in. */
    const val WATCH_DIR: String = "/sdcard/Download"

    /** How long to wait for M2's static report — the input the block decision needs. */
    const val STATIC_TIMEOUT_MS: Long = 60_000

    /** How long to wait for the composite score, which arrives after the decision and
     *  can be held up by a slow LLM provider. Generous, because nothing is blocked
     *  on it: the verdict is already on screen. */
    const val VERDICT_TIMEOUT_MS: Long = 180_000

    const val NCRP_URL: String = "https://cybercrime.gov.in/"

    private const val KEY_CONSUMER_SCREEN = "consumer_screen"

    /**
     * Whether tapping an APK shows the **consumer** screen or the analyst one.
     *
     * On by default: at tap time the person holding the phone is a victim, not an
     * analyst, and the evidence-first screen in `VerdictActivity` is written for the
     * second audience. Both screens read the same analysis — this only chooses which
     * projection of it a tap lands on. `VerdictActivity` remains reachable from the
     * Shield app itself, which is where an analyst would be looking anyway.
     */
    fun consumerScreen(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getBoolean(KEY_CONSUMER_SCREEN, true)

    fun setConsumerScreen(context: Context, value: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putBoolean(KEY_CONSUMER_SCREEN, value).apply()
    }

    fun backend(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_BACKEND, DEFAULT_BACKEND) ?: DEFAULT_BACKEND

    fun setBackend(context: Context, value: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY_BACKEND, value.trimEnd('/')).apply()
    }
}

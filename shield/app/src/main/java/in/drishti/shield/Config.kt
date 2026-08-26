package `in`.drishti.shield

import android.content.Context
import java.io.File

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

    /**
     * Presence of this file routes a **tap** to the consumer screen instead of the
     * analyst one. `scripts/demo_consumer.sh --tap-on` creates it.
     */
    const val CONSUMER_TAP_MARKER: String = "/sdcard/DrishtiStaging/consumer_tap.on"

    /**
     * Whether tapping an APK shows the **consumer** screen or the analyst one.
     *
     * **Off until the operator arms it**, and a file rather than a preference so that
     * arming it is one `adb` command with no UI in the way.
     *
     * Off is the right default today for one specific reason. The consumer screen
     * renders the contract-A15 `Verdict`, and the backend route that produces one
     * (`/api/jobs/{id}/verdict`) does not exist yet — so a tapped file that has no A15
     * verdict lands on the consumer screen's *undecided* state, which is correct and
     * honest but is not the beat `scripts/demo_run.sh` narrates for the cleared app.
     * When that route lands, arm this and the tap beat becomes the consumer beat with
     * no other change.
     *
     * Both screens read the same analysis; this only chooses which projection of it a
     * tap lands on. `VerdictActivity` remains reachable from the Shield app itself,
     * which is where an analyst would be looking anyway.
     */
    fun consumerScreen(): Boolean = File(CONSUMER_TAP_MARKER).exists()

    fun backend(context: Context): String =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .getString(KEY_BACKEND, DEFAULT_BACKEND) ?: DEFAULT_BACKEND

    fun setBackend(context: Context, value: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString(KEY_BACKEND, value.trimEnd('/')).apply()
    }
}

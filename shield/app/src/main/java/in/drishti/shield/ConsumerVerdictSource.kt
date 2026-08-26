package `in`.drishti.shield

import android.content.Context
import android.util.Log
import java.io.File
import org.json.JSONObject

/**
 * Where the consumer screen's [ConsumerVerdict] comes from — and it is never allowed
 * to matter to the screen.
 *
 * The screen takes a [Resolved] and renders it. It does not know whether the object
 * arrived from the backend, from a file the operator pushed for a rehearsal, or from
 * one bundled in the APK, and switching between those needs no UI change at all. That
 * is the whole reason this type exists: contract A15 is the seam, so the screen could
 * be built and rehearsed before the `/verdict` endpoint existed.
 *
 * What the screen *does* read is [Resolved.origin], for one line of text. A fixture
 * rendered as though it were a live analysis would be exactly the dishonesty
 * `CLAUDE.md` § *Honesty requirements* forbids, so a non-backend verdict is labelled
 * on screen, automatically, with no flag anyone can forget to set.
 */
object ConsumerVerdictSource {
    private const val TAG = "DrishtiShield"

    /** Where the operator drops a verdict to rehearse a specific outcome. */
    const val OVERRIDE_PATH: String = "/sdcard/DrishtiStaging/verdict.json"

    /** Bundled fixtures, one per `recommended_action`. Named by the demo script. */
    const val FIXTURE_BLOCK = "block"
    const val FIXTURE_REVIEW = "review"
    const val FIXTURE_MONITOR = "monitor"

    enum class Origin {
        /** Produced by the DRISHTI pipeline for the bytes actually on this device. */
        BACKEND,

        /** A file the operator pushed to [OVERRIDE_PATH]. Labelled on screen. */
        OVERRIDE_FILE,

        /** Shipped inside the APK. Labelled on screen. */
        BUNDLED_FIXTURE,
    }

    data class Resolved(val verdict: ConsumerVerdict, val origin: Origin) {
        val isLiveAnalysis: Boolean get() = origin == Origin.BACKEND
    }

    /**
     * Ask the backend for the A15 verdict of a job. Null while it is not available.
     *
     * Null is the ordinary case today, not an error: `GET /api/jobs/{id}/verdict` is
     * the route the pipeline will expose, and until it does this returns null and the
     * caller falls through to a fixture. Nothing here needs to change when it lands.
     */
    fun fromBackend(context: Context, jobId: String): Resolved? {
        val base = Config.backend(context.applicationContext)
        val json = DrishtiClient.consumerVerdict(base, jobId) ?: return null
        return runCatching { Resolved(ConsumerVerdict.fromJson(json), Origin.BACKEND) }
            .onFailure { Log.w(TAG, "verdict from backend did not parse", it) }
            .getOrNull()
    }

    /** The operator's pushed verdict, if there is one. */
    fun fromOverrideFile(): Resolved? {
        val file = File(OVERRIDE_PATH)
        if (!file.canRead()) return null
        return runCatching {
            Resolved(ConsumerVerdict.fromJson(JSONObject(file.readText())), Origin.OVERRIDE_FILE)
        }.onFailure { Log.w(TAG, "override verdict at $OVERRIDE_PATH did not parse", it) }
            .getOrNull()
    }

    /** One of the fixtures bundled in `assets/verdicts/`. */
    fun fromAsset(context: Context, name: String): Resolved? = runCatching {
        val text = context.assets.open("verdicts/$name.json").bufferedReader()
            .use { it.readText() }
        Resolved(ConsumerVerdict.fromJson(JSONObject(text)), Origin.BUNDLED_FIXTURE)
    }.onFailure { Log.w(TAG, "bundled fixture '$name' unavailable", it) }.getOrNull()

    /**
     * The resolution order, stated once: backend, then the operator's pushed file.
     *
     * Backend first, always — if the pipeline has an answer for these bytes, that is
     * the answer and nothing may override it. Null means neither has one *yet*; the
     * caller polls, and only falls back to a bundled fixture once it has waited.
     */
    fun live(context: Context, jobId: String?): Resolved? {
        if (jobId != null) fromBackend(context, jobId)?.let { return it }
        return fromOverrideFile()
    }
}

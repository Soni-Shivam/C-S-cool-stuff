package `in`.drishti.shield

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/**
 * The set of sha256 digests DRISHTI has decided to block, persisted across restarts.
 *
 * Layer 4 needs this: when a package appears on the device, its APK is hashed and
 * checked here. Without persistence, a reboot between the verdict and the install
 * would silently disarm the failsafe.
 *
 * It stores the *decision*, not just the score, because the score alone is not what
 * blocked — see [BlockDecision]. A Layer 4 warning that quoted "score 0" while
 * quarantining the package would read as a bug.
 */
object VerdictStore {
    private const val PREFS = "drishti_shield_verdicts"

    fun remember(
        context: Context,
        sha256: String,
        filename: String,
        score: Double,
        band: String,
        decision: BlockDecision,
    ) {
        val payload = JSONObject()
            .put("filename", filename)
            .put("score", score)
            .put("band", band)
            .put("block", decision.block)
            .put("basis", decision.basis.name)
            .put("headline", decision.headline)
            .put("detail", decision.detail)
            .put("citations", JSONArray(decision.citations))
            .put("at", System.currentTimeMillis())
        prefs(context).edit().putString(sha256.lowercase(), payload.toString()).apply()
    }

    fun lookup(context: Context, sha256: String): JSONObject? =
        prefs(context).getString(sha256.lowercase(), null)?.let {
            runCatching { JSONObject(it) }.getOrNull()
        }

    /** Rebuild the decision from a stored record, for the Layer 4 screen. */
    fun decisionOf(record: JSONObject): BlockDecision {
        val citations = mutableListOf<String>()
        record.optJSONArray("citations")?.let { arr ->
            for (i in 0 until arr.length()) citations += arr.optString(i)
        }
        return BlockDecision(
            block = record.optBoolean("block", false),
            basis = runCatching {
                BlockDecision.Basis.valueOf(record.optString("basis"))
            }.getOrDefault(BlockDecision.Basis.INSUFFICIENT_EVIDENCE),
            headline = record.optString("headline"),
            detail = record.optString("detail"),
            citations = citations,
        )
    }

    fun isBlocked(context: Context, sha256: String): Boolean =
        lookup(context, sha256)?.optBoolean("block", false) ?: false

    fun clear(context: Context) = prefs(context).edit().clear().apply()

    private fun prefs(context: Context) =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
}

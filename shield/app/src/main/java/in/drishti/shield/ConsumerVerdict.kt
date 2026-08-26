package `in`.drishti.shield

import org.json.JSONObject

/**
 * The Kotlin end of contract **A15** — the one `Verdict` every DRISHTI surface shares.
 *
 * **The source of truth is `drishti/contracts/verdict.py`.** Nothing is decided here.
 * This file only turns that object's JSON into typed Kotlin so a screen never touches
 * a raw dict, exactly as `Verdict.kt` does for `CompositeScore`.
 *
 * A hand-written mirror of a contract drifts — that is the failure mode `CLAUDE.md`
 * rule 1 exists to prevent — so this one is not maintained by anyone remembering.
 * `tests/contract/test_verdict_kotlin_parity.py` reads the pydantic models and this
 * file and fails if a field is added on either side and not the other, in either
 * direction. If that test is red, fix this file; do not weaken the test.
 *
 * Note the deliberate naming: this is `ConsumerVerdict`, not `Verdict`, because
 * [Verdict] in this package is already the on-device view of `CompositeScore`. Two
 * different projections of the same analysis, and the compiler keeps them apart.
 */
data class ConsumerVerdict(
    val sha256: String,
    val packageName: String,
    val threatScore: Int,
    val severityBand: String,
    val confidence: Double,
    /** `STATIC_ONLY` · `REPLAY` · `LIVE`. Read off the trace by the backend, never
     *  off a config flag — see the module docstring in `verdict.py`. */
    val provenance: String,
    val impersonatedTarget: String?,
    val victimProfile: VictimProfile,
    val behaviorsDetected: List<String>,
    val attackTechniques: List<String>,
    val evidenceRefs: List<String>,
    /** Plain language, safe to show a frightened non-technical person. Templated by
     *  the backend from grounded findings — never a free-form model sentence. */
    val consumerSummary: String,
    /** `BLOCK` · `REVIEW` · `MONITOR`. The consumer screen renders one of three
     *  layouts from this and nothing else. */
    val recommendedAction: String,
    val dynamicTrace: DynamicTraceSummary?,
    val adversarialElicitationDeployed: List<String>,
    val limitations: List<String>,
) {
    val blocks: Boolean get() = recommendedAction == "BLOCK"

    companion object {
        fun fromJson(json: JSONObject): ConsumerVerdict = ConsumerVerdict(
            sha256 = json.optString("sha256"),
            packageName = json.optString("package_name"),
            threatScore = json.optInt("threat_score", 0),
            severityBand = json.optString("severity_band", "UNKNOWN"),
            confidence = json.optDouble("confidence", 0.0),
            provenance = json.optString("provenance", "STATIC_ONLY"),
            impersonatedTarget = json.optString("impersonated_target")
                .takeIf { it.isNotBlank() && it != "null" },
            victimProfile = VictimProfile.fromJson(json.optJSONObject("victim_profile")),
            behaviorsDetected = getStrings(json, "behaviors_detected"),
            attackTechniques = getStrings(json, "attack_techniques"),
            evidenceRefs = getStrings(json, "evidence_refs"),
            consumerSummary = json.optString("consumer_summary"),
            recommendedAction = json.optString("recommended_action", "MONITOR"),
            dynamicTrace = json.optJSONObject("dynamic_trace")
                ?.let { DynamicTraceSummary.fromJson(it) },
            adversarialElicitationDeployed = getStrings(json, "adversarial_elicitation_deployed"),
            limitations = getStrings(json, "limitations"),
        )

        internal fun getStrings(json: JSONObject, key: String): List<String> {
            val out = mutableListOf<String>()
            json.optJSONArray(key)?.let { arr ->
                for (i in 0 until arr.length()) out += arr.optString(i)
            }
            return out
        }
    }
}

/** `VictimProfileView` — the social-engineering read, flattened for display. */
data class VictimProfile(
    val language: String?,
    val tactic: String?,
    val segment: String?,
) {
    companion object {
        fun fromJson(json: JSONObject?): VictimProfile {
            if (json == null) return VictimProfile(null, null, null)
            fun opt(key: String): String? =
                json.optString(key).takeIf { it.isNotBlank() && it != "null" }
            return VictimProfile(opt("language"), opt("tactic"), opt("segment"))
        }
    }
}

/**
 * `DynamicTraceView` — what the sandbox observed. Null until a detonation happens.
 *
 * `detonated = true` with three empty lists is a real state and is **not** benign:
 * an evasive sample that stalled and a clean app look identical from here.
 */
data class DynamicTraceSummary(
    val detonated: Boolean,
    val apiCalls: List<String>,
    val decryptedStrings: List<String>,
    val networkCaptures: List<String>,
) {
    companion object {
        fun fromJson(json: JSONObject): DynamicTraceSummary = DynamicTraceSummary(
            detonated = json.optBoolean("detonated", false),
            apiCalls = ConsumerVerdict.getStrings(json, "api_calls"),
            decryptedStrings = ConsumerVerdict.getStrings(json, "decrypted_strings"),
            networkCaptures = ConsumerVerdict.getStrings(json, "network_captures"),
        )
    }
}

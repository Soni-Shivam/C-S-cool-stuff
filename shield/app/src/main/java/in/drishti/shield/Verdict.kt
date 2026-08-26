package `in`.drishti.shield

import org.json.JSONObject

/**
 * The on-device mirror of the DRISHTI backend contracts.
 *
 * The repo's rule is that no raw dict crosses a module boundary. The boundary here is
 * HTTP, so this file is the Kotlin end of it: JSON is parsed exactly once, in the
 * `from…Json` factories, and every screen downstream reads typed objects. If a
 * backend contract changes, this is the single file that changes with it.
 *
 * Mirrors `drishti.contracts.score.CompositeScore` and the parts of
 * `drishti.contracts.static_report.StaticReport` the guard app needs.
 */

data class ScoreFactor(
    val symbol: String,
    val label: String,
    val raw: Double,
    val weight: Double,
    val contribution: Double,
)

enum class Band { CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN }

enum class Severity { CRITICAL, HIGH, MEDIUM, LOW, INFO, UNKNOWN }

/** Where a scan is in its life. The UI renders one screen per state. */
enum class ScanState { SCANNING, VERDICT, ERROR }

/** One matched permission-combination rule from `m2_static/rules/permission_combos.yaml`. */
data class PermissionCombo(
    val ruleId: String,
    val severity: Severity,
    val mitre: String?,
    val description: String,
)

/** The subset of M2's static report that the block decision and the dossier need. */
data class StaticEvidence(
    val packageName: String,
    val appLabel: String,
    val permissions: List<String>,
    val combos: List<PermissionCombo>,
    val urls: List<String>,
    val exportedUnprotected: List<String>,
    val partial: Boolean,
) {
    val critical: List<PermissionCombo> get() = combos.filter { it.severity == Severity.CRITICAL }
    val high: List<PermissionCombo> get() = combos.filter { it.severity == Severity.HIGH }

    companion object {
        fun fromJson(json: JSONObject): StaticEvidence {
            fun strings(key: String): List<String> {
                val out = mutableListOf<String>()
                json.optJSONArray(key)?.let { arr ->
                    for (i in 0 until arr.length()) out += arr.optString(i)
                }
                return out
            }
            val combos = mutableListOf<PermissionCombo>()
            json.optJSONArray("permission_combos")?.let { arr ->
                for (i in 0 until arr.length()) {
                    val c = arr.getJSONObject(i)
                    combos += PermissionCombo(
                        ruleId = c.optString("rule_id"),
                        severity = runCatching {
                            Severity.valueOf(c.optString("severity").uppercase())
                        }.getOrDefault(Severity.UNKNOWN),
                        mitre = c.optString("mitre").takeIf { it.isNotBlank() && it != "null" },
                        description = c.optString("description"),
                    )
                }
            }
            val exported = mutableListOf<String>()
            json.optJSONArray("exported_unprotected")?.let { arr ->
                for (i in 0 until arr.length()) exported += arr.getJSONObject(i).optString("name")
            }
            return StaticEvidence(
                packageName = json.optString("package"),
                appLabel = json.optString("app_label"),
                permissions = strings("permissions"),
                combos = combos,
                urls = strings("urls"),
                exportedUnprotected = exported,
                partial = json.optBoolean("partial", false),
            )
        }
    }
}

data class Verdict(
    val score: Double,
    val band: Band,
    val confidence: Double,
    val gamma: Double,
    val factors: List<ScoreFactor>,
    val explanation: String,
    val requiresHumanReview: Boolean,
    val limitations: List<String>,
) {
    companion object {
        fun fromScoreJson(json: JSONObject): Verdict {
            val factors = mutableListOf<ScoreFactor>()
            json.optJSONArray("factors")?.let { arr ->
                for (i in 0 until arr.length()) {
                    val f = arr.getJSONObject(i)
                    factors += ScoreFactor(
                        symbol = f.optString("symbol"),
                        label = f.optString("label"),
                        raw = f.optDouble("raw", 0.0),
                        weight = f.optDouble("weight", 0.0),
                        contribution = f.optDouble("contribution", 0.0),
                    )
                }
            }
            val limitations = mutableListOf<String>()
            json.optJSONArray("limitations")?.let { arr ->
                for (i in 0 until arr.length()) limitations += arr.optString(i)
            }
            return Verdict(
                score = json.optDouble("S", 0.0),
                band = runCatching { Band.valueOf(json.optString("band")) }
                    .getOrDefault(Band.UNKNOWN),
                confidence = json.optDouble("C", 0.0),
                gamma = json.optDouble("gamma", 0.0),
                factors = factors,
                explanation = json.optString("explanation", ""),
                requiresHumanReview = json.optBoolean("requires_human_review", false),
                limitations = limitations,
            )
        }
    }
}

/**
 * Why Shield did — or did not — block, and which evidence carried the decision.
 *
 * This type exists because of a real property of the system as built, and hiding it
 * would be the dishonest option. `m6_score.engine` deliberately refuses to let an
 * unavailable ML model or a mock LLM contribute to `S`; with neither a trained model
 * nor an LLM key present, `S` is **0 for every input, including real malware**. A
 * guard app that blocked on `S >= 65` would therefore never block, and one that
 * invented a number would be lying.
 *
 * So the block decision names its own basis, and the UI prints that basis next to the
 * score. When the ML and GenAI layers do become available, `S` carries the decision
 * and [Basis.COMPOSITE_SCORE] is what appears on screen instead — with no code change
 * here beyond which branch [decide] takes.
 */
data class BlockDecision(
    val block: Boolean,
    val basis: Basis,
    val headline: String,
    val detail: String,
    val citations: List<String>,
) {
    enum class Basis { COMPOSITE_SCORE, STATIC_EVIDENCE, INSUFFICIENT_EVIDENCE, CLEAR }

    companion object {
        /** `S >= 65` is the HIGH floor in `drishti/contracts/score.py`. */
        const val SCORE_FLOOR = 65.0

        /**
         * The static fallback policy, stated once, here.
         *
         * One CRITICAL combination, or two or more HIGH ones. This is a **policy
         * threshold, not a measured metric** — nothing in this repo has measured a
         * false-positive rate for it, and the UI says so rather than quoting a
         * number that does not exist.
         */
        const val STATIC_HIGH_COUNT = 2

        fun decide(verdict: Verdict?, static: StaticEvidence?): BlockDecision {
            if (verdict != null && verdict.score >= SCORE_FLOOR) {
                return BlockDecision(
                    block = true,
                    basis = Basis.COMPOSITE_SCORE,
                    headline = "Composite score ${verdict.score.toInt()}/100 (${verdict.band})",
                    detail = "M6 fused the available evidence and put this above the " +
                        "${SCORE_FLOOR.toInt()} HIGH floor.",
                    citations = verdict.factors
                        .filter { it.contribution > 0 }
                        .map { "${it.symbol} contributed ${"%.2f".format(it.contribution)}" },
                )
            }

            if (static != null && static.combos.isNotEmpty()) {
                val critical = static.critical
                val high = static.high
                val enough = critical.isNotEmpty() || high.size >= STATIC_HIGH_COUNT
                if (enough) {
                    val cited = (critical + high).map {
                        "${it.ruleId} (${it.severity.name.lowercase()}" +
                            (it.mitre?.let { m -> ", $m" } ?: "") + ") — ${it.description}"
                    }
                    return BlockDecision(
                        block = true,
                        basis = Basis.STATIC_EVIDENCE,
                        headline = "${critical.size} critical + ${high.size} high-severity " +
                            "permission combinations",
                        // Says only what it can verify. An earlier version asserted a
                        // *cause* for the low score — "the ML and GenAI layers are not
                        // admitted" — which stopped being true the moment a trained
                        // model landed, while the sentence stayed on screen. The score
                        // card below shows the factor breakdown; this card's job is to
                        // name what carried the decision, not to explain M6.
                        detail = if (verdict == null) {
                            "Decided on M2 static evidence alone. The composite score is " +
                                "still being computed and will appear below when it lands — " +
                                "the block does not wait for it, because the evidence cited " +
                                "here is already sufficient and is what carries the decision."
                        } else {
                            "The composite score is ${verdict.score.toInt()}, below the " +
                                "${SCORE_FLOOR.toInt()} HIGH floor, so it did not authorise " +
                                "this block. The M2 static evidence cited below did. See the " +
                                "factor breakdown for which layers M6 actually admitted."
                        },
                        citations = cited,
                    )
                }
            }

            if (static == null || static.partial) {
                return BlockDecision(
                    block = false,
                    basis = Basis.INSUFFICIENT_EVIDENCE,
                    headline = "Inconclusive",
                    detail = "Static analysis did not complete. An APK that produced no " +
                        "analysis is not the same thing as a safe one.",
                    citations = emptyList(),
                )
            }

            return BlockDecision(
                block = false,
                basis = Basis.CLEAR,
                headline = "No blocking evidence found",
                detail = "M2 matched ${static.combos.size} permission combination(s), none " +
                    "critical and fewer than $STATIC_HIGH_COUNT high. The composite score " +
                    "is ${verdict?.score?.toInt() ?: 0}.",
                citations = static.combos.map { "${it.ruleId} (${it.severity.name.lowercase()})" },
            )
        }
    }
}

/** One tracked APK: what we saw, and what DRISHTI said about it. */
data class Scan(
    val id: String,
    val filename: String,
    val path: String,
    val sha256: String,
    val sizeBytes: Long,
    /** Wall clock at the instant the file landed. The on-screen millisecond counter
     *  is measured from here, so the number on stage is the real detection latency. */
    val detectedAtMs: Long,
    val state: ScanState = ScanState.SCANNING,
    val stage: String = "uploading",
    val jobId: String? = null,
    val verdict: Verdict? = null,
    val static: StaticEvidence? = null,
    val decision: BlockDecision? = null,
    val error: String? = null,
    val verdictAtMs: Long? = null,
    val vetoEngaged: Boolean = false,
    /** True between the M2 verdict landing and the M6 score arriving. The screen says
     *  so rather than leaving a blank where a score will appear. */
    val scorePending: Boolean = false,
) {
    /**
     * Time from the file landing to the verdict being decidable.
     *
     * Frozen at [verdictAtMs], which is stamped when the **block decision** is made —
     * not when the composite score later arrives. The number on screen is the latency
     * that matters to a user about to tap an APK, and it must not drift upward
     * afterwards because a slow third-party layer finished.
     */
    val elapsedMs: Long get() = (verdictAtMs ?: System.currentTimeMillis()) - detectedAtMs
    val blocked: Boolean get() = decision?.block == true
}

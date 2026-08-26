package `in`.drishti.shield

import android.util.Log
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import org.json.JSONObject

/**
 * The only place this app talks to the DRISHTI backend.
 *
 * It uses the route surface frozen in `docs/PHASE_0_FOUNDATIONS.md` T0.6 and adds
 * nothing to it: `POST /api/jobs` to submit, then `GET /api/jobs/{id}/score` polled
 * until the pipeline reaches SCORE_PRELIM. Polling rather than SSE is a deliberate
 * choice — one fewer long-lived socket to lose when the emulator's network stack
 * hiccups on stage, and the poll interval is the resolution of the on-screen timer
 * anyway.
 *
 * Every call here is a degrade-gracefully boundary in the Kotlin sense: nothing
 * throws out of the public functions, failures come back as a typed [Result].
 */
object DrishtiClient {
    private const val TAG = "DrishtiShield"
    private const val BOUNDARY = "----DrishtiShieldBoundary7f3a"
    private const val POLL_INTERVAL_MS = 150L

    data class Submission(val jobId: String)

    /** True if the backend answers its liveness probe. Never throws. */
    fun health(base: String): Boolean = try {
        val conn = open("$base/api/health", "GET", connectMs = 1500, readMs = 1500)
        val ok = conn.responseCode == 200
        conn.disconnect()
        ok
    } catch (e: Exception) {
        Log.i(TAG, "backend health probe failed: ${e.message}")
        false
    }

    /**
     * Upload the APK for analysis. Multipart is hand-rolled so the app carries no
     * HTTP dependency; the field name `apk` is what `create_job` expects.
     */
    fun submit(base: String, apk: File): Result<Submission> = runCatching {
        val conn = open("$base/api/jobs", "POST", connectMs = 5000, readMs = 60_000)
        conn.doOutput = true
        conn.setChunkedStreamingMode(64 * 1024)
        conn.setRequestProperty("Content-Type", "multipart/form-data; boundary=$BOUNDARY")
        DataOutputStream(conn.outputStream.buffered()).use { out ->
            out.writeBytes("--$BOUNDARY\r\n")
            out.writeBytes(
                "Content-Disposition: form-data; name=\"apk\"; filename=\"${apk.name}\"\r\n"
            )
            out.writeBytes("Content-Type: application/vnd.android.package-archive\r\n\r\n")
            apk.inputStream().use { it.copyTo(out) }
            out.writeBytes("\r\n--$BOUNDARY--\r\n")
            out.flush()
        }
        val code = conn.responseCode
        if (code !in 200..299) {
            val detail = conn.errorStream?.bufferedReader()?.use { it.readText() }.orEmpty()
            conn.disconnect()
            throw IOException("submit returned HTTP $code: ${detail.take(200)}")
        }
        val body = conn.inputStream.bufferedReader().use { it.readText() }
        conn.disconnect()
        Submission(JSONObject(body).getString("job_id"))
    }.onFailure { Log.w(TAG, "submit failed", it) }

    /**
     * Poll `/score` until the pipeline produces one.
     *
     * The API's convention (see `drishti/api/deps.py`) is 404 + `not_produced_yet`
     * while a stage is still pending, so a 404 here means "keep waiting", not
     * "wrong URL". [onStage] is called with the job's current stage each tick so the
     * caller can drive a progress line without a second endpoint.
     */
    fun awaitVerdict(
        base: String,
        jobId: String,
        timeoutMs: Long,
        onStage: (String) -> Unit,
    ): Result<Verdict> = runCatching {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastStage = ""
        while (System.currentTimeMillis() < deadline) {
            val score = getJson("$base/api/jobs/$jobId/score")
            if (score != null) return@runCatching Verdict.fromScoreJson(score)

            val job = getJson("$base/api/jobs/$jobId")
            val stage = job?.optString("stage").orEmpty()
            if (stage == "failed") {
                throw IOException("pipeline failed: ${job?.optString("error").orEmpty()}")
            }
            if (stage.isNotEmpty() && stage != lastStage) {
                lastStage = stage
                onStage(stage)
            }
            Thread.sleep(POLL_INTERVAL_MS)
        }
        throw IOException("no verdict within ${timeoutMs}ms (last stage: $lastStage)")
    }.onFailure { Log.w(TAG, "awaitVerdict failed", it) }

    /**
     * Poll `/static` until M2 produces a report.
     *
     * Separate from [awaitVerdict] because the block decision needs M2, not M6 — and
     * M6's preliminary score sits behind the GenAI stage in the pipeline. Measured on
     * this laptop: static lands in ~5 s, while `genai_static` took **35 s** on a cold
     * free-tier LLM call (813 ms when cached). Waiting for the score before showing a
     * verdict put a third-party endpoint's latency directly into the demo's central
     * beat, for a layer the scorer then excludes as partial anyway.
     */
    fun awaitStatic(
        base: String,
        jobId: String,
        timeoutMs: Long,
        onStage: (String) -> Unit,
    ): Result<StaticEvidence> = runCatching {
        val deadline = System.currentTimeMillis() + timeoutMs
        var lastStage = ""
        while (System.currentTimeMillis() < deadline) {
            val report = getJson("$base/api/jobs/$jobId/static")
            if (report != null) return@runCatching StaticEvidence.fromJson(report)

            val job = getJson("$base/api/jobs/$jobId")
            val stage = job?.optString("stage").orEmpty()
            if (stage == "failed") {
                throw IOException("pipeline failed: ${job?.optString("error").orEmpty()}")
            }
            if (stage.isNotEmpty() && stage != lastStage) {
                lastStage = stage
                onStage(stage)
            }
            Thread.sleep(POLL_INTERVAL_MS)
        }
        throw IOException("no static report within ${timeoutMs}ms (last stage: $lastStage)")
    }.onFailure { Log.w(TAG, "awaitStatic failed", it) }

    /** The job record, for the dossier. Null rather than throwing. */
    fun job(base: String, jobId: String): JSONObject? = getJson("$base/api/jobs/$jobId")

    /**
     * The flat cross-surface `Verdict` of contract A15, for the consumer screen.
     *
     * Null while the route does not answer — which today includes "the route does not
     * exist yet". That is deliberate: `ConsumerVerdictSource` treats null as "fall
     * through to a fixture, and say on screen that it is one", so the consumer screen
     * could be built and rehearsed ahead of the endpoint and will pick up the real
     * object the moment it appears, with no change to any screen.
     */
    fun consumerVerdict(base: String, jobId: String): JSONObject? =
        getJson("$base/api/jobs/$jobId/verdict")

    /** The static report, for the dossier. Null while the stage is still pending. */
    fun staticReport(base: String, jobId: String): JSONObject? =
        getJson("$base/api/jobs/$jobId/static")

    /**
     * The backend's reporting package (`/artifacts/dossier`).
     *
     * Preferred over composing a dossier on the phone: it is built by `m7_report`
     * from the same evidence the report and the ledger use, so the complaint body a
     * victim pastes into the portal cannot drift from what the analysis actually
     * found. Null while the stage has not produced one.
     */
    fun dossier(base: String, jobId: String): JSONObject? =
        getJson("$base/api/jobs/$jobId/artifacts/dossier")

    /** Deep link into the dashboard for the same job, shown on the report screen. */
    fun dashboardUrl(uiBase: String, jobId: String): String = "$uiBase/?job=$jobId"

    // ── internals ────────────────────────────────────────────────────────────
    private fun getJson(url: String): JSONObject? = try {
        val conn = open(url, "GET", connectMs = 3000, readMs = 10_000)
        val code = conn.responseCode
        val result = if (code == 200) {
            JSONObject(conn.inputStream.bufferedReader().use { it.readText() })
        } else {
            conn.errorStream?.close()
            null
        }
        conn.disconnect()
        result
    } catch (e: Exception) {
        Log.i(TAG, "GET $url failed: ${e.message}")
        null
    }

    private fun open(url: String, method: String, connectMs: Int, readMs: Int):
        HttpURLConnection {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.requestMethod = method
        conn.connectTimeout = connectMs
        conn.readTimeout = readMs
        conn.useCaches = false
        conn.setRequestProperty("Accept", "application/json")
        conn.setRequestProperty("User-Agent", "DRISHTI-Shield/1.0")
        return conn
    }
}

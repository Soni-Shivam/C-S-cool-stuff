package `in`.drishti.shield

import android.content.Context
import android.util.Log
import java.io.File
import java.security.MessageDigest

/**
 * The one path from "here is an APK" to "here is a verdict".
 *
 * Layer 1 (the watcher) and Layer 2 (the tap interceptor) are different triggers for
 * the same analysis. Giving them one implementation is the same discipline as
 * `m5_ml/features.extract` serving both training and inference: two code paths would
 * drift, and the demo would show a different verdict depending on which layer fired.
 */
object ScanEngine {
    private const val TAG = "DrishtiShield"
    private const val SETTLE_POLL_MS = 40L
    private const val SETTLE_STABLE_READS = 2
    private const val SETTLE_TIMEOUT_MS = 8_000L

    fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { stream ->
            val buffer = ByteArray(1 shl 16)
            while (true) {
                val read = stream.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    /**
     * Wait until the file is a *complete* APK, not merely one that has stopped growing.
     *
     * The first version of this waited for the size to stop changing, and it produced
     * a wrong sha256 on the very first run of the demo: the emulator's shared storage
     * is FUSE-backed, the reported size reaches its final value before the tail of the
     * data is readable, and a size-stability check happily declares that complete. The
     * verdict was then computed over bytes that were not the file — which is the one
     * failure a hash-based product cannot survive.
     *
     * So size stability is now only the cheap first gate. The decisive test is
     * [hasZipEndRecord]: an APK is a ZIP, and a ZIP is complete exactly when its End Of
     * Central Directory record is present at the end. Nothing can write that record
     * before the rest of the archive is there.
     */
    fun settle(file: File): Boolean {
        val deadline = System.currentTimeMillis() + SETTLE_TIMEOUT_MS
        var last = -1L
        var stable = 0
        while (System.currentTimeMillis() < deadline) {
            if (!file.exists()) return false
            val size = file.length()
            if (size > 0 && size == last) {
                stable++
                if (stable >= SETTLE_STABLE_READS && hasZipEndRecord(file)) return true
            } else {
                stable = 0
            }
            last = size
            Thread.sleep(SETTLE_POLL_MS)
        }
        Log.w(TAG, "file never became a complete archive: ${file.name}")
        return false
    }

    /**
     * True if the file ends in a well-formed ZIP End Of Central Directory record.
     *
     * The EOCD signature is `PK\x05\x06` (0x06054b50 little-endian). It sits in the
     * last 22 bytes when there is no ZIP comment, and no further back than 22 + 65535
     * bytes when there is one — so scanning that tail backwards is bounded and cheap.
     */
    private fun hasZipEndRecord(file: File): Boolean = runCatching {
        val length = file.length()
        if (length < 22) return@runCatching false
        val window = minOf(length, 22L + 0xFFFF).toInt()
        val tail = ByteArray(window)
        java.io.RandomAccessFile(file, "r").use { raf ->
            raf.seek(length - window)
            raf.readFully(tail)
        }
        for (i in tail.size - 22 downTo 0) {
            if (tail[i] == 0x50.toByte() && tail[i + 1] == 0x4B.toByte() &&
                tail[i + 2] == 0x05.toByte() && tail[i + 3] == 0x06.toByte()
            ) {
                return@runCatching true
            }
        }
        false
    }.getOrDefault(false)

    /**
     * Hash the file, then hash it again and require the two to agree.
     *
     * Belt to [settle]'s braces. If the bytes are still moving under us the two digests
     * differ and we retry rather than publishing a verdict about a hash that never
     * existed. Cheap — these APKs are under a megabyte.
     */
    fun stableSha256(file: File): String? {
        repeat(3) {
            val sizeBefore = file.length()
            val first = runCatching { sha256(file) }.getOrNull() ?: return@repeat
            val second = runCatching { sha256(file) }.getOrNull() ?: return@repeat
            if (first == second && file.length() == sizeBefore) return first
            Log.w(TAG, "hash unstable for ${file.name}, re-reading")
            Thread.sleep(120)
        }
        return null
    }

    fun newScan(file: File, sha: String, detectedAt: Long, stage: String): Scan = Scan(
        id = "scan_" + sha.take(12),
        filename = file.name,
        path = file.absolutePath,
        sha256 = sha,
        sizeBytes = file.length(),
        detectedAtMs = detectedAt,
        stage = stage,
    )

    /**
     * Submit, decide, then fill in the score. Blocking — call it off the main thread.
     *
     * **Two phases, deliberately.** The block decision needs M2's static report; the
     * composite score sits behind the GenAI stage in the pipeline. On this laptop
     * static lands in about 5 s while a cold free-tier LLM call took 35 s, so waiting
     * for the score before showing anything put a third-party endpoint's latency
     * directly into the moment the whole product is about to demonstrate — for a
     * layer the scorer then excludes as partial anyway.
     *
     * So phase 1 decides and, if warranted, engages the veto. Phase 2 attaches the
     * score when it arrives. `verdictAtMs` is stamped in phase 1 and never moved, so
     * the latency shown is the latency to a decision.
     *
     * The Layer-3 veto engages here rather than in a screen, because the block has to
     * hold whether or not anyone is looking at the phone.
     */
    fun analyse(context: Context, initial: Scan, file: File): Scan {
        val app = context.applicationContext
        val base = Config.backend(app)
        var scan = initial

        val submission = DrishtiClient.submit(base, file)
        if (submission.isFailure) {
            scan = scan.copy(
                state = ScanState.ERROR,
                stage = "backend unreachable",
                error = "Could not reach DRISHTI at $base — " +
                    (submission.exceptionOrNull()?.message ?: "unknown error"),
                verdictAtMs = System.currentTimeMillis(),
            )
            ScanBus.publish(scan)
            return scan
        }

        val jobId = submission.getOrThrow().jobId
        scan = scan.copy(jobId = jobId, stage = "queued")
        ScanBus.publish(scan)

        // ── phase 1: decide on static evidence ───────────────────────────────
        val evidence = DrishtiClient.awaitStatic(base, jobId, Config.STATIC_TIMEOUT_MS) { stage ->
            scan = scan.copy(stage = stage)
            ScanBus.publish(scan)
        }
        if (evidence.isFailure) {
            scan = scan.copy(
                state = ScanState.ERROR,
                stage = "no static report",
                error = evidence.exceptionOrNull()?.message ?: "no static report",
                verdictAtMs = System.currentTimeMillis(),
            )
            ScanBus.publish(scan)
            return scan
        }

        val static = evidence.getOrThrow()
        val decision = BlockDecision.decide(null, static)
        val vetoed = if (decision.block) PolicyEngine.engageVeto(app) else false
        VerdictStore.remember(app, scan.sha256, scan.filename, 0.0, "PENDING", decision)
        scan = scan.copy(
            state = ScanState.VERDICT,
            stage = "scoring",
            static = static,
            decision = decision,
            vetoEngaged = vetoed,
            verdictAtMs = System.currentTimeMillis(),
            scorePending = true,
        )
        ScanBus.publish(scan)
        Log.i(
            TAG,
            "verdict scan=${scan.id} sha256=${scan.sha256.take(16)} " +
                "block=${scan.blocked} basis=${scan.decision?.basis} " +
                "veto=${scan.vetoEngaged} elapsed_ms=${scan.elapsedMs}",
        )

        // ── phase 2: attach the composite score when it lands ────────────────
        val verdict = DrishtiClient.awaitVerdict(base, jobId, Config.VERDICT_TIMEOUT_MS) { stage ->
            scan = scan.copy(stage = stage)
            ScanBus.publish(scan)
        }
        scan = if (verdict.isSuccess) {
            val v = verdict.getOrThrow()
            // Re-decide with the score in hand. If S now clears the HIGH floor the
            // basis becomes COMPOSITE_SCORE; if it does not, the static decision
            // stands unchanged — a score arriving never *un*-blocks.
            val merged = BlockDecision.decide(v, static)
            val finalDecision = if (merged.block) merged else decision
            VerdictStore.remember(app, scan.sha256, scan.filename, v.score, v.band.name, finalDecision)
            val stillVetoed = vetoed ||
                (finalDecision.block && PolicyEngine.engageVeto(app))
            scan.copy(
                stage = "verdict",
                verdict = v,
                decision = finalDecision,
                vetoEngaged = stillVetoed,
                scorePending = false,
            )
        } else {
            // The decision already stands; only the score is missing. That is a
            // degraded result, not a failed one, so the state stays VERDICT.
            scan.copy(
                stage = "score unavailable",
                scorePending = false,
                error = verdict.exceptionOrNull()?.message,
            )
        }
        ScanBus.publish(scan)
        Log.i(
            TAG,
            "score scan=${scan.id} score=${scan.verdict?.score} band=${scan.verdict?.band} " +
                "basis=${scan.decision?.basis} total_ms=" +
                "${System.currentTimeMillis() - scan.detectedAtMs}",
        )
        return scan
    }
}

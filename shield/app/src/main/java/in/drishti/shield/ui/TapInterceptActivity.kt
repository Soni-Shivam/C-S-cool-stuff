package `in`.drishti.shield.ui

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Log
import `in`.drishti.shield.Config
import `in`.drishti.shield.ScanBus
import `in`.drishti.shield.ScanEngine
import `in`.drishti.shield.VerdictStore
import java.io.File

/**
 * LAYER 2 — tap-time interception.
 *
 * Registering for `application/vnd.android.package-archive` puts DRISHTI Shield in
 * the chooser next to the package installer, so tapping an APK in a file manager or a
 * chat app can route here instead. On stage this is the "and even if you tap it"
 * beat: Layer 1 has usually already produced a verdict, so this screen resolves
 * instantly from the recorded hash rather than re-uploading.
 *
 * This activity is a router, not a screen: it resolves the URI to a file, hashes it,
 * and hands off to [VerdictActivity].
 */
class TapInterceptActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val uri = intent?.data
        if (uri == null) {
            finish()
            return
        }
        Thread { route(uri) }.apply { isDaemon = true }.start()
    }

    private fun route(uri: Uri) {
        val detectedAt = System.currentTimeMillis()
        val file = materialise(uri)
        if (file == null) {
            Log.w(TAG, "could not resolve $uri to a readable file")
            runOnUiThread {
                startActivity(Intent(this, VerdictActivity::class.java))
                finish()
            }
            return
        }

        val sha = ScanEngine.stableSha256(file) ?: run {
            Log.w(TAG, "could not obtain a stable hash for ${file.name}")
            runOnUiThread { finish() }
            return
        }
        val known = VerdictStore.lookup(this, sha)
        val existing = ScanBus.find("scan_" + sha.take(12))

        if (existing?.verdict != null) {
            // Layer 1 already answered for these exact bytes. Show that answer rather
            // than starting a second job — a different verdict for the same hash on the
            // same stage would be worse than useless.
            Log.i(TAG, "tap resolved from an existing Layer 1 verdict for ${sha.take(16)}")
        } else {
            val scan = ScanEngine.newScan(file, sha, detectedAt, "uploading to DRISHTI")
            ScanBus.publish(scan)
            Thread { ScanEngine.analyse(this, scan, file) }.apply { isDaemon = true }.start()
        }

        Log.i(TAG, "tap_intercepted uri=$uri sha256=${sha.take(16)} previously_seen=${known != null}")
        val scanId = "scan_" + sha.take(12)
        // A tap is the moment an install begins, and the person doing it is a victim,
        // not an analyst. Which projection of the same analysis they land on is a
        // preference, not two analyses — see `Config.consumerScreen`.
        val next = if (Config.consumerScreen(this)) {
            Intent(this, ConsumerVerdictActivity::class.java)
                .putExtra(ConsumerVerdictActivity.EXTRA_SCAN_ID, scanId)
                .putExtra(ConsumerVerdictActivity.EXTRA_APK_PATH, file.absolutePath)
        } else {
            Intent(this, VerdictActivity::class.java)
                .putExtra(VerdictActivity.EXTRA_SCAN_ID, scanId)
        }
        runOnUiThread {
            startActivity(next.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP))
            finish()
        }
    }

    /**
     * Get real bytes for the tapped URI.
     *
     * `file://` URIs point at something we can read directly. `content://` URIs are
     * copied into the app's own cache first — a content provider hands out a stream,
     * not a path, and the analysis needs a file to upload. The copy lands in
     * `cacheDir`, which is private to this app.
     */
    private fun materialise(uri: Uri): File? = runCatching {
        when (uri.scheme) {
            "file" -> uri.path?.let(::File)?.takeIf { it.canRead() }
            "content" -> {
                val name = displayName(uri) ?: "tapped.apk"
                val target = File(cacheDir, "tap-$name")
                contentResolver.openInputStream(uri)?.use { input ->
                    target.outputStream().use { input.copyTo(it) }
                } ?: return@runCatching null
                target
            }
            else -> null
        }
    }.getOrNull()

    private fun displayName(uri: Uri): String? = runCatching {
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
        }
    }.getOrNull()

    companion object {
        private const val TAG = "DrishtiShield"

        /** Where a forwarded APK is expected to land. Referenced by the main screen. */
        val watchDir: String get() = Config.WATCH_DIR
    }
}

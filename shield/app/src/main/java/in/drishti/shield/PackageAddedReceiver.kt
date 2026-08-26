package `in`.drishti.shield

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.util.Log
import java.io.File

/**
 * LAYER 4 — the failsafe.
 *
 * Layers 1–3 can all be bypassed: the file can arrive somewhere we do not watch, the
 * user can install via a route we do not intercept, the veto can be released by an
 * analyst. So the last layer assumes failure has already happened and asks a
 * different question — is anything on this device something DRISHTI already decided
 * to block?
 *
 * It hashes the installed package's own APK and compares that against [VerdictStore].
 * A content check, not a name check: renaming the file or the package does not evade
 * it.
 */
class PackageAddedReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val packageName = intent.data?.schemeSpecificPart ?: return
        if (packageName == context.packageName) return

        // Hashing an APK takes longer than a receiver may block for, so the work moves
        // off the main thread under goAsync().
        val pending = goAsync()
        Thread {
            try { inspect(context, packageName) } finally { pending.finish() }
        }.apply { isDaemon = true }.start()
    }

    private fun inspect(context: Context, packageName: String) {
        val sourceDir = runCatching {
            context.packageManager.getPackageInfo(packageName, 0).applicationInfo?.sourceDir
        }.getOrNull() ?: return

        val sha = runCatching { ScanEngine.sha256(File(sourceDir)) }.getOrNull() ?: return
        val record = VerdictStore.lookup(context, sha)
        Log.i(
            TAG,
            "package_added pkg=$packageName sha256=${sha.take(16)} known=${record != null}",
        )
        if (record == null || !record.optBoolean("block", false)) return

        // Quarantine first, prompt second. If the user dismisses the uninstall dialog
        // the package is still suspended and cannot launch.
        val quarantined = PolicyEngine.quarantine(context, packageName)
        Log.i(TAG, "failsafe_engaged pkg=$packageName quarantined=$quarantined")

        val stored = VerdictStore.decisionOf(record)
        val scan = Scan(
            id = "scan_" + sha.take(12),
            filename = record.optString("filename", packageName),
            path = sourceDir,
            sha256 = sha,
            sizeBytes = File(sourceDir).length(),
            detectedAtMs = System.currentTimeMillis(),
            state = ScanState.VERDICT,
            stage = "post-install failsafe",
            decision = stored.copy(
                detail = stored.detail + "\n\nThis package is already installed. Its APK " +
                    "hash matches a decision DRISHTI recorded earlier, so it has been " +
                    "suspended and its uninstall protection lifted for you.",
            ),
            verdictAtMs = System.currentTimeMillis(),
            vetoEngaged = quarantined,
        )
        ScanBus.publish(scan)
        Notifications.post(context, Notifications.ID_ALERT, Notifications.alert(context, scan))

        runCatching {
            context.startActivity(
                Intent(context, `in`.drishti.shield.ui.VerdictActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    putExtra(`in`.drishti.shield.ui.VerdictActivity.EXTRA_SCAN_ID, scan.id)
                    putExtra(`in`.drishti.shield.ui.VerdictActivity.EXTRA_PACKAGE, packageName)
                }
            )
        }
    }

    companion object {
        private const val TAG = "DrishtiShield"

        /** The user-facing uninstall prompt. DRISHTI proposes; the user disposes. */
        fun uninstallIntent(packageName: String): Intent =
            Intent(Intent.ACTION_DELETE, Uri.parse("package:$packageName"))
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
    }
}

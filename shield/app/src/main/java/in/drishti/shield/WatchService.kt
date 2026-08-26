package `in`.drishti.shield

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.FileObserver
import android.os.IBinder
import android.util.Log
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors

/**
 * LAYER 1 — the pre-install watcher, and the reason this product exists.
 *
 * Every other Android security product looks at an APK when the user taps it. By then
 * the user has already decided to trust it, and the dialog they get is one more thing
 * to dismiss. This service notices the file the moment it lands in the Download
 * directory and puts a verdict on screen before any tap happens.
 *
 * Two detectors run in parallel, on purpose:
 *   1. A [FileObserver] (inotify), which fires in single-digit milliseconds.
 *   2. A 250 ms directory sweep.
 *
 * The sweep is not redundancy theatre. inotify events on emulated shared storage are
 * delivered through a FUSE layer and are occasionally dropped; a demo that depends on
 * a single event source is a demo that fails once in twenty on stage. Whichever
 * detector sees the file first wins, and [inFlight] makes the second one a no-op.
 */
class WatchService : Service() {

    private val io = Executors.newFixedThreadPool(3)
    private val inFlight = ConcurrentHashMap<String, Long>()
    private var observer: FileObserver? = null
    private var sweeper: Thread? = null
    private var packageWatcher: PackageAddedReceiver? = null
    @Volatile private var running = false

    companion object {
        private const val TAG = "DrishtiShield"
        private const val SWEEP_INTERVAL_MS = 250L

        /** A repeat sighting of the same path inside this window is the other detector
         *  seeing the same event, not a new file. */
        private const val DEDUPE_WINDOW_MS = 15_000L

        fun start(context: Context) {
            val intent = Intent(context, WatchService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        Notifications.ensureChannels(this)
        goForeground("Watching ${Config.WATCH_DIR}")
        running = true
        startObserver()
        startSweeper()
        startPackageWatcher()
        Log.i(TAG, "watcher up on ${Config.WATCH_DIR}")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // START_STICKY: if the OS reclaims us, come back. A guard that stays dead
        // after one memory-pressure event is not a guard.
        return START_STICKY
    }

    override fun onDestroy() {
        running = false
        observer?.stopWatching()
        sweeper?.interrupt()
        packageWatcher?.let { runCatching { unregisterReceiver(it) } }
        io.shutdownNow()
        super.onDestroy()
    }

    /**
     * Register the Layer 4 receiver at runtime.
     *
     * The manifest declaration alone does not work, and finding out why cost a test
     * run: `ACTION_PACKAGE_ADDED` is **not** on API 26's implicit-broadcast exemption
     * list, so a manifest-declared receiver for it is silently never invoked. The
     * install went through, Layer 4 logged nothing at all, and the failure looked
     * like a hashing bug rather than a delivery one.
     *
     * A context-registered receiver is exempt from that restriction, and this service
     * is a foreground service that outlives the app's UI — so registering here is what
     * actually arms Layer 4. The manifest entry is kept for API < 26 and for OEM
     * builds that still deliver it.
     */
    private fun startPackageWatcher() {
        packageWatcher = PackageAddedReceiver().also { receiver ->
            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_PACKAGE_ADDED)
                addAction(Intent.ACTION_PACKAGE_REPLACED)
                addDataScheme("package")
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                registerReceiver(receiver, filter, Context.RECEIVER_EXPORTED)
            } else {
                @Suppress("UnspecifiedRegisterReceiverFlag")
                registerReceiver(receiver, filter)
            }
            Log.i(TAG, "layer 4 armed: PACKAGE_ADDED receiver registered at runtime")
        }
    }

    // ── detection ────────────────────────────────────────────────────────────
    @Suppress("DEPRECATION") // the File-based ctor is API 29; minSdk here is 26
    private fun startObserver() {
        val mask = FileObserver.CREATE or FileObserver.MOVED_TO or FileObserver.CLOSE_WRITE
        observer = object : FileObserver(Config.WATCH_DIR, mask) {
            override fun onEvent(event: Int, path: String?) {
                val name = path ?: return
                if (!name.endsWith(".apk", ignoreCase = true)) return
                onCandidate(File(Config.WATCH_DIR, name), "inotify")
            }
        }.also { it.startWatching() }
    }

    private fun startSweeper() {
        sweeper = Thread {
            val seen = HashSet<String>()
            // Prime with what is already there so restarting the service does not
            // re-raise a verdict for a file the operator has already dealt with.
            File(Config.WATCH_DIR).listFiles()
                ?.filter { it.name.endsWith(".apk", true) }
                ?.forEach { seen.add(it.name + ":" + it.length()) }
            while (running && !Thread.currentThread().isInterrupted) {
                try {
                    File(Config.WATCH_DIR).listFiles()
                        ?.filter { it.isFile && it.name.endsWith(".apk", true) }
                        ?.forEach { file ->
                            if (seen.add(file.name + ":" + file.length())) {
                                onCandidate(file, "sweep")
                            }
                        }
                    Thread.sleep(SWEEP_INTERVAL_MS)
                } catch (e: InterruptedException) {
                    return@Thread
                } catch (e: Exception) {
                    Log.i(TAG, "sweep tick failed: ${e.message}")
                }
            }
        }.also { it.isDaemon = true; it.start() }
    }

    /**
     * A candidate APK. [detectedAt] is stamped here, at the first observation, and is
     * what the on-screen millisecond counter measures from — so the number on stage is
     * the true file-landing-to-verdict latency and not a figure measured from a
     * convenient later point.
     */
    private fun onCandidate(file: File, source: String) {
        val detectedAt = System.currentTimeMillis()
        val key = file.absolutePath
        val previous = inFlight.putIfAbsent(key, detectedAt)
        if (previous != null && detectedAt - previous < DEDUPE_WINDOW_MS) return
        Log.i(TAG, "apk_detected path=$key source=$source")
        io.submit { handle(file, detectedAt) }
    }

    private fun handle(file: File, detectedAt: Long) {
        try {
            if (!ScanEngine.settle(file)) {
                Log.i(TAG, "file never settled, ignoring: ${file.name}")
                return
            }
            val sha = ScanEngine.stableSha256(file)
            if (sha == null) {
                Log.w(TAG, "could not obtain a stable hash for ${file.name}; not scanning")
                return
            }
            val scan = ScanEngine.newScan(file, sha, detectedAt, "uploading to DRISHTI")
            ScanBus.publish(scan)
            Notifications.post(this, Notifications.ID_ALERT, Notifications.alert(this, scan))
            surface(scan)

            val done = ScanEngine.analyse(this, scan, file)
            Notifications.post(this, Notifications.ID_ALERT, Notifications.alert(this, done))
            surface(done)
            goForeground(
                done.verdict?.let { "Last verdict: ${it.band} ${it.score.toInt()}/100" }
                    ?: "Watching ${Config.WATCH_DIR}"
            )
        } catch (e: Exception) {
            Log.w(TAG, "handle failed for ${file.name}", e)
        } finally {
            inFlight.remove(file.absolutePath)
        }
    }

    /**
     * Bring the verdict screen up.
     *
     * A background activity start is restricted on API 29+. Shield holds
     * SYSTEM_ALERT_WINDOW (granted by the operator via appops in
     * `scripts/demo_up.sh`), which is one of the documented exemptions. If the OS
     * refuses anyway, the full-screen-intent notification posted alongside is the
     * fallback and the screen is one tap away — so this never becomes a hard failure.
     */
    private fun surface(scan: Scan) {
        // Phase 2 re-surfaces a scan when its score lands. If a newer file has since
        // arrived, bringing this one back to the front would flicker the screen away
        // from the current verdict — `VerdictActivity` refuses the switch anyway, but
        // not raising the window at all is the version with no flicker in it.
        val newest = ScanBus.current
        if (newest != null && newest.id != scan.id && newest.detectedAtMs > scan.detectedAtMs) {
            return
        }
        try {
            startActivity(
                Intent(this, `in`.drishti.shield.ui.VerdictActivity::class.java).apply {
                    addFlags(
                        Intent.FLAG_ACTIVITY_NEW_TASK or
                            Intent.FLAG_ACTIVITY_CLEAR_TOP or
                            Intent.FLAG_ACTIVITY_REORDER_TO_FRONT
                    )
                    putExtra(`in`.drishti.shield.ui.VerdictActivity.EXTRA_SCAN_ID, scan.id)
                }
            )
        } catch (e: Exception) {
            Log.i(TAG, "background activity start refused (${e.message}); notification stands")
        }
    }

    private fun goForeground(text: String) {
        val notification = Notifications.watching(this, text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                Notifications.ID_WATCH,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
            )
        } else {
            startForeground(Notifications.ID_WATCH, notification)
        }
    }
}

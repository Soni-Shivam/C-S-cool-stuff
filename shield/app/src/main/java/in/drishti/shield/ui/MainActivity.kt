package `in`.drishti.shield.ui

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Toast
import `in`.drishti.shield.Config
import `in`.drishti.shield.DrishtiClient
import `in`.drishti.shield.PolicyEngine
import `in`.drishti.shield.Scan
import `in`.drishti.shield.ScanBus
import `in`.drishti.shield.ScanState
import `in`.drishti.shield.VerdictStore
import `in`.drishti.shield.WatchService

/**
 * The operator's console: is each layer actually armed, right now?
 *
 * Every row reports a fact read from the system at render time — is the watcher
 * running, is All-Files access granted, is this app device owner, does the backend
 * answer. None of it is a static "protected ✓" badge. If a layer is not armed the
 * card says so in the same place it would otherwise claim protection, because a
 * security console that overstates its own state is the failure mode being defended
 * against.
 */
class MainActivity : Activity() {

    companion object {
        /** Boolean extra that returns the device to the demo's starting state. */
        const val EXTRA_DEMO_RESET = "drishti_demo_reset"

        /** Boolean extra that fires the Layer 3 self-test. See [handleVetoSelfTest]. */
        const val EXTRA_VETO_SELFTEST = "drishti_veto_selftest"
    }

    private lateinit var body: LinearLayout
    private val refresh = Handler(Looper.getMainLooper())
    @Volatile private var backendUp: Boolean? = null

    private val listener: (Scan) -> Unit = { render() }

    private val repaint = object : Runnable {
        override fun run() {
            render()
            refresh.postDelayed(this, 1500)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Ui.BG)
        }
        body = Ui.column(this)
        root.addView(
            ScrollView(this).apply {
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
                isFillViewport = true
                addView(body)
            }
        )
        setContentView(root)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }
        WatchService.start(this)
        ScanBus.subscribe(listener)
        probeBackend()
        handleDemoReset(intent)
        handleVetoSelfTest(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleDemoReset(intent)
        handleVetoSelfTest(intent)
    }

    /**
     * Prove Layer 3 actually works, right now, before anybody is watching.
     *
     * WHY THIS EXISTS. `dpm list-owners` reporting this package is a CLAIM, not a test,
     * and the two came apart in rehearsal in the worst possible way. `demo_up.sh`
     * reinstalls Shield on every run; the reinstall drops the *active admin* record
     * while the *device owner* record survives, so `dpm list-owners` kept saying
     * "DeviceOwner" while `addUserRestriction` threw
     *
     *     SecurityException: Admin ComponentInfo{…DrishtiAdminReceiver} does not exist
     *     or is not owned by uid 10192
     *
     * The result was a demo that armed cleanly, announced "Layer 3 device owner HELD",
     * and then quietly failed to block anything — the veto engaged on the first
     * provisioning of an AVD and never again. Nothing in the setup path noticed,
     * because nothing in the setup path had ever engaged the veto.
     *
     * So this does: engage it, read the restriction back out of `UserManager`, and
     * release it. Three states, one log line, and `demo_up.sh` refuses to hand over a
     * stage-ready demo unless the middle one came back true. It is the same reasoning
     * `verify_containment.py` applies to the network — a security property you have not
     * exercised is a security property you do not have.
     *
     * **Guarded on [FLAG_DEBUGGABLE]**, for the reason spelled out on [handleDemoReset]:
     * this activity is exported, so an unguarded extra would let any installed app
     * toggle a device-owner restriction.
     */
    private fun handleVetoSelfTest(intent: Intent?) {
        if (intent?.getBooleanExtra(EXTRA_VETO_SELFTEST, false) != true) return
        val debuggable =
            (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!debuggable) return

        val owner = PolicyEngine.isDeviceOwner(this)
        val engaged = PolicyEngine.engageVeto(this)
        // Read the restriction back from UserManager rather than trusting engageVeto's
        // return: the whole point is to confirm the OS agrees the veto is in force.
        val observed = PolicyEngine.vetoEngaged(this)
        val released = PolicyEngine.releaseVeto(this)
        android.util.Log.i(
            "DrishtiShield",
            "veto_selftest owner=$owner engaged=$engaged observed=$observed released=$released",
        )
        render()
    }

    /**
     * Put the device back into the state the demo starts from, on request.
     *
     * `scripts/demo_run.sh` runs the cleared app and the blocked app back to back and
     * must be rerunnable, which means something has to release the Layer 3 veto that
     * the previous run engaged. Doing it from adb —
     * `am start -n in.drishti.shield/.ui.MainActivity --ez drishti_demo_reset true` —
     * keeps the reset in one place instead of scattering `dpm` calls through a shell
     * script.
     *
     * **Guarded on [FLAG_DEBUGGABLE].** `MainActivity` is exported because it is the
     * launcher, so without the guard any installed app could send this extra and clear
     * a device-owner restriction — the exact privilege escalation this app exists to
     * prevent. Debug builds are the only thing the demo ever ships; a release build has
     * no such surface at all.
     */
    private fun handleDemoReset(intent: Intent?) {
        if (intent?.getBooleanExtra(EXTRA_DEMO_RESET, false) != true) return
        val debuggable =
            (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        if (!debuggable) {
            Toast.makeText(this, "Demo reset refused: this is not a debug build", Toast.LENGTH_LONG)
                .show()
            return
        }
        VerdictStore.clear(this)
        val released = PolicyEngine.releaseVeto(this)
        // Layer 4's quarantine sets setUninstallBlocked, which makes `adb uninstall`
        // return DELETE_FAILED_OWNER_BLOCKED — so without this sweep a single rehearsal
        // where the decoy installed left it permanently stuck on the device and every
        // later reset silently failed to clear it.
        val freed = PolicyEngine.releaseAllQuarantines(this)
        android.util.Log.i(
            "DrishtiShield",
            "demo_reset veto_released=$released store_cleared=true " +
                "quarantines_released=${freed.size}${if (freed.isEmpty()) "" else " [${freed.joinToString(",")}]"}",
        )
        Toast.makeText(
            this,
            if (released) "Demo reset: veto released, verdict memory cleared"
            else "Demo reset: verdict memory cleared (no veto was held)",
            Toast.LENGTH_SHORT,
        ).show()
        render()
    }

    override fun onResume() {
        super.onResume()
        refresh.post(repaint)
    }

    override fun onPause() {
        refresh.removeCallbacksAndMessages(null)
        super.onPause()
    }

    override fun onDestroy() {
        ScanBus.unsubscribe(listener)
        super.onDestroy()
    }

    private fun probeBackend() {
        Thread {
            val up = DrishtiClient.health(Config.backend(this))
            backendUp = up
            runOnUiThread { render() }
        }.apply { isDaemon = true }.start()
    }

    private fun render() {
        body.removeAllViews()
        body.addView(Ui.text(this, "DRISHTI", Ui.SMALL, Ui.MUTED, bold = true))
        body.addView(Ui.text(this, "Shield", Ui.TITLE, Ui.ACCENT, bold = true))
        body.addView(
            Ui.text(
                this,
                "Four independent layers. Each one reports its real state below.",
                Ui.SMALL, Ui.MUTED, topMargin = 4,
            )
        )

        layer(
            "LAYER 1 — pre-install watcher",
            armed = hasStorageAccess(),
            armedText = "Watching ${Config.WATCH_DIR}. A verdict appears before any tap.",
            disarmedText = "All-files access is not granted, so the Download folder cannot " +
                "be observed. Grant it below or run scripts/demo_up.sh.",
            action = if (hasStorageAccess()) null else "Grant all-files access" to {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    runCatching {
                        startActivity(
                            Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                        )
                    }
                }
                Unit
            },
        )

        layer(
            "LAYER 2 — tap-time intercept",
            armed = true,
            armedText = "Registered for application/vnd.android.package-archive. Tapping an " +
                "APK offers DRISHTI Shield alongside the package installer.",
            disarmedText = "",
        )

        layer(
            "LAYER 3 — the veto",
            armed = PolicyEngine.isDeviceOwner(this),
            armedText = PolicyEngine.statusLine(this),
            disarmedText = "Not device owner. Provision with:\n" +
                "adb shell dpm set-device-owner in.drishti.shield/.DrishtiAdminReceiver\n" +
                "(requires a device with no accounts). Without it, a malicious verdict is " +
                "advisory only and the install will still succeed.",
        )

        layer(
            "LAYER 4 — post-install failsafe",
            armed = true,
            armedText = "Every newly installed package is hashed and checked against the " +
                "recorded verdicts. A rename does not evade it.",
            disarmedText = "",
        )

        // Backend ---------------------------------------------------------------
        val backend = Ui.card(this, if (backendUp == true) Ui.LOW else Ui.MEDIUM)
        backend.addView(Ui.text(this, "ANALYSIS BACKEND", Ui.SMALL, Ui.MUTED, bold = true))
        backend.addView(Ui.text(this, Config.backend(this), Ui.MONO, Ui.INK, mono = true, topMargin = 6))
        backend.addView(
            Ui.text(
                this,
                when (backendUp) {
                    true -> "Reachable. Static analysis and scoring run on the host."
                    false -> "Not reachable. Verdicts will report as inconclusive."
                    null -> "Probing…"
                },
                Ui.SMALL,
                if (backendUp == true) Ui.LOW else Ui.MEDIUM,
                topMargin = 6,
            )
        )
        backend.addView(Ui.button(this, "Re-probe") { backendUp = null; render(); probeBackend() })
        body.addView(backend)

        // Recent scans ----------------------------------------------------------
        val history = ScanBus.history.reversed()
        val scans = Ui.card(this, Ui.SURFACE)
        scans.addView(Ui.text(this, "RECENT SCANS", Ui.SMALL, Ui.MUTED, bold = true))
        if (history.isEmpty()) {
            scans.addView(Ui.text(this, "Nothing scanned yet this session.", Ui.SMALL, Ui.MUTED, topMargin = 6))
        } else {
            history.forEach { s ->
                val colour = when {
                    s.state == ScanState.SCANNING -> Ui.ACCENT
                    s.state == ScanState.ERROR -> Ui.MEDIUM
                    s.blocked -> Ui.CRITICAL
                    else -> Ui.LOW
                }
                val summary = s.decision?.let { "${it.headline} · ${s.elapsedMs} ms" } ?: s.stage
                scans.addView(
                    Ui.button(this, "${s.filename} — $summary", Ui.SURFACE, colour) {
                        startActivity(
                            Intent(this, VerdictActivity::class.java)
                                .putExtra(VerdictActivity.EXTRA_SCAN_ID, s.id)
                        )
                    }
                )
            }
        }
        body.addView(scans)

        val tools = Ui.row(this)
        tools.addView(
            Ui.button(this, "Open last verdict") {
                startActivity(Intent(this, VerdictActivity::class.java))
            }
        )
        tools.addView(
            Ui.button(this, "Reset demo state", Ui.SURFACE, Ui.MEDIUM) {
                VerdictStore.clear(this)
                PolicyEngine.releaseVeto(this)
                Toast.makeText(this, "Verdict memory cleared, veto released", Toast.LENGTH_LONG).show()
                render()
            }
        )
        body.addView(tools)
    }

    private fun layer(
        title: String,
        armed: Boolean,
        armedText: String,
        disarmedText: String,
        action: Pair<String, () -> Unit>? = null,
    ) {
        val card = Ui.card(this, if (armed) Ui.LOW else Ui.MEDIUM)
        val head = Ui.row(this)
        head.addView(Ui.pill(this, if (armed) "ARMED" else "NOT ARMED", if (armed) Ui.LOW else Ui.MEDIUM))
        head.addView(Ui.text(this, title, Ui.BODY, Ui.INK, bold = true))
        card.addView(head)
        card.addView(
            Ui.text(
                this,
                if (armed) armedText else disarmedText,
                Ui.SMALL, Ui.MUTED, mono = !armed, topMargin = 8,
            )
        )
        action?.let { (label, onClick) ->
            card.addView(Ui.button(this, label, Ui.MEDIUM, Ui.BG) { onClick() })
        }
        body.addView(card)
    }

    private fun hasStorageAccess(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == 0
        }
}

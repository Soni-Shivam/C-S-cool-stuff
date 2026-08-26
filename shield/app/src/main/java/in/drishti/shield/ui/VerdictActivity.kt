package `in`.drishti.shield.ui

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowManager
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import `in`.drishti.shield.BlockDecision
import `in`.drishti.shield.Config
import `in`.drishti.shield.PackageAddedReceiver
import `in`.drishti.shield.PolicyEngine
import `in`.drishti.shield.Scan
import `in`.drishti.shield.ScanBus
import `in`.drishti.shield.ScanState
import `in`.drishti.shield.ui.Ui.dp
import java.io.File
import java.util.Locale

/**
 * The screen the demo lives or dies on.
 *
 * Three states, one screen: SCANNING (blue, live millisecond counter), VERDICT (red
 * and blocking, or green and cleared), ERROR (amber, and honest about what it does
 * not know). The counter runs during SCANNING and freezes at the verdict, so the
 * number the room reads is the real end-to-end latency from the instant the file
 * landed — not a figure measured from a more flattering starting point.
 *
 * The "BASIS FOR THIS DECISION" card is the part worth defending in a code review:
 * it prints which evidence actually carried the block, including the case where the
 * composite score is zero because the ML and GenAI layers are unavailable. A guard
 * app that showed a confident red screen over a score of 0 without saying why would
 * be the exact failure this project exists to argue against.
 */
class VerdictActivity : Activity() {

    companion object {
        const val EXTRA_SCAN_ID = "scan_id"
        const val EXTRA_PACKAGE = "package_name"
    }

    private lateinit var root: LinearLayout
    private lateinit var body: LinearLayout
    private lateinit var timer: TextView
    private val ticker = Handler(Looper.getMainLooper())
    private var scan: Scan? = null
    private var installedPackage: String? = null

    private val listener: (Scan) -> Unit = { updated ->
        if (scan == null || updated.id == scan?.id) render(updated)
    }

    private val tick = object : Runnable {
        override fun run() {
            val s = scan ?: return
            if (s.state == ScanState.SCANNING) {
                timer.text = "${s.elapsedMs} ms"
                ticker.postDelayed(this, 16)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION") // setShowWhenLocked is API 27; the flags work on 26 too
        window.addFlags(
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD
        )
        buildChrome()
        handleIntent(intent)
        ScanBus.subscribe(listener)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIntent(intent)
    }

    override fun onDestroy() {
        ScanBus.unsubscribe(listener)
        ticker.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun handleIntent(intent: Intent) {
        installedPackage = intent.getStringExtra(EXTRA_PACKAGE)
        val id = intent.getStringExtra(EXTRA_SCAN_ID)
        val target = id?.let { ScanBus.find(it) } ?: ScanBus.current
        if (target != null) render(target) else renderIdle()
    }

    // ── chrome ───────────────────────────────────────────────────────────────
    private fun buildChrome() {
        root = LinearLayout(this).apply {
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
        timer = Ui.text(this, "0 ms", Ui.HUGE, Ui.ACCENT, bold = true).apply {
            gravity = Gravity.CENTER
        }
        setContentView(root)
    }

    private fun renderIdle() {
        body.removeAllViews()
        body.addView(Ui.text(this, "DRISHTI SHIELD", Ui.SMALL, Ui.MUTED, bold = true))
        body.addView(Ui.text(this, "No scan yet", Ui.TITLE, Ui.INK, bold = true, topMargin = 12))
        body.addView(
            Ui.text(
                this,
                "Layer 1 is watching ${Config.WATCH_DIR}. This screen appears by itself the " +
                    "moment an APK lands there — before anything is tapped.",
                Ui.BODY, Ui.MUTED, topMargin = 12,
            )
        )
    }

    private fun render(s: Scan) {
        scan = s
        val blocked = s.blocked
        val accent = when {
            s.state == ScanState.SCANNING -> Ui.ACCENT
            s.state == ScanState.ERROR -> Ui.MEDIUM
            blocked -> Ui.CRITICAL
            else -> Ui.LOW
        }
        root.setBackgroundColor(if (blocked) 0xFF1A0708.toInt() else Ui.BG)
        body.removeAllViews()

        // Banner ---------------------------------------------------------------
        val layerLabel =
            if (installedPackage != null) "LAYER 4 · POST-INSTALL FAILSAFE"
            else "LAYER 1 · PRE-INSTALL INTERCEPT"
        body.addView(Ui.text(this, "DRISHTI SHIELD · $layerLabel", Ui.SMALL, Ui.MUTED, bold = true))

        val headline = when {
            s.state == ScanState.SCANNING -> "ANALYSING…"
            s.state == ScanState.ERROR -> "NO VERDICT"
            blocked && s.vetoEngaged -> "INSTALL BLOCKED"
            blocked -> "MALICIOUS — NOT BLOCKED"
            else -> "NO BLOCKING EVIDENCE"
        }
        // The counter freezes at the decision. `scorePending` keeps the screen honest
        // about the fact that more is still arriving.
        val subtitle = when {
            s.state == ScanState.SCANNING -> "since the file landed — still counting"
            s.scorePending -> "from file landing to verdict — deeper analysis continues"
            else -> "from file landing to verdict on screen"
        }
        body.addView(Ui.text(this, headline, Ui.TITLE, accent, bold = true, topMargin = 8))

        // Timer ----------------------------------------------------------------
        (timer.parent as? LinearLayout)?.removeView(timer)
        timer.setTextColor(accent)
        timer.text = "${s.elapsedMs} ms"
        body.addView(timer)
        body.addView(
            Ui.text(
                this,
                subtitle,
                Ui.SMALL, Ui.MUTED,
            ).apply { gravity = Gravity.CENTER }
        )
        ticker.removeCallbacksAndMessages(null)
        if (s.state == ScanState.SCANNING) ticker.post(tick)

        body.addView(fileCard(s, accent))
        s.decision?.let { body.addView(basisCard(it, accent)) }
        if (s.verdict != null) {
            body.addView(scoreCard(s.verdict, accent))
        } else if (s.scorePending) {
            body.addView(pendingScoreCard())
        }
        s.static?.let { body.addView(staticCard(it)) }
        if (s.decision != null) body.addView(vetoCard(s))
        s.verdict?.limitations?.takeIf { it.isNotEmpty() }?.let { body.addView(limitCard(it)) }
        if (s.state == ScanState.ERROR) body.addView(errorCard(s))
        body.addView(actions(s))
    }

    // ── cards ────────────────────────────────────────────────────────────────
    private fun fileCard(s: Scan, accent: Int): View {
        val card = Ui.card(this, accent)
        card.addView(Ui.text(this, s.filename, Ui.BODY, Ui.INK, bold = true))
        s.static?.let {
            card.addView(
                Ui.text(this, "declares itself as \"${it.appLabel}\" · ${it.packageName}",
                    Ui.SMALL, Ui.MUTED, topMargin = 4)
            )
        }
        card.addView(Ui.text(this, "sha256 ${s.sha256}", Ui.MONO, Ui.MUTED, mono = true, topMargin = 6))
        card.addView(Ui.text(this, "${s.sizeBytes} bytes · ${s.path}", Ui.SMALL, Ui.MUTED, topMargin = 4))
        if (s.state == ScanState.SCANNING) {
            card.addView(Ui.text(this, "stage: ${s.stage}", Ui.SMALL, Ui.ACCENT, topMargin = 6))
        }
        s.jobId?.let {
            card.addView(Ui.text(this, "DRISHTI job $it", Ui.MONO, Ui.MUTED, mono = true, topMargin = 4))
        }
        return card
    }

    /** The card that says which evidence carried the decision. Never omitted. */
    private fun basisCard(decision: BlockDecision, accent: Int): View {
        val card = Ui.card(this, accent)
        card.addView(Ui.text(this, "BASIS FOR THIS DECISION", Ui.SMALL, Ui.MUTED, bold = true))
        card.addView(Ui.text(this, decision.headline, Ui.BODY, accent, bold = true, topMargin = 6))
        card.addView(
            Ui.pill(
                this,
                when (decision.basis) {
                    BlockDecision.Basis.COMPOSITE_SCORE -> "M6 composite score"
                    BlockDecision.Basis.STATIC_EVIDENCE -> "M2 static evidence"
                    BlockDecision.Basis.INSUFFICIENT_EVIDENCE -> "insufficient evidence"
                    BlockDecision.Basis.CLEAR -> "no blocking evidence"
                },
                accent,
            )
        )
        card.addView(Ui.text(this, decision.detail, Ui.SMALL, Ui.MUTED, topMargin = 8))
        decision.citations.forEach {
            card.addView(Ui.text(this, "• $it", Ui.SMALL, Ui.INK, topMargin = 6))
        }
        return card
    }

    private fun scoreCard(verdict: `in`.drishti.shield.Verdict, accent: Int): View {
        val card = Ui.card(this, Ui.SURFACE)
        card.addView(Ui.text(this, "M6 COMPOSITE SCORE", Ui.SMALL, Ui.MUTED, bold = true))
        val head = Ui.row(this)
        head.addView(Ui.pill(this, verdict.band.name, Ui.bandColor(verdict.band.name)))
        head.addView(
            Ui.text(this, "${verdict.score.toInt()} / 100", Ui.TITLE, accent, bold = true)
                .apply { layoutParams = LinearLayout.LayoutParams(WRAP_CONTENT, WRAP_CONTENT) }
        )
        card.addView(head)
        card.addView(
            Ui.text(
                this,
                "confidence C=${fmt(verdict.confidence)} · evidence completeness " +
                    "γ=${fmt(verdict.gamma)}",
                Ui.SMALL, Ui.MUTED, topMargin = 6,
            )
        )
        verdict.factors.forEach { f ->
            card.addView(
                Ui.text(
                    this,
                    "${f.symbol.padEnd(5)}${f.label.take(22).padEnd(24)}" +
                        "${fmt(f.raw)} × ${fmt(f.weight)} = ${fmt(f.contribution)}",
                    Ui.MONO, if (f.contribution > 0) Ui.INK else Ui.MUTED, mono = true, topMargin = 4,
                )
            )
        }
        return card
    }

    /**
     * Shown while the composite score is still being computed.
     *
     * The verdict is already decided and on screen; this card exists so the empty
     * space where a score will appear is explained rather than silently blank. A
     * security screen with an unexplained gap invites the reader to fill it in
     * themselves, usually optimistically.
     */
    private fun pendingScoreCard(): View {
        val card = Ui.card(this, Ui.SURFACE)
        card.addView(Ui.text(this, "M6 COMPOSITE SCORE", Ui.SMALL, Ui.MUTED, bold = true))
        card.addView(Ui.text(this, "still computing…", Ui.BODY, Ui.MUTED, topMargin = 6))
        card.addView(
            Ui.text(
                this,
                "The score fuses machine-learning and behavioural layers that take longer " +
                    "than static analysis. The decision above did not wait for it, and will " +
                    "not be weakened by it — a score can raise this verdict, never lower it.",
                Ui.SMALL, Ui.MUTED, topMargin = 6,
            )
        )
        return card
    }

    private fun staticCard(evidence: `in`.drishti.shield.StaticEvidence): View {
        val card = Ui.card(this, Ui.SURFACE)
        card.addView(
            Ui.text(this, "M2 STATIC EVIDENCE — ${evidence.combos.size} RULE MATCHES",
                Ui.SMALL, Ui.MUTED, bold = true)
        )
        evidence.combos.forEach { combo ->
            val colour = Ui.bandColor(combo.severity.name)
            card.addView(
                Ui.text(
                    this,
                    "${combo.ruleId}  [${combo.severity.name.lowercase()}${
                        combo.mitre?.let { " · $it" } ?: ""
                    }]",
                    Ui.SMALL, colour, bold = true, topMargin = 8,
                )
            )
            card.addView(Ui.text(this, combo.description, Ui.SMALL, Ui.MUTED, topMargin = 2))
        }
        // Defanged by the backend (hxxp), and shown that way on purpose.
        evidence.urls.filter { it.startsWith("hxxp") }.takeIf { it.isNotEmpty() }?.let { urls ->
            card.addView(Ui.text(this, "Embedded endpoints", Ui.SMALL, Ui.MUTED, bold = true, topMargin = 12))
            urls.forEach { card.addView(Ui.text(this, it, Ui.MONO, Ui.HIGH, mono = true, topMargin = 4)) }
        }
        return card
    }

    private fun vetoCard(s: Scan): View {
        val card = Ui.card(this, if (s.vetoEngaged) Ui.CRITICAL else Ui.MUTED)
        card.addView(
            Ui.text(
                this,
                if (s.vetoEngaged) "LAYER 3 VETO ENGAGED" else "LAYER 3 NOT ENGAGED",
                Ui.BODY, if (s.vetoEngaged) Ui.CRITICAL else Ui.MUTED, bold = true,
            )
        )
        card.addView(Ui.text(this, PolicyEngine.statusLine(this), Ui.SMALL, Ui.MUTED, topMargin = 6))
        if (s.vetoEngaged) {
            card.addView(
                Ui.text(
                    this,
                    "The OS package installer will now refuse this install. This is a " +
                        "DevicePolicyManager user restriction set by the device owner, " +
                        "not a dialog the user can dismiss.",
                    Ui.SMALL, Ui.MUTED, topMargin = 6,
                )
            )
        }
        return card
    }

    private fun limitCard(limitations: List<String>): View {
        val card = Ui.card(this, Ui.MUTED)
        card.addView(Ui.text(this, "LIMITATIONS (generated by the backend)", Ui.SMALL, Ui.MUTED, bold = true))
        limitations.forEach { card.addView(Ui.text(this, "• $it", Ui.SMALL, Ui.MUTED, topMargin = 4)) }
        return card
    }

    private fun errorCard(s: Scan): View {
        val card = Ui.card(this, Ui.MEDIUM)
        card.addView(Ui.text(this, "Analysis did not complete", Ui.BODY, Ui.MEDIUM, bold = true))
        card.addView(Ui.text(this, s.error ?: "unknown", Ui.SMALL, Ui.MUTED, topMargin = 6))
        card.addView(
            Ui.text(
                this,
                "DRISHTI reports this as inconclusive. An APK that produced no analysis is " +
                    "not the same thing as a safe one.",
                Ui.SMALL, Ui.MUTED, topMargin = 6,
            )
        )
        return card
    }

    // ── actions ──────────────────────────────────────────────────────────────
    private fun actions(s: Scan): View {
        val wrap = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
                topMargin = dp(8)
            }
        }
        val primary = Ui.row(this)
        val pkg = installedPackage
        if (pkg != null) {
            primary.addView(
                Ui.button(this, "Uninstall now", Ui.CRITICAL) {
                    // Lift the uninstall block first, or the system's own dialog cannot
                    // complete — a quarantine that also blocks the user is not a feature.
                    PolicyEngine.release(this, pkg)
                    startActivity(PackageAddedReceiver.uninstallIntent(pkg))
                }
            )
        } else {
            primary.addView(
                Ui.button(this, "Delete file", Ui.CRITICAL) {
                    val ok = runCatching { File(s.path).delete() }.getOrDefault(false)
                    toast(if (ok) "Deleted ${s.filename}" else "Could not delete ${s.filename}")
                }
            )
        }
        primary.addView(
            Ui.button(this, "Report") {
                startActivity(
                    Intent(this, ReportActivity::class.java)
                        .putExtra(ReportActivity.EXTRA_SCAN_ID, s.id)
                )
            }
        )
        wrap.addView(primary)

        val secondary = Ui.row(this)
        if (s.vetoEngaged) {
            secondary.addView(
                Ui.button(this, "Analyst override", Ui.SURFACE, Ui.MEDIUM) {
                    val released = PolicyEngine.releaseVeto(this)
                    toast(
                        if (released) "Veto released. Unknown-source installs are allowed again."
                        else "Cannot release: Shield is not device owner."
                    )
                    render(s.copy(vetoEngaged = !released))
                }
            )
        }
        secondary.addView(Ui.button(this, "Close") { finish() })
        wrap.addView(secondary)
        return wrap
    }

    private fun toast(message: String) =
        Toast.makeText(this, message, Toast.LENGTH_LONG).show()

    private fun fmt(value: Double) = String.format(Locale.US, "%.2f", value)
}

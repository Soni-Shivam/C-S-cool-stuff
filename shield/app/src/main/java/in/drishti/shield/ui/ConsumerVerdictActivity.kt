package `in`.drishti.shield.ui

import android.app.Activity
import android.app.NotificationManager
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.util.TypedValue
import android.view.Gravity
import android.view.View
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import `in`.drishti.shield.ConsumerVerdict
import `in`.drishti.shield.ConsumerVerdictSource
import `in`.drishti.shield.Notifications
import `in`.drishti.shield.PackageAddedReceiver
import `in`.drishti.shield.ScanBus
import `in`.drishti.shield.ui.Ui.dp
import java.io.File

/**
 * The screen a **person** sees. Two states, one activity.
 *
 * ### 1 — the interstitial
 *
 * It appears the instant an install begins, before anyone has been told anything is
 * wrong, and it must not frighten them: at this point we do not yet know that
 * anything *is* wrong, and a red screen that later says "actually, it's fine" teaches
 * people to ignore the next one. So: the mark, breathing, on near-black, and one
 * reassuring line. No spinner, no progress bar, no percentage.
 *
 * ### 2 — the verdict
 *
 * Driven **entirely** by [ConsumerVerdict.recommendedAction] and nothing else. BLOCK
 * breaks hard from the brand into red and amber — this is the one moment in the whole
 * product where the interface is allowed to alarm. REVIEW is softer and does not
 * block. MONITOR is informational.
 *
 * ### What is deliberately not here
 *
 * No score, no confidence, no severity band, no MITRE technique IDs, no evidence
 * references, no limitations list. Every one of those exists on the object and every
 * one of them belongs to the analyst portal. A consumer who is thirty seconds from
 * losing their savings does not need a number between 0 and 100 — they need one
 * sentence and one button, and each extra element on this screen measurably reduces
 * the chance that the sentence is read at all.
 * `tests/contract/test_verdict_kotlin_parity.py` fails if any of those fields is
 * referenced in this file, so the rule is enforced rather than remembered.
 */
class ConsumerVerdictActivity : Activity() {

    companion object {
        /** Job whose A15 verdict to show. Absent for a fixture rehearsal. */
        const val EXTRA_JOB_ID = "job_id"

        /**
         * The in-flight scan this screen is about.
         *
         * Layer 2 hands this over at the instant of the tap, which is *before* the
         * upload has returned a job id — so the job id cannot be an intent extra. The
         * screen looks it up on the bus while the interstitial breathes, which is
         * precisely the work the interstitial is covering.
         */
        const val EXTRA_SCAN_ID = "scan_id"

        /**
         * Which bundled fixture to fall back to: `block`, `review` or `monitor`.
         *
         * **Only a rehearsal launch sets this.** A tap on a real file never does, and
         * that asymmetry is deliberate: a canned verdict standing in for a real file's
         * analysis would put a red screen over an app that was actually cleared. When
         * there is a real file and no verdict for it, the screen says it could not
         * check — see [showUndecided].
         */
        const val EXTRA_FIXTURE = "fixture"

        /** The APK on disk this verdict is about, so the block CTA can delete it. */
        const val EXTRA_APK_PATH = "apk_path"

        /**
         * The interstitial is held for at least this long, even when the verdict is
         * already in hand.
         *
         * Two reasons, and the second one is why the number is this large.
         *
         * A verdict that appears instantly reads as canned — on a stage, an answer
         * that arrives before the screen has finished drawing looks like a hard-coded
         * one, and the audience stops believing the analysis happened at all. It is
         * also true of a real user: a security decision made in 200 ms is not trusted,
         * and the pause is what makes the answer feel weighed rather than guessed.
         *
         * This is a **display floor, not a fake delay**: the analysis really does run
         * underneath, and when it takes longer than this the screen simply waits for
         * it. Nothing about the verdict changes because of it.
         */
        const val MIN_INTERSTITIAL_MS = 3_400L

        /**
         * How long a real, in-flight analysis gets before the screen falls back to a
         * bundled fixture — which it then labels as one.
         *
         * Measured on this laptop, static analysis of the decoy lands in about five
         * seconds, so this leaves headroom without ever leaving the audience looking
         * at a breathing logo wondering whether it has hung.
         */
        private const val FALLBACK_AFTER_MS = 9_000L

        private const val POLL_MS = 400L

        private const val TAG = "DrishtiShield"
    }

    // ── palette ───────────────────────────────────────────────────────────────
    // The consumer surface has its own colours. Ui.kt's are tuned for the analyst
    // screens; these are tuned for a person holding a phone and, on the BLOCK
    // branch, for breaking away from the brand entirely.
    private val nearBlack = 0xFF0A0A12.toInt()
    private val purple = 0xFF7C3AED.toInt()
    private val softInk = 0xFFE7E3F5.toInt()
    private val mutedInk = 0xFF9C96BC.toInt()
    private val alarmRed = 0xFF7F0F12.toInt()
    private val alarmRedTop = 0xFFB3161B.toInt()
    private val amber = 0xFF8A5A05.toInt()
    private val amberTop = 0xFFC9860B.toInt()
    private val white = 0xFFFFFFFF.toInt()

    private lateinit var root: LinearLayout
    private val main = Handler(Looper.getMainLooper())
    private var shownAtMs = 0L
    private var settled = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        @Suppress("DEPRECATION") // setShowWhenLocked is API 27; the flags work on 26 too
        window.addFlags(
            WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED or
                WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON or
                WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD
        )
        root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(nearBlack)
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT)
        }
        setContentView(root)

        shownAtMs = System.currentTimeMillis()
        Log.i(TAG, "consumer_screen interstitial shown")
        showInterstitial()
        resolveInBackground()
    }

    /**
     * A second verdict replaces the one on screen, from the top.
     *
     * The activity is `singleTask`, so a second launch lands here rather than in
     * [onCreate] — and without this the screen would keep showing the previous
     * verdict while the operator wondered why their command did nothing. It restarts
     * at the interstitial deliberately: the new answer must be *seen* to be reached,
     * not appear as a silent swap of one red screen for another.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        main.removeCallbacksAndMessages(null)
        settled = false
        shownAtMs = System.currentTimeMillis()
        Log.i(TAG, "consumer_screen interstitial shown (re-entered)")
        showInterstitial()
        resolveInBackground()
    }

    /**
     * Take the heads-up notification down while this screen is up.
     *
     * Layer 1's alert is posted on a HIGH-importance channel, which is what lets a
     * verdict appear without a tap — and its banner then sits across the top of this
     * screen, over the sentence the whole design exists to get read. Measured on the
     * emulator: it covered the banner word for several seconds. `VerdictActivity`
     * solves the same problem the same way; the record stays in the shade.
     */
    override fun onResume() {
        super.onResume()
        runCatching {
            getSystemService(NotificationManager::class.java).cancel(Notifications.ID_ALERT)
        }
    }

    override fun onDestroy() {
        main.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    /** Back is not an exit from a block. The CTA is. */
    @Deprecated("Activity.onBackPressed is deprecated; this app carries no AppCompat")
    @Suppress("DEPRECATION")
    override fun onBackPressed() {
        if (!settled) return
        super.onBackPressed()
    }

    // ── state 1: the interstitial ─────────────────────────────────────────────

    /**
     * The reassuring screen. The wording is fixed and is the most carefully chosen
     * text in the app: the user is told a check is happening and that it is for them,
     * and is told nothing else, because nothing else is known yet.
     */
    private fun showInterstitial() {
        root.removeAllViews()
        root.gravity = Gravity.CENTER
        root.setBackgroundColor(nearBlack)

        root.addView(BreathingLogoView(this))
        root.addView(
            centred("Analysing… please wait a moment.", 26f, softInk, bold = true, top = 8)
        )
        root.addView(centred("This is for your safety.", 20f, mutedInk, top = 10))
        root.addView(centred("DRISHTI", 13f, purple, bold = true, top = 44).apply {
            letterSpacing = 0.5f
        })
    }

    // ── resolution ────────────────────────────────────────────────────────────

    /**
     * Get the verdict off the main thread, then show it no sooner than
     * [MIN_INTERSTITIAL_MS] after the interstitial appeared.
     *
     * The real analysis always wins. A fixture is only reached once the backend has
     * had [FALLBACK_AFTER_MS] to answer and has not — and when that happens the screen
     * says so rather than dressing a fixture up as a live result.
     */
    private fun resolveInBackground() {
        val explicitJob = intent?.getStringExtra(EXTRA_JOB_ID)
        val scanId = intent?.getStringExtra(EXTRA_SCAN_ID)
        val fixture = intent?.getStringExtra(EXTRA_FIXTURE)

        // A rehearsal names no file. It must not adopt an unrelated in-flight scan's
        // job — a verdict about a different APK is worse than no verdict at all.
        val rehearsal = explicitJob == null && scanId == null

        Thread {
            val fallbackAt = System.currentTimeMillis() + FALLBACK_AFTER_MS
            var resolved: ConsumerVerdictSource.Resolved? = null
            while (System.currentTimeMillis() < fallbackAt) {
                // Re-read each tick: Layer 2 launches this screen before the upload
                // has a job id, and the id appears on the bus a moment later.
                val jobId = explicitJob ?: scanId?.let { ScanBus.find(it)?.jobId }
                resolved = ConsumerVerdictSource.live(this, jobId)
                if (resolved != null) break
                // Nothing real is in flight and nothing was pushed: waiting out the
                // backend window would only stall the stage.
                if (rehearsal) break
                Thread.sleep(POLL_MS)
            }
            // Only a rehearsal falls back to a fixture. A real tap that produced no
            // verdict goes to the undecided screen instead of borrowing someone
            // else's answer.
            if (resolved == null && fixture != null) {
                resolved = ConsumerVerdictSource.fromAsset(this, fixture)
            }
            val held = (shownAtMs + MIN_INTERSTITIAL_MS) - System.currentTimeMillis()
            main.postDelayed({ settle(resolved) }, maxOf(0L, held))
        }.apply { isDaemon = true }.start()
    }

    private fun settle(resolved: ConsumerVerdictSource.Resolved?) {
        settled = true
        // The demo screen reads this line. It is the measured interstitial duration,
        // not the configured one, so a claim about it can be checked against a run.
        Log.i(
            TAG,
            "consumer_screen settled after ${System.currentTimeMillis() - shownAtMs} ms " +
                "(floor ${MIN_INTERSTITIAL_MS} ms) action=" +
                "${resolved?.verdict?.recommendedAction ?: "NONE"} " +
                "origin=${resolved?.origin ?: "NONE"}",
        )
        if (resolved == null) {
            showUndecided()
            return
        }
        showVerdict(resolved.verdict, resolved.isLiveAnalysis)
    }

    // ── state 2: the verdict ──────────────────────────────────────────────────

    private fun showVerdict(verdict: ConsumerVerdict, live: Boolean) {
        when (verdict.recommendedAction) {
            "BLOCK" -> paint(
                top = alarmRedTop,
                bottom = alarmRed,
                word = "DO NOT INSTALL",
                verdict = verdict,
                live = live,
                primary = "Delete this app",
                secondary = "Go back — do not proceed",
            )
            "REVIEW" -> paint(
                top = amberTop,
                bottom = amber,
                word = "BE CAREFUL",
                verdict = verdict,
                live = live,
                primary = "Delete this app",
                secondary = "I trust this — continue",
            )
            else -> paint(
                top = 0xFF241C4A.toInt(),
                bottom = nearBlack,
                word = "NOTHING HARMFUL FOUND",
                verdict = verdict,
                live = live,
                primary = null,
                secondary = "Continue",
            )
        }
    }

    /**
     * One layout, three moods.
     *
     * The word, the impersonation line and the summary are the only things on screen,
     * in that order, at sizes that read from the back of a room. The impersonation
     * line is the sentence that actually changes behaviour — "this app is pretending
     * to be your bank" lands where "malicious application detected" does not — so it
     * sits directly under the banner and is only drawn when the analysis actually
     * named a target.
     */
    private fun paint(
        top: Int,
        bottom: Int,
        word: String,
        verdict: ConsumerVerdict,
        live: Boolean,
        primary: String?,
        secondary: String,
    ) {
        root.removeAllViews()
        root.gravity = Gravity.TOP
        root.background = GradientDrawable(
            GradientDrawable.Orientation.TOP_BOTTOM,
            intArrayOf(top, bottom),
        )

        val scroller = ScrollView(this).apply {
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f)
            isFillViewport = true
        }
        val body = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_VERTICAL
            val p = dp(26)
            setPadding(p, dp(40), p, dp(16))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }

        body.addView(
            centred(word, 40f, white, bold = true).apply { letterSpacing = 0.02f }
        )

        verdict.impersonatedTarget?.let { target ->
            body.addView(
                centred("This app is impersonating $target.", 27f, white, bold = true, top = 22)
            )
        }

        body.addView(
            centred(verdict.consumerSummary, 21f, 0xF2FFFFFF.toInt(), top = 22).apply {
                setLineSpacing(dp(5).toFloat(), 1f)
            }
        )

        if (!live) body.addView(fixtureRibbon())

        scroller.addView(body)
        root.addView(scroller)
        root.addView(actions(verdict, primary, secondary))
    }

    /**
     * Shown when the object on screen did not come from a live analysis of these
     * bytes.
     *
     * `CLAUDE.md` § *Honesty requirements*: a replayed or fixture result is legitimate
     * to show and dishonest to present as live. Nobody has to remember to turn this on
     * — it is derived from where the object came from, and it disappears by itself the
     * moment a real verdict is available.
     */
    private fun fixtureRibbon(): View = TextView(this).apply {
        text = "REHEARSAL FIXTURE — not a live analysis of this file"
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 12f)
        setTextColor(0xCCFFFFFF.toInt())
        gravity = Gravity.CENTER
        background = GradientDrawable().apply {
            setColor(Color.argb(40, 0, 0, 0))
            cornerRadius = dp(8).toFloat()
            setStroke(dp(1), Color.argb(90, 255, 255, 255))
        }
        val p = dp(10)
        setPadding(p, p / 2, p, p / 2)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            topMargin = dp(28)
        }
    }

    private fun actions(
        verdict: ConsumerVerdict,
        primary: String?,
        secondary: String,
    ): View {
        val bar = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val p = dp(20)
            setPadding(p, 0, p, dp(28))
            layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        }
        primary?.let { label ->
            bar.addView(bigButton(label, white, 0xFF14121C.toInt()) { removeIt(verdict) })
        }
        bar.addView(
            bigButton(secondary, Color.argb(38, 255, 255, 255), white) { leave() }
        )
        return bar
    }

    /**
     * The destructive-but-safe action: get the file off the device, and offer the
     * system uninstall prompt if the package already made it on.
     *
     * A consumer app cannot silently uninstall anything, and pretending otherwise
     * would be a lie told with a button. What it can do is delete the APK it was
     * handed and hand the user to the OS's own removal flow — so that is exactly what
     * the button does, and the label says "delete", not "remove the threat".
     */
    private fun removeIt(verdict: ConsumerVerdict) {
        intent?.getStringExtra(EXTRA_APK_PATH)?.let { path ->
            runCatching { File(path).delete() }
        }
        val installed = runCatching {
            packageManager.getPackageInfo(verdict.packageName, 0)
            true
        }.getOrDefault(false)
        if (installed) {
            startActivity(PackageAddedReceiver.uninstallIntent(verdict.packageName))
        }
        leave()
    }

    private fun leave() {
        finish()
        startActivity(
            Intent(Intent.ACTION_MAIN)
                .addCategory(Intent.CATEGORY_HOME)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        )
    }

    /**
     * No verdict arrived. Says so, and does not guess.
     *
     * An app that produced no analysis is not the same thing as a safe one — the same
     * rule the backend applies to a sample that detonated and did nothing.
     */
    private fun showUndecided() {
        root.removeAllViews()
        root.gravity = Gravity.CENTER
        root.setBackgroundColor(nearBlack)
        root.addView(centred("WE COULD NOT CHECK THIS APP", 28f, softInk, bold = true))
        root.addView(
            centred(
                "The safety check did not finish, so we do not know whether this app " +
                    "is safe. Not knowing is not the same as safe. Please do not " +
                    "install it until it has been checked.",
                19f, mutedInk, top = 20,
            )
        )
        root.addView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                val p = dp(20)
                setPadding(p, dp(28), p, 0)
                layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
                addView(bigButton("Go back", Color.argb(38, 255, 255, 255), softInk) { leave() })
            }
        )
    }

    // ── small builders ────────────────────────────────────────────────────────

    private fun centred(
        value: CharSequence,
        size: Float,
        colour: Int,
        bold: Boolean = false,
        top: Int = 0,
    ): TextView = TextView(this).apply {
        text = value
        setTextSize(TypedValue.COMPLEX_UNIT_SP, size)
        setTextColor(colour)
        gravity = Gravity.CENTER
        if (bold) setTypeface(typeface, Typeface.BOLD)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            if (top > 0) topMargin = dp(top)
            val side = dp(20)
            leftMargin = side
            rightMargin = side
        }
    }

    /** Thumb-sized, full width, one per line. Nobody mis-taps under stress. */
    private fun bigButton(
        label: String,
        fill: Int,
        ink: Int,
        onClick: (View) -> Unit,
    ): Button = Button(this).apply {
        text = label
        isAllCaps = false
        setTextSize(TypedValue.COMPLEX_UNIT_SP, 19f)
        setTextColor(ink)
        setTypeface(typeface, Typeface.BOLD)
        gravity = Gravity.CENTER
        background = GradientDrawable().apply {
            setColor(fill)
            cornerRadius = dp(14).toFloat()
            setStroke(dp(1), Color.argb(70, 255, 255, 255))
        }
        minimumHeight = dp(60)
        setOnClickListener(onClick)
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT).apply {
            topMargin = dp(10)
        }
    }
}

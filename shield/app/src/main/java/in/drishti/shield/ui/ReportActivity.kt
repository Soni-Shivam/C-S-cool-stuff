package `in`.drishti.shield.ui

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Toast
import `in`.drishti.shield.Config
import `in`.drishti.shield.DrishtiClient
import `in`.drishti.shield.Scan
import `in`.drishti.shield.ScanBus
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import org.json.JSONObject

/**
 * Prepare the complaint package, and hand off to NCRP honestly.
 *
 * **Nothing here files a complaint.** cybercrime.gov.in has no public submission API,
 * and a product that implied otherwise would be lying to a victim at the worst
 * possible moment. The backend's own dossier says the same thing in a field —
 * `submission_is_manual`, always true — and this screen renders that field rather
 * than trusting itself to remember.
 *
 * The complaint body comes from `GET /api/jobs/{id}/artifacts/dossier`, built by
 * `m7_report.dossier` from the same evidence as the HTML report and the ledger. It is
 * not composed on the phone: two generators would drift, and the one a victim pastes
 * into a government form is the wrong one to let drift.
 *
 * `reportable` is false for LOW and MEDIUM bands. That is surfaced, with the
 * backend's reason, rather than hidden — a triage tool that encourages a complaint it
 * does not support degrades the portal for everyone using it.
 */
class ReportActivity : Activity() {

    companion object {
        const val EXTRA_SCAN_ID = "scan_id"
    }

    private lateinit var body: LinearLayout
    private var complaintText: String = ""

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

        val scan = intent.getStringExtra(EXTRA_SCAN_ID)?.let { ScanBus.find(it) } ?: ScanBus.current
        if (scan == null) {
            body.addView(Ui.text(this, "No incident to report", Ui.TITLE, Ui.INK, bold = true))
            return
        }

        // Render immediately from what the phone already knows, then again once the
        // backend's package arrives. The button is usable from the first frame.
        render(scan, null)
        Thread {
            val pack = scan.jobId?.let { DrishtiClient.dossier(Config.backend(this), it) }
            Handler(Looper.getMainLooper()).post { render(scan, pack) }
        }.apply { isDaemon = true }.start()
    }

    private fun render(scan: Scan, pack: JSONObject?) {
        complaintText = pack?.optString("text").takeUnless { it.isNullOrBlank() }
            ?: localFallback(scan)
        val reportable = pack?.optBoolean("reportable", false) ?: false
        val manual = pack?.optBoolean("submission_is_manual", true) ?: true
        val portal = pack?.optString("portal_url").takeUnless { it.isNullOrBlank() }
            ?: Config.NCRP_URL
        val helpline = pack?.optString("helpline").takeUnless { it.isNullOrBlank() }

        body.removeAllViews()
        body.addView(Ui.text(this, "COMPLAINT PACKAGE", Ui.SMALL, Ui.MUTED, bold = true))
        body.addView(
            Ui.text(this, "Prepare a report for cybercrime.gov.in", Ui.TITLE, Ui.INK,
                bold = true, topMargin = 6)
        )

        // The disclosure is first, not in a footnote, and it is driven by the
        // backend's own flag rather than by a hardcoded sentence.
        val disclosure = Ui.card(this, Ui.MEDIUM)
        disclosure.addView(
            Ui.text(this, "This does not file anything", Ui.BODY, Ui.MEDIUM, bold = true)
        )
        disclosure.addView(
            Ui.text(
                this,
                if (manual) {
                    "The national portal has no public submission API, so submission is a " +
                        "manual step you take yourself. DRISHTI prepares the package, puts " +
                        "it on your clipboard, and opens the official site so you land on " +
                        "the real portal rather than a lookalike."
                } else {
                    "The backend reported that submission is not manual for this package. " +
                        "That is unexpected — check the dossier before relying on it."
                },
                Ui.SMALL, Ui.MUTED, topMargin = 6,
            )
        )
        helpline?.let {
            disclosure.addView(
                Ui.text(this, "National cyber-crime helpline: $it", Ui.BODY, Ui.INK,
                    bold = true, topMargin = 10)
            )
            disclosure.addView(
                Ui.text(
                    this,
                    "For financial fraud, calling within the first hours matters more than " +
                        "the written complaint.",
                    Ui.SMALL, Ui.MUTED, topMargin = 4,
                )
            )
        }
        body.addView(disclosure)

        if (pack == null) {
            body.addView(
                Ui.card(this, Ui.MUTED).apply {
                    addView(Ui.text(this@ReportActivity, "Backend package unavailable",
                        Ui.BODY, Ui.MUTED, bold = true))
                    addView(Ui.text(this@ReportActivity,
                        "Showing a package composed on the device from the verdict this " +
                            "phone received. It carries the same facts but not the " +
                            "backend's indicator and technique lists.",
                        Ui.SMALL, Ui.MUTED, topMargin = 6))
                }
            )
        } else {
            // `reportable` is a threshold decision the backend owns. Surfacing the
            // negative case with its reason is the point — see the class doc.
            val gate = Ui.card(this, if (reportable) Ui.LOW else Ui.MEDIUM)
            gate.addView(
                Ui.text(
                    this,
                    if (reportable) "Meets the reporting threshold"
                    else "Below the reporting threshold",
                    Ui.BODY, if (reportable) Ui.LOW else Ui.MEDIUM, bold = true,
                )
            )
            gate.addView(
                Ui.text(this, pack.optString("reason"), Ui.SMALL, Ui.MUTED, topMargin = 6)
            )
            if (!reportable) {
                gate.addView(
                    Ui.text(
                        this,
                        "You can still file — this is DRISHTI's assessment, not a rule. " +
                            "The package below states its own limitations so the reader " +
                            "knows what it is.",
                        Ui.SMALL, Ui.MUTED, topMargin = 6,
                    )
                )
            }
            body.addView(gate)
        }

        val card = Ui.card(this, Ui.ACCENT)
        card.addView(Ui.text(this, complaintText, Ui.MONO, Ui.INK, mono = true))
        body.addView(card)

        val actions = Ui.row(this)
        actions.addView(
            Ui.button(this, "Copy complaint text", Ui.ACCENT, Ui.BG) {
                getSystemService(ClipboardManager::class.java)
                    .setPrimaryClip(ClipData.newPlainText("DRISHTI complaint package", complaintText))
                toast("Copied. Paste it into the portal's description field.")
            }
        )
        actions.addView(
            Ui.button(this, "Open the portal") {
                val opened = runCatching {
                    startActivity(
                        Intent(Intent.ACTION_VIEW, Uri.parse(portal))
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    )
                    true
                }.getOrDefault(false)
                // A stock emulator image often has no browser at all. Failing loudly
                // with the URL beats a silent ActivityNotFoundException on stage.
                if (!opened) toast("No browser on this device. Portal: $portal")
            }
        )
        body.addView(actions)
        body.addView(Ui.button(this, "Back") { finish() })
    }

    /**
     * What to show when the backend's package is not available.
     *
     * Deliberately thinner than the real dossier, and the screen says so: inventing
     * indicator and technique lists on the phone to make the fallback look complete
     * would be exactly the kind of drift this screen exists to avoid.
     */
    private fun localFallback(scan: Scan): String {
        val stamp = SimpleDateFormat("yyyy-MM-dd HH:mm:ss z", Locale.US)
        return buildString {
            appendLine("SUSPECTED FRAUDULENT ANDROID APPLICATION")
            appendLine()
            appendLine("SHA-256: ${scan.sha256}")
            appendLine()
            appendLine("File            ${scan.filename} (${scan.sizeBytes} bytes)")
            appendLine("Received        ${stamp.format(Date(scan.detectedAtMs))}")
            appendLine("Arrived in      ${scan.path}")
            scan.static?.let {
                appendLine("Declares itself ${it.appLabel} / ${it.packageName}")
            }
            appendLine()
            scan.decision?.let { d ->
                appendLine("DRISHTI DECISION")
                appendLine("  blocked   ${if (d.block) "YES" else "NO"}")
                appendLine("  basis     ${d.basis}")
                appendLine("  ${d.headline}")
                if (d.citations.isNotEmpty()) {
                    appendLine()
                    appendLine("EVIDENCE CITED")
                    d.citations.forEach { appendLine("  - $it") }
                }
            }
            scan.verdict?.let { v ->
                appendLine()
                appendLine("SCORE  ${v.score.toInt()}/100 (${v.band})  " +
                    "confidence ${"%.2f".format(v.confidence)}  γ ${"%.2f".format(v.gamma)}")
                if (v.limitations.isNotEmpty()) {
                    appendLine()
                    appendLine("LIMITATIONS OF THIS AUTOMATED ANALYSIS")
                    v.limitations.forEach { appendLine("  - $it") }
                }
            }
            appendLine()
            appendLine("DRISHTI job id  ${scan.jobId ?: "n/a"}")
            appendLine()
            appendLine("Prepared on-device by DRISHTI Shield because the analysis backend's")
            appendLine("reporting package could not be retrieved. This is a machine-generated")
            appendLine("triage product, not a forensic examination, and it has NOT been")
            appendLine("submitted to any authority.")
        }
    }

    private fun toast(message: String) = Toast.makeText(this, message, Toast.LENGTH_LONG).show()
}

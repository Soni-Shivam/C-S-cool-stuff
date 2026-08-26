"""The investigation report. `docs/PHASE_6_REPORT_UI_DEMO.md` T6.3.

One self-contained HTML file with no external assets, so it survives being emailed to
a fraud desk, attached to a complaint, or opened on an air-gapped machine.

Three properties this module must never lose, all of them from CLAUDE.md's honesty
requirements:

* **Limitations are derived, never written.** `_limitations()` reads real provenance
  flags — partial analysers, replay vs live, hand-authored traces, rejected claims,
  unverified containment — and a caveat appears because a flag is set, not because
  somebody remembered to mention it.
* **Every AI sentence carries its citations.** A claim without resolvable
  `evidence_refs` never reached the ledger, so it cannot reach this page either.
* **No observations is `inconclusive`, never benign.** A sample that stalled in the
  sandbox looks exactly like a clean app, and the report says so out loud.
"""

from __future__ import annotations

from html import escape
from typing import Any

from drishti.contracts.dynamic_trace import DynamicTrace, NetworkFlow, TraceSourceKind
from drishti.contracts.evidence import ChainVerification
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.job import Job
from drishti.contracts.score import CompositeScore, SeverityBand
from drishti.contracts.static_report import FileMeta, StaticReport

_BAND_COLOUR = {
    SeverityBand.CRITICAL: "#b3001b",
    SeverityBand.HIGH: "#d1470a",
    SeverityBand.MEDIUM: "#b8860b",
    SeverityBand.LOW: "#2f6f3e",
}

_CSS = """
:root { --ink:#14181f; --muted:#5a6572; --line:#dfe4ea; --bg:#fff; --panel:#f7f9fb; }
* { box-sizing:border-box; }
body { margin:0; padding:2.5rem clamp(1rem,5vw,4rem); background:var(--bg); color:var(--ink);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
h1 { font-size:1.6rem; margin:0 0 .25rem; }
h2 { font-size:1.1rem; margin:2.25rem 0 .75rem; padding-bottom:.35rem;
  border-bottom:2px solid var(--line); letter-spacing:.02em; text-transform:uppercase; }
h3 { font-size:.95rem; margin:1.25rem 0 .4rem; }
.sub { color:var(--muted); margin:0 0 1.5rem; }
.verdict { display:flex; gap:1.25rem; align-items:center; padding:1.1rem 1.35rem;
  border-radius:10px; color:#fff; margin:1.25rem 0; }
.score { font-size:2.6rem; font-weight:700; line-height:1; }
.band { font-size:1.05rem; font-weight:600; letter-spacing:.06em; }
table { border-collapse:collapse; width:100%; margin:.5rem 0 1rem; font-size:.9rem; }
th,td { text-align:left; padding:.45rem .6rem; border-bottom:1px solid var(--line);
  vertical-align:top; }
th { background:var(--panel); font-weight:600; }
code,.mono { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:.85em; }
.badge { display:inline-block; padding:.14rem .5rem; border-radius:999px; font-size:.72rem;
  font-weight:600; letter-spacing:.03em; border:1px solid currentColor; }
.b-live { color:#2f6f3e; } .b-replay { color:#b8860b; } .b-synth { color:#b3001b; }
.panel { background:var(--panel); border:1px solid var(--line); border-radius:8px;
  padding:.85rem 1.1rem; margin:.75rem 0; }
.limits { border-left:4px solid #b8860b; background:#fffaf0; }
.limits li { margin:.3rem 0; }
.refs { color:var(--muted); font-size:.78rem; }
.chain-ok { color:#2f6f3e; font-weight:600; }
.chain-bad { color:#b3001b; font-weight:600; }
footer { margin-top:3rem; padding-top:1rem; border-top:1px solid var(--line);
  color:var(--muted); font-size:.8rem; }
@media print { body { padding:0; } h2 { page-break-after:avoid; } tr { page-break-inside:avoid; } }
"""


def _e(value: Any) -> str:
    return escape(str(value), quote=True)


def _provenance_badge(trace: DynamicTrace | None) -> str:
    """Live / replay / hand-authored, read from the trace itself.

    Never from a config flag: the whole point is that a replayed capture cannot be
    presented as a live detonation by forgetting to flip a setting.
    """
    if trace is None:
        return '<span class="badge b-replay">NO DYNAMIC RUN</span>'
    if trace.synthetic:
        return '<span class="badge b-synth">HAND-AUTHORED FIXTURE — NOT A MEASUREMENT</span>'
    if trace.source == TraceSourceKind.REPLAY:
        return '<span class="badge b-replay">REPLAY OF A REAL CAPTURE</span>'
    return '<span class="badge b-live">LIVE DETONATION</span>'


def _limitations(
    score: CompositeScore,
    static: StaticReport | None,
    genai: GenAIVerdict | None,
    trace: DynamicTrace | None,
) -> list[str]:
    """Derive the caveats from real flags. Nothing in here is hardcoded prose.

    `score.limitations` is produced by the scorer from the signals it actually had;
    everything added below comes from a provenance field on an artefact. If a caveat
    is missing, the fix is a flag that was not set, never a sentence to paste in.
    """
    items: list[str] = list(score.limitations)

    if static is not None and static.partial:
        errs = "; ".join(static.errors) or "unspecified"
        items.append(f"Static analysis completed only partially ({errs}).")

    if trace is None:
        items.append(
            "No dynamic analysis was performed. Findings describe what the code "
            "is capable of, not what it was observed doing."
        )
    else:
        if trace.synthetic and trace.source == TraceSourceKind.UNAVAILABLE:
            # `synthetic` covers two different situations and they must not read alike.
            # A reader told "hand-authored fixture" will ask which fixture — and when no
            # sandbox was reachable there is no fixture to show them.
            items.append(
                "No sandbox was available, so this sample was never executed. Nothing "
                "in this report was observed at runtime."
            )
        elif trace.synthetic:
            items.append(
                "The dynamic trace is a hand-authored fixture. It illustrates the "
                "pipeline and must not be read as evidence about this sample."
            )
        elif trace.source == TraceSourceKind.REPLAY:
            items.append(
                "The dynamic trace is a replay of a previously captured run, not a "
                "live detonation performed for this report."
            )
        if not trace.containment_verified and trace.source != TraceSourceKind.UNAVAILABLE:
            # Only meaningful when something ran. "Containment was not verified for this
            # run" implies there was a run whose isolation is in doubt; with no sandbox
            # at all it invents a failed safety check on top of an analysis that never
            # happened. The line above already says nothing was executed.
            items.append(
                "Sandbox containment was not verified for this run, so the network "
                "observations carry no isolation guarantee."
            )
        if not trace.detonated or trace.outcome == "inconclusive":
            # The single most important sentence in the document.
            items.append(
                "The sample produced no conclusive runtime behaviour. This is "
                "INCONCLUSIVE, not benign — environment-aware malware stalls in a "
                "sandbox and is indistinguishable from a clean app when it does."
            )
        if trace.evasion_observations:
            items.append(
                f"{len(trace.evasion_observations)} sandbox-detection check(s) were "
                "observed, so the runtime behaviour is likely suppressed."
            )
        # Our own content, disclosed from the flags on the flows themselves. The two
        # counts answer different questions and neither is derivable from the other.
        answered = sum(1 for flow in trace.network_flows if flow.synthesised)
        if answered:
            items.append(
                f"{answered} network response(s) were synthesised by DRISHTI and served "
                "to the sample because the destination did not answer. They are our "
                "content; nothing about them describes what that server would have sent."
            )
        withheld = sum(1 for flow in trace.network_flows if flow.injected_destination)
        if withheld:
            items.append(
                f"{withheld} network destination(s) were DRISHTI lab infrastructure — "
                "our sinkhole, our proxy, or a host named only in a response we wrote — "
                "and are excluded from the exported indicators."
            )

    if genai is not None:
        rejected = len(genai.rejected_claims)
        if rejected:
            items.append(
                f"{rejected} model-generated claim(s) failed verification and were "
                "excluded. They are retained in the ledger but are not asserted here."
            )
        if genai.disagreement_flag:
            note = genai.disagreement_note or "no note recorded"
            items.append(f"The model flagged disagreement with the fused score: {note}")
        if genai.provider == "mock":
            items.append(
                "GenAI analysis ran against a mock provider. No live model reasoned "
                "about this sample."
            )

    if score.C < 0.5:
        items.append(
            f"Overall confidence is low (C={score.C:.2f}). Treat the score as a "
            "triage signal requiring analyst review, not a verdict."
        )

    # Stable order, no duplicates. Written as a plain loop: the set-add-in-a-
    # comprehension trick relies on `add` returning None and reads as a bug.
    seen: set[str] = set()
    unique: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def _section_score(score: CompositeScore) -> str:
    if not score.factors:
        return ""
    rows = "".join(
        f"<tr><td class='mono'>{_e(f.symbol)}</td><td>{_e(f.label)}</td>"
        f"<td class='mono'>{f.raw:.3f}</td><td class='mono'>{f.weight:.2f}</td>"
        f"<td class='mono'>{f.contribution:+.2f}</td>"
        f"<td class='refs'>{_e(', '.join(f.evidence_refs) or '—')}</td></tr>"
        for f in score.factors
    )
    return (
        "<h2>How the score was computed</h2>"
        "<p class='sub'>The score is computed in Python from a fixed weight table. "
        "The language model contributes enumerated behaviour booleans; it never emits "
        "the number, so this decomposition is reproducible.</p>"
        "<table><thead><tr><th>Term</th><th>Meaning</th><th>Raw</th><th>Weight</th>"
        "<th>Contribution</th><th>Evidence</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _section_findings(genai: GenAIVerdict | None) -> str:
    if genai is None:
        return ""
    verified = genai.verified_claims
    if not verified:
        return (
            "<h2>Verified findings</h2><div class='panel'>No model-generated claim "
            "passed verification. Nothing is asserted in this section.</div>"
        )
    items = "".join(
        f"<li>{_e(c.text)}<div class='refs'>cites {_e(', '.join(c.evidence_refs))} "
        f"· agent {_e(c.agent)}</div></li>"
        for c in verified
    )
    return (
        "<h2>Verified findings</h2>"
        "<p class='sub'>Each sentence resolves to evidence nodes in the ledger. A "
        "claim citing nothing, or citing a node that does not exist, is rejected at "
        "write time and cannot appear here.</p>"
        f"<ul>{items}</ul>"
    )


def _section_techniques(genai: GenAIVerdict | None) -> str:
    if genai is None or not genai.techniques:
        return ""
    rows = "".join(
        f"<tr><td class='mono'>{_e(t.technique_id)}</td><td>{_e(t.name)}</td>"
        f"<td>{_e(t.tactic)}</td><td>{_e(t.layer)}</td>"
        f"<td class='refs'>{_e(', '.join(t.evidence_refs) or '—')}</td></tr>"
        for t in genai.techniques
    )
    return (
        "<h2>MITRE ATT&amp;CK (Mobile)</h2>"
        "<p class='sub'><em>static</em> means the capability is present in the code; "
        "<em>dynamic</em> means it was observed executing. They are not the same "
        "strength of evidence.</p>"
        "<table><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th>"
        "<th>Layer</th><th>Evidence</th></tr></thead>"
        f"<tbody>{rows}</tbody></table>"
    )


def _section_static(static: StaticReport | None) -> str:
    if static is None:
        return ""
    combos = "".join(
        f"<tr><td class='mono'>{_e(c.rule_id)}</td>"
        f"<td class='mono'>{_e(' + '.join(p.rsplit('.', 1)[-1] for p in c.permissions))}</td>"
        f"<td>{_e(c.severity.value if hasattr(c.severity, 'value') else c.severity)}</td>"
        f"<td>{_e(c.description)}</td>"
        f"<td class='mono'>{_e(c.mitre or '—')}</td></tr>"
        for c in static.permission_combos
    )
    combo_block = (
        "<h3>Dangerous permission combinations</h3>"
        "<p class='sub'>The combination is the signal, not any single permission. "
        "<code>RECEIVE_SMS</code> alone is a messaging app; <code>RECEIVE_SMS + "
        "INTERNET + no launcher activity</code> is an OTP exfiltration surface.</p>"
        "<table><thead><tr><th>Rule</th><th>Permissions</th><th>Severity</th>"
        "<th>Why it matters</th><th>MITRE</th>"
        f"</tr></thead><tbody>{combos}</tbody></table>"
        if combos
        else ""
    )

    live_paths = [p for p in static.call_paths if p.reachable_from_lifecycle]
    paths = "".join(
        f"<tr><td class='mono'>{_e(p.sink_signature)}</td>"
        f"<td class='mono'>{_e(p.entrypoint)}</td><td>{_e(p.entrypoint_kind)}</td>"
        f"<td class='mono'>{len(p.path)}</td></tr>"
        for p in live_paths[:25]
    )
    path_block = (
        "<h3>Sink paths reachable from an app entrypoint</h3>"
        "<p class='sub'>Only lifecycle-reachable paths are listed. Dead library code "
        "reaches dangerous sinks routinely and must not count as a finding.</p>"
        "<table><thead><tr><th>Sink</th><th>Entrypoint</th><th>Kind</th><th>Hops</th>"
        f"</tr></thead><tbody>{paths}</tbody></table>"
        if paths
        else ""
    )

    cert = static.certificate
    cert_flags = [
        name
        for name, on in (
            ("reused by known-bad samples", cert.known_bad_reuse),
            ("brand mismatch", cert.brand_mismatch),
            ("debug certificate", cert.debug_cert),
        )
        if on
    ]
    cert_block = (
        "<h3>Signing certificate</h3><table>"
        f"<tr><th>Subject</th><td class='mono'>{_e(cert.subject)}</td></tr>"
        f"<tr><th>SHA-256</th><td class='mono'>{_e(cert.sha256)}</td></tr>"
        f"<tr><th>Valid from</th><td>{_e(cert.not_before)} ({cert.age_days} days old)</td></tr>"
        f"<tr><th>Flags</th><td>{_e(', '.join(cert_flags) or 'none')}</td></tr>"
        "</table>"
    )

    return (
        "<h2>Static analysis</h2>"
        "<table>"
        f"<tr><th>Package</th><td class='mono'>{_e(static.package)}</td></tr>"
        f"<tr><th>Label</th><td>{_e(static.app_label)}</td></tr>"
        f"<tr><th>Version</th><td>{_e(static.version_name)} ({static.version_code})</td></tr>"
        f"<tr><th>SDK</th><td>min {static.min_sdk} / target {static.target_sdk}</td></tr>"
        f"<tr><th>Permissions</th><td>{len(static.permissions)} declared, "
        f"{len(static.declared_not_used)} unused</td></tr>"
        f"<tr><th>Exported unprotected</th><td>{len(static.exported_unprotected)}</td></tr>"
        f"<tr><th>Packer hints</th><td>{_e(', '.join(static.packer_hints) or 'none')}</td></tr>"
        f"<tr><th>Native libs</th><td>{_e(', '.join(static.native_libs) or 'none')}</td></tr>"
        "</table>"
        f"{cert_block}{combo_block}{path_block}"
    )


def _flow_origin(flow: NetworkFlow) -> str:
    """How this row came to exist, in the two facts a reader has to keep apart.

    Whose destination it was, and who wrote the reply. Collapsing them into one
    "synthesised" label either credits us with the sample's C2 or credits the adversary
    with our sinkhole, depending on which way you collapse it.
    """
    if flow.injected_destination:
        return "lab infrastructure"
    return "we answered" if flow.synthesised else "observed"


def _section_dynamic(trace: DynamicTrace | None) -> str:
    if trace is None:
        return (
            "<h2>Dynamic analysis</h2>"
            "<div class='panel'>No detonation was performed for this sample.</div>"
        )

    flows = "".join(
        f"<tr><td class='mono'>{_e(f.method)}</td><td class='mono'>{_e(f.host)}</td>"
        f"<td class='mono'>{_e(f.url)[:90]}</td><td>{_e(f.status if f.status else '—')}</td>"
        f"<td>{f.occurrences}</td><td>{_flow_origin(f)}</td></tr>"
        for f in trace.network_flows[:30]
    )
    flow_block = (
        "<h3>Network activity</h3>"
        # Two different provenance facts, kept apart on purpose. A destination the
        # sample chose stays a finding even when we are the ones who answered it.
        "<p class='sub'><em>we answered</em> means the response body came from our own "
        "emulated C2 because the destination did not reply — the destination is still "
        "the sample's. <em>lab infrastructure</em> means the destination itself is ours "
        "(our sinkhole or our proxy) and is never exported as an indicator.</p>"
        "<table><thead><tr><th>Method</th><th>Host</th><th>URL</th><th>Status</th>"
        f"<th>Times</th><th>Origin</th></tr></thead><tbody>{flows}</tbody></table>"
        if flows
        else ""
    )

    evasion = "".join(
        f"<tr><td>{_e(o.probe_kind)}</td><td class='mono'>{_e(o.queried)}</td>"
        f"<td>{_e(o.result)}</td>"
        f"<td>{('stalled ' + str(o.stall_duration_ms) + 'ms') if o.followed_by_stall else 'continued'}</td>"
        f"<td>{_e(o.inferred_requirement or '—')}</td></tr>"
        for o in trace.evasion_observations
    )
    evasion_block = (
        "<h3>Environment checks performed by the sample</h3>"
        "<p class='sub'>A probe that misses and is followed by a stall is the "
        "signature of environment-aware malware deciding it is being watched. It is "
        "also what tells the frontier layer which morph would wake the sample up.</p>"
        "<table><thead><tr><th>Probe</th><th>Queried</th><th>Result</th>"
        f"<th>After</th><th>Inferred requirement</th></tr></thead><tbody>{evasion}</tbody></table>"
        if evasion
        else ""
    )

    return (
        "<h2>Dynamic analysis</h2>"
        f"<p>{_provenance_badge(trace)}</p>"
        "<table>"
        f"<tr><th>Outcome</th><td><strong>{_e(trace.outcome)}</strong></td></tr>"
        f"<tr><th>Detonated</th><td>{_e(trace.detonated)} "
        f"({_e(trace.detonation_reason or 'no rule fired')})</td></tr>"
        f"<tr><th>API events</th><td>{len(trace.api_events)}</td></tr>"
        f"<tr><th>Network flows</th><td>{len(trace.network_flows)}</td></tr>"
        f"<tr><th>DEX loads</th><td>{len(trace.dex_loads)}</td></tr>"
        f"<tr><th>Emulator image</th><td class='mono'>{_e(trace.emulator_image or 'unrecorded')}</td></tr>"
        f"<tr><th>VM instance</th><td class='mono'>{_e(trace.vm_instance_id or 'unrecorded')}</td></tr>"
        f"<tr><th>Containment verified</th><td>{_e(trace.containment_verified)}</td></tr>"
        f"<tr><th>Captured at</th><td>{_e(trace.captured_at or 'unrecorded')}</td></tr>"
        f"<tr><th>Morphs applied</th><td>{_e(', '.join(trace.morphs_applied) or 'none')}</td></tr>"
        "</table>"
        f"{flow_block}{evasion_block}"
    )


def _section_chain(chain: ChainVerification | None) -> str:
    if chain is None:
        return ""
    if chain.ok:
        body = (
            f"<p class='chain-ok'>Chain intact — {chain.node_count} evidence nodes "
            "verified from genesis.</p>"
        )
    else:
        body = (
            f"<p class='chain-bad'>CHAIN VERIFICATION FAILED at seq "
            f"{chain.first_bad_seq}: {_e(chain.reason)}</p>"
            "<p>This report must not be relied upon until the discrepancy is explained.</p>"
        )
    return (
        "<h2>Evidence integrity</h2>"
        "<p class='sub'>Every finding above is a node in an append-only, "
        "hash-chained, Ed25519-signed ledger. Altering any node invalidates its hash "
        "and every link after it.</p>"
        f"<div class='panel'>{body}</div>"
    )


def render(
    *,
    job: Job,
    meta: FileMeta,
    score: CompositeScore,
    static: StaticReport | None = None,
    genai: GenAIVerdict | None = None,
    trace: DynamicTrace | None = None,
    chain: ChainVerification | None = None,
) -> str:
    """Render the full investigation report as one self-contained HTML document."""
    colour = _BAND_COLOUR.get(score.band, "#5a6572")
    limits = _limitations(score, static, genai, trace)
    limit_items = "".join(f"<li>{_e(x)}</li>" for x in limits) or (
        "<li>No limitations were flagged by the pipeline.</li>"
    )

    actions = "".join(
        f"<tr><td class='mono'>{_e(a.action)}</td><td>{_e(a.rationale)}</td>"
        f"<td>{'confirmed by ' + _e(a.confirmed_by) if a.confirmed_by else 'awaiting human confirmation'}</td></tr>"
        for a in score.actions_proposed
    )
    action_block = (
        "<h2>Recommended actions</h2>"
        "<p class='sub'>DRISHTI proposes and records. It does not execute: every "
        "consequential action is gated on a named human.</p>"
        "<table><thead><tr><th>Action</th><th>Rationale</th><th>Status</th></tr></thead>"
        f"<tbody>{actions}</tbody></table>"
        if actions
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DRISHTI report — {_e(meta.filename)}</title>
<style>{_CSS}</style></head><body>

<h1>APK Investigation Report</h1>
<p class="sub">{_e(meta.filename)} · <span class="mono">{_e(meta.sha256)}</span></p>

<div class="verdict" style="background:{colour}">
  <div class="score">{score.S}</div>
  <div>
    <div class="band">{_e(score.band.value)}</div>
    <div>confidence C={score.C:.2f} · gamma={score.gamma:.2f}</div>
  </div>
</div>

<div class="panel">{_e(score.explanation) or "No explanation was produced."}</div>

<h2>Sample</h2>
<table>
  <tr><th>Filename</th><td>{_e(meta.filename)}</td></tr>
  <tr><th>SHA-256</th><td class="mono">{_e(meta.sha256)}</td></tr>
  <tr><th>Size</th><td>{meta.size_bytes:,} bytes</td></tr>
  <tr><th>Package</th><td class="mono">{_e(meta.package or "unknown")}</td></tr>
  <tr><th>App label</th><td>{_e(meta.app_label or "unknown")}</td></tr>
  <tr><th>Job</th><td class="mono">{_e(job.id)}</td></tr>
  <tr><th>Analysed</th><td>{_e(job.created_at)}</td></tr>
</table>

{_section_score(score)}
{_section_findings(genai)}
{_section_techniques(genai)}
{_section_static(static)}
{_section_dynamic(trace)}
{_section_chain(chain)}
{action_block}

<h2>Limitations</h2>
<p class="sub">Generated from the pipeline's own provenance flags, not written by
hand. Each entry is present because a specific signal was missing, partial, replayed,
or rejected.</p>
<div class="panel limits"><ul>{limit_items}</ul></div>

<footer>
Generated by DRISHTI automated APK triage. This document is machine-generated
evidence: it records what was observed and what was not. It is a triage product and
does not replace analyst judgement.
</footer>
</body></html>
"""

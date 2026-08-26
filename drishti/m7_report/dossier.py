"""The incident dossier: what a victim or a bank needs in order to report a sample.

Play Protect answers "should this install?". It does not hand the person holding the
phone a document they can attach to a complaint. This module produces that document.

**Scope, stated plainly, because the surrounding claim is easy to overstate:**

* India's National Cyber Crime Reporting Portal (cybercrime.gov.in) has **no public
  submission API**. Nothing here files a complaint. It assembles the facts a complaint
  needs and deep-links the human to the portal, and the UI must say exactly that.
* Nothing here uploads the sample anywhere. `CLAUDE.md`'s hard boundaries forbid
  distributing a real sample outside the analysis project's own private bucket, and
  a convenient "submit to a sharing platform" button is precisely the thing that rule
  exists to prevent.

What it *does* give you is the part that is genuinely slow by hand: the hash, the
package identity, the certificate, the observed infrastructure, the technique
mapping, and a ledger reference that lets a reviewer re-verify every claim.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from drishti.contracts.dynamic_trace import DynamicTrace
from drishti.contracts.evidence import ChainVerification
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.score import CompositeScore, SeverityBand
from drishti.contracts.static_report import FileMeta, StaticReport

#: The national portal and helpline. Both are public, stable entry points; neither is
#: an API. The deep link is the portal root on purpose — inventing a form-prefill URL
#: we have not verified would be a fabricated capability.
NCRP_PORTAL_URL = "https://cybercrime.gov.in/"
NCRP_HELPLINE = "1930"

#: Reporting is only proposed for verdicts we would actually stand behind. Filing a
#: national complaint about a MEDIUM-confidence triage result wastes a real
#: investigator's time and degrades the signal for everyone using the portal.
REPORTABLE_BANDS = (SeverityBand.CRITICAL, SeverityBand.HIGH)


@dataclass(frozen=True)
class Dossier:
    """A reporting package. `submission_is_manual` is not decoration."""

    sha256: str
    reportable: bool
    reason: str
    summary: str
    facts: dict[str, Any]
    indicators: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)
    portal_url: str = NCRP_PORTAL_URL
    helpline: str = NCRP_HELPLINE
    #: Always True. No code path files a complaint automatically, and no caller may
    #: present this package as having been submitted.
    submission_is_manual: bool = True

    def as_text(self) -> str:
        """A plain-text block a human can paste into the portal's description field."""
        lines = [
            "SUSPECTED FRAUDULENT ANDROID APPLICATION",
            "",
            f"SHA-256: {self.sha256}",
            "",
            self.summary,
            "",
            "TECHNICAL FACTS",
        ]
        lines += [f"  {key}: {value}" for key, value in self.facts.items()]

        if self.indicators:
            lines += ["", "OBSERVED INFRASTRUCTURE"]
            lines += [f"  {i}" for i in self.indicators]

        if self.techniques:
            lines += ["", "TECHNIQUES (MITRE ATT&CK Mobile)"]
            lines += [f"  {t}" for t in self.techniques]

        # The caveats are not an appendix. A complaint that overstates its own
        # certainty is worse for the recipient than one that does not exist.
        lines += ["", "LIMITATIONS OF THIS AUTOMATED ANALYSIS"]
        lines += [f"  - {c}" for c in self.caveats] or ["  - none flagged"]
        lines += [
            "",
            "Prepared by DRISHTI automated APK triage. This is a machine-generated",
            "triage product, not a forensic examination. It has NOT been submitted to",
            f"any authority; submission via {self.portal_url} is a manual step.",
        ]
        return "\n".join(lines)


def build(
    *,
    meta: FileMeta,
    score: CompositeScore,
    static: StaticReport | None = None,
    genai: GenAIVerdict | None = None,
    dynamic: DynamicTrace | None = None,
    chain: ChainVerification | None = None,
) -> Dossier:
    """Assemble the reporting package for one analysed sample."""
    reportable = score.band in REPORTABLE_BANDS
    reason = (
        f"Score {score.S} ({score.band.value}) meets the reporting threshold."
        if reportable
        else (
            f"Score {score.S} ({score.band.value}) is below the reporting threshold. "
            "Filing a national complaint on a low-confidence triage result consumes "
            "investigator time that a real victim needs."
        )
    )

    facts: dict[str, Any] = {
        "filename": meta.filename,
        "size_bytes": f"{meta.size_bytes:,}",
        "package": meta.package or "unknown",
        "app_label": meta.app_label or "unknown",
        "drishti_score": f"{score.S}/100 ({score.band.value})",
        "analysis_confidence": f"{score.C:.2f}",
    }
    if static is not None:
        facts["signing_cert_sha256"] = static.certificate.sha256
        facts["signing_cert_subject"] = static.certificate.subject
        facts["certificate_age_days"] = static.certificate.age_days
        facts["permissions_declared"] = len(static.permissions)
        if static.certificate.brand_mismatch and static.certificate.brand_claimed:
            facts["impersonated_brand"] = static.certificate.brand_claimed
    if chain is not None:
        facts["evidence_chain"] = (
            f"{chain.node_count} nodes, integrity {'VERIFIED' if chain.ok else 'FAILED'}"
        )

    # Only observed infrastructure. A URL string sitting in a DEX is a string; listing
    # it to law enforcement as contacted infrastructure would be an assertion we have
    # not earned, and `synthesised` flows were served by our own harness.
    indicators = [
        f"{flow.host}  (observed {flow.method} {flow.url[:120]})"
        for flow in (dynamic.network_flows if dynamic else ())
        if not flow.synthesised
    ]
    seen: set[str] = set()
    deduped: list[str] = []
    for indicator in indicators:
        if indicator not in seen:
            seen.add(indicator)
            deduped.append(indicator)
    indicators = deduped

    techniques = [
        f"{t.technique_id}  {t.name}  ({t.tactic}, observed: {t.layer})"
        for t in (genai.techniques if genai else ())
    ]

    caveats = list(score.limitations)
    if dynamic is None:
        caveats.append("No dynamic analysis was performed; capability only, not behaviour.")
    elif dynamic.synthetic:
        caveats.append("The dynamic trace is a hand-authored fixture, not a measurement.")
    if genai is not None and genai.rejected_claims:
        caveats.append(
            f"{len(genai.rejected_claims)} model-generated claim(s) failed verification "
            "and are excluded from this dossier."
        )

    summary = score.explanation or "Automated static and dynamic triage of an Android package."

    return Dossier(
        sha256=meta.sha256,
        reportable=reportable,
        reason=reason,
        summary=summary,
        facts=facts,
        indicators=indicators,
        techniques=techniques,
        caveats=caveats,
    )

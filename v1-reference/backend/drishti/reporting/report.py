from collections import defaultdict

from drishti.reporting.models import (
    AndroidAnalysisReport,
    CapabilityFinding,
    CitedStatement,
    ConfidenceReport,
    EvidenceReference,
    Indicator,
    ProvenanceReport,
)

_CONSEQUENCES = {
    "banker_overlay_accessibility": "The declared capabilities could support credential capture through overlays and accessibility control.",
    "accessibility_abuse": "The accessibility capability could read screen content or automate user-interface actions if enabled by the user.",
    "otp_interception": "The SMS permissions could expose one-time passwords or other message content.",
    "dropper_install": "The package-install capability could be used to request installation of additional software.",
    "overlay_attack": "The overlay capability could place deceptive content over another app.",
    "device_admin_persistence": "The device-admin capability could make removal more difficult if the user grants it.",
    "sms_send_fraud": "The SMS capability could send messages that incur charges or support fraud.",
    "contacts_exfil": "Contact access could expose address-book data if the app reads and transmits it.",
}


def _provenance(node: dict) -> str:
    source = str(node.get("source_tool", ""))
    if source == "sandbox_real":
        return "observed"
    if source == "sandbox_sim":
        return "simulated"
    if node.get("type") == "ml_signal":
        return "ml"
    if node.get("type") in {"genai_claim", "mitre_tag"}:
        return "genai"
    if node.get("type") == "score_factor":
        return "scoring"
    return "static"


def _dynamic_notice(status: str) -> str:
    if status == "observed":
        return "Includes a SHA-256-matched observation artifact produced independently by the no-egress detonator."
    if status == "simulated":
        return "Dynamic behavior is simulated from static hypotheses and was not observed executing."
    return "No dynamic execution evidence is included; the verdict uses static analysis, ML, and GenAI reasoning."


def build_android_report(
    result,
    *,
    analysis_id: str,
    ml_model_version: str = "baseline-synthetic-v1",
    gemini_live: bool | None = None,
) -> AndroidAnalysisReport:
    """Convert a pipeline result into a citation-safe, Android-friendly report."""
    verdict = result.verdict
    nodes = list(result.ledger)
    by_id = {n["id"]: n for n in nodes}
    valid_verdict_refs = [ref for ref in verdict.evidence_refs if ref in by_id]

    combos = list(result.static.get("combos", []))
    capabilities: list[CapabilityFinding] = []
    consequence_by_text: dict[str, CitedStatement] = {}
    technique_refs: dict[str, set[str]] = defaultdict(set)
    suspicious_permissions: set[str] = set()

    for combo in combos:
        matching = [
            n["id"] for n in nodes
            if n.get("type") == "api_sink" and n.get("content") == combo.get("label")
        ]
        if not matching:
            continue
        permissions = [str(p) for p in combo.get("permissions", [])]
        techniques = [str(t) for t in combo.get("mitre", [])]
        suspicious_permissions.update(permissions)
        capabilities.append(CapabilityFinding(
            capability_id=str(combo.get("id", "unknown")),
            text=str(combo.get("label", "Suspicious capability")),
            permissions=permissions,
            mitre_techniques=techniques,
            evidence_refs=matching,
        ))
        for technique in techniques:
            technique_refs[technique].update(matching)
        consequence = _CONSEQUENCES.get(str(combo.get("id", "")))
        if consequence:
            consequence_by_text[consequence] = CitedStatement(
                text=consequence, evidence_refs=matching
            )

    # Runtime wording mirrors provenance. A simulated node never becomes an
    # observed claim, even if its text resembles one.
    for node in nodes:
        if node.get("type") != "dynamic_obs":
            continue
        content = str(node.get("content", ""))
        if node.get("source_tool") == "sandbox_real" and content.startswith("[OBSERVED]"):
            text = content.removeprefix("[OBSERVED]").strip()
            consequence_by_text[text] = CitedStatement(
                text=f"Observed by the isolated detonator: {text}", evidence_refs=[node["id"]]
            )

    for technique in result.static.get("mitre", []):
        technique_refs[str(technique)]  # retain only when refs were found below
    if verdict.verified and valid_verdict_refs:
        for technique in verdict.attack_techniques:
            technique_refs[str(technique)].update(valid_verdict_refs)

    mitre = [
        CitedStatement(text=technique, evidence_refs=sorted(refs))
        for technique, refs in sorted(technique_refs.items()) if refs
    ]

    iocs: list[Indicator] = []
    for kind, values in result.static.get("iocs", {}).items():
        for value in values:
            refs = [
                n["id"] for n in nodes
                if n.get("type") == "ioc" and n.get("content") == f"{kind}: {value}"
            ]
            if refs:
                iocs.append(Indicator(kind=kind, value=str(value), evidence_refs=refs))

    if verdict.verified and valid_verdict_refs:
        summary = CitedStatement(text=verdict.summary, evidence_refs=valid_verdict_refs)
    else:
        summary = CitedStatement(
            text="No citation-verified GenAI conclusion was available; review the verified findings below.",
            evidence_refs=[],
        )

    evidence = [
        EvidenceReference(
            id=n["id"], type=n["type"], source=n["source_tool"],
            statement=n["content"], location=n.get("location"),
            confidence=float(n.get("confidence", 0.0)), provenance=_provenance(n),
        )
        for n in nodes
        if n.get("type") not in {"genai_claim", "mitre_tag"}
        or (
            bool(n.get("refs"))
            and all(ref in by_id for ref in n.get("refs", []))
        )
    ]
    live = gemini_live if gemini_live is not None else verdict.provider == "gemini"
    return AndroidAnalysisReport(
        analysis_id=analysis_id,
        sha256=verdict.sha256,
        threat_score=verdict.threat_score,
        severity=verdict.severity_band,
        confidence=ConfidenceReport(value=verdict.confidence, label=verdict.confidence_label),
        provenance=ProvenanceReport(
            ml_model_version=ml_model_version,
            gemini_status="live" if live else "mock",
            dynamic_status=verdict.dynamic_status,
            notice=_dynamic_notice(verdict.dynamic_status),
        ),
        genai_summary=summary,
        potential_consequences=list(consequence_by_text.values()),
        suspicious_permissions=sorted(suspicious_permissions),
        suspicious_capabilities=capabilities,
        mitre_mobile_techniques=mitre,
        iocs=iocs,
        evidence=evidence,
    )

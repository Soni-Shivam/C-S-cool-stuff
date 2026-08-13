"""End-to-end triage orchestrator: M1 -> M2 -> M5 -> M4 -> M6, all
writing to one signed evidence ledger, producing a final DrishtiVerdict."""
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

from drishti.genai.reason import reason
from drishti.ingestion import ingest, load_known_bad
from drishti.ledger import Ledger, generate_key, sign_ledger
from drishti.llm import get_provider
from drishti.ml import classify, load_or_train_baseline
from drishti.models import DrishtiVerdict
from drishti.sandbox import absent_result, ingest_real, interrogate
from drishti.scoring.anomaly import Escalation, collect_anomaly_signals, escalate
from drishti.scoring.engine import score_verdict
from drishti.static.analyzer import analyze_parsed
from drishti.static.androguard_adapter import parse_apk
from drishti.static.yara_scan import compile_rules, scan_bytes

_DATA = Path(__file__).resolve().parent.parent / "data"
_DEFAULT_KNOWN_BAD = _DATA / "known_bad_hashes.txt"


def _confidence_label(c: float) -> str:
    if c >= 0.75:
        return "High"
    if c >= 0.5:
        return "Medium"
    return "Low"


class AnalysisResult(BaseModel):
    verdict: DrishtiVerdict
    static: dict
    ml: dict
    dynamic: dict
    ledger: list[dict]
    ledger_signature: dict
    provider: str
    escalation: dict | None = None


def run_pipeline(
    apk_path: str,
    *,
    timestamp: str,
    provider=None,
    classifier=None,
    known_bad: dict | None = None,
    # Direct-library callers retain the historical simulated demo default.
    # The public API always passes absent/observed explicitly and never simulates.
    dynamic_mode: Literal["absent", "simulated", "observed"] = "simulated",
    observations: dict | str | Path | None = None,
    reputation_feed=None,
    allow_label_derived_reputation: bool = False,
) -> AnalysisResult:
    led = Ledger()
    provider = provider or get_provider()
    classifier = classifier or load_or_train_baseline()
    if known_bad is None:
        known_bad = load_known_bad(_DEFAULT_KNOWN_BAD)

    # M1 ingest
    bundle = ingest(apk_path, led, timestamp, known_bad=known_bad,
                    reputation_feed=reputation_feed,
                    allow_label_derived_reputation=allow_label_derived_reputation)

    # M2 static (parse once; reuse for M5)
    parsed = parse_apk(bundle.path)
    try:
        yara_hits = scan_bytes(Path(bundle.path).read_bytes(), compile_rules())
    except Exception:  # noqa: BLE001
        yara_hits = []
    static = analyze_parsed(parsed, bundle, led, timestamp, yara_hits=yara_hits)

    # M5 ML
    ml = classify(parsed, classifier, led, timestamp)

    # Dynamic input is always explicit. Nothing in this pipeline executes an APK.
    if dynamic_mode == "absent":
        if observations is not None:
            raise ValueError("observations supplied while dynamic_mode is absent")
        dynamic = absent_result()
    elif dynamic_mode == "simulated":
        if observations is not None:
            raise ValueError("observations cannot be supplied for simulated dynamics")
        dynamic = interrogate(static, ml, led, timestamp)
    elif dynamic_mode == "observed":
        if observations is None:
            raise ValueError("observed dynamics require an independently produced artifact")
        dynamic = ingest_real(
            observations, led, timestamp, expected_sha256=bundle.sha256
        )
    else:
        raise ValueError(f"unsupported dynamic mode: {dynamic_mode}")

    # M4 GenAI reasoning (grounded, verifier-gated)
    genai = reason(static, ml, bundle, led, provider, timestamp, dynamic_result=dynamic)

    # M6 composite scoring.
    # R comes from the graded reputation feed. A curated exact known-bad match still pins
    # R=1.0; otherwise we use the feed's grade, which falls back to the unknown floor
    # (never 0.0) so an unrecognised zero-day is not discounted on reputation grounds.
    r = 1.0 if bundle.intel_hit else bundle.reputation_r
    g = static.signature_severity
    # Only independently observed behavior can increase the runtime score.
    d = max(0.0, dynamic.b_dynamic - g) if dynamic.status == "observed" else 0.0
    gamma = 0.95 if dynamic.status == "observed" else 0.80
    scored = score_verdict(
        r=r, p_cal=ml.p_cal, b=genai.behavioral_risk, g=g, d=d, gamma=gamma,
        confirmed_malicious=bundle.intel_hit,
    )
    led.append("score_factor", "drishti.scoring",
               f"R={r} P_cal={ml.p_cal:.3f} B={genai.behavioral_risk:.3f} G={g:.3f} D={d:.3f} "
               f"-> S={scored['score']} ({scored['band']}), C={scored['confidence']}",
               location="scoring", confidence=scored["confidence"], timestamp=timestamp,
               refs=genai.evidence_refs)

    # Zero-day escalator. Every other signal rewards familiarity, so a novel family can be
    # quiet on R, G and P_cal at once and settle in Low. This raises the floor on novelty
    # grounds and flags review; it can never reduce a score or band.
    escalation = escalate(
        score=scored["score"], band=scored["band"],
        signals=collect_anomaly_signals(
            reputation_verdict=bundle.reputation_verdict,
            reputation_detections=bundle.reputation_detections,
            p_cal=ml.p_cal, behavioral_risk=genai.behavioral_risk,
            signature_severity=g,
            static_mitre=list(static.mitre or []),
            observed_mitre=list(dynamic.mitre_observed or []),
            dynamic_status=dynamic.status,
            dynamic_outcome=getattr(dynamic, "outcome", None),
            packed_or_obfuscated=bool(getattr(static, "packed", False)),
            dangerous_capability_count=len(static.combos or []),
            evidence_refs=genai.evidence_refs,
        ),
    )
    if escalation.escalated or escalation.requires_human_review:
        led.append(
            "score_factor", "drishti.scoring.anomaly",
            f"Anomaly escalation: score {escalation.anomaly_score:.2f} from "
            f"{len(escalation.signals)} novelty signal(s) "
            f"[{', '.join(s.signal_id for s in escalation.signals)}]; "
            f"{escalation.original_band}/{escalation.original_score} -> "
            f"{escalation.escalated_band}/{escalation.escalated_score}; "
            f"human_review={escalation.requires_human_review}",
            location="scoring", confidence=escalation.anomaly_score, timestamp=timestamp,
            refs=genai.evidence_refs)

    verdict = DrishtiVerdict(
        sha256=bundle.sha256,
        threat_score=escalation.escalated_score,
        severity_band=escalation.escalated_band,
        confidence=scored["confidence"],
        confidence_label=_confidence_label(scored["confidence"]),
        impersonated_target=genai.impersonated_target,
        victim_profile=genai.victim_profile,
        adversarial_elicitation_deployed=genai.adversarial_elicitation_deployed,
        attack_techniques=genai.attack_techniques or static.mitre,
        iocs=static.iocs,
        evidence_refs=genai.evidence_refs,
        summary=genai.summary,
        provider=genai.provider,
        verified=genai.verified,
        dynamic_status=dynamic.status,
        dynamic_simulated=dynamic.status == "simulated",
    )

    signature = sign_ledger(led, generate_key())
    return AnalysisResult(
        verdict=verdict,
        static=static.model_dump(),
        ml=ml.model_dump(),
        dynamic=dynamic.model_dump(),
        ledger=[n.model_dump() for n in led.nodes],
        ledger_signature=signature,
        provider=provider.name,
        escalation={
            "anomaly_score": escalation.anomaly_score,
            "escalated": escalation.escalated,
            "requires_human_review": escalation.requires_human_review,
            "original_score": escalation.original_score,
            "original_band": escalation.original_band,
            "escalated_score": escalation.escalated_score,
            "escalated_band": escalation.escalated_band,
            "user_warning": escalation.user_warning,
            "rationale": escalation.rationale,
            "signals": [
                {"id": s.signal_id, "description": s.description, "weight": s.weight}
                for s in escalation.signals
            ],
        },
    )

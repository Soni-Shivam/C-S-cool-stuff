"""End-to-end triage orchestrator: M1 -> M2 -> M5 -> M3(sim) -> M4 -> M6, all
writing to one signed evidence ledger, producing a final DrishtiVerdict."""
from pathlib import Path

from pydantic import BaseModel

from drishti.genai.reason import reason
from drishti.ingestion import ingest, load_known_bad
from drishti.ledger import Ledger, generate_key, sign_ledger
from drishti.llm import get_provider
from drishti.ml import classify, load_or_train_baseline
from drishti.models import DrishtiVerdict
from drishti.sandbox import interrogate
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


def run_pipeline(apk_path: str, *, timestamp: str, provider=None, classifier=None,
                 known_bad: dict | None = None) -> AnalysisResult:
    led = Ledger()
    provider = provider or get_provider()
    classifier = classifier or load_or_train_baseline()
    if known_bad is None:
        known_bad = load_known_bad(_DEFAULT_KNOWN_BAD)

    # M1 ingest
    bundle = ingest(apk_path, led, timestamp, known_bad=known_bad)

    # M2 static (parse once; reuse for M5)
    parsed = parse_apk(bundle.path)
    try:
        yara_hits = scan_bytes(Path(bundle.path).read_bytes(), compile_rules())
    except Exception:  # noqa: BLE001
        yara_hits = []
    static = analyze_parsed(parsed, bundle, led, timestamp, yara_hits=yara_hits)

    # M5 ML
    ml = classify(parsed, classifier, led, timestamp)

    # M3 simulated dynamic interrogation
    dynamic = interrogate(static, ml, led, timestamp)

    # M4 GenAI reasoning (grounded, verifier-gated)
    genai = reason(static, ml, bundle, led, provider, timestamp, dynamic_result=dynamic)

    # M6 composite scoring
    r = 1.0 if bundle.intel_hit else 0.05
    g = static.signature_severity
    d = max(0.0, dynamic.b_dynamic - g)  # runtime behaviour beyond static expectation
    gamma = 0.95  # all evidence layers present
    scored = score_verdict(
        r=r, p_cal=ml.p_cal, b=genai.behavioral_risk, g=g, d=d, gamma=gamma,
        confirmed_malicious=bundle.intel_hit,
    )
    led.append("score_factor", "drishti.scoring",
               f"R={r} P_cal={ml.p_cal:.3f} B={genai.behavioral_risk:.3f} G={g:.3f} D={d:.3f} "
               f"-> S={scored['score']} ({scored['band']}), C={scored['confidence']}",
               location="scoring", confidence=scored["confidence"], timestamp=timestamp,
               refs=genai.evidence_refs)

    verdict = DrishtiVerdict(
        sha256=bundle.sha256,
        threat_score=scored["score"],
        severity_band=scored["band"],
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
        dynamic_simulated=True,
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
    )

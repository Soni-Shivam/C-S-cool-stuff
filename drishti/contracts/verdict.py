"""The `Verdict` — one flat object every surface consumes. Contract addendum A15.

**This is a PROJECTION, not a new source of truth.** Every field is derived from
contracts that already exist: `CompositeScore`, `StaticReport`, `GenAIVerdict`,
`DynamicTrace`, `FileMeta`. Nothing here is computed for the first time, and nothing
here may disagree with the artefact it came from.

That distinction is the whole point. Five workstreams — the consumer Android screen, the
analyst portal, the static pipeline, the sandbox and the elicitation layer — need one
agreed shape to build against. The failure mode is each of them defining its own
near-identical `Verdict` and drifting, which is exactly what `CLAUDE.md` rule 1 exists to
prevent. So the shape is defined ONCE here, and `build_verdict()` is the ONLY way to
produce one.

Three properties are load-bearing and enforced by tests:

* **`provenance` is derived from the trace, never passed in.** `STATIC_ONLY` when no
  detonation ran, `REPLAY` when the trace came from a fixture, `LIVE` only when a real
  run produced it. This is what drives the on-screen badge, and a config flag must never
  be able to make a replay look live.
* **A sample that detonated but produced nothing is not benign.** `detonated=False` with
  observations absent stays `MONITOR`/`REVIEW` with the reason stated; silence from an
  evasive sample and silence from a clean app are indistinguishable.
* **`decrypted_strings` are redacted before they leave the lab.** Plaintext recovered
  from a real sample can contain a victim's OTP, card number or credentials. It goes
  through `redact_text` on the way into this object, because this object is rendered on
  a phone screen and in a browser.
"""

from __future__ import annotations

from typing import Literal

from drishti.contracts.base import DrishtiModel
from drishti.contracts.dynamic_trace import DynamicTrace, NetworkFlow, TraceSourceKind
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.score import CompositeScore, SeverityBand
from drishti.contracts.static_report import FileMeta, StaticReport

Provenance = Literal["STATIC_ONLY", "REPLAY", "LIVE"]
RecommendedAction = Literal["BLOCK", "REVIEW", "MONITOR"]


class VictimProfileView(DrishtiModel):
    """The social-engineering read, flattened for display."""

    language: str | None = None
    tactic: str | None = None
    segment: str | None = None


class DynamicTraceView(DrishtiModel):
    """What the sandbox actually observed. `null` on the parent until a run happens.

    `detonated=True` with three empty lists is a real and important state: the app ran
    and did nothing observable. It is NOT the same as never having run, which is why
    this object exists rather than the fields being optional on the parent.
    """

    detonated: bool = False
    api_calls: tuple[str, ...] = ()
    decrypted_strings: tuple[str, ...] = ()
    network_captures: tuple[str, ...] = ()


class Verdict(DrishtiModel):
    """The flat, cross-surface view of one analysed APK.

    Consumed by the consumer warning screen, the analyst portal, and the demo scripts.
    Produced only by `build_verdict()`.
    """

    sha256: str
    package_name: str
    threat_score: int
    severity_band: SeverityBand
    confidence: float
    provenance: Provenance

    impersonated_target: str | None = None
    victim_profile: VictimProfileView = VictimProfileView()
    behaviors_detected: tuple[str, ...] = ()
    attack_techniques: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    #: Plain language, no jargon, safe to show a non-technical person. Templated from
    #: grounded findings — never a free-form model sentence, because this is the text a
    #: frightened user reads and acts on.
    consumer_summary: str = ""
    recommended_action: RecommendedAction = "MONITOR"

    dynamic_trace: DynamicTraceView | None = None
    adversarial_elicitation_deployed: tuple[str, ...] = ()

    #: Why the analysis is incomplete, derived from provenance flags. The analyst portal
    #: renders these; the consumer screen does not.
    limitations: tuple[str, ...] = ()


#: Bands at or above which we tell a consumer to stop.
_BLOCK_BANDS = (SeverityBand.CRITICAL, SeverityBand.HIGH)


def _provenance(trace: DynamicTrace | None) -> Provenance:
    """Read provenance off the trace itself. Never off a config flag."""
    if trace is None:
        return "STATIC_ONLY"
    if trace.synthetic or trace.source == TraceSourceKind.REPLAY:
        return "REPLAY"
    return "LIVE"


def _recommended_action(score: CompositeScore) -> RecommendedAction:
    """Map the band to what we ask a human to do.

    Deliberately NOT read from `actions_proposed`, which is a richer analyst-facing list
    (quarantine, push_ioc, notify_customers). The consumer surface has exactly three
    outcomes and collapsing to them here keeps that decision in one place.
    """
    if score.band in _BLOCK_BANDS:
        return "BLOCK"
    if score.band is SeverityBand.MEDIUM or score.requires_human_review:
        return "REVIEW"
    return "MONITOR"


def _consumer_summary(
    score: CompositeScore,
    static: StaticReport | None,
    genai: GenAIVerdict | None,
    action: RecommendedAction,
) -> str:
    """One or two sentences a non-technical person can act on.

    Templated from grounded facts rather than generated. A model sentence here would be
    the one piece of unverified text on the screen a frightened user trusts most, and it
    would sit outside the ledger's grounding rule.
    """
    target = genai.victim.impersonated_target if genai and genai.victim else None
    brand = target or (static.certificate.brand_claimed if static else None)

    if action == "BLOCK":
        opening = (
            f"This app is pretending to be {brand}."
            if brand
            else "This app is not what it claims to be."
        )
        harm = _plain_harm(genai)
        return f"{opening} {harm} Do not install it."

    if action == "REVIEW":
        return (
            "We could not confirm this app is safe. It asks for permissions that could "
            "be used to read your messages or show fake screens over your banking app. "
            "Install it only if you are certain you trust the sender."
        )
    return "We found nothing harmful in this app, but we could not check everything."


#: Every one of the sixteen keys in `m4_genai.safety.BEHAVIOUR_WEIGHTS`, each mapped to
#: a sentence a non-technical reader understands.
#:
#: The keys are copied EXACTLY from that weight table, which is the whole of `B` and
#: therefore load-bearing — they are not renameable to suit this file. An earlier draft
#: here invented shorter names (`reads_sms`, `hides_icon`) that match nothing the model
#: ever emits, so every real sample fell through to the generic sentence while the tests
#: passed on fixtures using the invented names. Coverage is asserted by
#: `test_every_behaviour_key_has_a_consumer_sentence`, so a new behaviour cannot be added
#: to the weight table without someone writing the sentence a victim will read.
#:
#: Ordered worst-first: the first asserted behaviour is the one shown, and "it can empty
#: your account" matters more to a frightened user than "it reads your device id".
_PLAIN_HARM: tuple[tuple[str, str], ...] = (
    ("overlays_other_apps", "It can draw fake screens on top of your banking app."),
    ("reads_sms_content", "It can read your text messages, including one-time passwords."),
    (
        "sends_sms_without_user_action",
        "It can send text messages from your phone without telling you.",
    ),
    ("abuses_accessibility_service", "It can tap and type on your phone by itself."),
    ("impersonates_a_known_brand", "It is dressed up to look like an app you trust."),
    ("intercepts_notifications", "It can read your notifications, including bank alerts."),
    ("monitors_clipboard", "It watches anything you copy, including account numbers."),
    ("exfiltrates_over_network", "It sends your information to someone else's server."),
    ("encrypts_data_before_sending", "It hides what it sends so you cannot see it."),
    ("loads_dex_at_runtime", "It downloads more code after you install it."),
    ("requests_device_admin", "It asks for control of your phone so you cannot remove it."),
    ("hides_or_disables_its_own_icon", "It hides itself after installation."),
    ("harvests_contacts_or_call_log", "It copies your contacts and call history."),
    ("harvests_device_identifiers", "It collects details that identify your phone."),
    (
        "gates_behaviour_on_installed_apps",
        "It checks which banking apps you have before acting.",
    ),
    ("detects_analysis_environment", "It tries to hide its behaviour from security checks."),
)


def _plain_harm(genai: GenAIVerdict | None) -> str:
    """Describe the worst confirmed behaviour without jargon.

    Only behaviours the model actually ASSERTED are described. The fallback sentence is
    deliberately vague rather than inventing a specific harm we did not observe.
    """
    if genai is None or not genai.behaviours:
        return "It behaves like an app built to steal money."
    for key, sentence in _PLAIN_HARM:
        if genai.behaviours.get(key):
            return sentence
    return "It behaves like an app built to steal money."


def _flow_note(flow: NetworkFlow) -> str:
    """The provenance suffix for one flow on the demo screen."""
    if flow.injected_destination:
        return "  [lab infrastructure]"
    return "  [reply synthesised]" if flow.synthesised else ""


def _dynamic_view(trace: DynamicTrace | None) -> DynamicTraceView | None:
    """Flatten the trace for display, redacting anything recovered from the sample."""
    if trace is None:
        return None
    from drishti.m3_dynamic.redaction import redact_text

    # `api` only — never `args`. Hooked arguments are sample-derived and can carry the
    # very plaintext the decrypted-blob branch below is careful to redact.
    api_calls = tuple(event.api for event in trace.api_events[:60])
    # Plaintext recovered from a real sample can carry a victim's OTP, card number or
    # credentials. This object is rendered on a phone and in a browser, so it is
    # redacted on the way in rather than at each of the surfaces that display it.
    decrypted = tuple(
        redact_text(blob.plaintext_preview, message_body=True)
        for blob in trace.decrypted_blobs[:20]
        if getattr(blob, "plaintext_preview", None)
    )
    # Two provenance facts, never collapsed into one label: `[reply synthesised]` says
    # we wrote the response body to a destination the SAMPLE chose (which stays a
    # finding); `[lab infrastructure]` says the destination is ours — our sinkhole or
    # our proxy — and is not the sample contacting anybody.
    captures = tuple(
        f"{flow.method} {flow.host}{_flow_note(flow)}" for flow in trace.network_flows[:40]
    )
    return DynamicTraceView(
        detonated=trace.detonated,
        api_calls=api_calls,
        decrypted_strings=decrypted,
        network_captures=captures,
    )


def build_verdict(
    *,
    meta: FileMeta,
    score: CompositeScore,
    static: StaticReport | None = None,
    genai: GenAIVerdict | None = None,
    trace: DynamicTrace | None = None,
) -> Verdict:
    """Project the pipeline's artefacts into the one shape every surface consumes.

    The ONLY way to build a `Verdict`. Every value is copied from an artefact that
    already computed it; nothing is decided here except the flattening itself and the
    three-way consumer action.
    """
    action = _recommended_action(score)
    victim = genai.victim if genai else None

    behaviours = (
        tuple(sorted(name for name, present in genai.behaviours.items() if present))
        if genai
        else ()
    )
    techniques = tuple(t.technique_id for t in genai.techniques) if genai else ()

    return Verdict(
        sha256=meta.sha256,
        package_name=meta.package or (static.package if static else "unknown"),
        threat_score=score.S,
        severity_band=score.band,
        confidence=score.C,
        provenance=_provenance(trace),
        impersonated_target=victim.impersonated_target if victim else None,
        victim_profile=VictimProfileView(
            language=victim.language if victim else None,
            tactic=victim.tactic if victim else None,
            segment=victim.segment if victim else None,
        ),
        behaviors_detected=behaviours,
        attack_techniques=techniques,
        evidence_refs=tuple(score.ledger_refs),
        consumer_summary=_consumer_summary(score, static, genai, action),
        recommended_action=action,
        dynamic_trace=_dynamic_view(trace),
        adversarial_elicitation_deployed=(tuple(genai.elicitation_deployed) if genai else ()),
        limitations=tuple(score.limitations),
    )

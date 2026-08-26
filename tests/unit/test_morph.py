"""Morph validation, rendering, elicitation and the trace diff.

docs/PHASE_5_FRONTIER.md T5.1/T5.2/T5.3, CLAUDE.md rule 7.

`validate_morph` is a security gate: the LLM's morph params are untrusted input to a
command surface. The hostile-params test feeds it the things an attacker would and
asserts every one raises. The elicitor tests prove a morph without a cited observation
is dropped — we morph in response to a probe, never on a vibe.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.config import Settings
from drishti.contracts.dynamic_trace import SyntheticC2Response
from drishti.contracts.evidence import EvidenceType
from drishti.contracts.frontier import Morph, MorphKind, MorphPlan
from drishti.ledger.store import LedgerStore
from drishti.m3_dynamic.morph import (
    MorphValidationError,
    apply_morphs,
    diff_traces,
    measure_behaviour_change,
    render_morph_config,
    validate_morph,
)
from drishti.m4_genai.agents.adversarial_elicitor import plan_morphs
from drishti.m4_genai.client import LLMClient


def _morph(kind: MorphKind, params: dict, derived=("obs_1",)) -> Morph:
    return Morph(kind=kind, params=params, rationale="test", derived_from=derived)


# ── validate_morph accepts the good ──────────────────────────────────────────
def test_a_valid_install_packages_morph_passes() -> None:
    validate_morph(_morph(MorphKind.INSTALL_PACKAGES, {"packages": ["com.sbi.yono"]}))


def test_a_valid_build_props_morph_passes() -> None:
    validate_morph(_morph(MorphKind.BUILD_PROPS, {"MODEL": "Redmi Note 12", "BRAND": "Xiaomi"}))


def test_a_valid_sim_locale_morph_passes() -> None:
    validate_morph(_morph(MorphKind.SIM_LOCALE, {"sim_country_iso": "in", "sim_operator": "40570"}))


# ── validate_morph rejects the hostile (T5.2) ────────────────────────────────
HOSTILE = [
    (MorphKind.INSTALL_PACKAGES, {"packages": ["com.x; rm -rf /"]}),
    (MorphKind.INSTALL_PACKAGES, {"packages": ["../../../etc/passwd"]}),
    (MorphKind.INSTALL_PACKAGES, {"packages": ["com.x" * 40]}),
    (MorphKind.INSTALL_PACKAGES, {"packages": ["com." + "a" * 200]}),
    (MorphKind.INSTALL_PACKAGES, {"packages": [f"com.x{i}" for i in range(50)]}),
    (MorphKind.INSTALL_PACKAGES, {"packages": ["com.x`whoami`"]}),
    (MorphKind.INSTALL_PACKAGES, {"packages": ["Com.Uppercase.Bad"]}),
    (MorphKind.SMS_HISTORY, {"count": 999_999}),
    (MorphKind.SMS_HISTORY, {"count": 5, "bodies": ["x" * 5000]}),
    (MorphKind.CLOCK_SKEW, {"offset_days": 10_000_000}),
    (MorphKind.BUILD_PROPS, {"SERIAL": "$(reboot)"}),
    (MorphKind.SIM_LOCALE, {"sim_country_iso": "india; drop"}),
    (MorphKind.FILES_PRESENT, {"names": ["../../secret"]}),
    (MorphKind.INSTALL_PACKAGES, {"packages": ["com.x‮thing"]}),
    (MorphKind.INSTALL_PACKAGES, {"packages": ["com.x\x00null"]}),
]


@pytest.mark.parametrize("kind,params", HOSTILE)
def test_every_hostile_morph_is_rejected(kind: MorphKind, params: dict) -> None:
    with pytest.raises(MorphValidationError):
        validate_morph(_morph(kind, params))


def test_a_non_dict_params_is_rejected() -> None:
    morph = Morph(kind=MorphKind.INSTALL_PACKAGES, params={}, rationale="x")
    with pytest.raises(MorphValidationError):
        validate_morph(morph.model_copy(update={"params": {"packages": "notalist"}}))


# ── rendering injects as a JSON literal ──────────────────────────────────────
def test_render_emits_a_json_literal_not_concatenation() -> None:
    config = render_morph_config(
        (_morph(MorphKind.INSTALL_PACKAGES, {"packages": ["com.sbi.yono"]}),)
    )
    assert config.startswith("const MORPH_CONFIG = {")
    assert config.rstrip().endswith("};")
    assert '"com.sbi.yono"' in config


def test_render_revalidates_and_refuses_a_hostile_morph() -> None:
    with pytest.raises(MorphValidationError):
        render_morph_config((_morph(MorphKind.INSTALL_PACKAGES, {"packages": ["a; rm -rf /"]}),))


# ── apply_morphs plans without a runner and gates on human_reviewed ──────────
@pytest.fixture
def ledger(tmp_path: Path):
    store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    store.open("job_morph")
    # seed an evasion observation node the morph can cite
    node = store.append(
        type=EvidenceType.EVASION_CHECK,
        source_tool="test",
        content={"kind": "probe", "queried": "com.sbi.yono"},
    )
    store._obs_id = node.id  # type: ignore[attr-defined]
    yield store
    store.close()


def test_apply_without_a_runner_plans_but_does_not_apply(ledger) -> None:
    obs = ledger._obs_id  # type: ignore[attr-defined]
    plan = MorphPlan(
        id="plan_1",
        morphs=(
            _morph(MorphKind.INSTALL_PACKAGES, {"packages": ["com.sbi.yono"]}, derived=(obs,)),
        ),
        generated_by="test",
        human_reviewed=True,
    )
    result = apply_morphs(plan, ledger=ledger, runner=None)
    assert result.applied is False
    assert result.operations
    assert result.ledger_refs
    node = ledger.get(result.ledger_refs[0])
    assert node is not None and node.type is EvidenceType.MORPH_ACTION


def test_apply_gates_on_human_reviewed(ledger) -> None:
    obs = ledger._obs_id  # type: ignore[attr-defined]

    class Runner:
        def __init__(self):
            self.injected = []

        def inject(self, config: str) -> None:
            self.injected.append(config)

    plan = MorphPlan(
        id="plan_2",
        morphs=(
            _morph(MorphKind.INSTALL_PACKAGES, {"packages": ["com.sbi.yono"]}, derived=(obs,)),
        ),
        generated_by="test",
        human_reviewed=False,
    )
    runner = Runner()
    result = apply_morphs(plan, ledger=ledger, runner=runner)
    assert result.applied is False
    assert runner.injected == [], "an unreviewed plan must not touch the AVD"

    reviewed = plan.model_copy(update={"human_reviewed": True})
    result2 = apply_morphs(reviewed, ledger=ledger, runner=runner)
    assert result2.applied is True
    assert runner.injected, "a reviewed plan applies"


# ── the elicitor grounds every morph ─────────────────────────────────────────
@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        groq_api_key="gsk-test",
        db_path=tmp_path / "d.db",
        ledger_key_path=tmp_path / "k.pem",
        log_path=tmp_path / "l.jsonl",
        llm_cache_dir=tmp_path / "cache",
    )


def test_the_fallback_grounds_a_package_morph_without_a_model(ledger, settings) -> None:
    obs = ledger._obs_id  # type: ignore[attr-defined]
    observations = [
        {
            "id": obs,
            "probe": "getPackageInfo",
            "morph": "install_packages",
            "queried": "com.sbi.yono",
        }
    ]
    client = LLMClient(settings)  # mock provider -> PlanOut won't parse -> fallback
    plan = plan_morphs(observations, ledger, "job_morph", client)
    assert plan.morphs
    assert plan.morphs[0].kind is MorphKind.INSTALL_PACKAGES
    assert plan.morphs[0].derived_from == (obs,), "the morph must cite the observation"
    assert plan.human_reviewed is False


def test_no_observations_yields_an_empty_plan(ledger, settings) -> None:
    plan = plan_morphs([], ledger, "job_morph", LLMClient(settings))
    assert plan.morphs == ()


# ── the trace diff — the before/after slide ──────────────────────────────────
class _Trace:
    def __init__(self, events, techniques, detonated):
        self.total_events = events
        self.techniques = tuple(techniques)
        self.detonated = detonated
        self.api_events = ()
        self.evasion_observations = ()


def test_the_diff_shows_a_dormant_sample_waking_up() -> None:
    before = _Trace(3, (), False)
    after = _Trace(47, ("T1417", "T1516"), True)
    delta = diff_traces(before, after)
    assert delta.woke_up is True
    assert delta.event_delta == 44
    assert delta.new_techniques == ("T1417", "T1516")
    assert delta.detonated_after and not delta.detonated_before


def test_a_morph_that_changed_nothing_reads_as_nothing() -> None:
    before = _Trace(3, ("T1418",), False)
    after = _Trace(3, ("T1418",), False)
    delta = diff_traces(before, after)
    assert delta.woke_up is False
    assert delta.new_techniques == ()


# ── behaviour_changed is MEASURED from that diff, never asserted ─────────────
# `SyntheticC2Response.behaviour_changed` is the honest "did serving this work" metric.
# A default of True would make every synthesised response look effective; a default of
# False would hide a real result. It is filled from a trace diff or left None.
def _served() -> SyntheticC2Response:
    return SyntheticC2Response(
        t_ms=4200,
        host="gate.evil.tk",
        url="http://gate.evil.tk/api/poll",
        response_kind="command_poll",
        served_body='{"status": "ok", "cmd": "noop"}',
        provably_inert=True,
        reasoning="Answered the beacon with an inert command poll.",
    )


def test_behaviour_changed_is_false_when_pass_two_showed_nothing_new() -> None:
    """A negative result recorded is the point. It must not read as unmeasured."""
    before = _Trace(12, ("T1418",), True)
    after = _Trace(12, ("T1418",), True)
    (response,) = measure_behaviour_change((_served(),), before=before, after=after)
    assert response.behaviour_changed is False


def test_behaviour_changed_is_true_when_pass_two_revealed_a_new_technique() -> None:
    before = _Trace(12, ("T1418",), True)
    after = _Trace(31, ("T1418", "T1407"), True)
    (response,) = measure_behaviour_change((_served(),), before=before, after=after)
    assert response.behaviour_changed is True


def test_behaviour_changed_records_how_it_was_measured() -> None:
    """The number in the reasoning is what a reader checks the claim against."""
    before = _Trace(12, ("T1418",), True)
    after = _Trace(31, ("T1418", "T1407"), True)
    (response,) = measure_behaviour_change((_served(),), before=before, after=after)
    assert "T1407" in response.reasoning
    assert response.reasoning.startswith("Answered the beacon"), "the original reasoning is kept"


def test_with_no_second_pass_behaviour_changed_stays_unmeasured() -> None:
    """`None` means nobody looked. Claiming False would be claiming a measurement."""
    (response,) = measure_behaviour_change((_served(),), before=_Trace(12, (), True), after=None)
    assert response.behaviour_changed is None


def test_attribution_across_several_responses_is_disclosed() -> None:
    """A run-level diff cannot say WHICH of three responses moved the sample.

    Recording the same verdict on each without saying so would read as three
    independent confirmations of a single observation.
    """
    before = _Trace(12, ("T1418",), True)
    after = _Trace(31, ("T1418", "T1407"), True)
    responses = measure_behaviour_change(
        (_served(), _served(), _served()), before=before, after=after
    )
    assert all(r.behaviour_changed is True for r in responses)
    assert all("3 response" in r.reasoning for r in responses)


# ── the morph scripts themselves ─────────────────────────────────────────────
# The JS is what actually runs on the AVD; a kind whose script is missing hard-fails
# detonator_run.sh (return 5), and a script that emits its own observations would
# manufacture exactly the pass-1/pass-2 delta the loop claims to measure. Guard both.
_MORPH_DIR = Path(__file__).resolve().parents[2] / "drishti" / "m3_dynamic" / "scripts" / "morph"

#: Kinds implemented as a Frida script. GENERATIVE_C2 is handled by the generative-C2
#: addon, not by a morph script (see validate_morph); the content-provider kinds
#: (SMS_HISTORY, CONTACTS, ACCOUNTS) are deliberately unshipped rather than stubbed —
#: an absent script is refused, which is the honest state, whereas a stub would apply
#: nothing while a --morph-label claimed it had.
_SCRIPTED_KINDS = {
    MorphKind.BUILD_PROPS,
    MorphKind.SIM_LOCALE,
    MorphKind.INSTALL_PACKAGES,
    MorphKind.CLOCK_SKEW,
    MorphKind.FILES_PRESENT,
}


@pytest.mark.parametrize("kind", sorted(_SCRIPTED_KINDS, key=lambda k: k.value))
def test_each_scripted_morph_kind_has_a_script(kind: MorphKind) -> None:
    assert (_MORPH_DIR / f"{kind.value}.js").is_file()


@pytest.mark.parametrize("script", sorted(_MORPH_DIR.glob("*.js")))
def test_a_morph_script_never_emits_an_observation(script: Path) -> None:
    # A morph reports failure via hook_error but must never emit type:'observation' —
    # that would inflate the delta with events the sample did not produce.
    text = script.read_text(encoding="utf-8")
    assert "'observation'" not in text and '"observation"' not in text


@pytest.mark.parametrize("script", sorted(_MORPH_DIR.glob("*.js")))
def test_a_morph_script_is_self_contained(script: Path) -> None:
    # compose_hooks() does not prepend a shared prelude, so each script must define its
    # own DRISHTI_MORPH fallback and run regardless of load order.
    text = script.read_text(encoding="utf-8")
    assert "DRISHTI_MORPH" in text
    assert "'use strict'" in text

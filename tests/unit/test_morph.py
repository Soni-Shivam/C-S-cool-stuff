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
from drishti.contracts.evidence import EvidenceType
from drishti.contracts.frontier import Morph, MorphKind, MorphPlan
from drishti.ledger.store import LedgerStore
from drishti.m3_dynamic.morph import (
    MorphValidationError,
    apply_morphs,
    diff_traces,
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
        llm_provider="mock",
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

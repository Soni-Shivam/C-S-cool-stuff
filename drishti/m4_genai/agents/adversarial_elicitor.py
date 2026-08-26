"""Adversarial Elicitor: observed probes -> a validated, grounded morph plan.

docs/PHASE_5_FRONTIER.md T5.3, the paper §6.2.

The evasion detector says a sample probed its environment and stalled. This agent
turns those structured observations into a `MorphPlan` — what to synthesise so the
sample proceeds on the next pass. Three properties keep it honest and safe:

  * **Structured input only.** The prompt sees probe kinds, queried targets and stall
    flags — never a raw sample string. There is no attacker-controlled free text in
    the turn, so the injection surface is minimal by construction.
  * **Every morph is grounded.** A morph whose `derived_from` does not cite a real
    observation node is dropped. We morph in response to an observed probe, never on a
    vibe — that constraint is what makes this elicitation rather than fabrication.
  * **Every morph is validated.** `validate_morph` runs on the model's output before it
    is kept, because the model's params are untrusted input to a command surface.

Degrades: a provider outage yields an empty plan with a reason, never an exception. A
deterministic fallback covers the common `install_packages` case from the observations
alone, so the loop still closes when the model is unavailable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field

from drishti.contracts.frontier import Morph, MorphKind, MorphPlan
from drishti.ledger.store import LedgerStore
from drishti.logging import get_logger
from drishti.m3_dynamic.morph import MorphValidationError, validate_morph
from drishti.util import new_id

log = get_logger(__name__)

_PROMPTS = Path(__file__).resolve().parents[1] / "prompts"

#: The evasion detector's morph strings mapped to the enum the applicator consumes.
_MORPH_ALIASES: dict[str, MorphKind] = {
    "install_packages": MorphKind.INSTALL_PACKAGES,
    "sms_history": MorphKind.SMS_HISTORY,
    "sim_locale": MorphKind.SIM_LOCALE,
    "device_identity": MorphKind.BUILD_PROPS,
    "contacts": MorphKind.CONTACTS,
    "accounts": MorphKind.ACCOUNTS,
    "clock_skew": MorphKind.CLOCK_SKEW,
    "files_present": MorphKind.FILES_PRESENT,
}


class MorphOut(BaseModel):
    kind: str
    params: dict = Field(default_factory=dict)
    rationale: str = ""
    derived_from: list[str] = Field(default_factory=list)


class PlanOut(BaseModel):
    morphs: list[MorphOut] = Field(default_factory=list)
    expected_effect: str = ""
    reasoning: str = ""


def _system_prompt() -> str:
    environment = Environment(
        loader=FileSystemLoader(_PROMPTS),
        autoescape=select_autoescape(enabled_extensions=(), default=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    return environment.get_template("adversarial_elicitor.jinja").render()


def build_user_turn(observations: list[dict[str, Any]]) -> str:
    """Render the structured observations. No sample-derived free text appears here."""
    lines = ["Observed environment probes in pass 1 (the sample then stalled):"]
    for obs in observations:
        lines.append(
            f"- [{obs['id']}] probe={obs['probe']} morph_hint={obs['morph']} "
            f"queried={obs.get('queried', 'n/a')} occurrences={obs.get('occurrences', 1)}: "
            f"{obs.get('detail', '')}"
        )
    lines.append("\nReturn the required JSON morph plan.")
    return "\n".join(lines)


def plan_morphs(
    observations: list[dict[str, Any]],
    ledger: LedgerStore,
    job_id: str,
    client: Any | None,
) -> MorphPlan:
    """Produce a validated, grounded `MorphPlan` from structured observations.

    `observations` each carry an `id` that resolves to an `EVASION_CHECK` ledger node,
    a `probe`, a `morph` hint and the `queried` target. The returned plan cites those
    ids in `derived_from`; a morph that cites none is dropped.
    """
    if not observations:
        return MorphPlan(
            id=new_id("plan"),
            morphs=(),
            generated_by="adversarial_elicitor",
            expected_effect="",
        )

    valid_ids = {obs["id"] for obs in observations}
    raw = _from_model(observations, client) or PlanOut()
    morphs = _accept(raw.morphs, valid_ids)

    if not morphs:
        # Deterministic fallback: the most common case is a package probe, and the
        # observations name exactly which package. The loop closes without the model.
        morphs = _fallback(observations)

    plan = MorphPlan(
        id=new_id("plan"),
        morphs=tuple(morphs),
        generated_by="adversarial_elicitor" if raw.morphs else "adversarial_elicitor:fallback",
        expected_effect=(raw.expected_effect or "satisfy the observed probes and re-detonate")[
            :300
        ],
        # human_reviewed stays False: the UI gates real application on a human, and a
        # stub/auto plan must never apply itself.
        human_reviewed=False,
    )
    _record_plan(plan, ledger)
    log.info(
        "morph_plan_built",
        morphs=len(plan.morphs),
        source=plan.generated_by,
        grounded=all(m.derived_from for m in plan.morphs),
    )
    return plan


def _from_model(observations: list[dict[str, Any]], client: Any | None) -> PlanOut | None:
    if client is None:
        return None
    try:
        # `client` is deliberately untyped (Any) so a fake can be injected in tests;
        # the cast records the contract the real client honours.
        return cast(
            "PlanOut | None",
            client.complete_as(
                system=_system_prompt(),
                user=build_user_turn(observations),
                schema=PlanOut,
                purpose="adversarial_elicitor",
                max_output_tokens=800,
            ),
        )
    except Exception as exc:
        log.warning("elicitor_model_unavailable", error=str(exc))
        return None


def _accept(raw_morphs: list[MorphOut], valid_ids: set[str]) -> list[Morph]:
    """Keep only morphs that are grounded, of a known kind, and pass validation."""
    accepted: list[Morph] = []
    for item in raw_morphs[:8]:
        kind = _MORPH_ALIASES.get(item.kind) or _kind_or_none(item.kind)
        if kind is None:
            log.warning("morph_unknown_kind", kind=item.kind[:40])
            continue
        cited = tuple(ref for ref in item.derived_from if ref in valid_ids)
        if not cited:
            # Ungrounded morph — the same discipline as a rejected claim.
            log.warning("morph_ungrounded_dropped", kind=item.kind[:40])
            continue
        morph = Morph(
            kind=kind,
            params=item.params if isinstance(item.params, dict) else {},
            rationale=item.rationale.strip()[:300],
            derived_from=cited,
        )
        try:
            validate_morph(morph)
        except MorphValidationError as exc:
            log.warning("morph_failed_validation", kind=item.kind[:40], error=str(exc))
            continue
        accepted.append(morph)
    return accepted


def _kind_or_none(value: str) -> MorphKind | None:
    try:
        return MorphKind(value)
    except ValueError:
        return None


def _fallback(observations: list[dict[str, Any]]) -> list[Morph]:
    """Build an install_packages morph from package probes alone, when the model gave none."""
    packages: list[str] = []
    refs: list[str] = []
    for obs in observations:
        if obs.get("morph") != "install_packages":
            continue
        queried = obs.get("queried") or ""
        if _looks_like_package(queried):
            packages.append(queried)
            refs.append(obs["id"])
    if not packages:
        return []
    morph = Morph(
        kind=MorphKind.INSTALL_PACKAGES,
        params={"packages": sorted(set(packages))[:20]},
        rationale="the sample probed for these packages and then stalled",
        derived_from=tuple(dict.fromkeys(refs)),
    )
    try:
        validate_morph(morph)
    except MorphValidationError:
        return []
    return [morph]


def _looks_like_package(value: str) -> bool:
    import re

    return bool(re.fullmatch(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,6}", value))


def _record_plan(plan: MorphPlan, ledger: LedgerStore) -> None:
    if not plan.morphs:
        return
    from drishti.m3_dynamic.morph import apply_morphs

    # apply_morphs with no runner records the MORPH_ACTION nodes and applies nothing —
    # the plan is grounded and auditable before anyone chooses to run it.
    apply_morphs(plan, ledger=ledger, runner=None)


__all__ = ["build_user_turn", "plan_morphs"]

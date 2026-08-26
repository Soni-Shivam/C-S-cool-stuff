"""JIT morph applicator: validate a morph, render it safely, apply it, diff the result.

docs/PHASE_5_FRONTIER.md T5.1/T5.2, the paper §6.2, §6.4.

The evasion detector already emits morph *proposals* — "the sample probed for an
installed bank, found none, and stalled; try `install_packages`" (the paper's Fig 18).
This module is the applicator that closes the loop the proposal opens: it turns a
proposal into a validated `Morph`, renders it as a Frida config the sandbox injects,
applies it on the running AVD, and diffs pass-1 against pass-2 — the flat-trace vs
spiky-trace before/after that is the frontier's whole claim.

Two boundaries govern every line here:

  * **A morph changes what the sample OBSERVES, never what it can DO** (CLAUDE.md).
    The rendered config feeds an observational hook that substitutes a synthetic
    return value; it never sends an SMS, writes a file, or grants a permission.
  * **The LLM's morph params are untrusted input to a command surface.**
    `validate_morph` runs before anything reaches adb or JS, and params are injected
    as a JSON literal (`const MORPH_CONFIG = {...}`), never string-concatenated into a
    JS expression — the same discipline as SQL parameterisation, for the same reason.

The validation, rendering and diff are pure and laptop-testable. `apply_morphs` builds
the concrete operations and only touches adb/Frida on the sealed detonator; without a
runner it returns the planned operations and applies nothing.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from drishti.contracts.dynamic_trace import SyntheticC2Response
from drishti.contracts.frontier import Morph, MorphKind, MorphPlan
from drishti.logging import get_logger

log = get_logger(__name__)

#: Caps, straight from the spec. A morph is a small environmental nudge, not a dataset.
MAX_PACKAGES = 20
MAX_PACKAGE_LEN = 128
MAX_SMS = 200
MAX_SMS_BODY = 300
MAX_CONTACTS = 100
MAX_ACCOUNTS = 20
MAX_OFFSET_DAYS = 3650
MAX_STRING_LEN = 300

#: A valid Android package name. Deliberately strict: this string reaches `pm` and a
#: Frida `Java.use`, so anything outside this shape is refused rather than escaped.
_PACKAGE_RE = re.compile(r"[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,6}")

#: Build props a morph may set. A key outside this set is refused — we do not let the
#: model invent a system property to write.
_ALLOWED_BUILD_PROPS = frozenset(
    {"MODEL", "FINGERPRINT", "PRODUCT", "HARDWARE", "MANUFACTURER", "BRAND", "DEVICE"}
)

#: Characters that must never appear in any string value that reaches a command surface.
#: Shell metacharacters, path separators, null bytes, and the unicode bidi overrides
#: that hide `moc.live` as `evil.com` in a log.
_SHELL_META = set(";|&$`><\n\r\x00")
_BIDI_OVERRIDES = {"‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨"}

#: SIM locale fields a morph may set, and the value shapes they accept.
_SIM_FIELDS = {
    "sim_country_iso": re.compile(r"[a-z]{2}"),
    "network_operator_name": re.compile(r"[A-Za-z0-9 ]{1,20}"),
    "sim_operator": re.compile(r"[0-9]{5,6}"),
}


class MorphValidationError(ValueError):
    """A morph is unsafe or malformed. It never reaches adb or JS."""


def _reject_dangerous_string(value: str, *, allow_spaces: bool = True) -> None:
    if len(value) > MAX_STRING_LEN:
        raise MorphValidationError(f"string value too long: {len(value)} chars")
    if any(ch in _SHELL_META for ch in value):
        raise MorphValidationError(f"shell metacharacter in value: {value!r}")
    if any(ch in _BIDI_OVERRIDES for ch in value):
        raise MorphValidationError("unicode bidirectional override in value")
    if "/" in value or "\\" in value or ".." in value:
        raise MorphValidationError(f"path separator in value: {value!r}")
    if not allow_spaces and " " in value:
        raise MorphValidationError("unexpected whitespace in value")


def validate_morph(morph: Morph) -> None:
    """Raise `MorphValidationError` unless `morph` is safe to apply. T5.2.

    The security gate. Treats the model's own output as untrusted input to a command
    surface, because that is exactly what it is. Runs before `render_morph_config` and
    before anything touches the AVD.
    """
    if morph.kind not in set(MorphKind):
        raise MorphValidationError(f"unknown morph kind: {morph.kind!r}")
    params = morph.params
    if not isinstance(params, dict):
        raise MorphValidationError("morph params must be an object")

    if morph.kind is MorphKind.INSTALL_PACKAGES:
        _validate_packages(params)
    elif morph.kind is MorphKind.SMS_HISTORY:
        _validate_sms(params)
    elif morph.kind is MorphKind.CONTACTS:
        _validate_contacts(params)
    elif morph.kind is MorphKind.ACCOUNTS:
        _validate_accounts(params)
    elif morph.kind is MorphKind.SIM_LOCALE:
        _validate_sim(params)
    elif morph.kind is MorphKind.BUILD_PROPS:
        _validate_build_props(params)
    elif morph.kind is MorphKind.CLOCK_SKEW:
        _validate_clock(params)
    elif morph.kind is MorphKind.FILES_PRESENT:
        _validate_files(params)
    elif morph.kind is MorphKind.GENERATIVE_C2:
        # The C2 morph carries no adb/JS params — it flips a flag consumed by the
        # generative-C2 addon, whose own inertness gate is the boundary there.
        pass

    # Global sweep: no dangerous string anywhere in the params, whatever the kind.
    _sweep(params)


def _validate_packages(params: dict[str, Any]) -> None:
    packages = params.get("packages")
    if not isinstance(packages, list) or not packages:
        raise MorphValidationError("install_packages needs a non-empty 'packages' list")
    if len(packages) > MAX_PACKAGES:
        raise MorphValidationError(f"too many packages: {len(packages)} > {MAX_PACKAGES}")
    for pkg in packages:
        if not isinstance(pkg, str) or len(pkg) > MAX_PACKAGE_LEN:
            raise MorphValidationError(f"bad package value: {pkg!r}")
        if not _PACKAGE_RE.fullmatch(pkg):
            raise MorphValidationError(f"not a valid package name: {pkg!r}")


def _validate_sms(params: dict[str, Any]) -> None:
    count = params.get("count", 0)
    if not isinstance(count, int) or isinstance(count, bool) or not 0 <= count <= MAX_SMS:
        raise MorphValidationError(f"sms count out of range: {count!r}")
    for body in params.get("bodies", []) or []:
        if not isinstance(body, str) or len(body) > MAX_SMS_BODY:
            raise MorphValidationError("sms body too long or not a string")


def _validate_contacts(params: dict[str, Any]) -> None:
    contacts = params.get("contacts", []) or []
    if not isinstance(contacts, list) or len(contacts) > MAX_CONTACTS:
        raise MorphValidationError("contacts list missing or too long")


def _validate_accounts(params: dict[str, Any]) -> None:
    accounts = params.get("accounts", []) or []
    if not isinstance(accounts, list) or len(accounts) > MAX_ACCOUNTS:
        raise MorphValidationError("accounts list missing or too long")


def _validate_sim(params: dict[str, Any]) -> None:
    for key, value in params.items():
        pattern = _SIM_FIELDS.get(key)
        if pattern is None:
            raise MorphValidationError(f"unknown sim_locale field: {key!r}")
        if not isinstance(value, str) or not pattern.fullmatch(value):
            raise MorphValidationError(f"bad sim_locale value for {key}: {value!r}")


def _validate_build_props(params: dict[str, Any]) -> None:
    extra = set(params) - _ALLOWED_BUILD_PROPS
    if extra:
        raise MorphValidationError(f"disallowed build prop(s): {sorted(extra)}")
    for value in params.values():
        if not isinstance(value, str):
            raise MorphValidationError("build prop values must be strings")


def _validate_clock(params: dict[str, Any]) -> None:
    offset = params.get("offset_days", 0)
    if not isinstance(offset, int) or isinstance(offset, bool):
        raise MorphValidationError("clock offset_days must be an integer")
    if abs(offset) > MAX_OFFSET_DAYS:
        raise MorphValidationError(f"clock offset too large: {offset} days")


def _validate_files(params: dict[str, Any]) -> None:
    names = params.get("names", []) or []
    if not isinstance(names, list) or len(names) > MAX_CONTACTS:
        raise MorphValidationError("files list missing or too long")
    for name in names:
        if not isinstance(name, str):
            raise MorphValidationError("file name must be a string")
        # A morph declares that a file EXISTS by name; it must not smuggle a path.
        _reject_dangerous_string(name, allow_spaces=False)


def _sweep(value: Any, depth: int = 0) -> None:
    """Recursively reject a dangerous string anywhere in the params."""
    if depth > 6:
        raise MorphValidationError("params nested too deeply")
    if isinstance(value, str):
        _reject_dangerous_string(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise MorphValidationError("non-string param key")
            _sweep(item, depth + 1)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _sweep(item, depth + 1)
    elif isinstance(value, (int, float, bool)) or value is None:
        return
    else:
        raise MorphValidationError(f"non-JSON param value of type {type(value)}")


def render_morph_config(morphs: tuple[Morph, ...]) -> str:
    """Render validated morphs as a JSON-literal config for the Frida morph scripts.

    Emits `const MORPH_CONFIG = {...};`. Params are a `json.dumps` literal, never
    concatenated into a JS expression, so a value cannot break out of the string and
    become code — the rule-7 discipline the whole loop depends on.

    Validates again here, defensively: this function is the last gate before the value
    is written next to executable JS, and a caller that skipped `validate_morph` must
    still not be able to inject.
    """
    config: dict[str, list[dict[str, Any]]] = {"morphs": []}
    for morph in morphs:
        validate_morph(morph)
        config["morphs"].append({"kind": morph.kind.value, "params": morph.params})
    literal = json.dumps(config, ensure_ascii=True, separators=(",", ":"))
    return f"const MORPH_CONFIG = {literal};\n"


@dataclass(frozen=True)
class MorphOperation:
    """One concrete step the applicator would run on the AVD."""

    kind: str
    description: str
    frida_config: str = ""


@dataclass(frozen=True)
class AppliedMorphs:
    """The result of applying (or planning) a morph set."""

    operations: tuple[MorphOperation, ...] = ()
    applied: bool = False
    ledger_refs: tuple[str, ...] = ()
    errors: tuple[str, ...] = field(default_factory=tuple)


def apply_morphs(
    plan: MorphPlan,
    *,
    ledger: Any | None = None,
    runner: Any | None = None,
) -> AppliedMorphs:
    """Validate a plan, render it, and apply it on the AVD — or plan it if no runner.

    On the laptop `runner` is None: the operations are built and returned, nothing is
    applied, and `applied=False` says so honestly. On the detonator the runner injects
    the rendered config into the morph scripts. `human_reviewed` gates real application:
    a plan the analyst has not signed off is planned, never applied.
    """
    errors: list[str] = []
    valid: list[Morph] = []
    for morph in plan.morphs:
        try:
            validate_morph(morph)
            valid.append(morph)
        except MorphValidationError as exc:
            errors.append(f"rejected {morph.kind}: {exc}")
            log.warning("morph_rejected", kind=str(morph.kind), error=str(exc))

    operations = tuple(
        MorphOperation(
            kind=morph.kind.value,
            description=morph.rationale[:200],
            frida_config=render_morph_config((morph,)),
        )
        for morph in valid
    )

    refs: tuple[str, ...] = ()
    if ledger is not None and valid:
        refs = _record(plan, valid, ledger)

    if runner is None or not plan.human_reviewed:
        if runner is not None and not plan.human_reviewed:
            errors.append("plan not human_reviewed; planned but not applied")
        return AppliedMorphs(
            operations=operations, applied=False, ledger_refs=refs, errors=tuple(errors)
        )

    try:
        for operation in operations:
            runner.inject(operation.frida_config)
        return AppliedMorphs(
            operations=operations, applied=True, ledger_refs=refs, errors=tuple(errors)
        )
    except Exception as exc:  # a runner failure degrades to a planned result
        log.error("morph_apply_failed", error=str(exc))
        errors.append(f"apply failed: {type(exc).__name__}: {exc}")
        return AppliedMorphs(
            operations=operations, applied=False, ledger_refs=refs, errors=tuple(errors)
        )


def _record(plan: MorphPlan, morphs: list[Morph], ledger: Any) -> tuple[str, ...]:
    from drishti.contracts.evidence import EvidenceType

    refs: list[str] = []
    for morph in morphs:
        node = ledger.append(
            type=EvidenceType.MORPH_ACTION,
            source_tool="m3_dynamic:morph",
            content={
                "plan_id": plan.id,
                "kind": morph.kind.value,
                "params": morph.params,
                "rationale": morph.rationale[:300],
                "human_reviewed": plan.human_reviewed,
            },
            # derived_from is what makes this "adversarial elicitation" and not "throw
            # fake data and hope": a morph with no cited observation is not recorded.
            parents=morph.derived_from,
        )
        refs.append(node.id)
    return tuple(refs)


# ── the before/after trace diff — the frontier's single best slide ────────────
@dataclass(frozen=True)
class TraceDelta:
    """What changed between the pre-morph and post-morph passes."""

    events_before: int
    events_after: int
    techniques_before: tuple[str, ...]
    techniques_after: tuple[str, ...]
    new_techniques: tuple[str, ...]
    detonated_before: bool
    detonated_after: bool
    woke_up: bool

    @property
    def event_delta(self) -> int:
        return self.events_after - self.events_before


def diff_traces(before: Any, after: Any) -> TraceDelta:
    """Diff two `DynamicTrace`s (or anything exposing the same fields).

    The honest metric of the whole frontier: did morphing make a dormant sample act?
    `woke_up` is true when the second pass detonated where the first did not, or when it
    revealed techniques the first never showed. It is read from the traces, never
    asserted — a morph that changed nothing must be visible as a morph that changed
    nothing.
    """
    tb = _techniques(before)
    ta = _techniques(after)
    eb = _events(before)
    ea = _events(after)
    det_b = bool(getattr(before, "detonated", False))
    det_a = bool(getattr(after, "detonated", False))
    new = tuple(t for t in ta if t not in set(tb))
    woke = (det_a and not det_b) or bool(new) or (ea > eb and eb == 0)
    return TraceDelta(
        events_before=eb,
        events_after=ea,
        techniques_before=tb,
        techniques_after=ta,
        new_techniques=new,
        detonated_before=det_b,
        detonated_after=det_a,
        woke_up=woke,
    )


def measure_behaviour_change(
    responses: Sequence[SyntheticC2Response],
    *,
    before: Any,
    after: Any,
) -> tuple[SyntheticC2Response, ...]:
    """Fill `behaviour_changed` on each served response from a real pass-1/pass-2 diff.

    This is the honest "did answering the dead C2 work" metric, and it is the one field
    on `SyntheticC2Response` a reader would most like to be flattered by. So it is
    measured, never asserted: `diff_traces` decides, and a morph or a synthesised reply
    that changed nothing comes back `False`. `None` is reserved for *nobody looked* —
    with no second pass there is no measurement, and claiming `False` would itself be a
    claim about a run that never happened.

    Attribution is run-level and says so. A trace diff cannot tell which of three served
    responses moved the sample, so every response gets the same verdict and every
    response's `reasoning` records how many shared it. Silently repeating one observation
    across three records would read as three independent confirmations.
    """
    if after is None or not responses:
        return tuple(responses)

    delta = diff_traces(before, after)
    detail = (
        f"new technique(s) {', '.join(delta.new_techniques)}"
        if delta.new_techniques
        else f"no new techniques; {delta.events_before} -> {delta.events_after} event(s)"
    )
    note = (
        f"behaviour_changed={delta.woke_up}, measured by trace diff: {detail}. "
        f"Attribution is run-level across {len(responses)} response(s) served."
    )
    log.info(
        "c2_behaviour_measured",
        behaviour_changed=delta.woke_up,
        new_techniques=delta.new_techniques,
        responses=len(responses),
    )
    return tuple(
        response.model_copy(
            update={
                "behaviour_changed": delta.woke_up,
                "reasoning": f"{response.reasoning} {note}".strip(),
            }
        )
        for response in responses
    )


def _techniques(trace: Any) -> tuple[str, ...]:
    techs = getattr(trace, "techniques", None)
    if techs:
        return tuple(techs)
    mappings = getattr(trace, "evasion_observations", ())
    # Fall back to distinct api-event techniques when present.
    events = getattr(trace, "api_events", ())
    seen: list[str] = []
    for event in events:
        name = getattr(event, "api", "")
        if name and name not in seen:
            seen.append(name)
    del mappings
    return tuple(seen)


def _events(trace: Any) -> int:
    total = getattr(trace, "total_events", None)
    if isinstance(total, int):
        return total
    api = getattr(trace, "api_events", ())
    return sum(getattr(e, "count", 1) for e in api)

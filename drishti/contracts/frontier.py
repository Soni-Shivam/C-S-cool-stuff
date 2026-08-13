"""P5 frontier contracts: morph plans, and the sandbox plan they feed.

docs/01_DATA_CONTRACTS.md §8.

Safety note that belongs next to the types: a `Morph` is LLM-generated input to a
system-command surface. `validate_morph()` (T5.2) must reject filesystem paths
outside the VM, shell metacharacters in package names, and any `kind` not in the
enum — before anything touches adb or a Frida script. Params are injected as JSON
literals, never string-concatenated into expressions. Even though the LLM is ours,
its output is untrusted here.

Morphs change what the sample OBSERVES about its environment. They never add
capability to the sample. That distinction is the whole safety rationale.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import Field

from drishti.contracts.base import DrishtiModel


class MorphKind(StrEnum):
    INSTALL_PACKAGES = "install_packages"
    SMS_HISTORY = "sms_history"
    CONTACTS = "contacts"
    SIM_LOCALE = "sim_locale"
    BUILD_PROPS = "build_props"
    ACCOUNTS = "accounts"
    CLOCK_SKEW = "clock_skew"
    GENERATIVE_C2 = "generative_c2"
    FILES_PRESENT = "files_present"


class Morph(DrishtiModel):
    """One environment synthesis step.

    `derived_from` points at the `EVASION_CHECK` nodes that justified it. A morph
    with no derivation is a guess, and the frontier's claim is that it responds to
    observed behaviour — so the provenance is what makes the claim checkable.
    """

    kind: MorphKind
    params: dict = Field(default_factory=dict)
    rationale: str
    derived_from: tuple[str, ...] = ()


class MorphPlan(DrishtiModel):
    id: str
    morphs: tuple[Morph, ...] = ()
    generated_by: str
    expected_effect: str = ""
    max_runtime_s: int = 180
    human_reviewed: bool = False


class SandboxPlan(DrishtiModel):
    """Input to `TraceSource.run()`.

    `hooks` combines base hooks, sink-derived hooks, and hypothesis-targeted method
    signatures. That last part is the closed loop: static analysis decided what to
    watch and the sandbox watches exactly that.
    """

    hooks: tuple[str, ...] = ()
    duration_s: int = 120
    morphs: tuple[Morph, ...] = ()
    stimuli: tuple[str, ...] = ()
    generative_c2: bool = False
    pass_num: int = 1

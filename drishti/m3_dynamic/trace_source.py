"""`TraceSource` — the abstraction that makes Replay Mode cost 20 minutes, not 6 hours.

docs/PHASE_0_FOUNDATIONS.md T0.7, docs/01_DATA_CONTRACTS.md §3.1.

`00_GUIDING_MAP.md` §3 is blunt about why this exists at hour zero: Phase 4 is the
highest-risk work in the project, and if live detonation is not working by the H40
tripwire we switch to replaying a captured trace. The rest of the system cannot tell
the difference — **so long as it is disclosed.** The contracts doc calls the
`pre_morph`/`post_morph` fixture pair "the single most important risk-mitigation
artefact in the whole build".

Three honesty properties are enforced here rather than remembered:

1. A replayed trace **always** reports `source=REPLAY`. A replay cannot claim to be live.
2. A hand-authored fixture **always** yields `synthetic=True` and `partial=True`, so the
   report's Limitations section says so without anyone deciding to mention it.
3. The fixture is validated against `DynamicTrace` on load, so a fixture that has
   drifted from the contract fails loudly instead of half-populating a trace.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from drishti.contracts.base import DrishtiModel
from drishti.contracts.dynamic_trace import DynamicTrace, TraceSourceKind
from drishti.contracts.frontier import SandboxPlan
from drishti.logging import get_logger
from drishti.util import new_id

log = get_logger(__name__)

DEFAULT_FIXTURE_DIR = Path("data/fixtures/traces")


class TraceSourceUnavailableError(RuntimeError):
    """This source cannot produce a trace for this sample right now.

    Raised rather than returning an empty trace: an empty `DynamicTrace` is a claim
    that the sample did nothing, and "we could not observe it" is a different
    statement. Conflating them is how a broken sandbox starts reading as a clean app.
    """


class FixtureProvenance(DrishtiModel):
    """Where a fixture's contents came from. The disclosure, in the file itself."""

    kind: Literal["hand_authored", "captured"]
    note: str = ""
    authored_at: str | None = None
    #: Set only for `captured`: the sample and run the trace was really taken from.
    source_sha256: str | None = None
    captured_from_image: str | None = None


class TraceFixture(DrishtiModel):
    """A `pre_morph` / `post_morph` pair for one sample.

    Two halves rather than one trace, because the frontier narrative is a *change*:
    first run the sample does nothing, then the environment is synthesised and the
    payload fires. Replay has to reproduce that arc or the demo's central beat cannot
    be shown in replay mode.
    """

    fixture_version: Literal["1.0"] = "1.0"
    sha256: str
    provenance: FixtureProvenance
    pre_morph: dict[str, Any] = Field(default_factory=dict)
    post_morph: dict[str, Any] = Field(default_factory=dict)


class TraceSource(ABC):
    """Produces a `DynamicTrace` for one sample under one plan."""

    @abstractmethod
    def run(self, apk_path: Path, plan: SandboxPlan) -> DynamicTrace: ...

    @abstractmethod
    def available(self) -> bool: ...

    @property
    @abstractmethod
    def kind(self) -> TraceSourceKind: ...


class LiveSandboxSource(TraceSource):
    """Real detonation on the sealed GCE detonator. **Lands in P4 (T4.1 to T4.6).**

    Deliberately unavailable until then, and it raises rather than degrading: a live
    source that quietly returned an empty trace would make a missing sandbox look like
    a sample that did nothing.

    Note what this class does NOT do, and must never do: run on a laptop. Detonation
    happens only inside the sealed VM (CLAUDE.md).
    """

    def __init__(self, *, detonator_instance: str | None = None) -> None:
        self._detonator = detonator_instance

    @property
    def kind(self) -> TraceSourceKind:
        return TraceSourceKind.LIVE

    def available(self) -> bool:
        # P0: the lab is not built. P4 replaces this with a real health probe —
        # containment verified, emulator booted, frida responding.
        return False

    def run(self, apk_path: Path, plan: SandboxPlan) -> DynamicTrace:
        raise TraceSourceUnavailableError(
            "live detonation is not implemented until P4 (T4.1); no sample is ever executed locally"
        )


class ReplayTraceSource(TraceSource):
    """Replays `data/fixtures/traces/{sha256}.json`.

    `plan.morphs` selects the half: empty means pass 1 (`pre_morph`), non-empty means
    the frontier has applied morphs and we are in pass 2 (`post_morph`). That mirrors
    exactly what a live source would do, which is the point of the abstraction.
    """

    def __init__(self, fixture_dir: Path | str = DEFAULT_FIXTURE_DIR) -> None:
        self._dir = Path(fixture_dir)

    @property
    def kind(self) -> TraceSourceKind:
        return TraceSourceKind.REPLAY

    def available(self) -> bool:
        return self._dir.is_dir() and any(self._dir.glob("*.json"))

    def has_fixture_for(self, sha256: str) -> bool:
        return self._path_for(sha256).is_file()

    def _path_for(self, sha256: str) -> Path:
        return self._dir / f"{sha256}.json"

    def load_fixture(self, sha256: str) -> TraceFixture:
        path = self._path_for(sha256)
        if not path.is_file():
            raise TraceSourceUnavailableError(f"no replay fixture at {path}")
        return TraceFixture.model_validate_json(path.read_text(encoding="utf-8"))

    def run(self, apk_path: Path, plan: SandboxPlan, *, sha256: str | None = None) -> DynamicTrace:
        """Return the appropriate half, forced to declare what it is.

        `sha256` is accepted explicitly so a caller that already hashed the upload does
        not have to re-read a 300MB file just to find a fixture.
        """
        digest = sha256 or _sha256_of(apk_path)
        fixture = self.load_fixture(digest)

        half_name = "post_morph" if plan.morphs else "pre_morph"
        half = dict(fixture.post_morph if plan.morphs else fixture.pre_morph)
        if not half:
            raise TraceSourceUnavailableError(f"fixture {digest} has no {half_name} half")

        synthetic = fixture.provenance.kind == "hand_authored"

        # These are not defaults a fixture may override. A replay must present itself
        # as a replay, and a hand-authored trace must present itself as synthetic —
        # otherwise the disclosure depends on whoever wrote the JSON remembering to.
        half["run_id"] = new_id("run")
        half["source"] = TraceSourceKind.REPLAY.value
        half["synthetic"] = synthetic
        half["morphs_applied"] = tuple(m.kind.value for m in plan.morphs)
        if synthetic:
            half["partial"] = True
            disclosure = (
                "Dynamic trace is a hand-authored fixture, not a captured execution. "
                "No sample was detonated to produce it."
            )
            half["errors"] = (*tuple(half.get("errors") or ()), disclosure)

        trace = DynamicTrace.model_validate(half)
        log.info(
            "trace_replayed",
            sha256=digest,
            half=half_name,
            detonated=trace.detonated,
            synthetic=trace.synthetic,
        )
        return trace


def _sha256_of(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_trace_source(
    mode: Literal["live", "replay", "auto"],
    *,
    fixture_dir: Path | str = DEFAULT_FIXTURE_DIR,
    detonator_instance: str | None = None,
) -> TraceSource:
    """Pick a source for `sandbox_mode`.

    `auto` prefers live and falls back to replay — the parachute, wired in from hour
    one so the H40 tripwire is a 20-minute switch rather than a 6-hour rewrite.

    `live` is strict on purpose: asking for live and silently getting replay is the
    one behaviour that would make the disclosure meaningless.
    """
    live = LiveSandboxSource(detonator_instance=detonator_instance)
    replay = ReplayTraceSource(fixture_dir)

    if mode == "live":
        return live
    if mode == "replay":
        return replay
    if live.available():
        return live
    log.info("trace_source_fallback", requested="auto", chosen="replay")
    return replay

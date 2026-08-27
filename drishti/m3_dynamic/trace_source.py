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
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

from pydantic import Field

from drishti.config import Settings, get_settings
from drishti.contracts.base import DrishtiModel
from drishti.contracts.dynamic_trace import DynamicTrace, ObservationArtifact, TraceSourceKind
from drishti.contracts.frontier import SandboxPlan
from drishti.logging import get_logger
from drishti.m3_dynamic.detonator import (
    DetonatorClient,
    DetonatorTarget,
    RemoteDetonatorClient,
)
from drishti.m3_dynamic.ingest import artifact_to_trace
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


def _unsafe_reasons(artifact: ObservationArtifact) -> list[str]:
    """Name exactly the `safe_for_ingestion` predicates this artifact fails.

    One message per failed condition rather than one sentence listing every condition
    the gate checks: an ARM64-only APK fails only on `outcome`, and a refusal that also
    announced "snapshot lifecycle incomplete" sent the reader hunting for a dirty AVD
    that was in fact restored cleanly both times.
    """
    reasons: list[str] = []
    if artifact.outcome not in {"completed", "inconclusive"}:
        reasons.append(f"outcome={artifact.outcome}")
    if not artifact.package:
        reasons.append("no package name was recorded")
    if not artifact.metadata.containment_verified:
        reasons.append("containment not verified")
    if not artifact.metadata.containment_manifest_sha256:
        reasons.append("no signed containment manifest")
    snapshot = artifact.snapshot
    if snapshot is None:
        reasons.append("no snapshot lifecycle was recorded")
    else:
        if snapshot.before_restore != "passed":
            reasons.append(f"snapshot before_restore={snapshot.before_restore}")
        if snapshot.after_restore != "passed":
            reasons.append(f"snapshot after_restore={snapshot.after_restore}")
        if not snapshot.package_absent_after:
            reasons.append("the package was still present after restore")
    # Never return an empty list: the caller only calls this when the gate failed, and
    # "not safe to ingest: " with nothing after it is worse than an imprecise reason.
    return reasons or ["safe_for_ingestion is false for an unenumerated reason"]


class LiveSandboxSource(TraceSource):
    """Real detonation on the sealed GCE detonator (P4, T4.1-T4.6).

    Sequencing, refusal and provenance — nothing else. The execution lives on the VM
    behind `DetonatorClient`, and this class owns no code path that could run a sample
    locally. That is CLAUDE.md's one stated rule, expressed as a structure rather than
    as a comment asking future callers to be careful.

    It **raises rather than degrading**, everywhere. A live source that quietly returned
    an empty trace would make a missing sandbox look like a sample that did nothing, and
    those are opposite findings. The caller (`pipeline._sandbox`) catches
    `TraceSourceUnavailableError` and substitutes a stub that declares itself a stub;
    that disclosure is only possible because this class refuses instead of improvising.

    Two gates run before any trace is returned, and neither downgrades to a warning:

    * **Containment.** The harness re-verifies containment per sample and records the
      verdict in the artifact. An artifact whose containment was not verified aborts the
      run, because the signed manifest would otherwise attest a property nobody tested.
    * **Snapshot lifecycle.** `safe_for_ingestion` additionally requires the emulator to
      have come back clean — restored before, restored after, package gone. A dirty AVD
      means the *next* sample's trace is untrustworthy too.
    """

    def __init__(
        self,
        *,
        client: DetonatorClient | None = None,
        settings: Settings | None = None,
        duration_s: int | None = None,
        detonator_instance: str | None = None,
    ) -> None:
        if client is None:
            # Settings may refuse to construct for reasons that have nothing to do with
            # the sandbox — a missing LLM key, most often. M3 must not inherit M4's
            # configuration requirements, so an unresolvable environment yields an
            # UNCONFIGURED client that reports itself unavailable, which is the honest
            # answer: with no lab configured there is nowhere a sample may be executed.
            resolved: Settings | None = settings
            if resolved is None:
                try:
                    resolved = get_settings()
                except Exception as exc:
                    log.info("sandbox_settings_unavailable", error=str(exc)[:200])
            target = DetonatorTarget.from_settings(resolved) if resolved else None
            # An explicit instance name overrides the configured one, which is how a
            # batch driven at a specific VM stays a config change rather than an edit.
            if target is not None and detonator_instance:
                target = replace(target, instance=detonator_instance)
            client = RemoteDetonatorClient(target=target)
            if duration_s is None and resolved is not None:
                duration_s = resolved.sandbox_duration_s
        self.client = client
        self._duration_s = duration_s if duration_s is not None else 120

    @property
    def kind(self) -> TraceSourceKind:
        return TraceSourceKind.LIVE

    def available(self) -> bool:
        """True only when a detonator is configured and actually running.

        Deliberately *not* "start the VM if it is stopped". An idle nested-virt VM is
        the fastest way to consume a fixed research budget, so bringing the lab up is an
        operator action (`make lab-up`) and never a side effect of an accepted job.
        """
        try:
            state = self.client.instance_state()
        except Exception as exc:  # a health probe may not raise into the pipeline
            log.info("detonator_probe_failed", error=f"{type(exc).__name__}: {exc}"[:200])
            return False
        if state != "RUNNING":
            log.info("detonator_not_running", state=state)
            return False
        return True

    def run(self, apk_path: Path, plan: SandboxPlan, *, sha256: str | None = None) -> DynamicTrace:
        """Stage, detonate, collect, normalise. Any failure raises.

        `sha256` is accepted explicitly so a caller that already hashed the upload does
        not re-read a 300MB file, matching `ReplayTraceSource.run`.
        """
        if not self.available():
            raise TraceSourceUnavailableError(
                "the detonator is not running; start it with `make lab-up` before "
                "requesting a live detonation. No sample is ever executed locally."
            )
        digest = sha256 or _sha256_of(apk_path)

        try:
            self.client.stage(apk_path, digest)
            self.client.detonate(digest, morphs=plan.morphs, duration_s=self._duration_s)
            artifact = self.client.collect(digest, morphed=bool(plan.morphs))
        except TraceSourceUnavailableError:
            raise
        except Exception as exc:
            raise TraceSourceUnavailableError(
                f"detonation failed for {digest[:12]}: {type(exc).__name__}: {exc}"
            ) from exc

        if not artifact.metadata.containment_verified:
            # CLAUDE.md: a containment failure aborts. It never downgrades to a warning
            # on a trace that somebody might still read as a measurement.
            raise TraceSourceUnavailableError(
                f"containment was NOT verified for {digest[:12]}; the run is discarded"
            )
        if not artifact.safe_for_ingestion:
            raise TraceSourceUnavailableError(
                f"artifact for {digest[:12]} is not safe to ingest: "
                f"{', '.join(_unsafe_reasons(artifact))}"
            )

        trace = artifact_to_trace(
            artifact,
            source=TraceSourceKind.LIVE,
            morphs_applied=tuple(dict.fromkeys(m.kind.value for m in plan.morphs)),
        )
        log.info(
            "live_trace_collected",
            sha256=digest[:12],
            detonated=trace.detonated,
            api_events=len(trace.api_events),
            evasion=len(trace.evasion_observations),
        )
        return trace


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
    client: DetonatorClient | None = None,
) -> TraceSource:
    """Pick a source for `sandbox_mode`.

    `auto` prefers live and falls back to replay — the parachute, wired in from hour
    one so the H40 tripwire is a 20-minute switch rather than a 6-hour rewrite.

    `live` is strict on purpose: asking for live and silently getting replay is the
    one behaviour that would make the disclosure meaningless.
    """
    # `client` exists so a test can resolve a source without a health probe reaching
    # `gcloud`. CI never touches GCP (CLAUDE.md), and `auto` calls `available()` here.
    live = LiveSandboxSource(client=client, detonator_instance=detonator_instance)
    replay = ReplayTraceSource(fixture_dir)

    if mode == "live":
        return live
    if mode == "replay":
        return replay
    if live.available():
        return live
    log.info("trace_source_fallback", requested="auto", chosen="replay")
    return replay

"""`ObservationArtifact` -> `DynamicTrace`. The one conversion, used by both paths.

docs/PHASE_4_DYNAMIC_SANDBOX.md T4.6.

The detonator writes an `ObservationArtifact`; the rest of the system reads a
`DynamicTrace`. That conversion happens twice in the product's life — once offline when
a captured artifact is frozen into a replayable fixture, and once online when
`LiveSandboxSource` collects a fresh run off the sealed VM — and it must be the *same*
conversion, or a replay and a live run of the same detonation would disagree while both
looked authoritative. This module is that single function;
`scripts/observation_to_trace.py` is a CLI over it, and
`tests/contract/test_observation_ingest_parity.py` is what stops it becoming a copy.

Three rules are enforced here rather than remembered:

* **Aggregate before anything reaches the ledger or a prompt** (CLAUDE.md rule 11). One
  real sample called `Cipher.doFinal` 1,925 times in 103 seconds; a node per event would
  have blown both the ledger sanity band and the 12k-token prompt budget. Grouping keys
  on `(technique, mitre, hook)` and keeps an occurrence count, so the *rate* stays
  visible to a human without being able to move a score.
* **`detonated` is a written-down rule, not a judgement.** The sample installed, ran
  under instrumentation, and produced at least one observation. Anything less is
  `inconclusive` — never benign, because environment-aware stalling and a clean app are
  indistinguishable from the outside (CLAUDE.md honesty requirements).
* **A measurement is never `synthetic`.** `ObservationArtifact` pins `simulated` to
  `False` at the type level, so anything derived from one is a real execution. The flag
  exists to mark hand-authored fixtures, and this path can never produce one.
"""

from __future__ import annotations

from datetime import datetime

from drishti.contracts.dynamic_trace import (
    ApiEvent,
    DecryptedBlob,
    DexLoadEvent,
    DynamicTrace,
    EvasionObservation,
    NetworkFlow,
    ObservationArtifact,
    TraceSourceKind,
)
from drishti.logging import get_logger
from drishti.m3_dynamic import evasion
from drishti.m3_dynamic.normaliser import ObservationGroup, aggregate

log = get_logger(__name__)


def _offset_ms(stamp: str, start: str) -> int:
    """Milliseconds from the run's own start, so replay keeps the real relative timing."""
    try:
        delta = datetime.fromisoformat(stamp.replace("Z", "+00:00")) - datetime.fromisoformat(
            start.replace("Z", "+00:00")
        )
    except ValueError:
        return 0
    return max(0, int(delta.total_seconds() * 1000))


def _instance_id(artifact: ObservationArtifact) -> str | None:
    """The VM instance the run happened on, as recorded in the harness diagnostics."""
    return next(
        (d.split(":", 1)[1] for d in artifact.diagnostics if d.startswith("containment:")),
        None,
    )


def _evasion_observations(
    artifact: ObservationArtifact, groups_start: str
) -> tuple[EvasionObservation, ...]:
    """Lift the evasion detector's verdict onto the contract.

    Without this the frontier cannot fire on a real capture: `_frontier` reads
    `trace.evasion_observations` to decide what to synthesise, and a trace that dropped
    them on the floor during conversion would make every captured run look like a sample
    that never probed its environment.
    """
    normalised = aggregate([event.model_dump(mode="json") for event in artifact.observations])
    verdict = evasion.detect(normalised, installed_and_ran=bool(artifact.observations))
    if not verdict.stalled:
        return ()

    first_seen = {
        (event.technique, event.mitre, event.source_hook): event.occurred_at
        for event in reversed(artifact.observations)
    }
    lookup = {group.hook: group for group in normalised.groups}
    observations: list[EvasionObservation] = []
    for item in verdict.observations:
        group = lookup.get(item.probe)
        stamp = (
            first_seen.get((group.technique, group.mitre, group.hook), groups_start)
            if group
            else groups_start
        )
        observations.append(
            EvasionObservation(
                probe_kind=item.probe,
                # The detector names the morph that would answer the probe; the queried
                # target is what the sample actually asked about, when the hook recorded
                # it. `first_detail` is already redacted inside the guest.
                queried=(group.first_detail if group and group.first_detail else item.probe),
                result="MISS",
                t_ms=_offset_ms(stamp, groups_start),
                followed_by_stall=True,
                inferred_requirement=item.morph,
            )
        )
    return tuple(observations)


#: Dex paths that live inside the *installed* package rather than being written at
#: runtime. A split APK loading its own `classes.dex` is ordinary behaviour; calling it
#: drift would put a false positive straight into the `D` term.
_APK_INTERNAL_DEX_PREFIXES = ("/data/app/", "/system/", "/vendor/", "/product/")

#: Markers the hooks put in front of the value they captured. Parsing is deliberately
#: anchored on these: a detail that does not carry its marker yields no structured
#: record, rather than a record built out of a guess.
_DEX_MARKER = "path="
_URL_MARKER = "to="
_PLAINTEXT_MARKER = "plaintext="


def _after(detail: str, marker: str) -> str | None:
    """The value a hook wrote after its marker, or None if the marker is absent."""
    _, sep, rest = detail.partition(marker)
    value = rest.strip()
    return value if sep and value else None


def _structured(
    groups: tuple[ObservationGroup, ...], offsets: dict[str, int]
) -> tuple[tuple[DexLoadEvent, ...], tuple[NetworkFlow, ...], tuple[DecryptedBlob, ...]]:
    """Lift the evidence the hooks captured out of their flat `detail` strings.

    `ObservationEvent` carries one redacted string per observation, so the dropped-dex
    path, the C2 URL and the pre-encryption plaintext all arrive as prose. Leaving them
    there made the Sandbox tab report zero of each for samples that had genuinely
    produced them, and held `D` at zero for every run.

    Aggregation happens first and is preserved: 1,925 identical crypto operations are
    one record carrying `occurrences=1925`, never 1,925 records (CLAUDE.md rule 11).
    """
    dex: list[DexLoadEvent] = []
    flows: list[NetworkFlow] = []
    blobs: list[DecryptedBlob] = []

    for group in groups:
        detail = group.first_detail or ""
        t_ms = offsets.get(group.hook, 0)

        if group.hook.startswith("DexClassLoader") or group.mitre == "T1407":
            path = _after(detail, _DEX_MARKER)
            if path:
                dex.append(
                    DexLoadEvent(
                        t_ms=t_ms,
                        loader=group.hook,
                        path=path,
                        in_original_apk=path.startswith(_APK_INTERNAL_DEX_PREFIXES),
                    )
                )
            continue

        if group.hook.startswith("URL.open") or group.mitre in {"T1437", "T1095"}:
            url = _after(detail, _URL_MARKER)
            if url and "://" in url:
                flows.append(
                    NetworkFlow(
                        t_ms=t_ms,
                        method="GET",  # the hook records the connection, not the verb
                        url=url,
                        host=url.split("://", 1)[1].split("/", 1)[0],
                        # Neither flag may be inferred from an API hook: no proxy ran,
                        # and a real observation is not a synthesised C2 response.
                        tls_intercepted=False,
                        synthesised=False,
                    )
                )
            continue

        if group.hook.startswith("Cipher.") or group.mitre == "T1521":
            plaintext = _after(detail, _PLAINTEXT_MARKER)
            if plaintext:
                blobs.append(
                    DecryptedBlob(
                        t_ms=t_ms,
                        plaintext_preview=plaintext[:512],
                        length_bytes=len(plaintext),
                        contains_url="://" in plaintext,
                        contains_dex_magic=plaintext.startswith("dex\n"),
                        occurrences=group.occurrences,
                    )
                )

    return tuple(dex), tuple(flows), tuple(blobs)


def artifact_to_trace(
    artifact: ObservationArtifact,
    *,
    source: TraceSourceKind = TraceSourceKind.LIVE,
    morphs_applied: tuple[str, ...] = (),
) -> DynamicTrace:
    """Normalise one captured detonation into the trace contract.

    `source` defaults to LIVE because that is what produced the artifact. Only
    `ReplayTraceSource` may stamp REPLAY, and it does so on load rather than trusting
    whatever a fixture file happens to say.
    """
    events = [event.model_dump(mode="json") for event in artifact.observations]
    normalised = aggregate(events)

    start = artifact.observations[0].occurred_at if artifact.observations else artifact.started_at
    first_seen: dict[tuple[str, str, str], str] = {}
    for event in artifact.observations:
        first_seen.setdefault((event.technique, event.mitre, event.source_hook), event.occurred_at)

    api_events = tuple(
        ApiEvent(
            t_ms=_offset_ms(first_seen.get((g.technique, g.mitre, g.hook), start), start),
            api=g.hook,
            args=(g.first_detail,) if g.first_detail else (),
            count=g.occurrences,
        )
        for g in normalised.groups
    )

    offsets = {
        g.hook: _offset_ms(first_seen.get((g.technique, g.mitre, g.hook), start), start)
        for g in normalised.groups
    }
    dex_loads, network_flows, decrypted_blobs = _structured(normalised.groups, offsets)

    detonated = bool(artifact.observations) and artifact.outcome == "completed"

    return DynamicTrace(
        run_id=f"run_{artifact.sha256[:12]}",
        source=source,
        detonated=detonated,
        detonation_reason=(
            f"{len(artifact.observations)} instrumented observations across "
            f"{len(normalised.techniques)} distinct MITRE techniques"
            if detonated
            else "no observations were produced; treat as inconclusive, not benign"
        ),
        outcome=artifact.outcome,
        api_events=api_events,
        network_flows=network_flows,
        decrypted_blobs=decrypted_blobs,
        dex_loads=dex_loads,
        evasion_observations=_evasion_observations(artifact, start),
        morphs_applied=morphs_applied,
        emulator_image=artifact.metadata.emulator_image,
        vm_instance_id=_instance_id(artifact),
        harness_version=artifact.metadata.harness_version,
        containment_verified=artifact.metadata.containment_verified,
        captured_at=artifact.started_at,
        # Never derived from the artifact: an ObservationArtifact is a measurement by
        # construction (`simulated: Literal[False]`), so this path cannot mark one
        # hand-authored no matter what else went wrong in the run.
        synthetic=False,
        errors=tuple(normalised.errors),
        partial=bool(normalised.errors) or artifact.outcome != "completed",
    )

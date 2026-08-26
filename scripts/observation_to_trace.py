#!/usr/bin/env python3
"""Turn a captured `ObservationArtifact` into a replayable `TraceFixture`.

Step 2 of `data/fixtures/traces/README.md` §"Replacing a fixture with a real capture":
the detonator writes an `ObservationArtifact`, and the demo replays a `TraceFixture`.
This is the bridge, and it runs on a laptop because it only ever reads JSON.

Two honesty properties are structural here, not remembered:

* `provenance.kind` is **always** `captured`, and `source_sha256` /
  `captured_from_image` come out of the artifact's own metadata. `ReplayTraceSource`
  reads that kind to decide whether the resulting trace is `synthetic`, so a fixture
  written by this script declares itself a real measurement — and one that was typed
  by a human cannot, because this script refuses to write anything else.
* **`post_morph` is left empty.** No morphed pass has ever been run. An empty half
  makes `ReplayTraceSource` raise rather than serve pass 1's data as if it were pass
  2's, which is the difference between "we have not done that yet" and a fabricated
  before/after arc.

Usage:
    python scripts/observation_to_trace.py data/fixtures/observations/<sha>.json \
        --out data/fixtures/traces/
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from drishti.contracts.dynamic_trace import ObservationArtifact, TraceSourceKind
from drishti.m3_dynamic.normaliser import aggregate
from drishti.m3_dynamic.trace_source import FixtureProvenance, TraceFixture


def to_trace(artifact: ObservationArtifact) -> dict:
    """Build the `DynamicTrace` half of a fixture from one captured run.

    Events are aggregated first (CLAUDE.md rule 11): one real sample fired the same
    hook thousands of times, and a node per event would blow both the ledger sanity
    band and the prompt budget. `count` keeps the rate visible without letting it move
    a score.
    """
    events = [event.model_dump(mode="json") for event in artifact.observations]
    normalised = aggregate(events)

    # t_ms is measured from the run's own start, so a replayed trace keeps the real
    # relative timing rather than inventing one.
    start = artifact.observations[0].occurred_at if artifact.observations else artifact.started_at
    first_seen: dict[tuple[str, str, str], str] = {}
    for event in artifact.observations:
        first_seen.setdefault((event.technique, event.mitre, event.source_hook), event.occurred_at)

    def offset_ms(stamp: str) -> int:
        from datetime import datetime

        try:
            delta = datetime.fromisoformat(stamp.replace("Z", "+00:00")) - datetime.fromisoformat(
                start.replace("Z", "+00:00")
            )
        except ValueError:
            return 0
        return max(0, int(delta.total_seconds() * 1000))

    api_events = [
        {
            "t_ms": offset_ms(first_seen.get((group.technique, group.mitre, group.hook), start)),
            "api": group.hook,
            "args": (group.first_detail,) if group.first_detail else (),
            "count": group.occurrences,
        }
        for group in normalised.groups
    ]

    # `detonated` is a written-down rule, not a judgement: the sample installed, ran
    # under instrumentation, and produced at least one observation. No observations is
    # `inconclusive`, never benign — environment-aware stalling looks identical to a
    # clean app (CLAUDE.md honesty requirements).
    detonated = bool(artifact.observations) and artifact.outcome == "completed"

    return {
        "run_id": f"run_{artifact.sha256[:12]}",
        "source": TraceSourceKind.LIVE.value,  # overwritten to REPLAY on load
        "detonated": detonated,
        "detonation_reason": (
            f"{len(artifact.observations)} instrumented observations across "
            f"{len(normalised.techniques)} distinct MITRE techniques"
            if detonated
            else "no observations were produced; treat as inconclusive, not benign"
        ),
        "outcome": artifact.outcome,
        "api_events": api_events,
        "emulator_image": artifact.metadata.emulator_image,
        "vm_instance_id": next(
            (d.split(":", 1)[1] for d in artifact.diagnostics if d.startswith("containment:")),
            None,
        ),
        "harness_version": artifact.metadata.harness_version,
        "containment_verified": artifact.metadata.containment_verified,
        "captured_at": artifact.started_at,
        "synthetic": False,
        "errors": tuple(normalised.errors),
        "partial": bool(normalised.errors) or artifact.outcome != "completed",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=Path("data/fixtures/traces"))
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    written = Counter()
    for path in args.artifacts:
        artifact = ObservationArtifact.model_validate_json(path.read_text(encoding="utf-8"))
        if not artifact.observations:
            # A fixture with nothing in it would replay as a sample that did nothing.
            print(f"skip {artifact.sha256[:12]}: no observations ({artifact.outcome})")
            written["skipped"] += 1
            continue
        fixture = TraceFixture(
            sha256=artifact.sha256,
            provenance=FixtureProvenance(
                kind="captured",
                note=(
                    f"Live detonation of {artifact.package} on the sealed GCE detonator, "
                    f"containment manifest {artifact.metadata.containment_manifest_sha256}."
                ),
                authored_at=artifact.started_at,
                source_sha256=artifact.sha256,
                captured_from_image=artifact.metadata.emulator_image,
            ),
            pre_morph=to_trace(artifact),
            post_morph={},  # no morphed pass has been run; see the module docstring
        )
        target = args.out / f"{artifact.sha256}.json"
        target.write_text(
            json.dumps(fixture.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8"
        )
        print(f"wrote {target} ({len(artifact.observations)} observations)")
        written["written"] += 1
    print(f"written={written['written']} skipped={written['skipped']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

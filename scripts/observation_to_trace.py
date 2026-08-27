#!/usr/bin/env python3
"""Turn a captured `ObservationArtifact` into a replayable `TraceFixture`.

Step 2 of `data/fixtures/traces/README.md` §"Replacing a fixture with a real capture":
the detonator writes an `ObservationArtifact`, and the demo replays a `TraceFixture`.
This is the bridge, and it runs on a laptop because it only ever reads JSON.

**The conversion itself lives in `drishti.m3_dynamic.ingest`, not here.** This file is a
CLI over that function and must never grow a second copy of it: `LiveSandboxSource` runs
the same `artifact_to_trace` on a fresh collection, and if the two drifted then a replay
and a live run of the same detonation would disagree while both looked authoritative.
`tests/contract/test_observation_ingest_parity.py` enforces that.

Two honesty properties are structural here, not remembered:

* `provenance.kind` is **always** `captured`, and `source_sha256` /
  `captured_from_image` come out of the artifact's own metadata. `ReplayTraceSource`
  reads that kind to decide whether the resulting trace is `synthetic`, so a fixture
  written by this script declares itself a real measurement — and one that was typed
  by a human cannot, because this script refuses to write anything else.
* **`post_morph` is left empty** unless a morphed run was genuinely captured. An empty
  half makes `ReplayTraceSource` raise rather than serve pass 1's data as if it were
  pass 2's, which is the difference between "we have not done that yet" and a
  fabricated before/after arc.

Usage:
    python scripts/observation_to_trace.py data/fixtures/observations/<sha>.json \
        --out data/fixtures/traces/

    # backfill everything that produced observations
    python scripts/observation_to_trace.py data/fixtures/observations/*.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from drishti.contracts.dynamic_trace import ObservationArtifact
from drishti.m3_dynamic.ingest import artifact_to_trace
from drishti.m3_dynamic.trace_source import FixtureProvenance, TraceFixture


def build_fixture(artifact: ObservationArtifact) -> TraceFixture:
    """Freeze one captured run into the replay contract, provenance included."""
    return TraceFixture(
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
        pre_morph=artifact_to_trace(artifact).model_dump(mode="json"),
        post_morph={},  # no morphed pass has been run; see the module docstring
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=Path("data/fixtures/traces"))
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="only print the summary line (for backfilling the whole corpus)",
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    written: Counter[str] = Counter()
    for path in args.artifacts:
        artifact = ObservationArtifact.model_validate_json(path.read_text(encoding="utf-8"))
        if not artifact.observations:
            # A fixture with nothing in it would replay as a sample that did nothing.
            if not args.quiet:
                print(f"skip {artifact.sha256[:12]}: no observations ({artifact.outcome})")
            written["skipped"] += 1
            continue
        fixture = build_fixture(artifact)
        # The same guard as above, applied AFTER conversion. An artifact whose only
        # observations were dropped as untrustworthy (see `_overlay_claim_is_trustworthy`)
        # converts to a trace with nothing in it, and a fixture with nothing in it
        # replays as a sample that did nothing — which is a different statement from
        # "we could not observe it", and the more dangerous one.
        if not (fixture.pre_morph.get("api_events") or []):
            if not args.quiet:
                print(f"skip {artifact.sha256[:12]}: no trustworthy observations survived")
            written["skipped"] += 1
            continue
        target = args.out / f"{artifact.sha256}.json"
        target.write_text(
            json.dumps(fixture.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8"
        )
        if not args.quiet:
            print(f"wrote {target} ({len(artifact.observations)} observations)")
        written["written"] += 1
    print(f"written={written['written']} skipped={written['skipped']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

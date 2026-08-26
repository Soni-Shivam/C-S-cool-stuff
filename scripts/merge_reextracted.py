#!/usr/bin/env python3
"""Merge the re-extracted 1.2.0 rows into the local corpus, then PROVE the leak is gone.

Background. The certificate parser was fixed mid-batch, so the corpus ended up written
by two extractor versions with very different class balance. Freezing a vocabulary over
that mixture puts all four certificate features in the matrix and zero-fills whichever
half is missing — which encodes *when a row was extracted*, a direct proxy for the label.
`dataset.epoch_divergent_features` caught it and the columns were dropped as a guard.

The real fix was re-extracting the stale rows from the APKs retained in GCS. This script
lands that result and then checks the guard again, because a fix nobody verified is a
belief. It exits non-zero if divergence remains, so it cannot quietly report success.

Merge is a UNION keyed on sha256, newest wins — never an overwrite. The shard files get
rewritten by the requeue logic, so a naive replace can silently shrink the corpus.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drishti.m5_ml.dataset import epoch_divergent_features, load_jsonl

CORPUS = Path("data/corpus/features.jsonl")


def _read(path: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    if not path.exists():
        return rows
    with path.open() as handle:
        for line in handle:
            try:
                record = json.loads(line)
                rows[record["sha256"].lower()] = record
            except (json.JSONDecodeError, KeyError, AttributeError):
                continue
    return rows


def main() -> int:
    incoming_path = Path(sys.argv[1] if len(sys.argv) > 1 else "/tmp/reextracted.jsonl")

    existing = _read(CORPUS)
    incoming = _read(incoming_path)
    print(f"local corpus : {len(existing)} unique sha256")
    print(f"re-extracted : {len(incoming)} unique sha256")

    replaced = sum(1 for sha in incoming if sha in existing)
    merged = {**existing, **incoming}  # incoming wins: it is the newer extractor
    print(f"replaced     : {replaced}")
    print(f"new rows     : {len(incoming) - replaced}")
    print(f"merged total : {len(merged)}")

    if len(merged) < len(existing):
        print("REFUSING: the merge would shrink the corpus", file=sys.stderr)
        return 1

    CORPUS.parent.mkdir(parents=True, exist_ok=True)
    with CORPUS.open("w") as handle:
        for record in merged.values():
            handle.write(json.dumps(record) + "\n")
    print(f"wrote {CORPUS}")

    # ── the part that matters: confirm, do not assume ────────────────────────
    corpus = load_jsonl(CORPUS)
    print(
        f"\nusable samples: {len(corpus)}  (failed {corpus.skipped_failed}, "
        f"empty {corpus.skipped_empty})"
    )
    report = epoch_divergent_features(corpus.samples)
    print("\n── epoch divergence check ──")
    for version, stats in sorted(report.get("epochs", {}).items()):
        print(
            f"  {version:<8} n={stats['n']:<6} malware={stats['malware']:<5} "
            f"rate={stats['malware_rate']}"
        )
    divergent = report.get("divergent") or []
    print(f"  divergent features: {sorted(divergent) if divergent else 'NONE'}")

    if divergent:
        print(
            "\nFAILED: divergence remains — the certificate features must stay excluded.",
            file=sys.stderr,
        )
        return 1
    print("\nOK: single epoch. The four certificate features can be re-admitted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

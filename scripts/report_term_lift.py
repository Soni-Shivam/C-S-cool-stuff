"""Per-term lift and rank-AUC over a labelled run of the composite scorer.

`S = 0.25R + 0.50F_AI + 0.15G + 0.10D` assigns each term a weight taken from the
ideation deck. This reports what each term is actually worth on held-out data:
its mean on malware, its mean on benign, and the rank-AUC between them. A term at
AUC 0.5 is a coin flip; a term below 0.5 is anti-correlated and is actively making
the verdict worse.

The project has been here once already — `m6_score/engine.py` records an anomaly
detector whose lift was negative and which was promoting benign apps to a blocking
band. The only reason that was caught is that someone measured it. This script is
so the same question can be asked of every term, cheaply, whenever the model or
the prompts change.

    python scripts/report_term_lift.py /tmp/lift_results.csv
"""

from __future__ import annotations

import contextlib
import csv
import itertools
import sys
from collections import Counter

TERMS = ["S", "p_cal", "B", "G", "D", "R", "n_behaviours", "C", "gamma"]


def _floats(rows: list[dict], key: str) -> list[float]:
    out = []
    for r in rows:
        v = r.get(key)
        if v in (None, "", "None"):
            continue
        with contextlib.suppress(ValueError):
            out.append(float(v))
    return out


def rank_auc(pos: list[float], neg: list[float]) -> float | None:
    """Mann-Whitney U as AUC. Ties count a half, which keeps a constant term at 0.5."""
    if not pos or not neg:
        return None
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p, n in itertools.product(pos, neg))
    return wins / (len(pos) * len(neg))


def main(path: str) -> None:
    with open(path, newline="") as fh:
        rows = [r for r in csv.DictReader(fh) if r.get("ok") == "1"]
    mal = [r for r in rows if r["label"] == "1"]
    ben = [r for r in rows if r["label"] == "0"]
    print(f"usable rows: {len(rows)}  (malware={len(mal)} benign={len(ben)})")
    if len(ben) < 20 or len(mal) < 20:
        print("WARNING: fewer than 20 per class — treat every number below as indicative only.")
    print()

    print(f"{'term':<14}{'mal mean':>10}{'ben mean':>10}{'lift':>9}{'AUC':>8}   n(mal/ben)")
    print("-" * 66)
    for term in TERMS:
        p, n = _floats(mal, term), _floats(ben, term)
        if not p or not n:
            print(f"{term:<14}{'—':>10}{'—':>10}{'—':>9}{'—':>8}   {len(p)}/{len(n)}")
            continue
        pm, nm = sum(p) / len(p), sum(n) / len(n)
        auc = rank_auc(p, n)
        flag = ""
        if auc is not None and term not in {"gamma", "C"}:
            flag = (
                "  <-- coin flip"
                if 0.45 <= auc <= 0.55
                else ("  <-- ANTI-CORRELATED" if auc < 0.45 else "")
            )
        print(
            f"{term:<14}{pm:>10.3f}{nm:>10.3f}{pm - nm:>+9.3f}{auc:>8.3f}   {len(p)}/{len(n)}{flag}"
        )

    print("\nband distribution")
    for label, rs in (("malware", mal), ("benign", ben)):
        print(f"  {label:<8}", dict(Counter(r["band"] for r in rs)))

    print("\nsignal availability (a term that is missing cannot discriminate)")
    for label, rs in (("malware", mal), ("benign", ben)):
        if not rs:
            continue
        gp = sum(1 for r in rs if r.get("genai_partial") == "1")
        mp = sum(1 for r in rs if r.get("ml_partial") == "1")
        bmiss = sum(1 for r in rs if r.get("B") in ("", "None", None))
        print(
            f"  {label:<8} genai_partial={gp}/{len(rs)}  ml_partial={mp}/{len(rs)}  B_missing={bmiss}/{len(rs)}"
        )


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "/tmp/lift_results.csv")

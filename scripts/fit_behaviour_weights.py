"""Derive BEHAVIOUR_WEIGHTS / CONTEXT_WEIGHTS from measured corpus assertions.

This is the provenance for the tables in `drishti/m4_genai/safety.py` — the CLAUDE.md
rule that a number in the product must trace to a measurement, applied to B's weights.

Inputs
------
* a jobs dump: JSON list with per-job `sha256`, `behaviours` (the model's 16 booleans),
  and the static `lookalike`/`cert` fields — as served by the analysis VM's
  `/api/jobs/{id}/genai` and `/api/jobs/{id}/static`
* a label CSV with `sha256,label` (1 = malware), e.g. the VM's `/tmp/lift_results.csv`

Method
------
Each behaviour's weight is its smoothed log-likelihood ratio
`log(P(asserted|malware) / P(asserted|benign))`, add-0.5 smoothed, capped at
`WEIGHT_CAP`, and clamped at 0.0 — a model-asserted boolean must never carry negative
weight (injection channel + monotonicity; see safety.py). Deterministic context terms
get the same treatment but keep their sign, capped at `CONTEXT_CAP`.

Held-out quality is estimated with repeated stratified 5-fold CV, refitting the
weights inside every fold, so the printed AUC is never fit on what it reports.

Usage
-----
    python scripts/fit_behaviour_weights.py jobs_dump.json labels.csv
"""

from __future__ import annotations

import csv
import json
import math
import random
import sys

WEIGHT_CAP = 2.0
CONTEXT_CAP = 1.5
B_BASE = -2.0
CERT_STABLE_DAYS = 730  # a priori (Android ties upgrades to the signing key), not fitted


def _llr(fired_a: int, n_a: int, fired_b: int, n_b: int, cap: float) -> float:
    w = math.log(((fired_a + 0.5) / (n_a + 1)) / ((fired_b + 0.5) / (n_b + 1)))
    return max(-cap, min(cap, w))


def _context(row: dict) -> dict[str, bool]:
    cert = row.get("cert") or {}
    la = row.get("lookalike") or {}
    age = cert.get("age_days")
    return {
        "cert_signer_stable_years": age is not None
        and age >= CERT_STABLE_DAYS
        and not cert.get("debug_cert"),
        "debug_certificate": bool(cert.get("debug_cert")),
        "targets_installed_financial_apps": bool(la.get("targeted_financial_packages")),
    }


def fit(samples: list[dict]) -> tuple[dict[str, float], dict[str, float]]:
    keys = sorted({k for s in samples for k in s["b"]})
    n_m = sum(s["y"] for s in samples)
    n_b = len(samples) - n_m
    weights = {}
    for k in keys:
        c_m = sum(1 for s in samples if s["y"] and s["b"].get(k))
        c_b = sum(1 for s in samples if not s["y"] and s["b"].get(k))
        weights[k] = max(0.0, _llr(c_m, n_m, c_b, n_b, WEIGHT_CAP))
    ctx = {}
    for k in ("cert_signer_stable_years", "debug_certificate", "targets_installed_financial_apps"):
        c_m = sum(1 for s in samples if s["y"] and s["ctx"].get(k))
        c_b = sum(1 for s in samples if not s["y"] and s["ctx"].get(k))
        ctx[k] = _llr(c_m, n_m, c_b, n_b, CONTEXT_CAP)
    return weights, ctx


def b_value(s: dict, weights: dict[str, float], ctx_w: dict[str, float]) -> float:
    pos = [w for k, w in weights.items() if s["b"].get(k) and w > 0]
    if not pos:
        return 0.0
    z = B_BASE + sum(pos) + sum(w for k, w in ctx_w.items() if s["ctx"].get(k))
    return 1.0 / (1.0 + math.exp(-z))


def auc(pairs: list[tuple[float, int]]) -> float:
    pos = [v for v, y in pairs if y]
    neg = [v for v, y in pairs if not y]
    if not pos or not neg:
        return float("nan")
    wins = sum(1.0 if p > n else 0.5 if p == n else 0.0 for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def main() -> None:
    dump_path, label_path = sys.argv[1], sys.argv[2]
    with open(label_path) as handle:
        labels = {r["sha256"]: int(r["label"]) for r in csv.DictReader(handle)}
    with open(dump_path) as handle:
        raw = json.load(handle)
    samples = [
        {
            "y": labels[d["sha256"]],
            "b": {k: v is True for k, v in (d.get("behaviours") or {}).items()},
            "ctx": _context(d),
        }
        for d in raw
        if d.get("behaviours") and d.get("sha256") in labels
    ]
    print(f"n={len(samples)} malware={sum(s['y'] for s in samples)}")

    # held-out estimate: repeated stratified 5-fold CV, weights refitted per fold
    aucs = []
    for seed in range(10):
        rng = random.Random(seed)
        mal = [s for s in samples if s["y"]]
        ben = [s for s in samples if not s["y"]]
        rng.shuffle(mal)
        rng.shuffle(ben)
        folds: list[list[dict]] = [[] for _ in range(5)]
        for i, s in enumerate(mal + ben):
            folds[i % 5].append(s)
        preds = []
        for i in range(5):
            train = [s for j, f in enumerate(folds) if j != i for s in f]
            w, c = fit(train)
            preds += [(b_value(s, w, c), s["y"]) for s in folds[i]]
        aucs.append(auc(preds))
    print(
        f"held-out B AUC (10x stratified 5-fold CV): {sum(aucs) / len(aucs):.3f} "
        f"(min {min(aucs):.3f} max {max(aucs):.3f})"
    )

    # shipped table: fitted on ALL rows — say so wherever these numbers are shown
    weights, ctx = fit(samples)
    print("\nBEHAVIOUR_WEIGHTS (fit on all rows; report ONLY the CV numbers above):")
    for k, w in sorted(weights.items(), key=lambda kv: -kv[1]):
        print(f'    "{k}": {w:.2f},')
    print("measured context LLRs:")
    for k, w in ctx.items():
        print(f'    "{k}": {w:.2f},')


if __name__ == "__main__":
    main()

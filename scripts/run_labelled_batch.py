#!/usr/bin/env python3
"""Run a labelled set of real corpus APKs through the live API and score the result.

This is the end-to-end evidence run: real samples, the real pipeline, the same frozen
routes the dashboard reads. It exists because "the pipeline works" is a claim, and a
claim about a detector needs a confusion matrix and worked examples behind it.

What it reports, per sample: the verdict and band, every score term with its
contribution, the ML probability, `B` **and its signed evidence** (so a reader can see
which direction the behavioural layer pushed, which `B` alone cannot express), and the
grounded claims with the ledger nodes they cite.

What it reports overall: accuracy against the labels at the MEDIUM boundary, and the
ranking AUC of the composite versus the ML term alone — because the composite being
*worse* than the classifier it contains is the specific regression this project already
had once, and the only way to notice it is to measure it every time.

Samples are pulled to scratch one at a time and deleted immediately after submission, so
no corpus APK accumulates on disk. Nothing here executes a sample.

Usage:
    python scripts/run_labelled_batch.py sha_labels.csv --out /tmp/batch.txt
    # sha_labels.csv: lines of "<sha256>,<label>"  (1 = malware, 0 = benign)
"""

from __future__ import annotations

import argparse
import json
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

API = "http://127.0.0.1:8080"
BUCKET = "gs://cybershield-505518-corpus/apks"
SCRATCH = Path("/tmp/drishti-batch")
POLL_TIMEOUT_S = 900


def get(path: str) -> Any:
    try:
        with urllib.request.urlopen(f"{API}{path}", timeout=60) as r:
            return json.load(r)
    except Exception as exc:
        return {"_error": f"{type(exc).__name__}: {exc}"}


def fetch(sha: str) -> Path | None:
    """Pull one APK to ephemeral scratch. Sharded by the first two hex characters."""
    SCRATCH.mkdir(parents=True, exist_ok=True)
    local = SCRATCH / f"{sha}.apk"
    done = subprocess.run(
        ["gsutil", "-q", "cp", f"{BUCKET}/{sha[:2]}/{sha}.apk", str(local)],
        capture_output=True,
        text=True,
    )
    return local if done.returncode == 0 and local.is_file() else None


def submit(apk: Path) -> str | None:
    out = subprocess.run(
        ["curl", "-s", "-m", "900", "-X", "POST", f"{API}/api/jobs", "-F", f"apk=@{apk}"],
        capture_output=True,
        text=True,
    ).stdout
    try:
        return json.loads(out)["job_id"]
    except Exception:
        return None


def wait(job_id: str) -> str:
    deadline = time.time() + POLL_TIMEOUT_S
    while time.time() < deadline:
        stage = get(f"/api/jobs/{job_id}").get("stage")
        if stage in {"done", "failed", "error"}:
            return str(stage)
        time.sleep(4)
    return "timeout"


def auc(pos: list[float], neg: list[float]) -> float:
    """Rank AUC, ties at half credit. No sklearn dependency for a report script."""
    if not pos or not neg:
        return float("nan")
    wins = sum((p > n) + 0.5 * (p == n) for p in pos for n in neg)
    return wins / (len(pos) * len(neg))


def render(sha: str, label: int, job_id: str, stage: str) -> tuple[str, dict[str, Any]]:
    verdict = get(f"/api/jobs/{job_id}/verdict")
    scored = get(f"/api/jobs/{job_id}/score")
    ml = get(f"/api/jobs/{job_id}/ml")
    genai = get(f"/api/jobs/{job_id}/genai")
    static = get(f"/api/jobs/{job_id}/static")
    dynamic = get(f"/api/jobs/{job_id}/dynamic")

    truth = "MALWARE" if label == 1 else "BENIGN "
    lines = [
        "=" * 78,
        f"{truth}  {sha[:16]}  job={job_id}  stage={stage}",
        "=" * 78,
        f"  package        {static.get('package')}",
        f"  VERDICT        {verdict.get('threat_score')} {verdict.get('severity_band')}"
        f"   action={verdict.get('recommended_action')}"
        f"   confidence={verdict.get('confidence')}",
        f"  provenance     {verdict.get('provenance')}",
    ]

    terms = []
    for f in scored.get("factors", []) or []:
        terms.append(f"{f.get('symbol')}={f.get('raw', 0):.3f}*{f.get('weight')}")
    lines.append(f"  score terms    {'  '.join(terms)}")

    evidence = genai.get("behavioural_evidence")
    # The sign is the finding: negative means the behavioural layer argued the app's use
    # of a risky capability is legitimate, and under log-odds fusion that pulls S down.
    direction = (
        "n/a"
        if evidence is None
        else ("EXONERATES" if evidence < 0 else "AGGRAVATES" if evidence > 0 else "neutral")
    )
    lines += [
        f"  ml             p_raw={ml.get('p_malicious_raw')} p_cal={ml.get('p_calibrated')}"
        f" anomaly={ml.get('anomaly_score')}",
        f"  behavioural    B={genai.get('behavioural_risk_B')}"
        f"  evidence={evidence}  -> {direction}",
        f"  behaviours     {', '.join(k for k, v in (genai.get('behaviours') or {}).items() if v) or 'none'}",
        f"  dynamic        source={dynamic.get('source')} detonated={dynamic.get('detonated')}"
        f" dex={len(dynamic.get('dex_loads') or [])} net={len(dynamic.get('network_flows') or [])}",
    ]

    claims = genai.get("claims") or []
    passed = [c for c in claims if str(c.get("verifier_status", "")).upper() == "PASS"]
    lines.append(f"  GROUNDED CLAIMS ({len(passed)} verified / {len(claims)} made)")
    for c in claims:
        status = str(c.get("verifier_status", "?")).upper()
        lines.append(f"     [{status}] {c.get('text', '')[:150]}")
        lines.append(f"        cites: {', '.join(c.get('evidence_refs') or []) or 'NOTHING'}")
    if summary := genai.get("summary"):
        lines += ["  SUMMARY", f"     {summary[:400]}"]

    row = {
        "sha": sha,
        "label": label,
        "S": scored.get("S"),
        "band": scored.get("band"),
        "p_cal": ml.get("p_calibrated"),
        "B": genai.get("behavioural_risk_B"),
        "evidence": evidence,
        "claims_passed": len(passed),
        "claims_total": len(claims),
    }
    return "\n".join(lines), row


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("labels", type=Path, help="csv of <sha256>,<label>")
    ap.add_argument("--out", type=Path, default=Path("/tmp/batch_report.txt"))
    ap.add_argument("--api", default=API)
    args = ap.parse_args()

    global API
    API = args.api

    targets: list[tuple[str, int]] = []
    for line in args.labels.read_text().splitlines():
        if line.strip() and "," in line:
            sha, label = line.split(",")[:2]
            targets.append((sha.strip(), int(label)))

    blocks: list[str] = []
    rows: list[dict[str, Any]] = []
    for index, (sha, label) in enumerate(targets, 1):
        print(f"[{index}/{len(targets)}] {sha[:12]} label={label}", flush=True)
        apk = fetch(sha)
        if apk is None:
            print("    not in bucket, skipped", flush=True)
            continue
        job_id = submit(apk)
        apk.unlink(missing_ok=True)  # scratch never accumulates corpus APKs
        if job_id is None:
            print("    submit failed", flush=True)
            continue
        stage = wait(job_id)
        block, row = render(sha, label, job_id, stage)
        blocks.append(block)
        rows.append(row)
        print(
            f"    S={row['S']} {row['band']} p_cal={row['p_cal']} evidence={row['evidence']}",
            flush=True,
        )

    ok = [r for r in rows if isinstance(r.get("S"), int)]
    mal_s = [float(r["S"]) for r in ok if r["label"] == 1]
    ben_s = [float(r["S"]) for r in ok if r["label"] == 0]
    mal_p = [float(r["p_cal"] or 0) for r in ok if r["label"] == 1]
    ben_p = [float(r["p_cal"] or 0) for r in ok if r["label"] == 0]

    tp = sum(1 for r in ok if r["label"] == 1 and float(r["S"]) >= 40)
    fn = sum(1 for r in ok if r["label"] == 1 and float(r["S"]) < 40)
    fp = sum(1 for r in ok if r["label"] == 0 and float(r["S"]) >= 40)
    tn = sum(1 for r in ok if r["label"] == 0 and float(r["S"]) < 40)

    summary = [
        "",
        "=" * 78,
        "BATCH SUMMARY",
        "=" * 78,
        f"  scored              {len(ok)} / {len(targets)}",
        f"  malware mean S      {sum(mal_s) / len(mal_s):.1f}"
        if mal_s
        else "  malware mean S      -",
        f"  benign  mean S      {sum(ben_s) / len(ben_s):.1f}"
        if ben_s
        else "  benign  mean S      -",
        "",
        "  Confusion at S >= 40 (the MEDIUM boundary, i.e. 'a human looks at it')",
        f"     TP {tp:3}   FN {fn:3}      recall    {tp / (tp + fn):.2f}"
        if (tp + fn)
        else "     TP   0   FN   0",
        f"     FP {fp:3}   TN {tn:3}      precision {tp / (tp + fp):.2f}"
        if (tp + fp)
        else f"     FP {fp:3}   TN {tn:3}",
        "",
        "  Ranking AUC — the composite must not score worse than the term it contains",
        f"     composite S   {auc(mal_s, ben_s):.3f}",
        f"     p_cal alone   {auc(mal_p, ben_p):.3f}",
        "",
        f"  claims verified     {sum(r['claims_passed'] for r in ok)} / {sum(r['claims_total'] for r in ok)}",
    ]

    args.out.write_text("\n".join([*blocks, *summary]) + "\n", encoding="utf-8")
    print("\n".join(summary))
    print(f"\nwritten to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

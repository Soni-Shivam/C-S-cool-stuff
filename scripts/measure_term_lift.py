"""Run the composite pipeline over a labelled set and record every score term.

Purpose: measure each term's LIFT (malware mean vs benign mean, and AUC) so the
weights in S = 0.25R + 0.50F_AI + 0.15G + 0.10D can be argued from data instead of
from the ideation deck. Nothing here changes the product; it only observes it.

Samples are fetched to ephemeral scratch one at a time and deleted immediately after
the job is submitted, so no corpus APK accumulates on disk.
"""

from __future__ import annotations

import csv
import json
import subprocess
import time
import urllib.request
from pathlib import Path

API = "http://127.0.0.1:8080"
BUCKET = "gs://cybershield-505518-corpus/apks"
SCRATCH = Path("/tmp/drishti-lift")
OUT = Path("/tmp/lift_results.csv")
POLL_TIMEOUT_S = 600


def get(path: str) -> dict:
    with urllib.request.urlopen(f"{API}{path}", timeout=30) as r:
        return json.load(r)


def submit(apk: Path) -> str | None:
    """curl handles multipart more reliably here than hand-rolling it."""
    out = subprocess.run(
        ["curl", "-s", "-m", "600", "-X", "POST", f"{API}/api/jobs", "-F", f"apk=@{apk}"],
        capture_output=True,
        text=True,
    ).stdout
    try:
        return json.loads(out)["job_id"]
    except Exception:
        print(f"    submit failed: {out[:200]}")
        return None


def wait(job_id: str) -> bool:
    deadline = time.time() + POLL_TIMEOUT_S
    while time.time() < deadline:
        try:
            if get(f"/api/jobs/{job_id}").get("stage") in {"done", "failed", "error"}:
                return True
        except Exception:
            pass
        time.sleep(3)
    return False


def factor(score: dict, symbol: str) -> dict:
    for f in score.get("factors", []):
        if f.get("symbol") == symbol:
            return f
    return {}


def main() -> None:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    with open("/tmp/lift_set.csv", newline="") as fh:
        samples = list(csv.DictReader(fh))
    fields = [
        "sha256",
        "label",
        "S",
        "band",
        "C",
        "gamma",
        "p_cal",
        "B",
        "G",
        "D",
        "R",
        "n_behaviours",
        "ml_partial",
        "genai_partial",
        "ok",
    ]
    with OUT.open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()

        for i, s in enumerate(samples, 1):
            sha, label = s["sha256"], s["label"]
            apk = SCRATCH / f"{sha[:12]}.apk"
            print(f"[{i}/{len(samples)}] {sha[:12]} label={label}", flush=True)

            dl = subprocess.run(
                ["gcloud", "storage", "cp", f"{BUCKET}/{sha[:2]}/{sha}.apk", str(apk)],
                capture_output=True,
                text=True,
            )
            if dl.returncode != 0 or not apk.exists():
                print("    download failed", flush=True)
                w.writerow({"sha256": sha, "label": label, "ok": 0})
                fh.flush()
                continue

            job = submit(apk)
            apk.unlink(missing_ok=True)  # never let samples accumulate
            if not job or not wait(job):
                w.writerow({"sha256": sha, "label": label, "ok": 0})
                fh.flush()
                continue

            try:
                score = get(f"/api/jobs/{job}/score")
                genai = get(f"/api/jobs/{job}/genai")
                ml = get(f"/api/jobs/{job}/ml")
                fai = factor(score, "F_AI")
                row = {
                    "sha256": sha,
                    "label": label,
                    "S": score.get("S"),
                    "band": score.get("band"),
                    "C": score.get("C"),
                    "gamma": score.get("gamma"),
                    "p_cal": fai.get("inputs", {}).get("p_calibrated"),
                    "B": fai.get("inputs", {}).get("behavioural_risk_B"),
                    "G": factor(score, "G").get("raw"),
                    "D": factor(score, "D").get("raw"),
                    "R": factor(score, "R").get("raw"),
                    "n_behaviours": sum(
                        1 for v in (genai.get("behaviours") or {}).values() if v is True
                    ),
                    "ml_partial": int(bool(ml.get("partial"))),
                    "genai_partial": int(bool(genai.get("partial"))),
                    "ok": 1,
                }
                w.writerow(row)
                fh.flush()
                print(
                    f"    S={row['S']} {row['band']} p_cal={row['p_cal']} B={row['B']} "
                    f"G={row['G']} nbeh={row['n_behaviours']}",
                    flush=True,
                )
            except Exception as exc:
                print(f"    collect failed: {exc}", flush=True)
                w.writerow({"sha256": sha, "label": label, "ok": 0})
                fh.flush()

    print("DONE ->", OUT, flush=True)


if __name__ == "__main__":
    main()

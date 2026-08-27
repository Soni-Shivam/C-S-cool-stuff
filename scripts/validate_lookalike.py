"""Measure the benign-lookalike discriminator on real corpus APKs. **VM only.**

This replaces the throwaway `/tmp/validate_lookalike.py` that produced the first
(negative) reading over 18 samples. Three things it does that the throwaway did not:

* **Counts every signal separately for each true class.** A signal that fires on 100%
  of malware *and* 100% of benign is worse than useless, and a single pooled counter
  cannot show that. This is how `freshly_minted_certificate` hid.
* **Reports rank-AUC of `trojan_score`**, which is threshold-free. Means alone can look
  identical while the ordering is fine, and vice versa.
* **Names every benign sample that scored `TROJAN_SHAPE`.** That is the false positive
  that kills the product, and it must appear as a list of hashes, not as a rate.

Nothing here is executed: androguard parses the DEX as data. Samples are pulled from
the private corpus bucket into VM scratch and deleted immediately after analysis.

Threads are capped low on purpose — `AnalyzeAPK` holds the whole DEX and its call graph
per thread, so concurrent analyses are what fill memory, and the extraction shards own
most of this box already (`docs/CARRIED_FINDINGS.md` F1).
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
import tempfile
import threading
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path.home() / "CyberShield"))

# androguard logs through loguru at DEBUG — thousands of lines per APK, which buries
# the one line per sample that is the whole point of this run.
try:
    from loguru import logger as _loguru

    _loguru.remove()
except Exception:
    pass

from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import analyse
from drishti.m2_static.lookalike import TROJAN_SHAPE_THRESHOLD
from drishti.util import new_id

BUCKET = "gs://cybershield-505518-corpus/apks"
_local = threading.local()
_print_lock = threading.Lock()


def require_vm(override: bool) -> None:
    if not override:
        sys.exit("refusing to run: pass --i-am-the-extractor-vm. Samples never leave GCP.")
    product = Path("/sys/class/dmi/id/product_name")
    if not (product.exists() and "Google" in product.read_text()):
        sys.exit("refusing to run: this host does not look like a GCE instance.")


def labelled_hashes() -> dict[str, int]:
    """sha256 -> label, from whichever sample lists exist on this VM.

    The family-sourced candidates count as label 1: they come from MalwareBazaar, which
    holds malware only, and they are the population a *banking-trojan* discriminator has
    to be measured on. Measuring it on a decade of AndroZoo adware answers a different
    question and flatters nobody.
    """
    out: dict[str, int] = {}
    for name in ("samples.csv", "mb_samples.csv", "mb_recent.csv", "data/corpus/samples.csv"):
        path = Path.home() / "CyberShield" / name
        if not path.exists():
            continue
        with path.open(newline="") as fh:
            for row in csv.DictReader(fh):
                out.setdefault(row["sha256"].lower(), int(row["label"]))
    for sha in families():
        out.setdefault(sha, 1)
    return out


def families() -> dict[str, str]:
    """sha256 -> MalwareBazaar family, if a sourcing run left a candidates CSV behind."""
    out: dict[str, str] = {}
    for path in (
        Path("/tmp/deto_candidates.csv"),
        Path.home() / "CyberShield" / "deto_candidates.csv",
    ):
        if not path.exists():
            continue
        with path.open(newline="") as fh:
            for row in csv.DictReader(fh):
                out.setdefault(row["sha256"].lower(), row.get("family", ""))
    return out


def retained() -> list[str]:
    """Hashes of APKs actually present in the corpus bucket."""
    proc = subprocess.run(
        ["gcloud", "storage", "ls", "-r", f"{BUCKET}/**.apk"],
        capture_output=True,
        text=True,
        timeout=900,
    )
    return [
        line.strip().rsplit("/", 1)[-1].removesuffix(".apk")
        for line in proc.stdout.splitlines()
        if line.strip().endswith(".apk")
    ]


def store_for(root: Path) -> LedgerStore:
    """One ledger per worker thread — sqlite connections are not shareable."""
    existing = getattr(_local, "store", None)
    if existing is None:
        ident = threading.get_ident()
        existing = LedgerStore(root / f"v{ident}.db", root / f"v{ident}.key")
        _local.store = existing
    return existing


def analyse_one(sha: str, label: int, root: Path) -> dict | None:
    """Pull, analyse, delete. Returns one measurement row or None if unusable."""
    local = root / f"{sha}.apk"
    pull = subprocess.run(
        ["gcloud", "storage", "cp", "--quiet", f"{BUCKET}/{sha[:2]}/{sha}.apk", str(local)],
        capture_output=True,
        text=True,
        timeout=900,
    )
    if pull.returncode != 0 or not local.exists():
        return None
    try:
        store = store_for(root)
        store.open(new_id("job"))
        report = analyse(local, store)
    except Exception as exc:
        with _print_lock:
            print(f"  skip {sha[:12]} ({type(exc).__name__}: {exc})", file=sys.stderr)
        return None
    finally:
        local.unlink(missing_ok=True)

    assessment = report.lookalike
    if assessment is None:
        return None
    cert = report.certificate
    row = {
        "sha256": sha,
        "label": label,
        "verdict": assessment.verdict.value,
        "trojan_score": assessment.trojan_score,
        "dual_use_perms": len(assessment.shared_permissions),
        "publisher_trusted": assessment.publisher_trusted,
        "targets": list(assessment.targeted_financial_packages[:8]),
        "signals": {s.id: bool(s.present) for s in assessment.signals},
        "cert_not_before": getattr(cert, "not_before", "unknown"),
        "cert_age_days": getattr(cert, "age_days", -1),
        "package_strings": len(report.package_strings),
        "decompiled_methods": len(report.decompiled_methods),
        "errors": len(report.errors),
    }
    with _print_lock:
        print(
            f"  {sha[:12]}  label={label}  {row['verdict']:<22} score={row['trojan_score']:.3f} "
            f"pkgstr={row['package_strings']:<5} cert={row['cert_not_before'][:10]} "
            f"age={row['cert_age_days']}"
        )
    return row


def auc(pos: list[float], neg: list[float]) -> float:
    """Rank-AUC via Mann-Whitney, ties counted as half. 0.5 means no ordering at all."""
    if not pos or not neg:
        return float("nan")
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else (0.5 if p == n else 0.0)
    return wins / (len(pos) * len(neg))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--per-class", type=int, default=40)
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--json-out", type=Path, default=Path("/tmp/lookalike_validation.json"))
    parser.add_argument("--i-am-the-extractor-vm", action="store_true")
    args = parser.parse_args()

    require_vm(args.i_am_the_extractor_vm)

    labels = labelled_hashes()
    family_of = families()
    available = retained()
    # Families first among the malware picks: the demo narrative is a banking trojan,
    # so a validation that never sees one is answering a different question.
    malware = sorted(
        (h for h in available if labels.get(h.lower()) == 1),
        key=lambda h: (family_of.get(h.lower(), "") == "", h),
    )[: args.per_class]
    benign = [h for h in available if labels.get(h.lower()) == 0][: args.per_class]
    print(
        f"retained={len(available)}  labelled malware={len(malware)} benign={len(benign)}  "
        f"family-tagged among picks={sum(1 for h in malware if family_of.get(h.lower()))}\n"
    )

    rows: list[dict] = []
    with tempfile.TemporaryDirectory(dir="/var/tmp") as tmp:
        root = Path(tmp)
        work = [(h, 1) for h in malware] + [(h, 0) for h in benign]
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for result in pool.map(lambda hl: analyse_one(hl[0], hl[1], root), work):
                if result is not None:
                    result["family"] = family_of.get(result["sha256"].lower(), "")
                    rows.append(result)

    mal = [r for r in rows if r["label"] == 1]
    ben = [r for r in rows if r["label"] == 0]

    print("\n── verdict x true label ──")
    cross: Counter[tuple[int, str]] = Counter((r["label"], r["verdict"]) for r in rows)
    for (label, verdict), count in sorted(cross.items()):
        print(f"  label={label}  {verdict:<24} {count}")

    print("\n── signal firing rate, per class ──")
    signal_ids = sorted({sid for r in rows for sid in r["signals"]})
    print(f"  {'signal':<38} {'malware':>16}  {'benign':>16}")
    for sid in signal_ids:
        m = sum(1 for r in mal if r["signals"].get(sid))
        b = sum(1 for r in ben if r["signals"].get(sid))
        mr = f"{m}/{len(mal)} ({m / len(mal):.0%})" if mal else "-"
        br = f"{b}/{len(ben)} ({b / len(ben):.0%})" if ben else "-"
        print(f"  {sid:<38} {mr:>16}  {br:>16}")

    mal_scores = [r["trojan_score"] for r in mal]
    ben_scores = [r["trojan_score"] for r in ben]
    print("\n── trojan_score ──")
    if mal_scores:
        print(
            f"  malware mean {sum(mal_scores) / len(mal_scores):.3f}  n={len(mal_scores)}  "
            f"min {min(mal_scores):.3f}  max {max(mal_scores):.3f}"
        )
    if ben_scores:
        print(
            f"  benign  mean {sum(ben_scores) / len(ben_scores):.3f}  n={len(ben_scores)}  "
            f"min {min(ben_scores):.3f}  max {max(ben_scores):.3f}"
        )
    print(f"  rank-AUC {auc(mal_scores, ben_scores):.3f}   (0.5 = no discrimination)")
    print(f"  threshold in force: {TROJAN_SHAPE_THRESHOLD}")

    fp = [r for r in ben if r["verdict"] == "trojan_shape"]
    print(f"\n── benign samples called TROJAN_SHAPE: {len(fp)} ──")
    for r in fp:
        fired = ", ".join(sid for sid, on in r["signals"].items() if on)
        print(f"  {r['sha256']}  score={r['trojan_score']:.3f}  {fired}")

    tp = [r for r in mal if r["verdict"] == "trojan_shape"]
    print(f"\n── malware caught as TROJAN_SHAPE: {len(tp)}/{len(mal)} ──")
    for r in tp[:15]:
        print(
            f"  {r['sha256'][:16]}  {r['family'] or '-':<12} score={r['trojan_score']:.3f} "
            f"targets={','.join(r['targets'][:3]) or '-'}"
        )

    print("\n── by family (malware only) ──")
    fam: Counter[str] = Counter(r["family"] or "untagged" for r in mal)
    for name, count in fam.most_common():
        scores = [r["trojan_score"] for r in mal if (r["family"] or "untagged") == name]
        hits = sum(
            1 for r in mal if (r["family"] or "untagged") == name and r["verdict"] == "trojan_shape"
        )
        print(
            f"  {name:<14} n={count:<4} mean={sum(scores) / len(scores):.3f}  trojan_shape={hits}"
        )

    # A signal that searches decompiled bodies cannot fire when there are none. Report
    # the haystack size so a 0% firing rate can be told apart from a broken input.
    parsed = sum(1 for r in rows if r["cert_not_before"] not in ("unknown", "", None))
    print(f"\ncertificate not_before parsed on {parsed}/{len(rows)} samples")
    print(
        f"package_strings non-empty on {sum(1 for r in rows if r['package_strings'] > 0)}/{len(rows)}"
    )
    print(
        f"decompiled_methods non-empty on {sum(1 for r in rows if r['decompiled_methods'] > 0)}/{len(rows)}"
    )
    for label, group in ((1, mal), (0, ben)):
        if group:
            print(
                f"  label={label} median package_strings="
                f"{sorted(r['package_strings'] for r in group)[len(group) // 2]}  "
                f"median decompiled_methods="
                f"{sorted(r['decompiled_methods'] for r in group)[len(group) // 2]}"
            )

    args.json_out.write_text(json.dumps(rows, indent=2))
    print(f"\nwrote {len(rows)} rows -> {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

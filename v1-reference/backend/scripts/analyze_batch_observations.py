#!/usr/bin/env python3
"""Build a behavioural knowledge base from a batch of detonator artifacts.

Answers the questions a defender actually has after a detonation run:
  * which runtime techniques does each malware category exhibit?
  * which techniques appear ONLY in malware and never in the benign controls, i.e. which
    observations carry real discriminative weight?
  * which samples produced no behaviour at all -- environment-aware stalling, which is an
    evasion signal rather than a clean bill of health;
  * which techniques are invisible to static analysis and only appear at runtime, which is
    the justification for running M3 at all.

Consumes the sanitized SHA-bound artifacts written by dynamic_analyze.py. No APK bytes are
read, so this is safe to run outside the lab.

Usage:
    python scripts/analyze_batch_observations.py \\
        --results-dir observations --sample-list samples_batch.txt [--json out.json]
"""
from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def load_labels(path: Path | None) -> dict[str, dict]:
    """sha256 -> {label, tag, vt, date, pkg} from the batch selection list."""
    labels: dict[str, dict] = {}
    if not path or not path.is_file():
        return labels
    for line in path.read_text().splitlines():
        parts = line.strip().split(",")
        if len(parts) < 6:
            continue
        sha, label, tag, vt, date, pkg = parts[0], parts[1], parts[2], parts[3], parts[4], ",".join(parts[5:])
        labels[sha.lower()] = {"label": int(label), "tag": tag, "vt": int(vt or 0),
                               "date": date, "pkg": pkg}
    return labels


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results-dir", type=Path, required=True)
    ap.add_argument("--sample-list", type=Path)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()

    labels = load_labels(args.sample_list)
    artifacts = []
    for path in sorted(args.results_dir.glob("*.json")):
        try:
            data = json.loads(path.read_text())
        except Exception:  # noqa: BLE001
            continue
        if "sha256" not in data or "observations" not in data:
            continue
        artifacts.append(data)

    if not artifacts:
        print(f"no observation artifacts found in {args.results_dir}")
        return 1

    rows = []
    by_tag: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    tag_samples: dict[str, int] = collections.Counter()
    mal_tech: collections.Counter = collections.Counter()
    ben_tech: collections.Counter = collections.Counter()
    hook_counter: collections.Counter = collections.Counter()
    outcomes: collections.Counter = collections.Counter()
    containment_ok = 0
    snapshot_ok = 0

    for data in artifacts:
        sha = data["sha256"].lower()
        meta = data.get("metadata") or {}
        snap = data.get("snapshot") or {}
        info = labels.get(sha, {})
        label = info.get("label", 1)
        tag = info.get("tag", meta.get("sample_kind", "unknown"))
        techniques = sorted({o.get("mitre") for o in data["observations"] if o.get("mitre")})
        hooks = [o.get("source_hook") for o in data["observations"] if o.get("source_hook")]
        for hook in hooks:
            hook_counter[hook] += 1
        outcomes[data.get("outcome", "?")] += 1
        if meta.get("containment_verified"):
            containment_ok += 1
        if (snap.get("before_restore") == "passed" and snap.get("after_restore") == "passed"
                and snap.get("package_absent_after")):
            snapshot_ok += 1
        tag_samples[tag] += 1
        for technique in techniques:
            by_tag[tag][technique] += 1
            (mal_tech if label == 1 else ben_tech)[technique] += 1
        rows.append({
            "sha256": sha, "package": data.get("package"), "tag": tag, "label": label,
            "vt": info.get("vt"), "outcome": data.get("outcome"),
            "observations": len(data["observations"]), "techniques": techniques,
            "duration_s": round(float(data.get("duration_s") or 0), 1),
            "containment_verified": bool(meta.get("containment_verified")),
            "snapshot_clean": (snap.get("before_restore") == "passed"
                               and snap.get("after_restore") == "passed"
                               and bool(snap.get("package_absent_after"))),
        })

    n_mal = sum(1 for r in rows if r["label"] == 1)
    n_ben = sum(1 for r in rows if r["label"] == 0)

    print("=" * 96)
    print(f"BEHAVIOURAL KNOWLEDGE BASE  --  {len(rows)} detonations "
          f"({n_mal} malware, {n_ben} benign control)")
    print("=" * 96)

    print("\n--- integrity of the run ---")
    print(f"  containment manifest verified : {containment_ok}/{len(rows)}")
    print(f"  snapshot clean before+after   : {snapshot_ok}/{len(rows)}")
    print(f"  outcomes                      : {dict(outcomes)}")

    print("\n--- per sample ---")
    print(f"  {'sha':14s} {'tag':22s} {'vt':>3s} {'out':12s} {'obs':>3s}  techniques")
    for r in sorted(rows, key=lambda r: (-r["label"], r["tag"], r["sha256"])):
        kind = "BENIGN" if r["label"] == 0 else ""
        print(f"  {r['sha256'][:12]:14s} {r['tag'][:22]:22s} {str(r['vt'] or '-'):>3s} "
              f"{str(r['outcome'])[:12]:12s} {r['observations']:>3d}  "
              f"{','.join(r['techniques']) or '(none)'} {kind}")

    print("\n--- technique frequency by category ---")
    all_tech = sorted({t for c in by_tag.values() for t in c})
    if all_tech:
        header = "  " + f"{'category':24s}" + "".join(f"{t:>10s}" for t in all_tech) + "   n"
        print(header)
        for tag in sorted(by_tag):
            line = f"  {tag[:24]:24s}"
            for technique in all_tech:
                count = by_tag[tag][technique]
                line += f"{(str(count) if count else '.'):>10s}"
            print(line + f"   {tag_samples[tag]}")

    print("\n--- discriminative value (malware-only techniques) ---")
    if n_ben == 0:
        print("  no benign controls detonated, so discriminative power cannot be measured")
    else:
        for technique in sorted(set(mal_tech) | set(ben_tech)):
            m, b = mal_tech[technique], ben_tech[technique]
            m_rate, b_rate = m / max(n_mal, 1), b / max(n_ben, 1)
            verdict = ("MALWARE-ONLY" if b == 0 and m > 0 else
                       "shared" if b and m else "benign-only")
            print(f"  {technique:10s} malware {m}/{n_mal} ({m_rate:.0%})  "
                  f"benign {b}/{n_ben} ({b_rate:.0%})   {verdict}")

    print("\n--- stalling / evasion (no behaviour under instrumentation) ---")
    silent = [r for r in rows if r["observations"] == 0]
    if not silent:
        print("  every sample produced at least one observation")
    for r in silent:
        print(f"  {r['sha256'][:12]} {r['tag']:22s} outcome={r['outcome']} "
              f"-> INCONCLUSIVE, not benign")

    print("\n--- most frequently triggered hooks ---")
    for hook, count in hook_counter.most_common(12):
        print(f"  {count:>3d}x  {hook}")

    if args.json:
        args.json.write_text(json.dumps({
            "samples": rows,
            "technique_by_category": {k: dict(v) for k, v in by_tag.items()},
            "malware_technique_counts": dict(mal_tech),
            "benign_technique_counts": dict(ben_tech),
            "counts": {"malware": n_mal, "benign": n_ben,
                       "containment_verified": containment_ok,
                       "snapshot_clean": snapshot_ok},
            "outcomes": dict(outcomes),
            "hooks": dict(hook_counter),
        }, indent=2))
        print(f"\nmachine-readable summary -> {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

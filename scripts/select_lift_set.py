"""Pick a balanced, deterministic set of test-split samples that exist in the bucket.

Test split only: the classifier never saw these, so P_cal is an honest number rather
than a memory. Balanced 50/50 so per-term means are comparable without reweighting.
"""

from __future__ import annotations

import csv
import glob
import random
import sys

N_PER_CLASS = int(sys.argv[1]) if len(sys.argv) > 1 else 30
MAX_BYTES = 30_000_000

with open("/tmp/bucket_shas.txt") as _fh:
    bucket = {line.strip() for line in _fh if line.strip()}
rows: dict[str, tuple[int, str, str, int]] = {}

for path in glob.glob("features/*.csv"):
    try:
        with open(path, newline="") as fh:
            for r in csv.DictReader(fh):
                sha = (r.get("sha256") or "").strip().lower()
                if not sha or r.get("split") != "test":
                    continue
                try:
                    label = int(r["label"])
                    size = int(r.get("apk_size") or 0)
                except (ValueError, KeyError, TypeError):
                    continue
                if sha in bucket and 0 < size < MAX_BYTES:
                    rows[sha] = (label, r.get("pkg_name", ""), r.get("vt_detection", ""), size)
    except OSError:
        continue

mal = sorted(s for s, v in rows.items() if v[0] == 1)
ben = sorted(s for s, v in rows.items() if v[0] == 0)
print(f"test-split present in bucket: malware={len(mal)} benign={len(ben)}")

random.seed(20260826)
pick = random.sample(mal, min(N_PER_CLASS, len(mal))) + random.sample(
    ben, min(N_PER_CLASS, len(ben))
)

with open("/tmp/lift_set.csv", "w", newline="") as out:
    w = csv.writer(out)
    w.writerow(["sha256", "label", "pkg", "vt", "size"])
    for s in pick:
        label, pkg, vt, size = rows[s]
        w.writerow([s, label, pkg, vt, size])

print(f"selected {len(pick)} samples -> /tmp/lift_set.csv")

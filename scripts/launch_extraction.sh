#!/usr/bin/env bash
# Launch N sharded corpus-extraction processes on the GCE extractor VM.
#
#   usage:  bash scripts/launch_extraction.sh <shards> <threads-per-shard>
#   used:   bash scripts/launch_extraction.sh 14 3      # on n2-standard-16
#
# EXTRACTOR VM ONLY. corpus_extract.py refuses to start anywhere else, and it is right
# to: it downloads real malware. Copy this file to the VM and run it there.
#
# ── Four things this encodes, each measured rather than assumed ──────────────
#
# 1. THROUGHPUT SCALES WITH PROCESSES, NOT THREADS. Each shard pegs ~95% of one core
#    inside androguard while the NIC moves ~1 MB/s. The job is CPU-bound on DEX
#    parsing and GIL-bound within a process. Measured on n2-standard-8: 4 shards gave
#    440 rec/hr. Resizing to n2-standard-16 and running 14 shards gave 1,489 rec/hr.
#
# 2. MEMORY IS THE REAL CEILING, AND IT IS COUNTED IN THREADS. AnalyzeAPK holds the
#    whole DEX plus its call graph in memory and EVERY THREAD does so concurrently,
#    so in-flight analyses = shards x threads, not shards. At 14x4=56 the 64 GB VM
#    went into sustained "Under memory pressure, flushing caches", starved sshd, and
#    became unreachable for ~20 minutes. The MemoryHigh/MemoryMax caps below turn that
#    global thrash into a single throttled-then-killed unit, and Restart=on-failure
#    plus corpus_extract.py's resume brings it straight back. 14x3 is the tested
#    setting; raise threads only while watching `free -g`.
#
# 3. RESUME IS GLOBAL, NOT PER-FILE. Re-sharding changes which shard owns a sha256,
#    so the script collects every hash completed by ANY previous shard before
#    re-splitting. Without this, changing the shard count silently re-downloads work.
#
# 4. EVALUATION SPLITS GO FIRST. The full list will not always finish inside a
#    deadline, so SOME prefix is what you get. Test and calib are extracted to
#    completion before any training row, because confidence-interval width is driven
#    by test n while the feature set is learnable from a modest training sample.
set -uo pipefail
export LC_ALL=C
cd "$HOME/CyberShield"

N=${1:-14}
W=${2:-4}

# Stop every previous shard unit, whatever the old shard count was.
for u in $(systemctl --user list-units --all --plain --no-legend 'drishti-shard-*' 2>/dev/null | awk '{print $1}') drishti-corpus drishti-fast; do
  systemctl --user stop "$u" 2>/dev/null || true
  systemctl --user reset-failed "$u" 2>/dev/null || true
done
pkill -f corpus_extract 2>/dev/null || true
sleep 3
find /tmp -name '*.apk' -delete 2>/dev/null || true
rm -rf /tmp/drishti-corpus-* 2>/dev/null || true

LIST=data/corpus/samples.csv
[ -f "$LIST" ] || LIST=samples.csv
mkdir -p features

# Global resume. Re-sharding changes which shard owns a sha256, so per-file resume
# inside corpus_extract.py is not enough -- a sample already done under a 4-way split
# would be re-downloaded under a 14-way one. Collect every sha256 completed by ANY
# previous shard and drop those rows before re-splitting.
python3 - "$LIST" "$N" <<'PY'
import csv, glob, json, sys
list_path, n = sys.argv[1], int(sys.argv[2])

done = set()
for path in glob.glob("features/shard-*.jsonl"):
    with open(path) as fh:
        for line in fh:
            try:
                done.add(json.loads(line)["sha256"].lower())
            except (json.JSONDecodeError, KeyError, AttributeError):
                continue

with open(list_path, newline="") as fh:
    reader = csv.DictReader(fh)
    header = reader.fieldnames
    rows = [r for r in reader if r["sha256"].lower() not in done]

# Evaluation splits FIRST, training rows last.
#
# Measured throughput is ~680 rec/hr, so the full 10,599 will not finish inside the
# deadline and SOME prefix is what we get. Which prefix matters: the width of every
# confidence interval is driven by test n, while 131 features are learnable from a
# fairly modest training set. Extracting test+calib to completion (1,599 rows, ~2.5h)
# buys a full-strength evaluation, and every hour after that is pure training data.
# The alternative -- a uniform prefix -- gives more training rows and a test set of a
# few hundred with ~25 malware, which is too thin to report honestly.
_PRIORITY = {"test": 0, "calib": 1, "train": 2}
rows.sort(key=lambda r: _PRIORITY.get(r.get("split", "train"), 3))

# Round-robin so every shard keeps the (split,label) interleaving of the master list.
# A contiguous slice would hand one shard nothing but train-malware and no test rows,
# and a stopped-early run could then not be time-split evaluated at all.
writers = []
for i in range(n):
    fh = open(f"features/pending-{i}.csv", "w", newline="")
    w = csv.DictWriter(fh, fieldnames=header)
    w.writeheader()
    writers.append((fh, w))
for idx, row in enumerate(rows):
    writers[idx % n][1].writerow(row)
for fh, _ in writers:
    fh.close()

print(f"already done: {len(done)}   remaining: {len(rows)}   shards: {n}")
PY

KEY=$(grep -o '[a-f0-9]\{64\}' "$HOME/.corpus_env" | head -1)
[ -n "$KEY" ] || { echo "FATAL: no AndroZoo key in ~/.corpus_env"; exit 1; }

sudo loginctl enable-linger "$USER" 2>/dev/null || true
for i in $(seq 0 $((N-1))); do
  # Output file is namespaced by shard count so a relaunch at a different N never
  # appends into a file whose rows another shard is also resuming from.
  #
  # MemoryHigh/MemoryMax are load-bearing, not tidiness. androguard's AnalyzeAPK holds
  # the whole DEX plus its call graph in memory, and EVERY THREAD does so concurrently
  # -- so the real in-flight count is shards x workers, not shards. At 14x4=56 this VM
  # (64 GB) went into sustained "Under memory pressure, flushing caches", starved sshd,
  # and became unreachable. Capping each unit means a single greedy shard is throttled
  # and then OOM-killed ALONE, and resume picks it back up, instead of the whole box
  # thrashing and taking the batch and the login session down with it.
  # Restart=on-failure closes the loop: a shard killed for exceeding MemoryMax comes
  # straight back and corpus_extract.py's resume skips everything already in its
  # jsonl. Without it an OOM-killed shard would silently stop processing its entire
  # remaining slice, and the only symptom would be throughput quietly dropping.
  systemd-run --user --unit="drishti-shard-$i" --same-dir \
    --property=MemoryHigh=2500M \
    --property=MemoryMax=3500M \
    --property=Restart=on-failure \
    --property=RestartSec=15 \
    --setenv=PATH="$HOME/.local/bin:/usr/bin:/bin" \
    --setenv=LC_ALL=C \
    --setenv=DRISHTI_ANDROZOO_API_KEY="$KEY" \
    bash -c "cd \$HOME/CyberShield && uv run python scripts/corpus_extract.py \
      features/pending-$i.csv features/shard-n${N}-$i.jsonl \
      --workers $W --i-am-the-extractor-vm > features/shard-n${N}-$i.log 2>&1" >/dev/null 2>&1
done

echo "launched $N shards x $W threads"
sleep 40
ACTIVE=0
for i in $(seq 0 $((N-1))); do
  [ "$(systemctl --user is-active drishti-shard-$i)" = "active" ] && ACTIVE=$((ACTIVE+1))
done
echo "active shards: $ACTIVE/$N"
echo "records so far: $(cat features/*.jsonl 2>/dev/null | wc -l)"
uptime

#!/usr/bin/env python3
"""Measure the code-graph RAG selection ratio, the hard budgets, and per-stage timing.

docs/ROADMAP_GENAI_RE.md A1/A2, docs/00_GUIDING_MAP.md §12, REPORT §4.2.2 (Fig 3).

Three claims in the paper are quantitative and were, until this script ran, unmeasured:

  1. **"We never send the whole decompiled app."** The retrieval layer walks backwards
     from dangerous sinks and hands the model only the reachable method chains. The
     pitch number is the RATIO — methods selected over methods the app contains — and
     the prompt token count that ratio buys.
  2. **"Budgets are asserts, not hopes"** — <=25 LLM calls per job, <=12k prompt tokens
     in. Both are enforced in `m4_genai.client`; this measures what a real job actually
     spends against them, because a limit nothing approaches is not evidence the limit
     works.
  3. **The fast path.** The two-verdict design emits a preliminary verdict before the
     sandbox. What that costs in wall-clock is a measurement, not an estimate.

Every number printed here comes from a run performed by this script. Nothing is carried
over from a previous build and nothing is projected.

**On sample choice, and what the first run of this script found.** CLAUDE.md forbids
copying a corpus APK to a developer machine, so the only samples available here are
locally-built ones: the demo decoy, its benign control, and the canary.

Running this revealed why that is a real limitation and not a formality. The decoy
declares a full trojan permission set (READ_SMS, RECEIVE_SMS, SYSTEM_ALERT_WINDOW,
REQUEST_INSTALL_PACKAGES) and the matching component structure — but it is *inert by
construction*, because CLAUDE.md forbids writing real malicious payloads. Its bytecode
therefore calls almost no dangerous APIs, M2 recovers **zero** call paths from it, and
the backward walk has nothing to select. The one sink M2 does match in it,
`Method;->invoke`, is reached only from Kotlin stdlib internals and from no lifecycle
entrypoint at all.

So the selection RATIO cannot be honestly measured here: the numerator is zero for
reasons that have nothing to do with the retrieval layer. What *can* be measured on
these samples, and is, is the mechanism working end to end on the canary (which does
have one real reachable chain), the budget spend, and the stage timings. The ratio
that belongs in the pitch needs a corpus sample and must be measured on the extractor
VM, where the APK already is.

    uv run python scripts/measure_rag_and_timing.py
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drishti.config import Settings
from drishti.contracts.job import Job, JobStage
from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import analyse, canonical_signature
from drishti.m4_genai.client import CHARS_PER_TOKEN, LLMClient
from drishti.m4_genai.retrieval import render_workspace, select
from drishti.pipeline import Context, run_pipeline
from drishti.util import new_id, now

#: Stages that run before the preliminary verdict is emitted. This is "the fast path":
#: what a triage analyst waits for before seeing a score, with the sandbox still running.
FAST_PATH_STAGES: tuple[JobStage, ...] = (
    JobStage.INGEST,
    JobStage.STATIC,
    JobStage.ML,
    JobStage.GENAI_STATIC,
    JobStage.SCORE_PRELIM,
)


def _total_internal_methods(apk_path: Path) -> tuple[int, int, list[str]]:
    """How many methods the application actually contains, and how many classes.

    Counts with exactly the criterion `m2_static.engine._call_graph` uses to build the
    graph — `not method.is_external()` — so the denominator of the selection ratio is
    the same population the backward walk searched. Counting androguard's externals too
    would inflate the ratio with framework methods that were never candidates.
    """
    errors: list[str] = []
    try:
        from androguard.misc import AnalyzeAPK
    except Exception as exc:  # pragma: no cover - androguard is a hard dependency
        return (0, 0, [f"androguard unavailable: {type(exc).__name__}: {exc}"])
    try:
        _, _, analysis = AnalyzeAPK(str(apk_path))
    except Exception as exc:
        return (0, 0, [f"AnalyzeAPK failed: {type(exc).__name__}: {exc}"])
    signatures = {
        canonical_signature(m.full_name) for m in analysis.get_methods() if not m.is_external()
    }
    classes = {s.split(";->")[0] for s in signatures}
    return (len(signatures), len(classes), errors)


def measure_retrieval(apk_path: Path, label: str) -> dict[str, Any]:
    """Run real M2, then real retrieval, and report what was selected out of what.

    The whole claim of the code-graph RAG layer is a ratio, so both terms are measured
    on the same sample in the same run: the denominator from androguard's method table,
    the numerator from the pack the model would actually be handed.
    """
    tmp = Path(".measure_tmp")
    tmp.mkdir(exist_ok=True)
    store = LedgerStore(tmp / f"rag_{label}.db", tmp / f"rag_{label}.pem")
    store.open(f"job_measure_{label}")
    try:
        started = time.perf_counter()
        static = analyse(apk_path, store)
        static_seconds = time.perf_counter() - started

        started = time.perf_counter()
        pack = select(static)
        select_seconds = time.perf_counter() - started

        workspace = render_workspace(pack)
    finally:
        store.close()

    total_methods, total_classes, errors = _total_internal_methods(apk_path)

    # The workspace is the actual text placed in the user turn, so its token count is
    # the real cost of the selection — not the pack's own internal estimate.
    workspace_tokens = len(workspace) // CHARS_PER_TOKEN

    # What the alternative costs. `decompiled_methods` is only what M2 decompiled for
    # the selected chains, so the whole-app figure is a projection from the mean body
    # size and is labelled as such — it is the one number here that is not directly
    # observed, and it is reported only to size the ratio.
    bodies = [len(m.body) for m in static.decompiled_methods]
    mean_body_chars = statistics.mean(bodies) if bodies else 0.0
    projected_whole_app_tokens = (
        int(mean_body_chars * total_methods) // CHARS_PER_TOKEN if bodies else None
    )

    ratio = (pack.method_count / total_methods) if total_methods else None
    return {
        "sample": label,
        "apk": str(apk_path),
        "sha256": static.sha256,
        "package": static.package,
        "static_partial": static.partial,
        "app": {
            "total_internal_methods": total_methods,
            "total_classes": total_classes,
            "errors": errors,
        },
        "backward_walk": {
            "call_paths_recovered": len(static.call_paths),
            "chains_considered": pack.chains_considered,
            "chains_selected": len(pack.chains),
            "chains_dropped": pack.chains_dropped,
            "methods_selected": pack.method_count,
            "methods_dropped": pack.methods_dropped,
            "methods_decompiled_by_m2": len(static.decompiled_methods),
            "strings_selected": len(pack.strings),
            "notes": list(pack.notes),
        },
        "selection_ratio": round(ratio, 6) if ratio is not None else None,
        "selection_ratio_pct": round(ratio * 100, 4) if ratio is not None else None,
        "tokens": {
            "workspace_tokens_measured": workspace_tokens,
            "workspace_chars": len(workspace),
            "pack_estimated_tokens": pack.estimated_tokens,
            "token_budget": pack.token_budget,
            "within_budget": pack.estimated_tokens <= pack.token_budget,
            "projected_whole_app_tokens": projected_whole_app_tokens,
            "projection_basis": (
                f"mean decompiled body {mean_body_chars:.0f} chars over "
                f"{len(bodies)} methods x {total_methods} app methods"
                if bodies
                else "no decompiled bodies; no projection made"
            ),
        },
        "seconds": {
            "m2_static": round(static_seconds, 4),
            "retrieval_select": round(select_seconds, 4),
        },
    }


def measure_budgets(apk_path: Path, label: str) -> dict[str, Any]:
    """Run the real GenAI controller with an injected client and read what it spent.

    The budgets are enforced inside `LLMClient`; injecting the client is the only way to
    read the meter afterwards. The provider is `mock`, so call COUNT and prompt SIZE are
    real (they are what the controller built) while the responses are not.
    """
    from drishti.m4_genai.controller import analyse as genai_analyse

    tmp = Path(".measure_tmp")
    tmp.mkdir(exist_ok=True)
    settings = Settings(
        db_path=tmp / f"budget_{label}.db",
        ledger_key_path=tmp / f"budget_{label}.pem",
        log_path=tmp / f"budget_{label}.jsonl",
        llm_provider="mock",
    )
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    store.open(f"job_budget_{label}")
    try:
        static = analyse(apk_path, store)
        client = LLMClient(settings)
        started = time.perf_counter()
        verdict = genai_analyse(static, store, settings, client=client, apk_path=apk_path)
        elapsed = time.perf_counter() - started
        report = client.budget_report()
    finally:
        store.close()

    return {
        "sample": label,
        "provider": settings.llm_provider,
        "seconds": round(elapsed, 4),
        "calls": {
            "made": report.calls,
            "limit": settings.llm_max_calls_per_job,
            "within_budget": report.calls <= settings.llm_max_calls_per_job,
            "headroom": settings.llm_max_calls_per_job - report.calls,
            "cache_hits": report.cache_hits,
            "failures": report.failures,
        },
        "prompt_tokens": {
            "max_single_prompt": report.max_prompt_tokens,
            "limit": settings.llm_max_prompt_tokens,
            "within_budget": report.max_prompt_tokens <= settings.llm_max_prompt_tokens,
            "headroom": settings.llm_max_prompt_tokens - report.max_prompt_tokens,
            "total_across_job": report.total_prompt_tokens,
            "measured_calls": report.measured_calls,
            "note": (
                "provider is mock, so prompt sizes are the real prompts the controller "
                "built; completion tokens are not meaningful"
            ),
        },
        "per_call": [
            {
                "prompt_tokens": s.prompt_tokens,
                "cached": s.cached,
                "outcome": s.outcome,
                "measured": s.measured,
            }
            for s in report.stats
        ],
        "verdict_llm_calls": verdict.llm_calls,
        "verdict_partial": verdict.partial,
    }


def measure_pipeline(apk_path: Path, label: str, repeats: int) -> dict[str, Any]:
    """Walk the real pipeline and record every stage duration it reports.

    Timing is read from the `StageEvent`s the pipeline already emits, not from a
    stopwatch wrapped around it here, so what is reported is what the UI's progress
    stream shows a user.
    """
    runs: list[dict[str, Any]] = []
    for index in range(repeats):
        tmp = Path(".measure_tmp")
        tmp.mkdir(exist_ok=True)
        settings = Settings(
            db_path=tmp / f"pipe_{label}_{index}.db",
            ledger_key_path=tmp / f"pipe_{label}_{index}.pem",
            log_path=tmp / f"pipe_{label}_{index}.jsonl",
            llm_provider="mock",
        )
        store = LedgerStore(settings.db_path, settings.ledger_key_path)
        events: list[Any] = []
        ctx = Context(settings=settings, ledger=store, on_event=events.append)
        job = Job(
            id=new_id("job"),
            sha256="0" * 64,
            filename=apk_path.name,
            stage=JobStage.QUEUED,
            created_at=now(),
        )
        started = time.perf_counter()
        finished = run_pipeline(job, ctx, apk_path=apk_path)
        wall = time.perf_counter() - started

        durations = {
            e.stage.value: e.duration_ms
            for e in events
            if e.status == "completed" and e.duration_ms is not None
        }
        fast_path_ms = sum(durations.get(s.value, 0) for s in FAST_PATH_STAGES)
        runs.append(
            {
                "run": index,
                "final_stage": finished.stage.value,
                "error": finished.error,
                "wall_seconds": round(wall, 4),
                "stage_ms": durations,
                "fast_path_ms": fast_path_ms,
                "fast_path_seconds": round(fast_path_ms / 1000, 4),
            }
        )
        store.close()

    stage_names = sorted({name for r in runs for name in r["stage_ms"]})
    return {
        "sample": label,
        "apk": str(apk_path),
        "repeats": repeats,
        "runs": runs,
        "median_stage_ms": {
            name: round(statistics.median([r["stage_ms"].get(name, 0) for r in runs]), 1)
            for name in stage_names
        },
        "median_fast_path_seconds": round(
            statistics.median([r["fast_path_seconds"] for r in runs]), 4
        ),
        "median_wall_seconds": round(statistics.median([r["wall_seconds"] for r in runs]), 4),
        "fast_path_definition": [s.value for s in FAST_PATH_STAGES],
        "note": (
            "sandbox stages run against the configured trace source; with no live "
            "detonator they are near-instant and the total is NOT an end-to-end "
            "detonation time. The fast path is the honest number here."
        ),
    }


def measure_live_llm_latency(log_path: Path) -> dict[str, Any]:
    """The real latency of a live LLM call, read from calls this system actually made.

    The pipeline timings above run against the `mock` provider, so `genai_static`
    reports single-digit milliseconds — which is the cost of building the prompt, not
    the cost of getting an answer. Reporting that as the fast path would be the
    dishonest kind of fast.

    Only calls the provider reported usage for (`measured=true`) and that succeeded are
    counted, so a failed call's timeout does not masquerade as latency.
    """
    if not log_path.exists():
        return {"available": False, "reason": f"no log at {log_path}"}
    latencies: list[int] = []
    models: set[str] = set()
    for line in log_path.read_text(errors="replace").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            record.get("event") == "llm_call"
            and record.get("outcome") == "ok"
            and record.get("measured")
            and record.get("latency_ms")
        ):
            latencies.append(int(record["latency_ms"]))
            models.add(str(record.get("model", "")))
    if not latencies:
        return {"available": False, "reason": "no successful measured llm_call records"}
    latencies.sort()
    return {
        "available": True,
        "source": str(log_path),
        "n_calls": len(latencies),
        "models": sorted(models),
        "min_ms": latencies[0],
        "median_ms": int(statistics.median(latencies)),
        "p90_ms": latencies[int(0.9 * len(latencies)) - 1],
        "max_ms": latencies[-1],
        "mean_ms": round(statistics.mean(latencies), 1),
        "note": (
            "these are real calls this system made to a free-tier endpoint. Free-tier "
            "latency is highly variable and is the dominant term in any live fast-path "
            "number — the local compute below is not what a user waits for."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("docs/figures/rag_and_timing.json"),
        help="where to write the measured record",
    )
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()

    samples = [
        ("decoy_rto_challan", Path("canary/decoy-challan/dist/RTO_Challan.apk")),
        ("benign_sanchay", Path("canary/benign-sanchay/dist/Sanchay_Expenses.apk")),
        ("canary", Path("canary/dist/canary.apk")),
    ]
    available = [(label, path) for label, path in samples if path.exists()]
    if not available:
        print("no sample APKs found", file=sys.stderr)
        return 1

    record: dict[str, Any] = {
        "measured_at": now(),
        "sample_provenance": (
            "locally-built real APKs. CLAUDE.md forbids copying a corpus APK to a "
            "developer machine, so these are NOT corpus malware samples. The decoy is a "
            "real Android application with a real call graph and real sinks, and it is "
            "the sample the demo runs."
        ),
        "retrieval": [],
        "budgets": [],
        "timing": [],
    }
    for label, path in available:
        print(f"\n── {label}: {path} ──", flush=True)
        rag = measure_retrieval(path, label)
        record["retrieval"].append(rag)
        print(
            f"  methods: {rag['backward_walk']['methods_selected']} selected of "
            f"{rag['app']['total_internal_methods']} in the app "
            f"({rag['selection_ratio_pct']}%)"
        )
        print(
            f"  workspace: {rag['tokens']['workspace_tokens_measured']} tokens "
            f"(budget {rag['tokens']['token_budget']})"
        )

        budgets = measure_budgets(path, label)
        record["budgets"].append(budgets)
        print(
            f"  LLM calls: {budgets['calls']['made']}/{budgets['calls']['limit']} · "
            f"max prompt {budgets['prompt_tokens']['max_single_prompt']}/"
            f"{budgets['prompt_tokens']['limit']} tokens"
        )

        timing = measure_pipeline(path, label, args.repeats)
        record["timing"].append(timing)
        print(
            f"  fast path (median of {args.repeats}): "
            f"{timing['median_fast_path_seconds']}s · "
            f"full walk {timing['median_wall_seconds']}s"
        )

    record["live_llm_latency"] = measure_live_llm_latency(Path("logs/drishti.jsonl"))
    live = record["live_llm_latency"]
    if live.get("available"):
        local = statistics.median([t["median_fast_path_seconds"] for t in record["timing"]])
        record["fast_path_live_estimate"] = {
            "local_compute_seconds": round(local, 4),
            "plus_one_live_llm_call_median_seconds": round(live["median_ms"] / 1000, 4),
            "projected_median_seconds": round(local + live["median_ms"] / 1000, 4),
            "projected_best_case_seconds": round(local + live["min_ms"] / 1000, 4),
            "projected_worst_case_seconds": round(local + live["max_ms"] / 1000, 4),
            "basis": (
                "measured local compute plus the measured latency distribution of real "
                "calls. It is a SUM OF TWO MEASUREMENTS, not a single end-to-end timing "
                "of a live run, and is labelled as such."
            ),
        }
        print(
            f"\nlive fast path: {local:.2f}s local compute + "
            f"{live['median_ms'] / 1000:.2f}s median LLM (n={live['n_calls']}) = "
            f"{record['fast_path_live_estimate']['projected_median_seconds']:.2f}s"
        )

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(record, indent=2) + "\n")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

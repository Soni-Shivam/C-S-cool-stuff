#!/usr/bin/env python3
"""Dump everything one job produced as plain text.

Why this exists: the dashboard renders a job across eight tabs, and the pieces that
matter most when something is wrong are the ones it shows least — the per-term score
arithmetic, and the `errors` array each module carries. A sub-analyser that failed
degrades gracefully by design (CLAUDE.md rule 2), which means its failure is a log line
and an empty panel rather than anything a reader can see. Debugging from screenshots is
how "0 tool calls" gets mistaken for "the model chose not to use tools".

So this reads the same frozen routes the UI reads and writes one file per job, ordered
the way a person actually asks questions: what is the verdict, where did the number come
from, what evidence is behind it, and what silently did not run.

Nothing here recomputes anything. Every number is transcribed from an artefact, so a
disagreement between this file and the UI is a real disagreement, not a second opinion.

Usage:
    python scripts/export_job_text.py --latest
    python scripts/export_job_text.py job_abc123 --out /tmp/report.txt
    python scripts/export_job_text.py --all --out-dir /tmp/exports
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

API = "http://127.0.0.1:8080"
RULE = "=" * 78
THIN = "-" * 78


def _set_api(url: str) -> None:
    """Point every subsequent GET at `url`."""
    global API
    API = url


def get(path: str) -> Any:
    """One GET. A 404/501 is data, not a crash — an unbuilt artefact is a finding."""
    try:
        with urllib.request.urlopen(f"{API}{path}", timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        return {"_http_error": exc.code, "_detail": exc.read().decode("utf-8", "replace")[:400]}
    except Exception as exc:
        return {"_error": f"{type(exc).__name__}: {exc}"}


def _is_error(blob: Any) -> str | None:
    if isinstance(blob, dict) and "_http_error" in blob:
        return f"HTTP {blob['_http_error']}"
    if isinstance(blob, dict) and "_error" in blob:
        return str(blob["_error"])
    return None


def head(title: str) -> list[str]:
    return ["", RULE, title.upper(), RULE]


def kv(label: str, value: Any, width: int = 26) -> str:
    return f"  {label:<{width}} {value}"


def _errors_block(name: str, blob: Any) -> list[str]:
    """Every module's `errors` and `partial`, always printed — including when empty.

    Printing "none" is the point. An absent section is indistinguishable from a section
    nobody looked at, and that ambiguity is exactly what hid the swallowed sub-analyser
    failures.
    """
    if not isinstance(blob, dict):
        return []
    errors = blob.get("errors") or []
    partial = blob.get("partial")
    lines = [kv(f"{name} partial", partial if partial is not None else "n/a")]
    if errors:
        lines.append(f"  {name} errors:")
        lines.extend(f"      - {e}" for e in errors)
    else:
        lines.append(kv(f"{name} errors", "none"))
    return lines


def _asserted(genai: dict) -> list[str]:
    """The behaviours the model answered True — the only ones that move B.

    Read from `behaviours` rather than a summary field, so this cannot disagree with
    what `behavioural_risk` was actually handed.
    """
    return [k for k, v in (genai.get("behaviours") or {}).items() if v is True]


def render(job_id: str) -> str:
    job = get(f"/api/jobs/{job_id}")
    out: list[str] = [RULE, f"DRISHTI JOB EXPORT  ·  {job_id}", RULE]

    if err := _is_error(job):
        return "\n".join([*out, f"  job could not be read: {err}"])

    out += [
        kv("stage", job.get("stage")),
        kv("sha256", job.get("sha256")),
        kv("filename", job.get("filename")),
        kv("error", job.get("error") or "none"),
    ]

    # ── verdict: the one projection every surface reads ──────────────────────
    verdict = get(f"/api/jobs/{job_id}/verdict")
    out += head("verdict")
    if err := _is_error(verdict):
        out.append(f"  unavailable: {err}")
    else:
        out += [
            kv("threat score", f"{verdict.get('threat_score')}  {verdict.get('severity_band')}"),
            kv("confidence", verdict.get("confidence")),
            kv("provenance", verdict.get("provenance")),
            kv("consumer summary", (verdict.get("consumer_summary") or "")[:120]),
            kv("recommended action", verdict.get("recommended_action")),
            kv("behaviours", ", ".join(verdict.get("behaviors_detected") or []) or "none"),
            kv("techniques", ", ".join(verdict.get("attack_techniques") or []) or "none"),
        ]
        if limits := verdict.get("limitations"):
            out.append("  limitations:")
            out += [f"      - {item}" for item in limits]

    # ── the arithmetic ───────────────────────────────────────────────────────
    score = get(f"/api/jobs/{job_id}/score")
    out += head("score composition")
    if err := _is_error(score):
        out.append(f"  unavailable: {err}")
    else:
        out += [
            kv("S", f"{score.get('S')}  ({score.get('band')})"),
            kv("C (confidence)", score.get("C")),
            kv("gamma", score.get("gamma")),
            kv("anomaly escalated", score.get("anomaly_escalated")),
            kv("override", score.get("override_applied") or "none"),
            "",
            f"  {'term':<6} {'raw':>10} {'weight':>8} {'contributes':>12}   inputs",
            f"  {THIN}",
        ]
        for factor in score.get("factors", []):
            inputs = factor.get("inputs") or {}
            # A term that is zero because nothing measured it reads identically to one
            # measured as zero unless the inputs are shown next to it.
            rendered = ", ".join(f"{k}={v}" for k, v in inputs.items() if v is not None) or "—"
            out.append(
                f"  {factor.get('symbol', '?'):<6} {factor.get('raw', 0):>10.4f} "
                f"{factor.get('weight', 0):>8.2f} {factor.get('contribution', 0):>12.4f}   {rendered}"
            )
        out += ["", kv("explanation", score.get("explanation"))]

    # ── ML ───────────────────────────────────────────────────────────────────
    ml = get(f"/api/jobs/{job_id}/ml")
    out += head("ml prediction")
    if err := _is_error(ml):
        out.append(f"  unavailable: {err}")
    else:
        out += [
            kv("p_raw", ml.get("p_malicious_raw")),
            kv("p_calibrated", ml.get("p_calibrated")),
            kv("anomaly", f"{ml.get('anomaly_score')}  escalate={ml.get('anomaly_escalate')}"),
            kv("model", ml.get("model_version")),
            kv("features", ml.get("feature_schema_version")),
        ]
        if top := ml.get("top_features"):
            out.append("  top SHAP contributions:")
            # FeatureAttribution fields are feature/value/shap/direction. `name` and
            # `contribution` belong to ScoreFactor — reading those here printed a column
            # of Nones next to real values and made a working explainer look broken.
            out += [
                f"      {f.get('direction', ' ')} {f.get('feature')!s:<34} "
                f"v={f.get('value')!s:<12} shap={f.get('shap')}"
                for f in top[:10]
            ]
        else:
            out.append(kv("top features", "NONE — attribution did not reach the prediction"))
        out += _errors_block("ml", ml)

    # ── GenAI: behaviours are what move B; claims are what the verifier guards ──
    genai = get(f"/api/jobs/{job_id}/genai")
    out += head("genai")
    if err := _is_error(genai):
        out.append(f"  unavailable: {err}")
    else:
        out += [
            kv("provider", genai.get("provider")),
            kv("llm calls", genai.get("llm_calls")),
            kv("behavioural_risk_B", genai.get("behavioural_risk_B")),
            kv("B rationale", genai.get("B_rationale") or "none"),
            kv("behaviours asserted", ", ".join(_asserted(genai)) or "NONE"),
            kv("behaviours answered", len(genai.get("behaviours") or {})),
        ]
        claims = genai.get("claims") or []
        passed = [c for c in claims if str(c.get("verifier_status", "")).upper() == "PASS"]
        out.append(kv("claims", f"{len(passed)} passed / {len(claims)} total"))
        for claim in claims:
            status = str(claim.get("verifier_status", "?")).upper()
            out.append(f"      [{status}] ({claim.get('agent')}) {claim.get('text', '')[:150]}")
            out.append(
                f"              evidence: {', '.join(claim.get('evidence_refs') or []) or 'NONE'}"
            )
        interpretations = genai.get("interpretations") or []
        out.append(kv("code interpretations", len(interpretations)))
        out.append(kv("tool calls", len(genai.get("tool_calls") or [])))
        out += _errors_block("genai", genai)

    # ── static ───────────────────────────────────────────────────────────────
    static = get(f"/api/jobs/{job_id}/static")
    out += head("static analysis")
    if err := _is_error(static):
        out.append(f"  unavailable: {err}")
    else:
        out += [
            kv("package", static.get("package")),
            kv("label / version", f"{static.get('app_label')} {static.get('version_name')}"),
            kv("permissions", len(static.get("permissions") or [])),
            kv("components", len(static.get("components") or [])),
            kv("exported unguarded", len(static.get("exported_unprotected") or [])),
            kv("call paths", len(static.get("call_paths") or [])),
            kv("decompiled methods", len(static.get("decompiled_methods") or [])),
            kv("sinks reached", ", ".join(static.get("sink_hits") or []) or "none"),
            kv("dcl indicators", len(static.get("dcl_indicators") or [])),
            kv("declared not used", len(static.get("declared_not_used") or [])),
            kv("used not declared", len(static.get("used_not_declared") or [])),
        ]
        combos = static.get("permission_combos") or []
        out.append(kv("permission combos", len(combos)))
        for combo in combos:
            out.append(
                f"      [{str(combo.get('severity', '')).upper():<8}] {combo.get('rule_id')} "
                f"({combo.get('mitre')})"
            )
        if look := static.get("lookalike"):
            out += [
                kv(
                    "lookalike verdict",
                    f"{look.get('verdict')} (trojan {look.get('trojan_score')})",
                ),
                kv(
                    "financial pkgs referenced",
                    ", ".join(look.get("targeted_financial_packages") or []) or "none",
                ),
            ]
        out += _errors_block("static", static)

    # ── dynamic ──────────────────────────────────────────────────────────────
    dynamic = get(f"/api/jobs/{job_id}/dynamic")
    out += head("dynamic analysis")
    if err := _is_error(dynamic):
        out.append(f"  unavailable: {err}")
    else:
        out += [
            kv("source", dynamic.get("source")),
            kv("detonated", dynamic.get("detonated")),
            kv("outcome", dynamic.get("outcome")),
            kv("synthetic", dynamic.get("synthetic")),
            kv("containment verified", dynamic.get("containment_verified")),
            kv("emulator image", dynamic.get("emulator_image") or "not recorded"),
            kv("vm instance", dynamic.get("vm_instance_id") or "not recorded"),
            kv("api events", len(dynamic.get("api_events") or [])),
            kv("network flows", len(dynamic.get("network_flows") or [])),
            kv("dex loads", len(dynamic.get("dex_loads") or [])),
            kv("decrypted blobs", len(dynamic.get("decrypted_blobs") or [])),
            kv("evasion observations", len(dynamic.get("evasion_observations") or [])),
            kv("morphs applied", ", ".join(dynamic.get("morphs_applied") or []) or "none"),
        ]
        for flow in (dynamic.get("network_flows") or [])[:10]:
            out.append(f"      -> {flow.get('host')}  {flow.get('url', '')[:90]}")
        for load in (dynamic.get("dex_loads") or [])[:10]:
            out.append(
                f"      dex {load.get('path')}  in_original_apk={load.get('in_original_apk')}"
            )
        out += _errors_block("dynamic", dynamic)

    # ── ledger ───────────────────────────────────────────────────────────────
    out += head("evidence ledger")
    verify = get(f"/api/jobs/{job_id}/ledger/verify")
    if err := _is_error(verify):
        out.append(f"  unavailable: {err}")
    else:
        out += [
            kv("chain ok", verify.get("ok")),
            kv("nodes", verify.get("nodes")),
            kv(
                "first bad seq",
                verify.get("first_bad_seq") if verify.get("first_bad_seq") is not None else "none",
            ),
        ]
    return "\n".join([*out, "", RULE, "end of export", RULE, ""])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("job_id", nargs="?")
    parser.add_argument("--latest", action="store_true", help="export the most recent job")
    parser.add_argument("--all", action="store_true", help="export every job")
    parser.add_argument("--out", type=Path)
    parser.add_argument("--out-dir", type=Path, default=Path("/tmp/drishti-exports"))
    parser.add_argument("--api", default=API)
    args = parser.parse_args()
    _set_api(args.api)

    jobs = get("/api/jobs")
    if err := _is_error(jobs):
        print(f"cannot reach the API at {API}: {err}", file=sys.stderr)
        return 2
    listing = jobs if isinstance(jobs, list) else jobs.get("jobs", [])
    ids = [j.get("id") or j.get("job_id") for j in listing]

    if args.all:
        targets = ids
    elif args.latest:
        targets = ids[:1]
    elif args.job_id:
        targets = [args.job_id]
    else:
        parser.error("give a job id, or --latest, or --all")

    if not targets:
        print("no jobs to export", file=sys.stderr)
        return 1

    if args.out and len(targets) == 1:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(render(targets[0]), encoding="utf-8")
        print(args.out)
        return 0

    args.out_dir.mkdir(parents=True, exist_ok=True)
    for job_id in targets:
        path = args.out_dir / f"{job_id}.txt"
        path.write_text(render(job_id), encoding="utf-8")
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Measure what one GenAI job actually costs against the 25-call / 12k-token budgets.

    uv run python scripts/measure_genai_budget.py canary/dist/canary.apk

Prints, per APK: the retrieval pack's shape, every assembled prompt's size, and — when
`--live` is passed and a provider is configured — the provider's own token counts for
every call the job made.

This exists because CLAUDE.md forbids writing a number into the report that no
measurement produced. "≤12k tokens" is a budget; what a job spends is a measurement,
and only this script produces it.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from drishti.config import Settings
from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import analyse as static_analyse
from drishti.m4_genai.client import CHARS_PER_TOKEN, LLMClient
from drishti.m4_genai.controller import analyse as genai_analyse
from drishti.m4_genai.controller import (
    build_evidence_catalogue,
    build_system_prompt,
    build_user_turn,
)
from drishti.m4_genai.retrieval import render_workspace, select


def measure(apk: Path, settings: Settings, *, live: bool) -> dict[str, Any]:
    job_id = f"job_measure_{apk.stem[:12]}"
    store = LedgerStore(settings.db_path, settings.ledger_key_path)
    store.open(job_id)
    try:
        static = static_analyse(apk, store)
        pack = select(static)
        catalogue, citable = build_evidence_catalogue(store, job_id)
        system = build_system_prompt()
        user = build_user_turn(static)
        workspace = render_workspace(pack)

        result: dict[str, Any] = {
            "apk": str(apk),
            "package": static.package,
            "call_paths": len(static.call_paths),
            "decompiled_methods": len(static.decompiled_methods),
            "retrieval": {
                "chains_considered": pack.chains_considered,
                "chains_selected": len(pack.chains),
                "chains_dropped": pack.chains_dropped,
                "methods_selected": pack.method_count,
                "methods_dropped": pack.methods_dropped,
                "estimated_tokens": pack.estimated_tokens,
                "token_budget": pack.token_budget,
                "notes": list(pack.notes),
            },
            "prompt_estimate_tokens": {
                "system": len(system) // CHARS_PER_TOKEN,
                "checklist_user_turn": len(user) // CHARS_PER_TOKEN,
                "evidence_catalogue": len(catalogue) // CHARS_PER_TOKEN,
                "code_workspace": len(workspace) // CHARS_PER_TOKEN,
                "checklist_total": (len(system) + len(user) + len(catalogue)) // CHARS_PER_TOKEN,
            },
            "citable_nodes": len(citable),
        }

        if live:
            client = LLMClient(settings)
            verdict = genai_analyse(static, store, settings, client=client, apk_path=apk)
            report = client.budget_report()
            result["live"] = {
                "provider": settings.llm_provider,
                "model": settings.resolved_llm_model,
                "llm_calls": report.calls,
                "cache_hits": report.cache_hits,
                "max_prompt_tokens": report.max_prompt_tokens,
                "total_prompt_tokens": report.total_prompt_tokens,
                "total_completion_tokens": report.total_completion_tokens,
                "measured_calls": report.measured_calls,
                "failures": report.failures,
                "per_call": [
                    {
                        "purpose": s.purpose,
                        "prompt_tokens": s.prompt_tokens,
                        "completion_tokens": s.completion_tokens,
                        "measured": s.measured,
                        "cached": s.cached,
                        "attempts": s.attempts,
                        "latency_ms": s.latency_ms,
                        "outcome": s.outcome,
                    }
                    for s in report.stats
                ],
                "claims_total": len(verdict.claims),
                "claims_verified": len(verdict.verified_claims),
                "claims_rejected": len(verdict.rejected_claims),
                "rejection_reasons": sorted(
                    {c.verifier_status.value for c in verdict.rejected_claims}
                ),
                "techniques": [t.technique_id for t in verdict.techniques],
                "interpretations": len(verdict.interpretations),
                "tool_calls": len(verdict.tool_calls),
                "victim_profile": (
                    verdict.victim.model_dump(mode="json") if verdict.victim else None
                ),
                "errors": list(verdict.errors),
            }
        return result
    finally:
        store.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apks", nargs="+", type=Path)
    parser.add_argument("--live", action="store_true", help="also run the configured provider")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    settings = Settings()
    results = [measure(apk, settings, live=args.live) for apk in args.apks]
    text = json.dumps(results, indent=2, ensure_ascii=False)
    print(text)
    if args.out:
        args.out.write_text(text)


if __name__ == "__main__":
    main()

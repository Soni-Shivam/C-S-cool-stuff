#!/usr/bin/env python3
"""Retrieval-only RAG ratio on real corpus APKs. Extractor VM.

The pitch number (REPORT 4.2.2): methods the backward walk selects vs methods the app
contains, and the prompt tokens that buys. Uses the SAME select()/render_workspace() the
controller uses — this is a lens on the real retrieval layer, not a reimplementation.

Runs only the retrieval measurement, deliberately: the full budget/timing path needs the
current m4_genai controller, and this VM's checkout predates its apk_path signature. The
ratio does not depend on that path.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

# androguard logs thousands of DEBUG lines through loguru; drop them so the one result
# line per sample is readable.
try:
    from loguru import logger as _loguru

    _loguru.remove()
except Exception:
    pass

sys.path.insert(0, str(Path.home() / "CyberShield"))

from androguard.misc import AnalyzeAPK

from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import analyse
from drishti.m4_genai.client import CHARS_PER_TOKEN
from drishti.m4_genai.retrieval import render_workspace, select


def total_methods(apk: Path) -> int:
    try:
        _, _, dx = AnalyzeAPK(str(apk))
        # internal methods only — external/framework methods are not the app's code
        return sum(1 for m in dx.get_methods() if not m.is_external())
    except Exception as exc:
        print(f"  total_methods failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return -1


def measure(apk: Path, label: str) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        store = LedgerStore(root / "l.db", root / "k.pem")
        store.open(f"rag_{label}")
        try:
            report = analyse(apk, store)
        finally:
            store.close()
    selection = select(report)
    workspace = render_workspace(selection)
    tokens = len(workspace) // CHARS_PER_TOKEN
    total = total_methods(apk)
    selected = selection.method_count
    call_paths = len(report.call_paths)
    ratio = (100.0 * selected / total) if total > 0 else float("nan")
    print(
        f"RESULT {label}: selected={selected} of total_methods={total} "
        f"({ratio:.3f}%) | call_paths={call_paths} | workspace_tokens={tokens} "
        f"(prompt budget 12000) | partial={report.partial}"
    )


def main() -> int:
    for arg in sys.argv[1:]:
        apk = Path(arg)
        label = apk.stem[:16]
        if not apk.exists():
            print(f"RESULT {label}: MISSING {apk}")
            continue
        try:
            measure(apk, label)
        except Exception as exc:
            print(f"RESULT {label}: ERROR {type(exc).__name__}: {exc}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

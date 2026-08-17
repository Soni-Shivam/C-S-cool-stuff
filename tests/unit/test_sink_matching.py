"""Sink markers must match the signature format androguard actually emits.

The sink layer was dead code for its entire life: androguard emits
`Lcom/foo/Bar; method (Args)Ret` with a SPACE separator, while every marker in the
taxonomy uses the smali `;->` form. The substring never matched, so every real sample
reported zero sinks and zero call paths — and that looks exactly like "this app does
nothing interesting" rather than like a bug.

No existing test caught it, because the call-graph tests build their graphs by hand
using the very format the matcher expected. This file tests the seam between
androguard's output and our matcher, which is where the defect actually lived.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import analyse, canonical_signature
from drishti.m2_static.sinks import SINK_SIGNATURES

CANARY = Path(__file__).resolve().parents[2] / "canary" / "dist" / "canary.apk"


def test_androguard_format_is_canonicalised() -> None:
    raw = "Landroid/content/pm/PackageManager; getPackageInfo (Ljava/lang/String; I)Landroid/x;"
    assert canonical_signature(raw) == "Landroid/content/pm/PackageManager;->getPackageInfo"


def test_canonicalisation_is_idempotent() -> None:
    once = canonical_signature("Lcom/foo/Bar; baz (I)V")
    assert canonical_signature(once) == once


def test_a_signature_without_the_separator_is_untouched() -> None:
    assert canonical_signature("already/canonical;->method") == "already/canonical;->method"


def test_markers_match_canonicalised_signatures() -> None:
    """The property that was false for the whole life of the sink taxonomy."""
    raw = "Landroid/content/pm/PackageManager; getPackageInfo (Ljava/lang/String; I)Landroid/x;"
    canonical = canonical_signature(raw)
    assert SINK_SIGNATURES["pkg_query"] in canonical, (
        "the pkg_query marker must match a real androguard signature once canonicalised"
    )
    assert SINK_SIGNATURES["pkg_query"] not in raw, (
        "and must NOT match the raw form — that mismatch is the bug this guards"
    )


@pytest.mark.skipif(not CANARY.exists(), reason="canary APK not built")
def test_the_canary_reaches_its_sinks_from_a_lifecycle_entrypoint() -> None:
    """End-to-end proof on a real APK, which is the only thing that caught this.

    `pkg_query` reachable from `onCreate` is the thread the entire frontier demo hangs
    on: the canary probes PackageManager at startup, the probe misses, a morph installs
    the package, and re-detonation turns the miss into a hit. While the matcher was
    broken this was invisible.
    """
    with tempfile.TemporaryDirectory() as scratch:
        tmp = Path(scratch)
        store = LedgerStore(tmp / "l.db", tmp / "k.pem")
        store.open("job_sink")
        try:
            report = analyse(CANARY, store)
        finally:
            store.close()

    assert report.sink_hits, "a real APK must reach at least one sink"
    assert "pkg_query" in report.sink_hits
    assert report.call_paths, "at least one attributed call path must be found"
    reachable = [p for p in report.call_paths if p.reachable_from_lifecycle]
    assert reachable, "a sink reachable from a lifecycle entrypoint must be found"
    assert any("onCreate" in p.entrypoint for p in reachable)

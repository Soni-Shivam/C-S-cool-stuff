#!/usr/bin/env python3
"""Generate report figures by *executing the real modules*, not by drawing mock-ups.

Every number in every figure this script emits is produced by calling the shipped code
path — `normaliser.aggregate`, `containment.is_reachable`, `evasion.detect`, the sink
taxonomy, the MITRE KB. Nothing is typed in by hand. That is the point: a figure in a
report is a claim, and CLAUDE.md's honesty requirements say a claim must trace to a
measurement.

Writes to docs/figures/. Safe to re-run; it overwrites deterministically and touches no
network, no GCP, and no sample.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from drishti.m2_static.sinks import SINKS
from drishti.m3_dynamic import evasion, normaliser
from drishti.m3_dynamic.containment import (
    NEGATIVE_CONTROL,
    assert_probe_trustworthy,
)
from drishti.m4_genai.safety import BEHAVIOUR_WEIGHTS

FIGURES = Path(__file__).resolve().parent.parent / "docs" / "figures"

# Matches the existing 01-07 figures so the report reads as one document.
INK = "#1a1a1a"
MUTED = "#5a6472"
GOLD = "#a06a12"
GREEN = "#1a6b46"
RED = "#a03028"
GRID = "#d8dce2"

plt.rcParams.update(
    {
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "axes.edgecolor": GRID,
        "axes.labelcolor": MUTED,
        "text.color": INK,
        "xtick.color": MUTED,
        "ytick.color": MUTED,
        "font.size": 11,
        "axes.grid": True,
        "grid.color": GRID,
        "grid.linewidth": 0.6,
        "axes.spines.top": False,
        "axes.spines.right": False,
    }
)


def _title(ax, title: str, subtitle: str = "") -> None:
    ax.set_title(title, loc="left", fontsize=15, fontweight="bold", pad=18 if subtitle else 10)
    if subtitle:
        ax.text(0, 1.02, subtitle, transform=ax.transAxes, fontsize=10.5, color=MUTED, va="bottom")


def _save(fig, name: str) -> None:
    path = FIGURES / name
    fig.savefig(path, dpi=160, bbox_inches="tight", facecolor="white")
    plt.close(fig)
    print(f"  wrote {path.relative_to(FIGURES.parent.parent)}")


def _crypto_events(n: int) -> list[dict[str, str]]:
    """The v1 case: one sample called Cipher.doFinal 1,925 times in 103 seconds."""
    return [
        {
            "technique": "crypto_operation",
            "mitre": "T1521",
            "source_hook": "Cipher.doFinal",
            "detail": "AES/CBC/PKCS5Padding, 256 bytes",
        }
        for _ in range(n)
    ]


def figure_rule11() -> dict[str, float]:
    """Rule 11: aggregation must not move the score. Run it and show the invariance."""
    one = normaliser.aggregate(_crypto_events(1))
    many = normaliser.aggregate(_crypto_events(1925))

    # Same shape, plus four other techniques, to show grouping across a realistic trace.
    mixed_events = [
        *_crypto_events(1925),
        {"technique": "sms_read", "mitre": "T1412", "source_hook": "SmsManager.getDefault"},
        {"technique": "code_load", "mitre": "T1407", "source_hook": "DexClassLoader.$init"},
        {"technique": "pkg_query", "mitre": "T1418", "source_hook": "PackageManager.getInstalled"},
        {"technique": "device_id", "mitre": "T1426", "source_hook": "TelephonyManager.getDeviceId"},
    ]
    mixed = normaliser.aggregate(mixed_events)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 4.6), gridspec_kw={"width_ratios": [1.15, 1]})

    labels = ["1 event", "1,925 events"]
    events = [one.total_events, many.total_events]
    groups = [len(one.groups), len(many.groups)]
    x = range(len(labels))
    ax1.bar([i - 0.19 for i in x], events, width=0.36, color=RED, label="raw events")
    ax1.bar([i + 0.19 for i in x], groups, width=0.36, color=GREEN, label="ledger nodes")
    ax1.set_yscale("log")
    ax1.set_xticks(list(x))
    ax1.set_xticklabels(labels)
    ax1.set_ylabel("count (log scale)")
    for i, (e, g) in enumerate(zip(events, groups, strict=True)):
        ax1.text(i - 0.19, e * 1.15, f"{e:,}", ha="center", fontweight="bold", fontsize=11)
        ax1.text(i + 0.19, g * 1.15, str(g), ha="center", fontweight="bold", fontsize=11)
    ax1.legend(frameon=False, loc="upper left")
    _title(
        ax1,
        "Rule 11 — aggregation before the ledger",
        "1,925 near-identical events collapse to one node. The 50-400 sanity band survives.",
    )

    ax2.axis("off")
    ax2.text(0, 0.92, "b_dynamic is unchanged", fontsize=14, fontweight="bold", color=INK)
    ax2.text(
        0,
        0.80,
        "The signal keys on which DISTINCT techniques fired\nand how severe they are — never on how often.",
        fontsize=10.5,
        color=MUTED,
        va="top",
    )
    rows = [
        ("1 event, 1 group", one.b_dynamic),
        ("1,925 events, 1 group", many.b_dynamic),
        (f"1,929 events, {len(mixed.groups)} groups", mixed.b_dynamic),
    ]
    for i, (label, value) in enumerate(rows):
        y = 0.52 - i * 0.15
        ax2.text(0, y, label, fontsize=11, color=INK)
        ax2.text(0.72, y, f"b_dynamic = {value:.4f}", fontsize=11, fontweight="bold", color=GOLD)
    identical = one.b_dynamic == many.b_dynamic
    ax2.text(
        0,
        0.04,
        ("IDENTICAL — occurrence count cannot move the score" if identical else "MISMATCH"),
        fontsize=11,
        fontweight="bold",
        color=GREEN if identical else RED,
    )
    _save(fig, "08_rule11_aggregation.png")
    return {
        "b_one": one.b_dynamic,
        "b_many": many.b_dynamic,
        "b_mixed": mixed.b_dynamic,
        "mixed_groups": len(mixed.groups),
        "identical": identical,
    }


def figure_containment() -> dict[str, bool]:
    """v1's probe passed vacuously. Run both probes and show the trustworthiness gate."""

    def v1_broken(_serial: str, _command: str) -> str:
        """toybox has no -z: `nc -z` exits 1 with 'Unknown option', for EVERY host."""
        return "nc: Unknown option 'z'\nDRISHTI_RC=1"

    def correct(_serial: str, command: str) -> str:
        # A truthful emulator: only the listener the positive control starts is reachable.
        if "45999" in command and "-l" not in command:
            return "DRISHTI_RC=0"
        if "-l" in command:
            return "DRISHTI_RC=0"
        return "DRISHTI_RC=1"

    def always_open(_serial: str, _command: str) -> str:
        return "DRISHTI_RC=0"

    probes = [
        ("v1's probe\n(nc -z)", v1_broken),
        ("always-reachable\nprobe", always_open),
        ("shipped probe", correct),
    ]
    results = []
    for label, runner in probes:
        ok, reason = assert_probe_trustworthy("emulator-5554", runner=runner)
        results.append((label, ok, reason))

    fig, ax = plt.subplots(figsize=(12.5, 4.4))
    ax.axis("off")
    _title(
        ax,
        "Containment verification is a test, not a claim",
        f"assert_probe_trustworthy() runs a negative control ({NEGATIVE_CONTROL[0]}:{NEGATIVE_CONTROL[1]}) "
        "and a positive control before any verdict is believed.",
    )
    for i, (label, ok, reason) in enumerate(results):
        y = 0.66 - i * 0.235
        colour = GREEN if ok else RED
        ax.add_patch(
            plt.Rectangle(
                (0, y - 0.055),
                1.0,
                0.19,
                transform=ax.transAxes,
                facecolor=(colour + "18"),
                edgecolor="none",
                zorder=0,
            )
        )
        ax.text(0.015, y + 0.075, label.replace("\n", " "), fontsize=11.5, fontweight="bold")
        ax.text(
            0.30,
            y + 0.075,
            "TRUSTED" if ok else "REJECTED",
            fontsize=11.5,
            fontweight="bold",
            color=colour,
        )
        ax.text(0.44, y + 0.078, reason[:78], fontsize=9.5, color=MUTED)
    ax.text(
        0.015,
        0.02,
        "v1 shipped the first row: every containment check passed regardless of the real "
        "network state,\nand the signed manifest attested containment that had never been tested.",
        fontsize=10,
        color=RED,
        style="italic",
    )
    _save(fig, "09_containment_probe.png")
    return {label: ok for label, ok, _ in results}


def figure_evasion() -> dict[str, str]:
    """The frontier trigger. Three trace shapes through the real detector."""
    probe_only = normaliser.aggregate(
        [
            {
                "technique": "pkg_query",
                "mitre": "T1418",
                "source_hook": "PackageManager.getInstalled",
            },
            {
                "technique": "device_id",
                "mitre": "T1426",
                "source_hook": "TelephonyManager.getDeviceId",
            },
        ]
    )
    silent = normaliser.aggregate([])
    # An app that found what it wanted is loud. Below QUIET_EVENT_THRESHOLD (12) even a
    # trace with real actions is called stalling — a probe followed by three events is
    # not an app getting on with its job.
    active = normaliser.aggregate(
        [
            {
                "technique": "pkg_query",
                "mitre": "T1418",
                "source_hook": "PackageManager.getInstalled",
            },
            *_crypto_events(14),
            *[
                {"technique": "sms_read", "mitre": "T1412", "source_hook": "SmsManager.getDefault"}
                for _ in range(4)
            ],
            {"technique": "code_load", "mitre": "T1407", "source_hook": "DexClassLoader.$init"},
        ]
    )

    cases = [
        ("probes, then nothing", probe_only),
        ("no observations at all", silent),
        (f"probes AND {active.total_events} events of real action", active),
    ]
    fig, ax = plt.subplots(figsize=(12.5, 4.6))
    ax.axis("off")
    _title(
        ax,
        "Evasion detection — what triggers a morph",
        "A sample that only asks questions is stalling. A sample that acts is not, even if it also asked.",
    )
    out = {}
    for i, (label, trace) in enumerate(cases):
        verdict = evasion.detect(trace)
        out[label] = verdict.reason
        y = 0.66 - i * 0.235
        colour = RED if verdict.stalled else GREEN
        ax.add_patch(
            plt.Rectangle(
                (0, y - 0.055),
                1.0,
                0.19,
                transform=ax.transAxes,
                facecolor=(colour + "18"),
                edgecolor="none",
                zorder=0,
            )
        )
        ax.text(0.015, y + 0.088, label, fontsize=11.5, fontweight="bold")
        ax.text(
            0.30,
            y + 0.088,
            "STALLED" if verdict.stalled else "RAN",
            fontsize=11.5,
            fontweight="bold",
            color=colour,
        )
        morphs = ", ".join(verdict.morphs) if verdict.morphs else "—"
        ax.text(0.44, y + 0.115, f"morphs: {morphs}", fontsize=10, color=INK)
        ax.text(0.44, y + 0.035, verdict.reason[:84], fontsize=9, color=MUTED)
    ax.text(
        0.015,
        0.02,
        "A sample that produced no observations is inconclusive, never benign — "
        "environment-aware stalling\nlooks identical to a clean app if you let it.",
        fontsize=10,
        color=MUTED,
        style="italic",
    )
    _save(fig, "10_evasion_detection.png")
    return out


def figure_detection_surface() -> dict[str, int]:
    """What the system can actually recognise, counted from the shipped taxonomies."""
    kb = json.loads((FIGURES.parent.parent / "data" / "kb" / "mitre_mobile.json").read_text())
    techniques = kb["techniques"]

    categories: dict[str, int] = {}
    for sink in SINKS:
        categories[sink.category] = categories.get(sink.category, 0) + 1

    sink_mitre = {s.mitre for s in SINKS}
    dynamic_mitre = set(normaliser.TECHNIQUE_SEVERITY)
    covered = (sink_mitre | dynamic_mitre) & set(techniques)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13.5, 5.2), gridspec_kw={"width_ratios": [1, 1]})

    names = sorted(categories, key=lambda k: categories[k])
    ax1.barh(names, [categories[n] for n in names], color=GOLD, height=0.68)
    for i, n in enumerate(names):
        ax1.text(categories[n] + 0.08, i, str(categories[n]), va="center", fontsize=10)
    ax1.set_xlabel("sinks")
    _title(ax1, f"Static sink taxonomy — {len(SINKS)} sinks", f"{len(categories)} categories")

    ax2.axis("off")
    _title(
        ax2,
        "MITRE ATT&CK Mobile coverage",
        "Mapping is deterministic — the LLM is not in this path.",
    )
    stats = [
        ("techniques in KB", len(techniques)),
        ("reachable from static sinks", len(sink_mitre & set(techniques))),
        ("reachable from dynamic hooks", len(dynamic_mitre & set(techniques))),
        ("covered by at least one layer", len(covered)),
        ("behaviours in the weight table", len(BEHAVIOUR_WEIGHTS)),
    ]
    for i, (label, value) in enumerate(stats):
        y = 0.72 - i * 0.135
        ax2.text(0, y, label, fontsize=11.5, color=INK)
        ax2.text(0.86, y, str(value), fontsize=13, fontweight="bold", color=GOLD, ha="right")
        ax2.plot([0, 0.88], [y - 0.035, y - 0.035], color=GRID, lw=0.8)
    ax2.text(
        0,
        0.03,
        "An id absent from the KB is dropped, never passed through with a blank name.",
        fontsize=9.5,
        color=MUTED,
        style="italic",
    )
    _save(fig, "11_detection_surface.png")
    return {
        "sinks": len(SINKS),
        "categories": len(categories),
        "kb_techniques": len(techniques),
        "covered": len(covered),
        "behaviours": len(BEHAVIOUR_WEIGHTS),
    }


def main() -> int:
    FIGURES.mkdir(parents=True, exist_ok=True)
    print("generating report figures from live module calls")
    summary = {
        "rule11": figure_rule11(),
        "containment": figure_containment(),
        "evasion": figure_evasion(),
        "detection_surface": figure_detection_surface(),
    }
    out = FIGURES / "generated_metrics.json"
    out.write_text(json.dumps(summary, indent=2, default=str) + "\n")
    print(f"  wrote {out.relative_to(FIGURES.parent.parent)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

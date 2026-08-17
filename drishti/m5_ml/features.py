"""The sole shared static-report feature extractor for training and inference."""

from __future__ import annotations

from dataclasses import dataclass
from math import log1p

from drishti.contracts.static_report import ComponentKind, StaticReport

FEATURE_SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True)
class FeatureVector:
    """A named sparse vector; callers may project it onto a frozen training vocabulary."""

    schema_version: str
    values: dict[str, float]


def extract(static: StaticReport) -> FeatureVector:
    """Extract deterministic Drebin-style features from exactly one StaticReport."""
    values: dict[str, float] = {}
    for permission in static.permissions:
        values[f"perm:{permission.rsplit('.', 1)[-1]}"] = 1.0
    for combo in static.permission_combos:
        values[f"combo:{combo.rule_id}"] = 1.0
    for sink in static.sink_hits:
        values[f"sink:{sink}"] = 1.0
    for kind in ComponentKind:
        count = sum(component.kind is kind for component in static.components)
        values[f"component:{kind.value}:log_count"] = log1p(count)
    values.update(
        {
            "archive:entropy_mean": static.entropy_mean,
            "archive:dex_count": float(static.dex_count),
            "archive:native_lib_count": float(len(static.native_libs)),
            "archive:packer_hint_count": float(len(static.packer_hints)),
            "cert:age_days": float(static.certificate.age_days),
            "cert:brand_mismatch": float(static.certificate.brand_mismatch),
            "cert:known_bad_reuse": float(static.certificate.known_bad_reuse),
            "cert:debug": float(static.certificate.debug_cert),
            "drift:declared_not_used": float(len(static.declared_not_used)),
            "drift:used_not_declared": float(len(static.used_not_declared)),
        }
    )
    return FeatureVector(schema_version=FEATURE_SCHEMA_VERSION, values=dict(sorted(values.items())))

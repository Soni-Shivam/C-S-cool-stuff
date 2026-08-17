"""The sole shared static-report feature extractor for training and inference.

docs/PHASE_2_ML_AND_SCORING.md T2.1, docs/00_GUIDING_MAP.md §11 risk R3.

**There is no second code path.** Training calls `extract()` over `StaticReport`s produced
by running real M2 on the corpus; inference calls it on the live `StaticReport`. R3 —
train/inference feature skew — is rated High probability and "model useless in prod", and
the defence is structural rather than careful: one function, one frozen vocabulary, and
`tests/contract/test_feature_parity.py` asserting both.

Features are emitted as a **named sparse mapping**, then projected onto a frozen
vocabulary by `project()`. Naming matters beyond tidiness: SHAP explanations render
`perm:RECEIVE_SMS` rather than `f_0142`, which is what makes the explainability panel
worth showing.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from math import log1p
from pathlib import Path
from urllib.parse import urlparse

from drishti.contracts.static_report import ComponentKind, StaticReport

#: Bump ONLY with a regenerated golden file in the same commit. The parity test compares
#: this, so a silent bump would turn the R3 tripwire into a rubber stamp.
FEATURE_SCHEMA_VERSION = "1.1.0"

#: Substrings that mark a suspicious API surface. Kept explicit and small rather than
#: learned: this list is read by humans during triage and cited in the report.
SUSPICIOUS_API_TOKENS: tuple[str, ...] = (
    "getDeviceId",
    "getSubscriberId",
    "getSimSerialNumber",
    "sendTextMessage",
    "getInstalledPackages",
    "getPackageInfo",
    "DexClassLoader",
    "PathClassLoader",
    "loadClass",
    "Cipher",
    "doFinal",
    "Runtime.exec",
    "ProcessBuilder",
    "setComponentEnabledSetting",
    "addView",
    "AccessibilityService",
    "getClipboardManager",
    "getPrimaryClip",
    "MediaProjection",
    "NotificationListenerService",
    "getAccountsByType",
    "getLastKnownLocation",
    "registerReceiver",
    "getMemoryInfo",
)

#: URL shorteners collapse the destination, so their presence is itself a signal.
_SHORTENER_HOSTS: frozenset[str] = frozenset(
    {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"}
)

_IP_LITERAL = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

#: Analytics/CDN hosts that appear in overwhelmingly benign apps. A URL to one of these
#: is not evidence, and counting it as such would swamp the genuine C2 signal.
_KNOWN_GOOD_SUFFIXES: tuple[str, ...] = (
    "googleapis.com",
    "google.com",
    "gstatic.com",
    "crashlytics.com",
    "facebook.com",
    "cloudflare.com",
    "android.com",
    "schemas.android.com",
)


@dataclass(frozen=True)
class FeatureVector:
    """A named sparse vector; callers project it onto a frozen training vocabulary."""

    schema_version: str
    values: dict[str, float]


def _short(permission: str) -> str:
    return permission.rsplit(".", 1)[-1]


def _url_features(urls: tuple[str, ...]) -> dict[str, float]:
    """Shape of the outbound surface, without trusting any single URL.

    Counts and flags only — never the URL itself, which would put attacker-controlled
    strings into a feature name and, through SHAP, into the report.
    """
    hosts: list[str] = []
    for raw in urls:
        try:
            host = (urlparse(raw).hostname or "").lower()
        except ValueError:
            continue
        if host:
            hosts.append(host)

    unknown = [
        h for h in hosts if not any(h == s or h.endswith("." + s) for s in _KNOWN_GOOD_SUFFIXES)
    ]
    return {
        "url:count": float(len(urls)),
        "url:distinct_hosts": float(len(set(hosts))),
        "url:unknown_host_count": float(len(unknown)),
        "url:has_ip_literal": float(any(_IP_LITERAL.match(h) for h in hosts)),
        "url:has_shortener": float(any(h in _SHORTENER_HOSTS for h in hosts)),
        "url:has_cleartext": float(any(u.lower().startswith("http://") for u in urls)),
        "url:has_non_standard_port": float(
            any(":" in h for h in (u.split("//")[-1].split("/")[0] for u in urls))
        ),
    }


def extract(static: StaticReport) -> FeatureVector:
    """Extract deterministic Drebin-style features from exactly one StaticReport.

    The ONLY feature extractor. Training and inference both call this; there is no
    second path, and `tests/contract/test_feature_parity.py` is what keeps it that way.
    """
    values: dict[str, float] = {}

    # ── requested permissions ────────────────────────────────────────────────
    for permission in static.permissions:
        values[f"perm:{_short(permission)}"] = 1.0
    values["perm:count"] = float(len(static.permissions))

    # ── permission combinations (the signal is the combination, not the permission) ──
    for combo in static.permission_combos:
        values[f"combo:{combo.rule_id}"] = 1.0
    values["combo:count"] = float(len(static.permission_combos))

    # ── components ───────────────────────────────────────────────────────────
    for kind in ComponentKind:
        count = sum(component.kind is kind for component in static.components)
        values[f"component:{kind.value}:log_count"] = log1p(count)
    total_components = len(static.components) or 1
    values["component:exported_unprotected"] = float(len(static.exported_unprotected))
    values["component:exported_ratio"] = len(static.exported_unprotected) / total_components

    # ── intent surface ───────────────────────────────────────────────────────
    # Deep links on exported components are a genuine Level-2 finding (PHASE_1 T1.1).
    for scheme in static.deep_link_schemes:
        values[f"intent:scheme:{scheme.lower()}"] = 1.0
    values["intent:deep_link_count"] = float(len(static.deep_link_schemes))
    values["intent:has_custom_scheme"] = float(
        any(s.lower() not in ("http", "https") for s in static.deep_link_schemes)
    )

    # ── sinks, and whether they can actually run ─────────────────────────────
    for sink in static.sink_hits:
        values[f"sink:{sink}"] = 1.0
    values["sink:count"] = float(len(static.sink_hits))

    # `reachable_from_lifecycle` separates "this code exists" from "this code runs".
    # Dead library code reaches sinks constantly and must not score like live code.
    reachable = {p.sink_id for p in static.call_paths if p.reachable_from_lifecycle}
    for sink_id in reachable:
        values[f"reach:{sink_id}"] = 1.0
    values["reach:count"] = float(len(reachable))
    values["reach:path_count"] = float(len(static.call_paths))
    values["reach:min_depth"] = float(
        min((len(p.path) for p in static.call_paths if p.reachable_from_lifecycle), default=0)
    )

    # ── suspicious API surface ───────────────────────────────────────────────
    haystack = " ".join(
        [*(p.sink_signature for p in static.call_paths), *static.dcl_indicators, *static.sink_hits]
    )
    for token in SUSPICIOUS_API_TOKENS:
        values[f"api:{token}"] = float(token in haystack)
    values["api:dcl_indicator_count"] = float(len(static.dcl_indicators))
    values["api:reflection_count"] = float(static.reflection_count)
    values["api:crypto_constant_count"] = float(len(static.crypto_constants))

    # ── outbound surface ─────────────────────────────────────────────────────
    values.update(_url_features(static.urls))

    # ── packing / obfuscation ────────────────────────────────────────────────
    values.update(
        {
            "archive:entropy_mean": static.entropy_mean,
            "archive:dex_count": float(static.dex_count),
            "archive:multi_dex": float(static.dex_count > 1),
            "archive:native_lib_count": float(len(static.native_libs)),
            "archive:packer_hint_count": float(len(static.packer_hints)),
            "archive:high_entropy": float(static.entropy_mean > 7.2),
        }
    )
    for hint in static.packer_hints:
        values[f"archive:packer:{hint.lower()}"] = 1.0

    # ── certificate ──────────────────────────────────────────────────────────
    # Deliberately NOT "self-signed": every Android APK is. Age, reuse and brand
    # mismatch are the discriminating signals (PHASE_1 T1.2).
    values.update(
        {
            "cert:age_days": float(static.certificate.age_days),
            "cert:is_fresh": float(static.certificate.age_days < 90),
            "cert:brand_mismatch": float(static.certificate.brand_mismatch),
            "cert:known_bad_reuse": float(static.certificate.known_bad_reuse),
            "cert:debug": float(static.certificate.debug_cert),
        }
    )

    # ── over-privilege drift (static half of the D term) ─────────────────────
    declared = len(static.permissions) or 1
    values.update(
        {
            "drift:declared_not_used": float(len(static.declared_not_used)),
            "drift:used_not_declared": float(len(static.used_not_declared)),
            "drift:overprivilege_ratio": len(static.declared_not_used) / declared,
            "drift:has_undeclared_use": float(bool(static.used_not_declared)),
        }
    )

    # ── manifest hygiene ─────────────────────────────────────────────────────
    values.update(
        {
            "manifest:min_sdk": float(static.min_sdk),
            "manifest:target_sdk": float(static.target_sdk),
            "manifest:sdk_gap": float(static.target_sdk - static.min_sdk),
            # targetSdk < 31 keeps the legacy implicit-export default, which is how
            # unprotected components usually get there.
            "manifest:legacy_export_semantics": float(0 < static.target_sdk < 31),
            "manifest:very_old_min_sdk": float(0 < static.min_sdk < 21),
        }
    )

    return FeatureVector(schema_version=FEATURE_SCHEMA_VERSION, values=dict(sorted(values.items())))


# ── vocabulary pinning ───────────────────────────────────────────────────────
def build_vocabulary(vectors: list[FeatureVector]) -> list[str]:
    """Freeze the feature names seen across the TRAINING set, sorted.

    Sorted so column *i* means the same thing on every call and on every machine. Called
    once, at training time; inference loads the result and never recomputes it.
    """
    names: set[str] = set()
    for vector in vectors:
        names.update(vector.values)
    return sorted(names)


def project(vector: FeatureVector, vocabulary: list[str]) -> list[float]:
    """Project a sparse vector onto the frozen vocabulary, in vocabulary order.

    Two rules, and R3 lives in both:
      * a name absent from the vector is **zero-filled**, never omitted
      * a name absent from the vocabulary is **dropped**, never appended

    Appending an unseen feature would shift every later column and hand the model a
    vector it was never trained on — skew that no exception would announce.
    """
    return [float(vector.values.get(name, 0.0)) for name in vocabulary]


def load_vocabulary(path: Path) -> list[str]:
    """Load the frozen vocabulary. Inference uses this; it never calls build_vocabulary."""
    payload = json.loads(Path(path).read_text())
    if payload.get("schema_version") != FEATURE_SCHEMA_VERSION:
        raise ValueError(
            f"vocabulary at {path} was built for schema "
            f"{payload.get('schema_version')!r}, extractor is {FEATURE_SCHEMA_VERSION!r} — "
            "retrain rather than projecting onto a stale vocabulary"
        )
    return list(payload["features"])


def _write_golden() -> int:
    """Regenerate the committed parity fixture.

    Kept in the module so the failure message in `test_feature_parity.py` names a command
    that actually exists. Regenerating must be a deliberate act with a reviewable diff —
    never something a test does for itself, which would make the R3 tripwire a no-op.
    """
    import tempfile

    from drishti.ledger.store import LedgerStore
    from drishti.m2_static.engine import analyse

    repo = Path(__file__).resolve().parents[2]
    apk = repo / "canary" / "dist" / "canary.apk"
    if not apk.exists():
        print(f"error: {apk} is missing — run `bash canary/build.sh`")
        return 2

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
        store.open("job_golden")
        try:
            vector = extract(analyse(apk, store))
        finally:
            store.close()

    out = repo / "data" / "fixtures" / "features" / "canary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {"schema_version": vector.schema_version, "values": vector.values},
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    print(f"wrote {out} — {len(vector.values)} features, schema {vector.schema_version}")
    return 0


if __name__ == "__main__":
    import sys

    if "--write-golden" in sys.argv:
        raise SystemExit(_write_golden())
    print(__doc__)

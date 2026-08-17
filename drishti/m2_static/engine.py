"""Defensive, in-process APK static analysis.

Parsing here reads an APK as data. It never invokes ``adb``, starts an emulator, or
executes application code; real sample paths are still restricted to the extractor VM.
"""

from __future__ import annotations

import hashlib
import math
import re
import time
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

import networkx as nx  # type: ignore[import-untyped]

from drishti.contracts.evidence import EvidenceType
from drishti.contracts.static_report import (
    CallPath,
    CertificateInfo,
    Component,
    ComponentKind,
    StaticReport,
)
from drishti.ledger.store import LedgerStore
from drishti.m2_static.callgraph import backward_paths
from drishti.m2_static.hypotheses import derive_hypotheses
from drishti.m2_static.rules import effective_exported, evaluate_permission_combos
from drishti.m2_static.sinks import SINK_SIGNATURES

_URL = re.compile(r"https?://[^\s\"']+", re.IGNORECASE)
_PACKAGE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}$")
_CRYPTO = re.compile(r"(?:AES|DES|RSA)/(?:CBC|ECB|GCM)/[A-Za-z0-9]+")
#: Imported from the taxonomy so there is ONE definition of what a sink is.
#: drishti/m2_static/sinks.py carries severity and MITRE mapping alongside each marker.
_SINKS = SINK_SIGNATURES
_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def analyse(apk_path: Path, ledger: LedgerStore) -> StaticReport:
    """Return a partial-but-valid report when any static sub-analyser cannot parse input."""
    started = time.monotonic()
    digest = _sha256(apk_path)
    errors: list[str] = []
    refs: list[str] = []
    try:
        from androguard.misc import AnalyzeAPK

        apk, dalvik, analysis = AnalyzeAPK(str(apk_path))
    except Exception as exc:
        return _empty_report(
            digest,
            errors=(f"androguard parse failed: {type(exc).__name__}: {exc}",),
            duration_ms=_duration(started),
        )

    try:
        package = str(apk.get_package() or "unknown")
        label = str(apk.get_app_name() or package)
        version_name = str(apk.get_androidversion_name() or "unknown")
        version_code = _as_int(apk.get_androidversion_code())
        min_sdk = _as_int(apk.get_min_sdk_version())
        target_sdk = _as_int(apk.get_target_sdk_version())
        permissions = tuple(sorted(set(apk.get_permissions() or [])))
        components = _components(apk, target_sdk)
        permission_refs = _write_manifest_evidence(ledger, permissions, components)
        refs.extend(permission_refs.values())
        combos = evaluate_permission_combos(permissions=set(permissions), components=components)
        for combo in combos:
            node = ledger.append(
                type=EvidenceType.PERMISSION_COMBO,
                source_tool="m2.rules",
                content=combo.model_dump(mode="json"),
                parents=tuple(
                    permission_refs[p] for p in combo.permissions if p in permission_refs
                ),
            )
            refs.append(node.id)
        # AnalyzeAPK returns one DalvikVMFormat per DEX (a list even for a single-dex APK).
        strings = tuple(str(value) for vm in dalvik for value in vm.get_strings())
        urls = tuple(sorted({_defang(value) for value in strings if _URL.search(value)}))[:100]
        package_strings = tuple(sorted({value for value in strings if _PACKAGE.match(value)}))[:200]
        crypto = tuple(sorted({value for value in strings if _CRYPTO.search(value)}))[:100]
        dcl = tuple(
            value for value in strings if "DexClassLoader" in value or "PathClassLoader" in value
        )[:20]
        reflection_count = sum("java/lang/reflect" in value for value in strings)
        for value in (*urls, *package_strings[:40], *crypto[:40]):
            node = ledger.append(
                type=EvidenceType.STRING_CONST,
                source_tool="androguard",
                content={"value": value, "kind": _string_kind(value)},
                location=None,
            )
            refs.append(node.id)
        graph = _call_graph(analysis)
        sink_hits, paths = _sink_paths(graph, components)
        for sink_id in sorted(sink_hits):
            node = ledger.append(
                type=EvidenceType.SINK_HIT,
                source_tool="androguard",
                content={"sink_id": sink_id, "signature": _SINKS[sink_id]},
            )
            refs.append(node.id)
        for path in paths:
            node = ledger.append(
                type=EvidenceType.CALL_PATH,
                source_tool="androguard",
                content=path.model_dump(mode="json"),
                parents=tuple(refs[-1:]),
            )
            refs.append(node.id)
        entropy_mean, packer_hints, native_libs, dex_count = _archive_signals(apk_path)
        certificate = _certificate(apk, label, package, errors)
        cert_node = ledger.append(
            type=EvidenceType.CERTIFICATE,
            source_tool="androguard",
            content=certificate.model_dump(mode="json"),
        )
        refs.append(cert_node.id)
        hypotheses = derive_hypotheses(
            sink_hits=set(sink_hits),
            permission_combos=combos,
            package_strings=package_strings,
            urls=urls,
            dcl_indicators=dcl,
            evidence_refs=tuple(refs[-12:]),
        )
        for hypothesis in hypotheses:
            node = ledger.append(
                type=EvidenceType.AI_HYPOTHESIS,
                source_tool="m2.hypotheses",
                content=hypothesis.model_dump(mode="json"),
                parents=hypothesis.evidence_refs,
            )
            refs.append(node.id)
        return StaticReport(
            sha256=digest,
            package=package,
            app_label=label,
            version_name=version_name,
            version_code=version_code,
            min_sdk=min_sdk,
            target_sdk=target_sdk,
            permissions=permissions,
            permission_combos=combos,
            components=components,
            exported_unprotected=tuple(c for c in components if c.exported and not c.permission),
            certificate=certificate,
            native_libs=native_libs,
            dex_count=dex_count,
            entropy_mean=entropy_mean,
            packer_hints=packer_hints,
            dcl_indicators=dcl,
            reflection_count=reflection_count,
            urls=urls,
            crypto_constants=crypto,
            call_paths=paths,
            sink_hits=tuple(sorted(sink_hits)),
            hypotheses=hypotheses,
            ledger_refs=tuple(refs),
            partial=bool(errors),
            errors=tuple(errors),
            duration_ms=_duration(started),
        )
    except Exception as exc:
        errors.append(f"static analysis degraded: {type(exc).__name__}: {exc}")
        return _empty_report(digest, errors=tuple(errors), duration_ms=_duration(started))


def _components(apk: Any, target_sdk: int) -> tuple[Component, ...]:
    """Read component facts from Androguard 4's parsed manifest XML tree."""
    output: list[Component] = []
    for element in apk.get_android_manifest_xml().iter():
        local_name = str(element.tag).rsplit("}", 1)[-1]
        if local_name not in {kind.value for kind in ComponentKind}:
            continue
        name = element.get(f"{_ANDROID_NS}name")
        if not name:
            continue
        raw = element.get(f"{_ANDROID_NS}exported")
        permission = element.get(f"{_ANDROID_NS}permission")
        has_intent_filter = any(
            str(child.tag).rsplit("}", 1)[-1] == "intent-filter" for child in element
        )
        output.append(
            Component(
                name=str(name),
                kind=ComponentKind(local_name),
                exported=effective_exported(
                    explicit=None if raw is None else raw.lower() == "true",
                    has_intent_filter=has_intent_filter,
                    target_sdk=target_sdk,
                ),
                permission=str(permission) if permission else None,
            )
        )
    return tuple(output)


def _write_manifest_evidence(
    ledger: LedgerStore, permissions: tuple[str, ...], components: tuple[Component, ...]
) -> dict[str, str]:
    refs: dict[str, str] = {}
    for permission in permissions:
        refs[permission] = ledger.append(
            type=EvidenceType.MANIFEST_ENTRY,
            source_tool="androguard",
            content={"kind": "permission", "name": permission},
        ).id
    for component in components:
        ledger.append(
            type=EvidenceType.MANIFEST_ENTRY,
            source_tool="androguard",
            content={"kind": component.kind.value, **component.model_dump(mode="json")},
        )
    return refs


def _call_graph(analysis: Any) -> nx.DiGraph:
    graph = nx.DiGraph()
    for method in analysis.get_methods():
        if method.is_external():
            continue
        source = method.full_name
        for _, callee, _ in method.get_xref_to():
            graph.add_edge(source, callee.full_name)
    return graph


def _sink_paths(
    graph: nx.DiGraph, components: tuple[Component, ...]
) -> tuple[set[str], tuple[CallPath, ...]]:
    entrypoints = {
        node: "lifecycle"
        for node in graph
        if any(
            name in node
            for name in (
                "->onCreate(",
                "->onReceive(",
                "->onStartCommand(",
                "->onAccessibilityEvent(",
            )
        )
    }
    hits: set[str] = set()
    paths: list[CallPath] = []
    for sink_id, marker in _SINKS.items():
        for node in graph:
            if marker in node:
                hits.add(sink_id)
                paths.extend(
                    item.model_copy(update={"sink_id": sink_id, "sink_signature": node})
                    for item in backward_paths(graph, sink=node, entrypoints=entrypoints)
                )
    del components
    return hits, tuple(paths[:30])


def _archive_signals(path: Path) -> tuple[float, tuple[str, ...], tuple[str, ...], int]:
    with zipfile.ZipFile(path) as archive:
        dexes = [entry for entry in archive.infolist() if entry.filename.endswith(".dex")]
        entropies = [_entropy(archive.read(entry)) for entry in dexes]
        natives = tuple(
            sorted(
                entry.filename
                for entry in archive.infolist()
                if entry.filename.startswith("lib/") and entry.filename.endswith(".so")
            )
        )
    mean = sum(entropies) / len(entropies) if entropies else 0.0
    hints = ("high_entropy_dex",) if mean > 7.2 else ()
    return mean, hints, natives, max(len(dexes), 1)


def _certificate(apk: Any, label: str, package: str, errors: list[str]) -> CertificateInfo:
    try:
        cert = apk.get_certificates()[0]
        raw = cert.dump() if hasattr(cert, "dump") else bytes(cert)
        subject = str(cert.subject)
        issuer = str(cert.issuer)
        return CertificateInfo(
            sha256=hashlib.sha256(raw).hexdigest(),
            subject=subject,
            issuer=issuer,
            not_before="unknown",
            not_after="unknown",
            age_days=0,
            self_signed=subject == issuer,
            debug_cert="Android Debug" in subject,
            brand_mismatch=False,
            brand_claimed=None,
        )
    except Exception as exc:
        errors.append(f"certificate unavailable: {type(exc).__name__}")
        return CertificateInfo(
            sha256="0" * 64,
            subject="unknown",
            issuer="unknown",
            not_before="unknown",
            not_after="unknown",
            age_days=0,
            self_signed=False,
        )


def _empty_report(digest: str, *, errors: tuple[str, ...], duration_ms: int) -> StaticReport:
    return StaticReport(
        sha256=digest,
        package="unknown",
        app_label="unknown",
        version_name="unknown",
        version_code=0,
        min_sdk=0,
        target_sdk=0,
        certificate=CertificateInfo(
            sha256="0" * 64,
            subject="unknown",
            issuer="unknown",
            not_before="unknown",
            not_after="unknown",
            age_days=0,
            self_signed=False,
        ),
        partial=True,
        errors=errors,
        duration_ms=duration_ms,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    return -sum(
        (count / len(data)) * math.log2(count / len(data)) for count in Counter(data).values()
    )


def _as_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _duration(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


def _defang(value: str) -> str:
    return value.replace("http://", "hxxp://").replace("https://", "hxxps://")


def _string_kind(value: str) -> str:
    if value.startswith("hxxp"):
        return "url"
    if _PACKAGE.match(value):
        return "package"
    return "crypto"

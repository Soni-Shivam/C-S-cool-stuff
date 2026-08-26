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
        from drishti.m2_static.decompile import decompile_sink_methods

        decompiled_methods, decompile_errors = decompile_sink_methods(
            dalvik, analysis, paths, ledger
        )
        errors.extend(decompile_errors)
        refs.extend(method.evidence_ref for method in decompiled_methods)
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
        report = StaticReport(
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
            decompiled_methods=decompiled_methods,
            sink_hits=tuple(sorted(sink_hits)),
            hypotheses=hypotheses,
            ledger_refs=tuple(refs),
            partial=bool(errors),
            errors=tuple(errors),
            duration_ms=_duration(started),
        )

        # The benign-lookalike assessment runs LAST, because it reasons over the
        # assembled report — call paths, extracted strings, the certificate — rather
        # than over the APK. Permissions alone cannot separate a banking trojan from
        # Truecaller, which holds the same ones; this is what does.
        #
        # Wrapped: a failure here must degrade the report, never lose it. The whole
        # static analysis is more valuable than this one field.
        try:
            from drishti.m2_static.lookalike import assess as _assess_lookalike

            assessment = _assess_lookalike(report)
            lookalike_node = ledger.append(
                type=EvidenceType.OVERPRIVILEGE,
                source_tool="m2.lookalike",
                content=assessment.model_dump(mode="json"),
            )
            report = report.model_copy(
                update={
                    "lookalike": assessment,
                    "ledger_refs": (*report.ledger_refs, lookalike_node.id),
                }
            )
        except Exception as exc:  # pragma: no cover - defensive
            report = report.model_copy(
                update={
                    "partial": True,
                    "errors": (
                        *report.errors,
                        f"lookalike assessment failed: {type(exc).__name__}: {exc}",
                    ),
                }
            )
        return report
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


#: Components recorded individually before falling back to an aggregate. Real apps carry
#: hundreds; one measured sample had 453, which alone put a run at 516 ledger nodes
#: against the 50-400 sanity band in 00_GUIDING_MAP.md 12.
MAX_INDIVIDUAL_COMPONENTS = 25


def _write_manifest_evidence(
    ledger: LedgerStore, permissions: tuple[str, ...], components: tuple[Component, ...]
) -> dict[str, str]:
    """Record manifest facts without flooding the ledger.

    Permissions keep one node each: combo rules cite them as `parents`, so they must be
    individually addressable for the evidence graph to be a graph rather than a list.

    Components do not. A real app has hundreds of them and almost all are ordinary UI —
    one measured sample produced 453, putting a single run at 516 nodes against the
    50-400 band. This is the same aggregation rule CLAUDE.md rule 11 already demands for
    dynamic events, applied where the same explosion happens statically.

    What survives individually is what an analyst would actually click: components that
    are **exported without permission protection**, which is the attack surface. The rest
    are summarised per kind with counts, so nothing is lost from the report — only from
    the node count.
    """
    refs: dict[str, str] = {}
    for permission in permissions:
        refs[permission] = ledger.append(
            type=EvidenceType.MANIFEST_ENTRY,
            source_tool="androguard",
            content={"kind": "permission", "name": permission},
        ).id

    # Exported-and-unprotected first: these are the ones worth a node of their own.
    interesting = [c for c in components if c.exported and not c.permission]
    remainder = [c for c in components if not (c.exported and not c.permission)]
    for component in interesting[:MAX_INDIVIDUAL_COMPONENTS]:
        ledger.append(
            type=EvidenceType.MANIFEST_ENTRY,
            source_tool="androguard",
            content={"kind": component.kind.value, **component.model_dump(mode="json")},
        )

    summarised = remainder + interesting[MAX_INDIVIDUAL_COMPONENTS:]
    if summarised:
        counts: dict[str, int] = {}
        for component in summarised:
            counts[component.kind.value] = counts.get(component.kind.value, 0) + 1
        ledger.append(
            type=EvidenceType.MANIFEST_ENTRY,
            source_tool="androguard",
            content={
                "kind": "component_summary",
                "counts": counts,
                "total": len(summarised),
                "note": (
                    "components not exported-unprotected, or beyond the "
                    f"{MAX_INDIVIDUAL_COMPONENTS}-node cap, aggregated by kind"
                ),
            },
        )
    return refs


def canonical_signature(full_name: str) -> str:
    """Normalise androguard's method signature to the smali form everything else uses.

    androguard emits `Lcom/foo/Bar; methodName (Args)Ret` — class and method separated
    by "; ", NOT the `;->` form that smali, the sink taxonomy, and every Android write-up
    use. Matching `PackageManager;->getPackageInfo` against that string never succeeds,
    which is how the entire sink layer came to be dead code: zero sink hits and zero call
    paths on every real sample, with the failure looking exactly like "this app has no
    interesting behaviour".

    Found by running the pipeline over real malware. No unit test caught it, because the
    hand-built graph fixtures used the very format the matcher expected.
    """
    class_part, separator, rest = full_name.partition("; ")
    if not separator:
        return full_name
    method = rest.split(" ", 1)[0]
    return f"{class_part};->{method}"


def _call_graph(analysis: Any) -> nx.DiGraph:
    graph = nx.DiGraph()
    for method in analysis.get_methods():
        if method.is_external():
            continue
        source = canonical_signature(method.full_name)
        for _, callee, _ in method.get_xref_to():
            graph.add_edge(source, canonical_signature(callee.full_name))
    return graph


def _sink_paths(
    graph: nx.DiGraph, components: tuple[Component, ...]
) -> tuple[set[str], tuple[CallPath, ...]]:
    entrypoints = {
        node: "lifecycle"
        for node in graph
        if any(
            name in node
            # Canonical form is `Lcom/foo/Bar;->onCreate`, so match on `;->name`
            # rather than the `->name(` shape the raw androguard string never has.
            for name in (
                ";->onCreate",
                ";->onReceive",
                ";->onStartCommand",
                ";->onAccessibilityEvent",
                ";->onBind",
                ";->doInBackground",
                ";->onHandleIntent",
                ";->attachBaseContext",
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


#: Distinguished-name attributes, in the order a reader expects them, mapped from
#: asn1crypto's `native` keys to conventional short forms.
_DN_ATTRS = (
    ("common_name", "CN"),
    ("organizational_unit_name", "OU"),
    ("organization_name", "O"),
    ("locality_name", "L"),
    ("state_or_province_name", "ST"),
    ("country_name", "C"),
)


def _distinguished_name(name: Any) -> str:
    """Render an X.509 name as a readable DN.

    `str()` on an asn1crypto `Name` returns the object repr — literally
    `<asn1crypto.x509.Name 139086784924624 b'071\\x16...'>` — which is what a real run
    put into the report and the reporting dossier. Unreadable to an analyst and
    actively embarrassing in a document that goes to a fraud desk.
    """
    try:
        native = name.native
        parts = [f"{short}={native[key]}" for key, short in _DN_ATTRS if native.get(key)]
        if parts:
            return ", ".join(parts)
        # A name with only attributes we do not shorten is still better rendered as
        # its key=value pairs than as a repr.
        return ", ".join(f"{k}={v}" for k, v in native.items()) or "unknown"
    except Exception:
        # Never let cosmetics fail the analysis: a weird certificate must still
        # produce a StaticReport.
        text = str(name)
        return "unknown" if text.startswith("<") else text


def _certificate(apk: Any, label: str, package: str, errors: list[str]) -> CertificateInfo:
    try:
        cert = apk.get_certificates()[0]
        raw = cert.dump() if hasattr(cert, "dump") else bytes(cert)
        subject = _distinguished_name(cert.subject)
        issuer = _distinguished_name(cert.issuer)
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

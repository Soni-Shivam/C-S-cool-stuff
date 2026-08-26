"""Bounded decompilation for methods already selected by the sink-path analysis."""

from __future__ import annotations

from typing import Any

from drishti.contracts.evidence import EvidenceType
from drishti.contracts.static_report import CallPath, DecompiledMethod
from drishti.ledger.store import LedgerStore
from drishti.m2_static.engine import canonical_signature

MAX_DECOMPILED_METHODS = 12
MAX_METHOD_CHARS = 4_000


def decompile_sink_methods(
    dalvik: list[Any],
    analysis: Any,
    call_paths: tuple[CallPath, ...],
    ledger: LedgerStore,
) -> tuple[tuple[DecompiledMethod, ...], tuple[str, ...]]:
    """Recover bounded source for unique internal methods on dangerous call paths."""
    errors: list[str] = []
    try:
        from androguard.decompiler.decompiler import DecompilerDAD

        for vm in dalvik:
            vm.set_decompiler(DecompilerDAD(vm, analysis))
    except Exception as exc:
        return (), (f"DAD decompiler unavailable: {type(exc).__name__}: {exc}",)

    selected = _selected_signatures(call_paths)
    path_indexes = _path_indexes(call_paths)
    methods = {
        canonical_signature(method.full_name): method
        for method in analysis.get_methods()
        if not method.is_external()
    }
    output: list[DecompiledMethod] = []
    for signature in selected:
        method = methods.get(signature)
        if method is None:
            errors.append(f"decompile target not found: {signature}")
            continue
        try:
            encoded = method.get_method()
            source = str(encoded.get_source() or "").strip()
            if not source:
                errors.append(f"decompiler returned no source: {signature}")
                continue
            truncated = len(source) > MAX_METHOD_CHARS
            body = source[:MAX_METHOD_CHARS]
            line_count = max(1, body.count("\n") + 1)
            node = ledger.append(
                type=EvidenceType.DECOMPILED_METHOD,
                source_tool="androguard:dad",
                content={
                    "signature": signature,
                    "body": body,
                    "line_start": 1,
                    "line_end": line_count,
                    "truncated": truncated,
                },
                location=signature,
            )
            output.append(
                DecompiledMethod(
                    signature=signature,
                    body=body,
                    line_start=1,
                    line_end=line_count,
                    call_path_indexes=path_indexes.get(signature, ()),
                    evidence_ref=node.id,
                    truncated=truncated,
                )
            )
        except Exception as exc:
            errors.append(f"decompile failed for {signature}: {type(exc).__name__}: {exc}")
    return tuple(output), tuple(errors)


def _selected_signatures(call_paths: tuple[CallPath, ...]) -> tuple[str, ...]:
    selected: list[str] = []
    for path in call_paths:
        for signature in path.path:
            if signature == path.sink_signature or signature in selected:
                continue
            selected.append(signature)
            if len(selected) >= MAX_DECOMPILED_METHODS:
                return tuple(selected)
    return tuple(selected)


def _path_indexes(call_paths: tuple[CallPath, ...]) -> dict[str, tuple[int, ...]]:
    indexes: dict[str, list[int]] = {}
    for index, path in enumerate(call_paths):
        for signature in path.path:
            indexes.setdefault(signature, []).append(index)
    return {signature: tuple(values) for signature, values in indexes.items()}

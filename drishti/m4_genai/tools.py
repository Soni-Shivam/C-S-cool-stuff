"""Read-only, schema-validated tools for the reverse-engineering model."""

from __future__ import annotations

import base64
import codecs
import json
import time
from collections.abc import Callable
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

from drishti.contracts.evidence import EvidenceType
from drishti.contracts.genai_verdict import ToolCallRecord, VerifiedString
from drishti.contracts.static_report import StaticReport
from drishti.ledger.store import LedgerStore
from drishti.m4_genai.agents.technique_mapper import load_kb
from drishti.util import new_id

MAX_TOOL_CALLS = 8
#: ~500 tokens per tool result. Sized against a MEASURED ceiling, not a round number:
#: on the shipped Groq tier one request may not exceed 8,000 tokens, round 0 of the tool
#: loop already costs ~5,300, and round 1 must carry every tool result back. At the old
#: 8,000 chars (~2,000 tokens each) three tool calls needed 8,528 tokens and round 1 was
#: rejected outright — so the model called its tools and its findings were then thrown
#: away. A smaller window that completes beats a larger one that never returns.
MAX_TOOL_RESULT_CHARS = 2_000


class ToolRejectedError(ValueError):
    """A requested tool or argument is outside the defensive allowlist."""


class ReadMethodArgs(BaseModel):
    signature: str = Field(min_length=1, max_length=512)


class FindXrefsArgs(BaseModel):
    signature: str = Field(min_length=1, max_length=512)
    direction: Literal["callers", "callees"]


class MethodStringsArgs(BaseModel):
    signature: str = Field(min_length=1, max_length=512)


class VerifyTransformArgs(BaseModel):
    ciphertext: str = Field(min_length=1, max_length=4_096)
    transform: Literal["base64", "hex", "rot13", "xor"]
    xor_key: int | None = Field(default=None, ge=0, le=255)


class EvidenceArgs(BaseModel):
    node_id: str = Field(pattern=r"^[a-z]+_[0-9a-f]{4,64}$")


class MitreArgs(BaseModel):
    technique_id: str = Field(pattern=r"^T[0-9]{4}(?:\.[0-9]{3})?$")


class AnalysisToolbox:
    """Execute only allowlisted reads against one immutable analysis snapshot."""

    def __init__(self, static: StaticReport, ledger: LedgerStore, job_id: str) -> None:
        self.static = static
        self.ledger = ledger
        self.job_id = job_id
        self.calls = 0
        self.records: list[ToolCallRecord] = []
        self.verified_strings: list[VerifiedString] = []
        self._handlers: dict[str, tuple[type[BaseModel], Callable[[BaseModel], dict[str, Any]]]] = {
            "read_method": (ReadMethodArgs, self._read_method),
            "find_xrefs": (FindXrefsArgs, self._find_xrefs),
            "get_method_strings": (MethodStringsArgs, self._method_strings),
            "verify_string_transform": (VerifyTransformArgs, self._verify_transform),
            "get_evidence": (EvidenceArgs, self._get_evidence),
            "lookup_mitre": (MitreArgs, self._lookup_mitre),
        }

    @property
    def definitions(self) -> list[dict[str, Any]]:
        descriptions = {
            "read_method": "Read one bounded decompiled method by exact signature.",
            "find_xrefs": "Find callers or callees already present in recovered sink paths.",
            "get_method_strings": "Get bounded extracted strings relevant to a recovered method.",
            "verify_string_transform": "Verify a proposed Base64, hex, ROT13, or byte-XOR transform.",
            "get_evidence": "Read one immutable evidence node from this analysis job.",
            "lookup_mitre": "Read one technique from the local ATT&CK for Mobile knowledge base.",
        }
        return [
            {
                "type": "function",
                "function": {
                    "name": name,
                    "description": descriptions[name],
                    "parameters": model.model_json_schema(),
                },
            }
            for name, (model, _) in self._handlers.items()
        ]

    def execute(self, name: str, arguments: str | dict[str, Any]) -> dict[str, Any]:
        """Validate and execute one call, returning a bounded JSON-compatible result."""
        started = time.monotonic()
        tool_id = new_id("tool")
        raw: dict[str, Any]
        try:
            if self.calls >= MAX_TOOL_CALLS:
                raise ToolRejectedError(f"tool budget exhausted at {MAX_TOOL_CALLS} calls")
            self.calls += 1
            if name not in self._handlers:
                raise ToolRejectedError(f"unknown tool: {name}")
            raw = json.loads(arguments) if isinstance(arguments, str) else arguments
            if not isinstance(raw, dict):
                raise ToolRejectedError("tool arguments must be an object")
            model, handler = self._handlers[name]
            validated = model.model_validate(raw, strict=True)
            result = handler(validated)
            encoded = json.dumps(result, ensure_ascii=True)
            if len(encoded) > MAX_TOOL_RESULT_CHARS:
                result = {"truncated": True, "preview": encoded[:MAX_TOOL_RESULT_CHARS]}
            refs = tuple(str(ref) for ref in result.get("evidence_refs", ()))
            status: Literal["ok", "rejected", "error"] = "ok"
            summary = str(result.get("summary") or "tool completed")[:300]
        except (ToolRejectedError, ValidationError, json.JSONDecodeError) as exc:
            raw = arguments if isinstance(arguments, dict) else {"raw": str(arguments)[:500]}
            result = {"error": str(exc), "rejected": True}
            refs = ()
            status = "rejected"
            summary = str(exc)[:300]
        except Exception as exc:
            raw = arguments if isinstance(arguments, dict) else {"raw": str(arguments)[:500]}
            result = {"error": f"{type(exc).__name__}: {exc}"[:500]}
            refs = ()
            status = "error"
            summary = str(result["error"])

        duration_ms = round((time.monotonic() - started) * 1000)
        node = self.ledger.append(
            type=EvidenceType.AI_TOOL_CALL,
            source_tool="m4_genai:toolbox",
            content={
                "tool_id": tool_id,
                "name": name,
                "arguments": raw,
                "status": status,
                "result_summary": summary,
                "evidence_refs": list(refs),
                "duration_ms": duration_ms,
            },
            parents=refs,
        )
        verified_ref = node.id
        if name == "verify_string_transform" and status == "ok":
            deobfuscated = self.ledger.append(
                type=EvidenceType.DEOBFUSCATED_STRING,
                source_tool="m4_genai:fixed_transform",
                content={
                    "transform": result.get("transform"),
                    "ciphertext": str(raw.get("ciphertext") or "")[:4_096],
                    "plaintext": str(result.get("plaintext") or "")[:4_096],
                    "verified": bool(result.get("verified")),
                },
                parents=(node.id,),
            )
            verified_ref = deobfuscated.id
        self.records.append(
            ToolCallRecord(
                id=tool_id,
                name=name,
                arguments=raw,
                status=status,
                result_summary=summary,
                evidence_refs=(node.id, *refs),
                duration_ms=duration_ms,
            )
        )
        if name == "verify_string_transform" and status == "ok":
            self.verified_strings.append(
                VerifiedString(
                    ciphertext=str(raw.get("ciphertext") or "")[:4_096],
                    transform=str(result.get("transform") or "unknown"),
                    plaintext=str(result.get("plaintext") or "")[:4_096],
                    verified=bool(result.get("verified")),
                    reason=summary,
                    evidence_refs=(verified_ref,),
                )
            )
        return result

    def _read_method(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, ReadMethodArgs)
        method = next(
            (item for item in self.static.decompiled_methods if item.signature == args.signature),
            None,
        )
        if method is None:
            raise ToolRejectedError("method is not in the bounded sink-path workspace")
        return {
            "signature": method.signature,
            "body": method.body,
            "line_start": method.line_start,
            "line_end": method.line_end,
            "truncated": method.truncated,
            "evidence_refs": [method.evidence_ref],
            "summary": f"{method.line_end - method.line_start + 1} source lines returned",
        }

    def _find_xrefs(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, FindXrefsArgs)
        values: set[str] = set()
        for path in self.static.call_paths:
            for index, signature in enumerate(path.path):
                if signature != args.signature:
                    continue
                target = index - 1 if args.direction == "callers" else index + 1
                if 0 <= target < len(path.path):
                    values.add(path.path[target])
        return {"signatures": sorted(values)[:40], "summary": f"{len(values)} xrefs returned"}

    def _method_strings(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, MethodStringsArgs)
        if not any(m.signature == args.signature for m in self.static.decompiled_methods):
            raise ToolRejectedError("method is not in the bounded sink-path workspace")
        values = [*self.static.urls[:15], *self.static.crypto_constants[:20]]
        return {
            "strings": values,
            "scope": "APK-level extracted candidates; method-local xrefs were unavailable",
            "summary": f"{len(values)} bounded candidates returned",
        }

    def _verify_transform(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, VerifyTransformArgs)
        plaintext = verify_transform(args.ciphertext, args.transform, args.xor_key)
        return {
            "verified": True,
            "plaintext": plaintext,
            "transform": args.transform,
            "summary": f"{args.transform} reproduced by the fixed evaluator",
        }

    def _get_evidence(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, EvidenceArgs)
        node = self.ledger.get(args.node_id)
        if node is None or node.job_id != self.job_id:
            raise ToolRejectedError("evidence node does not exist in this job")
        return {
            "id": node.id,
            "type": node.type.value,
            "source_tool": node.source_tool,
            "content": node.content,
            "location": node.location,
            "evidence_refs": [node.id],
            "summary": f"{node.type.value} evidence returned",
        }

    def _lookup_mitre(self, args: BaseModel) -> dict[str, Any]:
        assert isinstance(args, MitreArgs)
        entry = load_kb().get(args.technique_id)
        if entry is None:
            raise ToolRejectedError("technique id is not in the local Mobile ATT&CK set")
        return {"technique_id": args.technique_id, **entry, "summary": entry["name"]}


def verify_transform(ciphertext: str, transform: str, xor_key: int | None = None) -> str:
    """Run one fixed transform. Sample-supplied code is never evaluated."""
    try:
        if transform == "base64":
            decoded = base64.b64decode(ciphertext, validate=True)
        elif transform == "hex":
            decoded = bytes.fromhex(ciphertext)
        elif transform == "rot13":
            return codecs.decode(ciphertext, "rot_13")[:4_096]
        elif transform == "xor":
            if xor_key is None:
                raise ToolRejectedError("xor_key is required for xor")
            decoded = bytes(value ^ xor_key for value in bytes.fromhex(ciphertext))
        else:
            raise ToolRejectedError(f"unsupported transform: {transform}")
        return decoded.decode("utf-8")[:4_096]
    except (ValueError, UnicodeDecodeError) as exc:
        raise ToolRejectedError(f"transform did not produce UTF-8 text: {exc}") from exc

"""mitmproxy capture addon. Writes redacted flows as JSONL; the harness reads the tail.

Runs only on the sealed detonator, where the sample's single interlocutor is this
proxy. The parse and record-building halves are pure so they are tested here without
mitmproxy present, mirroring `GenerativeC2Addon`: a dumb adapter over pure functions.

Two properties this file exists to hold:

* **Nothing raises into mitmproxy's event loop.** The addon is called inline on the
  proxy's own coroutine; an exception there kills the capture, and with it the only
  record of what the sample talked to. An unreadable body yields an empty preview.
* **Every string is redacted before it is written — host and path included, not just
  the bodies.** `CapturedFlow` gates only the two previews, so a credential in a URL
  (`GET /log/password=hunter2/`) is caught here or nowhere. Redaction always runs over
  a window wider than the field's bound and truncation happens afterwards; the reverse
  order chops a straddling secret into a fragment its rule no longer matches, which
  disarms the gate without failing anything. See `_redacted`.
* **A gate that still refuses costs the preview, not the flow.** If `CapturedFlow`
  rejects a preview anyway, it is dropped and the flow is recorded without it — host
  and path are the C2 evidence, and losing them to a redaction bug is the worse failure.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from drishti.contracts.dynamic_trace import CapturedFlow
from drishti.logging import get_logger
from drishti.m3_dynamic.redaction import redact_text

log = get_logger(__name__)

#: Stamped by the Generative C2 responder on a response *we* served. The capture hook
#: runs after it in the addon chain, so these are how provenance reaches the contract.
SYNTHESISED_HEADER = "x-drishti-synthesised"
KIND_HEADER = "x-drishti-kind"

#: Header values that mean "yes". Anything else — including absence — means observed.
_TRUTHY = frozenset({"1", "true", "yes", "on"})

#: Contract bounds, restated so hostile input is trimmed before it reaches validation.
MAX_SERVED_KIND = 32
MAX_METHOD = 16
MAX_SCHEME = 8
MAX_HOST = 253
MAX_PATH = 512
MAX_PREVIEW = 512

#: How much wider than a field's bound the redaction pass looks. Redaction runs over
#: `bound * FACTOR` characters and the result is truncated to `bound` afterwards, so a
#: secret straddling the bound is still matched whole. 4x covers every rule's longest
#: plausible match (a JWT) with room to spare, without regexing a whole body.
REDACTION_WINDOW_FACTOR = 4

DEFAULT_FLOW_LOG = "/opt/drishti/results/flows.jsonl"


def parse_flow_log(text: str) -> list[CapturedFlow]:
    """Parse a JSONL flow log into validated flows, dropping any line that is not one."""
    out: list[CapturedFlow] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            out.append(CapturedFlow.model_validate_json(line))
        except Exception:  # a corrupt or non-flow line is dropped, never fatal
            continue
    return out


def provenance_from_headers(headers: Any) -> tuple[bool, str | None]:
    """Read `(synthesised, served_kind)` from a response's headers.

    Returns `(False, None)` unless the responder stamped `X-DRISHTI-Synthesised`; the
    kind is never read on its own, so a flow we did not answer can never carry a label
    claiming we did.
    """
    lowered = _header_map(headers)
    if lowered.get(SYNTHESISED_HEADER, "").strip().lower() not in _TRUTHY:
        return False, None
    kind = lowered.get(KIND_HEADER, "").strip()[:MAX_SERVED_KIND]
    return True, kind or None


def build_flow_record(
    *,
    t_ms_epoch: int,
    method: str,
    scheme: str,
    host: str,
    path: str = "/",
    status: int | None = None,
    req_text: str = "",
    resp_text: str = "",
    resp_headers: Any = None,
) -> CapturedFlow:
    """Build one validated `CapturedFlow` from raw proxy values.

    Pure. Every input came from a process that just executed malware, so every string
    that will leave the guest — host and path included, not only the bodies — goes
    through `redact_text`, and each field is normalised to its contract bound. The
    query string is dropped (it is the likeliest place for exfiltrated data to sit).
    If validation still refuses a preview, the preview is dropped rather than the flow.
    """
    synthesised, served_kind = provenance_from_headers(resp_headers)
    fields: dict[str, Any] = {
        "t_ms_epoch": int(t_ms_epoch),
        "method": str(method).strip()[:MAX_METHOD] or "UNKNOWN",
        "scheme": str(scheme).strip()[:MAX_SCHEME] or "unknown",
        # `CapturedFlow` gates only the two body previews, so host and path are gated
        # here or nowhere: `GET /log/password=hunter2/` is a credential in a URL.
        "host": _redacted(str(host).strip(), MAX_HOST),
        "path": _redacted(str(path).split("?", 1)[0], MAX_PATH) or "/",
        "status": int(status) if status is not None else None,
        "synthesised": synthesised,
        "served_kind": served_kind,
    }
    try:
        return CapturedFlow(
            **fields,
            req_body_preview=_redacted(req_text, MAX_PREVIEW),
            resp_body_preview=_redacted(resp_text, MAX_PREVIEW),
        )
    except ValueError:
        # Fail closed on the body, not on the evidence: host, path and status are what
        # identify the C2, and a redaction miss must not delete them.
        log.warning("captured_flow_preview_dropped", host=fields["host"])
        return CapturedFlow(**fields, req_body_preview="", resp_body_preview="")


class FlowCaptureAddon:
    """A mitmproxy addon that appends one redacted JSON line per flow.

    A thin adapter over `build_flow_record`, deliberately dumb: it reads attributes off
    the flow object and never decides anything, so there is nothing here to get subtly
    wrong on a machine nobody can attach a debugger to mid-detonation.
    """

    def __init__(self, log_path: str | None = None) -> None:
        self._path = Path(log_path or os.environ.get("DRISHTI_FLOW_LOG", DEFAULT_FLOW_LOG))
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def response(self, flow: Any) -> None:
        """Record one completed flow. Never raises — mitmproxy calls this inline."""
        try:
            request = flow.request
            response = getattr(flow, "response", None)
            record = build_flow_record(
                t_ms_epoch=int(float(getattr(request, "timestamp_start", 0.0) or 0.0) * 1000),
                method=getattr(request, "method", ""),
                scheme=getattr(request, "scheme", ""),
                host=getattr(request, "host", ""),
                path=getattr(request, "path", "/"),
                status=getattr(response, "status_code", None) if response is not None else None,
                req_text=_body_text(request),
                resp_text=_body_text(response),
                resp_headers=getattr(response, "headers", None) if response is not None else None,
            )
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record.model_dump(mode="json"), ensure_ascii=True) + "\n")
        except Exception as exc:  # a capture bug must not kill the proxy
            log.warning("flow_capture_failed", error=str(exc))


def _redacted(value: str, limit: int) -> str:
    """Redact across a window wider than `limit`, then truncate to it.

    Order matters and is the whole point. Truncating first silently disarms the gate:
    a secret straddling the bound is chopped into a fragment its rule no longer
    matches, so it passes both `redact_text` and `contains_sensitive_text` — a JWT cut
    after its payload keeps every claim it carries. Redacting a wider window first
    means anything *starting* inside the bound is matched whole. The window is finite
    so a multi-megabyte body is not handed to the regex engine.
    """
    return redact_text(value[: limit * REDACTION_WINDOW_FACTOR], limit=limit)


def _body_text(msg: Any) -> str:
    """Best-effort body text. An undecodable or absent body is an empty preview."""
    if msg is None:
        return ""
    try:
        # Wider than MAX_PREVIEW on purpose — see `_redacted`. Truncation is the last
        # step, after redaction, never before it.
        return (msg.get_text(strict=False) or "")[: MAX_PREVIEW * REDACTION_WINDOW_FACTOR]
    except Exception:  # binary, truncated or streamed bodies are common
        return ""


def _header_map(headers: Any) -> dict[str, str]:
    """Lower-cased header lookup that works for a dict or mitmproxy's `Headers`."""
    if headers is None:
        return {}
    try:
        return {str(name).lower(): str(value) for name, value in headers.items()}
    except Exception:  # a malformed header block is not a reason to crash
        return {}

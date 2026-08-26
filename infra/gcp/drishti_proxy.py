"""The composed mitmproxy addon chain for the sealed detonator. Calls NO LLM.

    capture (always) -> bundle responder -> inert second stage -> sinkhole fallback

This is the sample's only interlocutor. `drishti-runtime` has no NAT and the host
iptables lockdown blackholes the rest, so every byte a sample receives during a
detonation is produced right here, from a bundle that was synthesised, grounded and
inertness-checked on the orchestrator *before* the VM was sealed. Nothing here reaches
a model, a network or the metadata server, and nothing here may import `m4_genai`.

Four properties this file exists to hold:

* **Nothing raises into mitmproxy's event loop.** The hook runs inline on the proxy's
  own coroutine; an exception there takes out the capture addon with it, and the flow
  log is the only record of what the sample talked to. Every failure path degrades to
  serving something inert and logging why.
* **Everything served is stamped as ours.** A response DRISHTI synthesised must be
  distinguishable from real attacker traffic for the whole life of the artifact —
  otherwise the report, and STIX after it, would publish our own content as an IOC.
  Both provenance headers are emitted, including on the sinkhole body, and the header
  names come from `capture_addon` so the writer and the reader cannot drift apart.
* **Inertness is re-verified at serve time.** `SyntheticC2Response.provably_inert` is
  decided on the orchestrator; the bundle then travels as a file staged onto a VM. It
  is treated as untrusted at the point of use: `assert_inert` runs again on the bytes
  about to hit the wire, and an entry that refuses costs itself, not the run.
* **The sinkhole is the floor, not an optional extra.** A dead C2 that receives a
  connection error behaves differently from one that receives an inert `200`, so an
  unhinted host still gets an answer. Absence of a bundle changes what the sample is
  told, never whether it is told something.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from drishti.contracts.c2_bundle import C2Bundle, C2BundleEntry
from drishti.logging import get_logger
from drishti.m3_dynamic.generative_c2 import (
    C2ResponseKind,
    C2SchemaHint,
    assert_inert,
    inert_payload_bytes,
)
from drishti.m3_dynamic.proxy.capture_addon import (
    KIND_HEADER,
    MAX_SERVED_KIND,
    SYNTHESISED_HEADER,
    FlowCaptureAddon,
)

log = get_logger(__name__)

#: Where the staged `C2Bundle` is read from. Unset for pass 1 (there is nothing to
#: stage yet); the per-run wrapper sets it for pass 2.
BUNDLE_ENV = "DRISHTI_C2_BUNDLE"

#: Stamped on every response so a reader can tell "no upstream was ever contacted"
#: from "the upstream answered". Carried over from the sinkhole this file replaces.
NO_UPSTREAM_HEADER = "x-drishti-no-upstream"

JSON_CONTENT_TYPE = "application/json"
#: A payload-URL fetch expects bytes, not JSON. `inert_payload_bytes()` is a 0x70-byte
#: DEX header with no classes in it.
STUB_CONTENT_TYPE = "application/octet-stream"

#: `served_kind` for the fallback. Not a `C2ResponseKind`: nothing was synthesised for
#: this host, and labelling it as if something had been would overstate the evidence.
SINKHOLE_KIND = "sinkhole"

#: Compact separators throughout: fewer bytes on the wire and a byte-stable body, so
#: two runs of the same bundle produce identical flow logs.
_COMPACT = (",", ":")
SINKHOLE_BODY = json.dumps(
    {"status": "sinkholed", "commands": []}, ensure_ascii=True, separators=_COMPACT
).encode("utf-8")
#: The fail-closed body: inert by construction, and the same shape `synthesise_response`
#: falls back to when its own gate refuses.
CANNED_OK_BODY = json.dumps({"status": "ok"}, ensure_ascii=True, separators=_COMPACT).encode(
    "utf-8"
)


@dataclass(frozen=True)
class ServedResponse:
    """One answer, ready for the wire, with the provenance that must travel with it."""

    status: int
    body: bytes
    content_type: str
    #: Carried into `CapturedFlow.served_kind` via the response headers.
    kind: str

    def headers(self) -> dict[str, str]:
        """The response headers, including both provenance headers.

        `capture_addon` reads `synthesised` and `served_kind` back off these. The header
        names are imported from it rather than spelled out here, because a typo would
        not fail anything — it would silently record our own content as the attacker's.
        """
        return {
            "Content-Type": self.content_type or JSON_CONTENT_TYPE,
            SYNTHESISED_HEADER: "true",
            # Bounded to the contract's limit here so a hostile bundle cannot push a
            # 4KB label into `CapturedFlow`, which would drop the whole preview.
            KIND_HEADER: self.kind[:MAX_SERVED_KIND],
            NO_UPSTREAM_HEADER: "true",
        }


def sinkhole_response() -> ServedResponse:
    """The floor: an inert `200` for a host no bundle entry claims."""
    return ServedResponse(200, SINKHOLE_BODY, JSON_CONTENT_TYPE, SINKHOLE_KIND)


def canned_ok_response() -> ServedResponse:
    """The fail-closed answer for an entry that cannot be proven inert at serve time."""
    return ServedResponse(
        200, CANNED_OK_BODY, JSON_CONTENT_TYPE, C2ResponseKind.CONNECTIVITY_OK.value
    )


def serve_entry(entry: C2BundleEntry) -> ServedResponse:
    """Turn one bundle entry into the bytes to serve. Pure, and never raises.

    A payload entry is answered with the inert DEX stub, never with the entry's own
    body: that entry exists precisely because the sample wanted a second stage, and the
    stub is the one thing a reader must not mistake for real attacker content.
    Everything else goes back through the inertness gate before it reaches the wire.
    """
    if entry.is_payload_url:
        return ServedResponse(
            200,
            inert_payload_bytes(),
            STUB_CONTENT_TYPE,
            C2ResponseKind.INERT_PAYLOAD_STUB.value,
        )
    return _revalidated(entry)


def _revalidated(entry: C2BundleEntry) -> ServedResponse:
    """Re-run the inertness gate on a staged body, or fall back to the canned ack.

    The bundle was written by a trusted builder and then left on a disk that a
    detonation run has write access to. `provably_inert` on the far side of that gap is
    a claim, not a proof, so the proof is redone here: this is the only place where the
    bytes actually become reachable by the sample.
    """
    try:
        payload = json.loads(entry.served_body)
        hint = C2SchemaHint(response_kind=_kind_of(entry.response_kind))
        result = assert_inert(payload, hint)
        body = json.dumps(result.body, ensure_ascii=True, separators=_COMPACT).encode("utf-8")
        if result.neutralisations:
            log.warning(
                "c2_bundle_entry_neutralised_at_serve_time",
                host=entry.host,
                neutralisations=len(result.neutralisations),
            )
        return ServedResponse(
            int(entry.served_status),
            body,
            entry.served_content_type or JSON_CONTENT_TYPE,
            str(entry.response_kind),
        )
    except Exception as exc:
        # Fail closed to the safest shape there is, and say so: "the bundle had an entry
        # for this host and we refused it" is a finding, not a detail.
        log.warning(
            "c2_bundle_entry_refused_at_serve_time",
            host=entry.host,
            path_prefix=entry.path_prefix,
            error=str(exc)[:200],
        )
        return canned_ok_response()


def _kind_of(value: str) -> C2ResponseKind:
    """The entry's declared kind, or the safest one. An unknown kind is not fatal."""
    try:
        return C2ResponseKind(str(value))
    except ValueError:
        return C2ResponseKind.CONNECTIVITY_OK


class BundleResponder:
    """Answers every request locally: from the bundle if it has one, else the sinkhole.

    A dumb adapter over the pure functions above, in the same shape as
    `FlowCaptureAddon`: the mitmproxy hook reads two attributes off the flow, asks
    `plan()` what to send, and swallows anything that goes wrong.
    """

    def __init__(self, bundle: C2Bundle | None) -> None:
        self._bundle = bundle

    def plan(self, host: str, path: str) -> ServedResponse:
        """What to serve for this request. Always an answer — never `None`."""
        matched = self._matched(host, path)
        if matched is None:
            return sinkhole_response()
        return matched

    def decide(self, host: str, path: str) -> tuple[int, bytes, str] | None:
        """The *bundle's* answer as `(status, body, content_type)`, or `None` for a miss.

        The provenance-free view, for callers that only want to know whether the bundle
        claims this request. The proxy hook uses `plan()`, because a response that
        reaches the sample must carry its provenance headers.
        """
        matched = self._matched(host, path)
        if matched is None:
            return None
        return (matched.status, matched.body, matched.content_type)

    def request(self, flow: Any) -> None:
        """Answer one request without contacting its upstream. Never raises."""
        try:
            request = flow.request
            host = str(getattr(request, "host", "") or "")
            # The query string is not part of the match: it carries the per-run ids and
            # exfiltrated data that make an exact path unmatchable.
            path = str(getattr(request, "path", "/") or "/").split("?", 1)[0]
            served = self.plan(host, path)
            flow.response = self._make_response(served)
        except Exception as exc:  # a responder bug must not kill capture
            log.warning("c2_response_failed", error=str(exc)[:200])

    @staticmethod
    def _make_response(served: ServedResponse) -> Any:
        """Build the mitmproxy response. Imported here — mitmproxy is a lab-only extra."""
        from mitmproxy import http

        return http.Response.make(served.status, served.body, served.headers())

    def _matched(self, host: str, path: str) -> ServedResponse | None:
        """The bundle's entry for this request, already turned into bytes."""
        if self._bundle is None:
            return None
        entry = self._bundle.matches(host, path)
        if entry is None:
            return None
        return serve_entry(entry)


def load_bundle(path: str | None = None) -> C2Bundle | None:
    """Read the staged bundle, or `None`. An unreadable bundle costs the bundle only.

    Pass 1 runs with `DRISHTI_C2_BUNDLE` unset by design. A missing or corrupt file is
    logged and treated the same way, because the alternative — mitmdump refusing to
    start — leaves the sample with no interlocutor at all, and it is started with
    `nohup`, so the failure would be silent.
    """
    raw = path or os.environ.get(BUNDLE_ENV, "")
    if not raw:
        log.info("c2_bundle_absent", reason="env unset — sinkholing every host")
        return None
    location = Path(raw)
    if not location.is_file():
        log.warning("c2_bundle_missing", path=str(location))
        return None
    try:
        bundle = C2Bundle.model_validate_json(location.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("c2_bundle_unreadable", path=str(location), error=str(exc)[:200])
        return None
    log.info(
        "c2_bundle_loaded",
        sha256=bundle.sha256,
        entries=len(bundle.entries),
        built_at=bundle.built_at,
    )
    return bundle


def build_addons() -> list[Any]:
    """The chain mitmdump loads. Capture first: it must see every flow, answered or not."""
    return [FlowCaptureAddon(), BundleResponder(load_bundle())]


addons = build_addons()

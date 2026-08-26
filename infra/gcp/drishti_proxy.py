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

**Known limitation — the inert second stage is built but not reachable end to end.**
A payload-stub entry's *body* names a download URL, and `assert_inert` rewrites every
URL-shaped value to `generative_c2.SINKHOLE_URL`, which is `http://127.0.0.1:9/inert`.
That is the **guest's own** loopback on the discard port, so a sample that follows the
bait never puts a packet on the emulated NIC and this proxy never sees the fetch.
`_payload_urls` therefore registers a route that, in practice, nothing arrives on. It is
implemented and tested anyway, because the alternative — pointing the bait at a host the
proxy can see — means rewriting the one function that makes "we never serve capability"
true. The stub is reported as *built, not exercised*; do not let anything claim a
second stage was downloaded until a real fetch shows up in `flows.jsonl`.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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


# ── Self-registration in sys.modules, and why this is not optional ────────────
#
# MEASURED 2026-08-27 on m3-detonator: `mitmdump -s drishti_proxy.py` refused to start
# with `AttributeError: 'NoneType' object has no attribute '__dict__'` raised from
# `dataclasses._is_type`, and because runtime_prepare.sh nohups mitmdump the only symptom
# in the field is an EMPTY flow log — which reads as "the sample never beaconed".
#
# mitmproxy's script loader builds this module with `module_from_spec` and calls
# `exec_module` WITHOUT putting it in `sys.modules`. `from __future__ import annotations`
# makes every annotation below a string, so `@dataclass` asks
# `sys.modules[cls.__module__].__dict__` whether an annotation names `dataclasses.KW_ONLY`
# — and that lookup returns None. The facade below is an ordinary object whose `__dict__`
# *is* this module's globals, so the lookup resolves against the real namespace rather
# than an empty stand-in. `setdefault`, so a loader that does register us (the provision
# check in detonator_provision.sh does) keeps its own module object.
class _SelfFacade:  # noqa: D101 - internal shim, documented above
    pass


_self_facade = _SelfFacade()
_self_facade.__dict__ = globals()
sys.modules.setdefault(__name__, _self_facade)  # type: ignore[arg-type]

#: Where the staged `C2Bundle` is read from. Unset for pass 1 (there is nothing to
#: stage yet); the per-run wrapper sets it for pass 2.
BUNDLE_ENV = "DRISHTI_C2_BUNDLE"

#: The sha256 of the sample currently being detonated, set by the per-run wrapper. When
#: it is set, a bundle whose own `sha256` differs is refused outright: a bundle left at
#: the staged path from an earlier sample would otherwise be served to this one, and
#: `C2Bundle.sha256` exists precisely because "serving one sample's answers to another
#: would fabricate behaviour". Unset (pass 1, or a wrapper that does not pin it) keeps
#: the previous behaviour.
SAMPLE_SHA_ENV = "DRISHTI_SAMPLE_SHA256"

#: Stamped on every response so a reader can tell "no upstream was ever contacted"
#: from "the upstream answered". Carried over from the sinkhole this file replaces.
NO_UPSTREAM_HEADER = "x-drishti-no-upstream"

JSON_CONTENT_TYPE = "application/json"
#: A payload-URL fetch expects bytes, not JSON. `inert_payload_bytes()` is a 0x70-byte
#: DEX header with no classes in it.
STUB_CONTENT_TYPE = "application/octet-stream"

#: The only content types this system serves: control responses (JSON) and the inert
#: DEX stub. `served_content_type` arrives from an untrusted file, so it is allow-listed
#: rather than sanitised — `application/json\r\nX-Evil: 2` otherwise reaches the wire
#: verbatim and splits a header the capture addon then reads back as ours.
ALLOWED_CONTENT_TYPES = (JSON_CONTENT_TYPE, STUB_CONTENT_TYPE)

#: HTTP's own status bounds. `http.Response.make` raises outside them, and a raise in
#: the request hook leaves `flow.response` unset — which makes mitmproxy forward the
#: request UPSTREAM, past the sinkhole floor. `served_status` is untrusted, so it is
#: clamped here rather than trusted to be sane.
MIN_STATUS = 100
MAX_STATUS = 599
DEFAULT_STATUS = 200

#: `served_kind` for the fallback. Not a `C2ResponseKind`: nothing was synthesised for
#: this host, and labelling it as if something had been would overstate the evidence.
SINKHOLE_KIND = "sinkhole"

#: Scheme detector for finding the URLs a payload-stub body hands the sample. Same shape
#: as `generative_c2._URL_RE`, restated rather than imported because that one is private
#: and is part of the inertness gate, which this file must not reach into.
_URL_RE = re.compile(r"[a-z][a-z0-9+.\-]*://", re.IGNORECASE)
#: `assert_inert` already caps nesting at `MAX_JSON_DEPTH`; this is the same bound
#: restated so the walk terminates on a body that somehow got past it.
_MAX_WALK_DEPTH = 6

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


def safe_status(value: Any) -> int:
    """An HTTP status inside 100..599, or `DEFAULT_STATUS`. Never raises.

    Out of range is not a rounding error worth preserving: `Response.make` refuses it,
    and that refusal used to propagate into the request hook and leave `flow.response`
    unset, which lets mitmproxy forward the request upstream. Whatever the bundle
    claimed, an inert answer beats a trip to the wire.
    """
    try:
        status = int(value)
    except Exception:
        return DEFAULT_STATUS
    return status if MIN_STATUS <= status <= MAX_STATUS else DEFAULT_STATUS


def safe_content_type(value: Any) -> str:
    """The bundle's content type if this system actually serves it, else JSON.

    Allow-listed rather than sanitised: anything outside the two types the responder
    emits is either a mistake or an attempt to smuggle structure into a header, and
    neither is worth reproducing faithfully.
    """
    candidate = str(value or "").strip()
    return candidate if candidate in ALLOWED_CONTENT_TYPES else JSON_CONTENT_TYPE


def safe_header_value(value: Any) -> str:
    """A header value with every control character removed. Never raises.

    CR and LF are the ones that matter — they end a header line, so a value carrying
    them writes headers of its own — but the whole C0 range plus DEL goes, because none
    of it is legal in a field value and some of it survives a naive length truncation.
    """
    return "".join(ch for ch in str(value or "") if 0x20 <= ord(ch) != 0x7F)


@dataclass(frozen=True)
class ServedResponse:
    """One answer, ready for the wire, with the provenance that must travel with it.

    Normalised on construction, so no code path can build one that is unsafe to send.
    `status`, `content_type` and `kind` all originate in the staged bundle, which is an
    untrusted file at the point of use for exactly the same reason `served_body` is.
    """

    status: int
    body: bytes
    content_type: str
    #: Carried into `CapturedFlow.served_kind` via the response headers.
    kind: str

    def __post_init__(self) -> None:
        """Clamp the three bundle-derived fields. Frozen, so written through `object`."""
        object.__setattr__(self, "status", safe_status(self.status))
        object.__setattr__(self, "content_type", safe_content_type(self.content_type))
        object.__setattr__(self, "kind", safe_header_value(self.kind))

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
            # 4KB label into `CapturedFlow`, which would drop the whole preview. The
            # control-character strip runs in `__post_init__`, i.e. BEFORE this cut: a
            # CRLF sitting at index 30 would otherwise survive the truncation intact.
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


def payload_stub_response() -> ServedResponse:
    """The inert second stage: 0x70 bytes of DEX header with no classes in it.

    Served *only* on a path this proxy itself injected as a download URL — never on a
    beacon path. See `_payload_urls`.
    """
    return ServedResponse(
        200,
        inert_payload_bytes(),
        STUB_CONTENT_TYPE,
        C2ResponseKind.INERT_PAYLOAD_STUB.value,
    )


def serve_entry(entry: C2BundleEntry) -> ServedResponse:
    """Turn one bundle entry into the bytes to serve. Pure, and never raises.

    Every entry, payload stub included, is answered with its own JSON body, re-proven
    inert. `is_payload_url` does **not** mean "this path is the download"; it means
    "this entry's body names a download URL". The entry's `path_prefix` is the sample's
    first observed *beacon* path and its body is JSON, so answering it with DEX bytes
    and `application/octet-stream` breaks the sample's parser and the bait is never
    delivered. The DEX stub belongs on the injected URL's own path — `_payload_urls`.
    """
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
        kind = _kind_of(entry.response_kind)
        result = assert_inert(payload, C2SchemaHint(response_kind=kind))
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
            # Always JSON, never `entry.served_content_type`: `body` is the OUTPUT of
            # `assert_inert`, so it is compact JSON whatever the entry claimed. Passing
            # a staged `text/html` through would label these bytes as something they are
            # not — and the refusal path below already normalises to JSON, so trusting
            # the field here made the two paths disagree about the same body.
            JSON_CONTENT_TYPE,
            # The RESOLVED kind, not `entry.response_kind`. `_kind_of` fell back for an
            # unknown value, and the sanitiser ran with that fallback; stamping the raw
            # string would put one shape on the wire while a different one was enforced.
            kind.value,
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


def _payload_urls(bundle: C2Bundle | None) -> frozenset[tuple[str, str]]:
    """The `(host, path)` pairs this bundle's payload-stub bodies actually point at.

    Read off the **served** bodies, not the staged ones: `assert_inert` rewrites every
    URL-shaped value, so the URL the sample is handed is the only one worth routing. A
    request that arrives on one of these is the sample following our bait, and it — and
    only it — is answered with `inert_payload_bytes()`.

    In practice this set is `{("127.0.0.1", "/inert")}`, which the guest resolves to its
    own loopback: the fetch never crosses the emulated NIC and never reaches this proxy.
    That is a known, disclosed gap (module docstring), not an accident. Do not "fix" it
    by pointing `generative_c2.SINKHOLE_URL` somewhere reachable — that constant is the
    reason "we never serve capability" is provable.

    Never raises: a body that will not parse simply contributes no route, and the entry
    still answers its own beacon path through `serve_entry`.
    """
    if bundle is None:
        return frozenset()
    targets: set[tuple[str, str]] = set()
    for entry in bundle.entries:
        if not entry.is_payload_url:
            continue
        try:
            payload = json.loads(serve_entry(entry).body)
            for url in _url_strings(payload):
                # `urlsplit` raises on a malformed IPv6 literal, and `hostname` parses
                # the authority again — both are inside the guard for that reason.
                parts = urlsplit(url)
                host = (parts.hostname or "").strip().lower()
                if host:
                    targets.add((host, parts.path or "/"))
        except Exception as exc:  # a bad entry costs a route, never the proxy
            log.warning("c2_payload_route_skipped", host=entry.host, error=str(exc)[:200])
    return frozenset(targets)


def _url_strings(value: Any, depth: int = 0) -> list[str]:
    """Every URL-shaped string in a decoded JSON body. Bounded, and never raises."""
    if depth > _MAX_WALK_DEPTH:
        return []
    if isinstance(value, str):
        return [value] if _URL_RE.search(value) else []
    if isinstance(value, dict):
        return [u for v in value.values() for u in _url_strings(v, depth + 1)]
    if isinstance(value, (list, tuple)):
        return [u for v in value for u in _url_strings(v, depth + 1)]
    return []


class BundleResponder:
    """Answers every request locally: from the bundle if it has one, else the sinkhole.

    A dumb adapter over the pure functions above, in the same shape as
    `FlowCaptureAddon`: the mitmproxy hook reads two attributes off the flow, asks
    `plan()` what to send, and swallows anything that goes wrong.
    """

    def __init__(self, bundle: C2Bundle | None) -> None:
        self._bundle = bundle
        self._payload_targets = _payload_urls(bundle)

    def payload_targets(self) -> frozenset[tuple[str, str]]:
        """The `(host, path)` pairs that would be answered with the inert DEX stub.

        Exposed so a run can *report* whether the second stage was ever reachable rather
        than assume it. On a real bundle every pair is `("127.0.0.1", "/inert")` — see
        the module docstring's limitation note.
        """
        return self._payload_targets

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
        """Answer one request without contacting its upstream. Never raises.

        Fail-closed in both halves. Deciding *what* to serve can fail (an undecodable
        flow); *building* the response can fail too. Either way the flow still gets an
        inert answer, because leaving `flow.response` unset is not "declining" — it is
        mitmproxy's instruction to forward the request to its real upstream, which is
        the one outcome the sinkhole floor exists to make impossible.
        """
        try:
            request = flow.request
            host = str(getattr(request, "host", "") or "")
            # The query string is not part of the match: it carries the per-run ids and
            # exfiltrated data that make an exact path unmatchable.
            path = str(getattr(request, "path", "/") or "/").split("?", 1)[0]
            served = self.plan(host, path)
        except Exception as exc:  # a responder bug must not kill capture
            log.warning("c2_response_failed", error=str(exc)[:200])
            served = canned_ok_response()
        try:
            flow.response = self._make_response(served)
        except Exception as exc:
            log.warning("c2_response_build_failed", kind=served.kind, error=str(exc)[:200])
            self._fail_closed(flow)

    def _fail_closed(self, flow: Any) -> None:
        """Last resort when the planned response could not be built. Never raises.

        Tries the canned inert `200` first — a `Response.make` that refused the planned
        one usually accepts this — and kills the flow if even that fails, because with
        no usable response factory the only remaining way to keep the sample off the
        network is to drop the connection.
        """
        try:
            flow.response = self._make_response(canned_ok_response())
            return
        except Exception as exc:
            log.warning("c2_canned_response_failed", error=str(exc)[:200])
        try:
            flow.kill()
        except Exception as exc:
            # Nothing further is available. Logged loudly: this is the only path in the
            # file where "no upstream is ever contacted" rests on mitmproxy's own
            # behaviour rather than on something this addon did.
            log.warning("c2_flow_kill_failed", error=str(exc)[:200])

    @staticmethod
    def _make_response(served: ServedResponse) -> Any:
        """Build the mitmproxy response. Imported here — mitmproxy is a lab-only extra."""
        from mitmproxy import http

        return http.Response.make(served.status, served.body, served.headers())

    def _matched(self, host: str, path: str) -> ServedResponse | None:
        """The bundle's answer for this request, already turned into bytes.

        The payload-URL route is checked first: it is an exact `(host, path)` match,
        which is strictly more specific than any entry's prefix.
        """
        if (host, path) in self._payload_targets:
            return payload_stub_response()
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

    When `DRISHTI_SAMPLE_SHA256` names the sample under detonation, a bundle built for a
    different one is refused: a stale file at the staged path is otherwise served in
    full, and answers belonging to another sample are fabricated behaviour.
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
    expected = os.environ.get(SAMPLE_SHA_ENV, "").strip().lower()
    if expected and expected != bundle.sha256.strip().lower():
        # Structural, not procedural: the staged path is reused run to run, so a bundle
        # left behind by the previous sample is readable, valid and completely wrong.
        # Serving it would invent C2 behaviour for a sample that never had any, which is
        # a fabricated finding, not a degraded one. Refuse it and sinkhole instead.
        log.warning(
            "c2_bundle_sample_mismatch",
            path=str(location),
            expected_sha256=expected,
            bundle_sha256=bundle.sha256,
        )
        return None
    log.info(
        "c2_bundle_loaded",
        sha256=bundle.sha256,
        entries=len(bundle.entries),
        built_at=bundle.built_at,
    )
    return bundle


def build_addons() -> list[Any]:
    """The chain mitmdump loads. Capture first: it must see every flow, answered or not.

    Nothing here may raise. mitmdump executes this module at load; a raise means the
    process exits, and `runtime_prepare.sh` starts it under `nohup`, so the exit is
    silent and shows up only as an empty flow log hours later. `FlowCaptureAddon()`
    creates its log directory, which is exactly the kind of step that fails on a full or
    read-only disk — so losing capture costs capture, and the responder still answers.
    """
    chain: list[Any] = []
    try:
        chain.append(FlowCaptureAddon())
    except Exception as exc:
        # Loud, because a detonation that runs without capture produces no evidence at
        # all. The run must be read as inconclusive, never as "the sample stayed quiet".
        log.error("flow_capture_unavailable", error=str(exc)[:200])
    chain.append(BundleResponder(load_bundle()))
    return chain


addons = build_addons()

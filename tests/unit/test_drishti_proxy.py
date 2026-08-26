"""The composed detonator proxy: capture + bundle responder + sinkhole.

`infra/gcp/drishti_proxy.py` runs under mitmdump on the sealed VM, so it is loaded here
by path rather than imported as a package module. mitmproxy is a lab extra and is NOT
installed on a laptop, so every test below exercises the pure decision half; the one
adapter test substitutes a fake response factory for `mitmproxy.http.Response.make`.
"""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import sys
import tempfile
from typing import Any

from drishti.contracts.c2_bundle import C2Bundle, C2BundleEntry
from drishti.m3_dynamic.proxy.capture_addon import (
    FlowCaptureAddon,
    provenance_from_headers,
)

_MODULE_PATH = pathlib.Path(__file__).resolve().parents[2] / "infra" / "gcp" / "drishti_proxy.py"


def _load_proxy_module() -> Any:
    """Load the on-VM proxy script.

    `DRISHTI_FLOW_LOG` is pointed at a temp file for the duration of the import: the
    module builds its addon chain at import time (mitmproxy reads a module-level
    `addons`), and the default log path is `/opt/drishti/results/`, which does not exist
    off the VM. The previous value is restored so no other test inherits it.
    """
    tmp_dir = tempfile.mkdtemp(prefix="drishti-proxy-test-")
    previous = os.environ.get("DRISHTI_FLOW_LOG")
    os.environ["DRISHTI_FLOW_LOG"] = os.path.join(tmp_dir, "flows.jsonl")
    try:
        spec = importlib.util.spec_from_file_location("drishti_proxy", _MODULE_PATH)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # Registered before execution because `@dataclass` resolves annotations through
        # `sys.modules[cls.__module__]`; mitmproxy's own script loader registers it too.
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        if previous is None:
            os.environ.pop("DRISHTI_FLOW_LOG", None)
        else:
            os.environ["DRISHTI_FLOW_LOG"] = previous


proxy = _load_proxy_module()


def _bundle() -> C2Bundle:
    return C2Bundle(
        sha256="a" * 64,
        built_at="2026-08-26T00:00:00Z",
        entries=(
            C2BundleEntry(
                host="gate.evil.tk",
                path_prefix="/reg",
                response_kind="registration_ack",
                served_status=200,
                served_content_type="application/json",
                served_body='{"status": "ok"}',
                derived_from=("ledger://x",),
            ),
            C2BundleEntry(
                host="gate.evil.tk",
                path_prefix="/payload",
                response_kind="inert_payload_stub",
                served_status=200,
                served_content_type="application/json",
                served_body='{"url": "http://gate.evil.tk/payload/x.dex"}',
                is_payload_url=True,
                derived_from=("ledger://y",),
            ),
        ),
    )


# ── the brief's three: matching, the inert second stage, and the miss ──────────


def test_responder_serves_matching_entry() -> None:
    r = proxy.BundleResponder(_bundle())
    decided = r.decide("gate.evil.tk", "/reg/1")
    assert decided is not None
    status, body, ctype = decided
    assert status == 200
    assert b'"status":"ok"' in body
    assert ctype == "application/json"


def test_responder_serves_inert_dex_on_payload_path() -> None:
    r = proxy.BundleResponder(_bundle())
    decided = r.decide("gate.evil.tk", "/payload/x.dex")
    assert decided is not None
    _status, body, ctype = decided
    assert body[:8] == b"dex\n035\x00"
    assert len(body) == 0x70  # header only: a loader validates the magic and finds no code
    assert ctype == "application/octet-stream"


def test_responder_passes_unknown_host_to_fallback() -> None:
    r = proxy.BundleResponder(_bundle())
    assert r.decide("clients3.google.com", "/") is None


# ── item 4: both provenance headers, read back by the capture addon ────────────


def test_served_headers_round_trip_through_capture_provenance() -> None:
    """The capture addon must be able to read our provenance back off the wire.

    Asserted against `provenance_from_headers` itself rather than against a hardcoded
    header spelling: if the two ever disagree, a response DRISHTI synthesised would be
    recorded as attacker traffic and could be published as an IOC.
    """
    r = proxy.BundleResponder(_bundle())
    served = r.plan("gate.evil.tk", "/reg/1")
    assert provenance_from_headers(served.headers()) == (True, "registration_ack")


def test_payload_stub_declares_its_kind() -> None:
    r = proxy.BundleResponder(_bundle())
    served = r.plan("gate.evil.tk", "/payload/x.dex")
    assert provenance_from_headers(served.headers()) == (True, "inert_payload_stub")


def test_sinkhole_response_is_also_marked_synthesised() -> None:
    """The sinkhole body is our content too. Unlabelled, it reads as attacker traffic."""
    r = proxy.BundleResponder(None)
    served = r.plan("gate.evil.tk", "/anything")
    assert provenance_from_headers(served.headers()) == (True, proxy.SINKHOLE_KIND)


def test_served_headers_declare_no_upstream() -> None:
    r = proxy.BundleResponder(_bundle())
    headers = r.plan("gate.evil.tk", "/reg/1").headers()
    assert headers[proxy.NO_UPSTREAM_HEADER] == "true"
    assert headers["Content-Type"] == "application/json"


def test_served_kind_is_bounded_like_the_contract_field() -> None:
    """`CapturedFlow.served_kind` caps at 32 chars; an absurd bundle must not break it."""
    bundle = C2Bundle(
        sha256="b" * 64,
        entries=(
            C2BundleEntry(
                host="h.tk",
                path_prefix="/",
                response_kind="k" * 4096,
                served_body='{"status": "ok"}',
                derived_from=("ledger://z",),
            ),
        ),
    )
    served = proxy.BundleResponder(bundle).plan("h.tk", "/")
    assert len(served.headers()[proxy.KIND_HEADER]) == 32


# ── item 5: inertness is re-verified at serve time, not trusted from the file ──


def test_tampered_bundle_body_falls_back_to_the_canned_ok() -> None:
    """The bundle is a file staged onto a VM. Trust it at the point of use, not before.

    `provably_inert` is set on the orchestrator; the bytes reach the wire here, so the
    gate runs here too. A base64 DEX smuggled into an entry must never be served.
    """
    bundle = C2Bundle(
        sha256="c" * 64,
        entries=(
            C2BundleEntry(
                host="gate.evil.tk",
                path_prefix="/reg",
                response_kind="registration_ack",
                served_body=json.dumps({"blob": "ZGV4CgAAAAAAAAAAAAAA"}),
                derived_from=("ledger://x",),
            ),
        ),
    )
    served = proxy.BundleResponder(bundle).plan("gate.evil.tk", "/reg")
    assert served.body == proxy.CANNED_OK_BODY
    assert served.kind == "connectivity_ok"
    assert b"ZGV4" not in served.body


def test_non_json_bundle_body_falls_back_to_the_canned_ok() -> None:
    bundle = C2Bundle(
        sha256="d" * 64,
        entries=(
            C2BundleEntry(
                host="gate.evil.tk",
                path_prefix="/reg",
                response_kind="config",
                served_content_type="text/html",
                served_body="<html>not a control response</html>",
                derived_from=("ledger://x",),
            ),
        ),
    )
    served = proxy.BundleResponder(bundle).plan("gate.evil.tk", "/reg")
    assert served.body == proxy.CANNED_OK_BODY
    assert served.content_type == "application/json"


def test_serve_time_gate_neutralises_a_url_value() -> None:
    """A URL that survived into a bundle entry is sinkholed before it is served."""
    bundle = C2Bundle(
        sha256="e" * 64,
        entries=(
            C2BundleEntry(
                host="gate.evil.tk",
                path_prefix="/cfg",
                response_kind="config",
                served_body=json.dumps({"next": "http://second-stage.tk/x.apk"}),
                derived_from=("ledger://x",),
            ),
        ),
    )
    served = proxy.BundleResponder(bundle).plan("gate.evil.tk", "/cfg")
    assert b"second-stage.tk" not in served.body


# ── item 6: the sinkhole is the floor. Absence of a bundle changes nothing ─────


def test_plan_sinkholes_an_unknown_host() -> None:
    """A dead C2 that gets a connection error behaves differently from one that gets 200."""
    served = proxy.BundleResponder(_bundle()).plan("clients3.google.com", "/")
    assert served.status == 200
    assert json.loads(served.body) == {"status": "sinkholed", "commands": []}


def test_plan_sinkholes_a_hinted_host_on_an_unhinted_path() -> None:
    """The builder emits one entry per host at its FIRST observed path. This is intended."""
    served = proxy.BundleResponder(_bundle()).plan("gate.evil.tk", "/api/b")
    assert json.loads(served.body) == {"status": "sinkholed", "commands": []}


def test_plan_sinkholes_when_no_bundle_was_staged() -> None:
    """Pass 1 runs with no bundle at all and must still answer every request."""
    r = proxy.BundleResponder(None)
    assert r.decide("gate.evil.tk", "/reg") is None
    assert json.loads(r.plan("gate.evil.tk", "/reg").body) == {
        "status": "sinkholed",
        "commands": [],
    }


# ── loading the bundle: a bad file costs the bundle, never the proxy ───────────


def test_load_bundle_reads_a_staged_file(tmp_path: pathlib.Path, monkeypatch: Any) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(_bundle().model_dump_json(), encoding="utf-8")
    monkeypatch.setenv(proxy.BUNDLE_ENV, str(path))
    loaded = proxy.load_bundle()
    assert loaded is not None
    assert len(loaded.entries) == 2


def test_load_bundle_is_none_when_unset(monkeypatch: Any) -> None:
    monkeypatch.delenv(proxy.BUNDLE_ENV, raising=False)
    assert proxy.load_bundle() is None


def test_load_bundle_is_none_when_missing(tmp_path: pathlib.Path, monkeypatch: Any) -> None:
    monkeypatch.setenv(proxy.BUNDLE_ENV, str(tmp_path / "absent.json"))
    assert proxy.load_bundle() is None


def test_load_bundle_survives_a_corrupt_file(tmp_path: pathlib.Path, monkeypatch: Any) -> None:
    path = tmp_path / "bundle.json"
    path.write_text("{not json", encoding="utf-8")
    monkeypatch.setenv(proxy.BUNDLE_ENV, str(path))
    assert proxy.load_bundle() is None  # the proxy still runs, sinkholing everything


# ── the mitmproxy adapter, exercised without mitmproxy ────────────────────────


class _FakeFlow:
    def __init__(self, host: str, path: str) -> None:
        self.request = type("Req", (), {"host": host, "path": path})()
        self.response: Any = None


class _RecordingResponder:
    """A responder whose response factory is a plain tuple, so no mitmproxy is needed."""

    @staticmethod
    def _make_response(served: Any) -> Any:
        return (served.status, served.body, served.headers())


def _responder(bundle: C2Bundle | None) -> Any:
    cls = type("TestResponder", (_RecordingResponder, proxy.BundleResponder), {})
    return cls(bundle)


def test_request_hook_answers_from_the_bundle() -> None:
    flow = _FakeFlow("gate.evil.tk", "/reg/1?id=7")
    _responder(_bundle()).request(flow)
    status, body, headers = flow.response
    assert status == 200
    assert b'"status":"ok"' in body
    assert provenance_from_headers(headers) == (True, "registration_ack")


def test_request_hook_sinkholes_an_unknown_host() -> None:
    flow = _FakeFlow("clients3.google.com", "/generate_204")
    _responder(_bundle()).request(flow)
    _status, body, _headers = flow.response
    assert json.loads(body) == {"status": "sinkholed", "commands": []}


def test_request_hook_never_raises_on_a_hostile_flow() -> None:
    """An exception here kills capture, and with it the record of what the sample called."""

    class Exploding:
        @property
        def request(self) -> Any:
            raise RuntimeError("flow decode failed")

    flow = Exploding()
    _responder(_bundle()).request(flow)  # must not raise


def test_request_hook_declines_when_the_response_factory_fails(monkeypatch: Any) -> None:
    """A broken factory (no mitmproxy, a bad status) logs and declines. It never raises."""

    def boom(_served: Any) -> Any:
        raise RuntimeError("mitmproxy unavailable")

    monkeypatch.setattr(proxy.BundleResponder, "_make_response", staticmethod(boom))
    flow = _FakeFlow("gate.evil.tk", "/reg/1")
    proxy.BundleResponder(_bundle()).request(flow)
    assert flow.response is None


# ── the chain mitmdump actually loads ─────────────────────────────────────────


def test_build_addons_puts_capture_first(tmp_path: pathlib.Path, monkeypatch: Any) -> None:
    monkeypatch.setenv("DRISHTI_FLOW_LOG", str(tmp_path / "flows.jsonl"))
    monkeypatch.delenv(proxy.BUNDLE_ENV, raising=False)
    addons = proxy.build_addons()
    assert isinstance(addons[0], FlowCaptureAddon)
    assert isinstance(addons[1], proxy.BundleResponder)


def test_module_exposes_addons_for_mitmdump() -> None:
    assert len(proxy.addons) == 2

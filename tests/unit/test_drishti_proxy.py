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


def _load_proxy_module(*, register: bool = True, name: str = "drishti_proxy") -> Any:
    """Load the on-VM proxy script.

    `DRISHTI_FLOW_LOG` is pointed at a temp file for the duration of the import: the
    module builds its addon chain at import time (mitmproxy reads a module-level
    `addons`), and the default log path is `/opt/drishti/results/`, which does not exist
    off the VM. The previous value is restored so no other test inherits it.

    `register=False` reproduces mitmproxy's own script loader, which does **not** put the
    module in `sys.modules` — see `test_module_loads_the_way_mitmdump_loads_it`.
    """
    tmp_dir = tempfile.mkdtemp(prefix="drishti-proxy-test-")
    previous = os.environ.get("DRISHTI_FLOW_LOG")
    os.environ["DRISHTI_FLOW_LOG"] = os.path.join(tmp_dir, "flows.jsonl")
    try:
        spec = importlib.util.spec_from_file_location(name, _MODULE_PATH)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        if register:
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


def test_module_loads_the_way_mitmdump_loads_it() -> None:
    """Regression: mitmproxy execs the script WITHOUT registering it in `sys.modules`.

    MEASURED 2026-08-27 on m3-detonator. `from __future__ import annotations` makes every
    annotation a string, so `@dataclass` asks `sys.modules[cls.__module__].__dict__`
    whether one names `KW_ONLY`; unregistered, that lookup returns None and mitmdump
    exits during startup. runtime_prepare.sh nohups mitmdump, so the only symptom in the
    field is an empty `flows.jsonl` — indistinguishable from a sample that never beaconed.
    Every other test here registers the module first and so cannot see this.
    """
    module = _load_proxy_module(register=False, name="drishti_proxy_unregistered")
    assert [type(a).__name__ for a in module.addons] == ["FlowCaptureAddon", "BundleResponder"]


# ── the brief's three: matching, the inert second stage, and the miss ──────────


def test_responder_serves_matching_entry() -> None:
    r = proxy.BundleResponder(_bundle())
    decided = r.decide("gate.evil.tk", "/reg/1")
    assert decided is not None
    status, body, ctype = decided
    assert status == 200
    assert b'"status":"ok"' in body
    assert ctype == "application/json"


def test_responder_serves_inert_dex_on_the_injected_payload_url() -> None:
    """The DEX stub belongs on the URL we injected, not on the entry's beacon path.

    The plan's original version of this test asserted DEX bytes on `/payload/x.dex`
    because `is_payload_url` was read as "this path IS the download". It is not: it
    means "this entry's BODY names a download URL". The URL actually handed to the
    sample is whatever survived `assert_inert`, and that is the one path the stub may
    answer on. See `test_payload_entry_serves_its_json_body_on_the_beacon_path`.
    """
    r = proxy.BundleResponder(_bundle())
    targets = r.payload_targets()
    assert targets, "the payload-stub entry injected no URL to route"
    host, path = next(iter(targets))
    decided = r.decide(host, path)
    assert decided is not None
    _status, body, ctype = decided
    assert body[:8] == b"dex\n035\x00"
    assert len(body) == 0x70  # header only: a loader validates the magic and finds no code
    assert ctype == "application/octet-stream"


def test_the_injected_payload_url_is_the_guest_loopback_and_so_unreachable() -> None:
    """Pins the disclosed gap so nobody claims a second stage was ever downloaded.

    `assert_inert` rewrites every URL to `generative_c2.SINKHOLE_URL`
    (`http://127.0.0.1:9/inert`), which the GUEST resolves to itself. A sample that
    follows the bait never crosses the emulated NIC, so this route exists but no request
    can arrive on it. Changing `SINKHOLE_URL` to make it reachable would be rewriting
    the inertness gate; if this test ever fails, that is what happened.
    """
    assert proxy.BundleResponder(_bundle()).payload_targets() == {("127.0.0.1", "/inert")}


def test_payload_entry_serves_its_json_body_on_the_beacon_path() -> None:
    """A dropper's beacon path must get JSON, not 0x70 bytes of DEX.

    `path_prefix` is the sample's first observed beacon path and `served_body` is the
    JSON that baits the second stage. Answering it with `application/octet-stream` and
    DEX bytes breaks the sample's parser, so the bait is never delivered — on droppers,
    which is exactly where `derive_hints` picks `INERT_PAYLOAD_STUB`.
    """
    r = proxy.BundleResponder(_bundle())
    served = r.plan("gate.evil.tk", "/payload/x.dex")
    assert served.content_type == "application/json"
    assert b"dex\n035" not in served.body
    assert json.loads(served.body)["url"] == "http://127.0.0.1:9/inert"


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
    """`CapturedFlow.served_kind` caps at 32 chars; an absurd bundle must not break it.

    Two halves. The responder resolves an unknown kind through `_kind_of` and stamps the
    RESOLVED value, so the wire and the sanitiser agree about which shape was enforced;
    and `ServedResponse` still bounds the header for any caller that supplies its own.
    """
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
    assert served.headers()[proxy.KIND_HEADER] == "connectivity_ok"
    assert (
        len(
            proxy.ServedResponse(200, b"{}", "application/json", "k" * 4096).headers()[
                proxy.KIND_HEADER
            ]
        )
        == 32
    )


def test_an_unknown_kind_is_stamped_as_the_kind_the_sanitiser_actually_used() -> None:
    """M2: `_kind_of` falls back, so the raw string would describe a shape never enforced."""
    bundle = C2Bundle(
        sha256="7" * 64,
        entries=(
            C2BundleEntry(
                host="h.tk",
                path_prefix="/",
                response_kind="not_a_real_kind",
                served_body='{"status": "ok"}',
                derived_from=("ledger://z",),
            ),
        ),
    )
    served = proxy.BundleResponder(bundle).plan("h.tk", "/")
    assert provenance_from_headers(served.headers()) == (True, "connectivity_ok")


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
    """A broken factory logs and gives up quietly. It never raises.

    This flow has no `kill()`, so even the fail-closed last resort is unavailable and
    `flow.response` stays unset. What is asserted is only that the hook returns instead
    of raising — an exception here would take the capture addon down with it. The
    fail-closed behaviour itself is asserted below, on a flow that can be killed.
    """

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


# ── C1: the emulator's -http-proxy flag is resolved host-side ─────────────────

_INFRA = pathlib.Path(__file__).resolve().parents[2] / "infra" / "gcp"


def _http_proxy_flag_lines(script: str) -> list[str]:
    """Every line of a launch script that actually passes `-http-proxy`.

    Comment lines are excluded on purpose: the surrounding comments name 10.0.2.2 to
    explain why it belongs in `settings put global http_proxy` and nowhere else.
    """
    text = (_INFRA / script).read_text(encoding="utf-8")
    return [
        stripped
        for line in text.splitlines()
        if "-http-proxy" in (stripped := line.strip()) and not stripped.startswith("#")
    ]


def test_emulator_launch_flag_targets_the_hosts_own_loopback() -> None:
    """`-http-proxy` is a flag to the emulator PROCESS, which runs on the host.

    10.0.2.2 is the guest-side alias for the host loopback and is correct only for
    `settings put global http_proxy`, which the guest resolves. Passed to the host
    process it is an ordinary RFC1918 address that the detonator's `-A OUTPUT -j DROP`
    blackholes: the emulator boots healthy, detonation "succeeds", and flows.jsonl
    stays empty — a zero-flow batch that reads as "the sample never beaconed".
    """
    for script in ("emulator_control.sh", "detonator_provision.sh"):
        lines = _http_proxy_flag_lines(script)
        assert lines, f"{script} no longer launches the emulator with -http-proxy"
        for line in lines:
            assert "127.0.0.1:8080" in line, line
            assert "10.0.2.2" not in line, line


# ── I1: mitmproxy's connection strategy is load-bearing for containment ───────


def test_mitmdump_pins_the_eager_connection_strategy() -> None:
    """`lazy` would answer the containment probe before any upstream was tried.

    `containment.verify()` reads rc 0 from a connect to 169.254.169.254:80 as REACHABLE.
    With guest TCP terminating at our proxy, `lazy` answers immediately and turns every
    FORBIDDEN probe into a false REACHABLE; `eager` connects upstream first, so a blocked
    destination still fails the connect.

    **CORRECTED 2026-08-27 — `eager` is necessary but NOT sufficient.** Measured on
    m3-detonator with the proxy live and the host lockdown applied, the probe still
    reported `169.254.169.254:80 is REACHABLE` and aborted the batch. `eager` never got a
    say: the *emulator's* `-http-proxy` shim terminates the guest's port-80 TCP itself,
    before anything reaches mitmproxy, so the guest's connect() succeeds regardless.
    Nothing actually got through (an in-guest GET for the instance id returned zero bytes;
    the same request from the host timed out against the DROP rule), so containment held
    and only the measurement broke. The escape hatch is `DRISHTI_EMULATOR_PROXY=none` in
    emulator_control.sh, where the full measurement is recorded. Keep this pin: it is
    still what stops `lazy` from adding a second, independent false REACHABLE.
    """
    text = (_INFRA / "runtime_prepare.sh").read_text(encoding="utf-8")
    assert "--set connection_strategy=eager" in text


# ── M5: the `clean` snapshot is live state, not a rebuildable artifact ────────


def test_provision_guards_the_clean_snapshot() -> None:
    """Re-running `detonator_provision.sh all` must not re-cut `clean`."""
    text = (_INFRA / "detonator_provision.sh").read_text(encoding="utf-8")
    body = text.split("step_snapshot() {", 1)[1].split("\n}", 1)[0]
    assert "stamped snapshot" in body
    assert "stamp snapshot" in body
    assert "DRISHTI_FORCE_SNAPSHOT" in body


# ── I2: a bundle answers for exactly one sample ───────────────────────────────


def test_load_bundle_refuses_a_bundle_built_for_another_sample(
    tmp_path: pathlib.Path, monkeypatch: Any
) -> None:
    """A stale bundle left at the staged path would fabricate the next sample's C2."""
    path = tmp_path / "bundle.json"
    path.write_text(_bundle().model_dump_json(), encoding="utf-8")  # sha256 = "a" * 64
    monkeypatch.setenv(proxy.BUNDLE_ENV, str(path))
    monkeypatch.setenv(proxy.SAMPLE_SHA_ENV, "f" * 64)
    assert proxy.load_bundle() is None  # every host sinkholes instead


def test_load_bundle_accepts_the_bundle_built_for_this_sample(
    tmp_path: pathlib.Path, monkeypatch: Any
) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(_bundle().model_dump_json(), encoding="utf-8")
    monkeypatch.setenv(proxy.BUNDLE_ENV, str(path))
    monkeypatch.setenv(proxy.SAMPLE_SHA_ENV, "A" * 64)  # case is not a mismatch
    loaded = proxy.load_bundle()
    assert loaded is not None and loaded.sha256 == "a" * 64


def test_load_bundle_keeps_current_behaviour_when_no_sample_sha_is_pinned(
    tmp_path: pathlib.Path, monkeypatch: Any
) -> None:
    path = tmp_path / "bundle.json"
    path.write_text(_bundle().model_dump_json(), encoding="utf-8")
    monkeypatch.setenv(proxy.BUNDLE_ENV, str(path))
    monkeypatch.delenv(proxy.SAMPLE_SHA_ENV, raising=False)
    assert proxy.load_bundle() is not None


# ── I3: status, content type and kind are untrusted too, not just the body ────


def _entry_bundle(**overrides: Any) -> C2Bundle:
    fields: dict[str, Any] = {
        "host": "gate.evil.tk",
        "path_prefix": "/reg",
        "response_kind": "registration_ack",
        "served_body": '{"status": "ok"}',
        "derived_from": ("ledger://x",),
    }
    fields.update(overrides)
    return C2Bundle(sha256="9" * 64, entries=(C2BundleEntry(**fields),))


def test_absurd_served_status_is_clamped_rather_than_raising() -> None:
    """`http.Response.make` raises outside 100..599, and a raise in the request hook
    leaves `flow.response` unset — which makes mitmproxy forward the request UPSTREAM."""
    served = proxy.BundleResponder(_entry_bundle(served_status=999999)).plan("gate.evil.tk", "/reg")
    assert served.status == 200
    assert proxy.MIN_STATUS <= served.status <= proxy.MAX_STATUS


def test_a_plausible_served_status_is_preserved() -> None:
    served = proxy.BundleResponder(_entry_bundle(served_status=404)).plan("gate.evil.tk", "/reg")
    assert served.status == 404


def test_served_content_type_is_allow_listed() -> None:
    """A header-splitting content type must never reach `Content-Type` verbatim."""
    hostile = "application/json\r\nX-Evil: 2"
    served = proxy.BundleResponder(_entry_bundle(served_content_type=hostile)).plan(
        "gate.evil.tk", "/reg"
    )
    assert served.content_type == "application/json"
    assert served.headers()["Content-Type"] == "application/json"


def test_header_values_carry_no_control_characters() -> None:
    """A CRLF in `response_kind` survives truncation and round-trips out of capture."""
    served = proxy.BundleResponder(
        _entry_bundle(response_kind="config\r\nX-Evil: 2", served_content_type="text/html\r\nx: 1")
    ).plan("gate.evil.tk", "/reg")
    for name, value in served.headers().items():
        assert not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value), (name, value)
    read_back = provenance_from_headers(served.headers())
    assert read_back[0] is True
    assert "\r" not in (read_back[1] or "") and "\n" not in (read_back[1] or "")


def test_direct_construction_is_normalised_too() -> None:
    """The clamp lives on the value object, so no construction path can bypass it."""
    served = proxy.ServedResponse(999999, b"{}", "text/html", "k\r\nx: 1")
    assert served.status == 200
    assert served.content_type == "application/json"
    assert "\r" not in served.kind


def test_the_inert_dex_content_type_stays_allowed() -> None:
    """The allow-list must not narrow the one non-JSON response this system serves."""
    served = proxy.BundleResponder(_bundle()).plan("127.0.0.1", "/inert")
    assert served.content_type == "application/octet-stream"


def test_a_json_body_is_never_labelled_with_the_entrys_own_content_type() -> None:
    """M3: `served_body` is replaced by `assert_inert`'s output, so the label must be too.

    The refusal path already normalises to JSON. The success path used to pass a staged
    `text/html` straight through, which labelled compact JSON as HTML — the two paths
    disagreeing about the same bytes.
    """
    bundle = C2Bundle(
        sha256="8" * 64,
        entries=(
            C2BundleEntry(
                host="h.tk",
                path_prefix="/",
                response_kind="config",
                served_content_type="text/html",
                served_body='{"status": "ok"}',
                derived_from=("ledger://z",),
            ),
        ),
    )
    served = proxy.BundleResponder(bundle).plan("h.tk", "/")
    assert served.body == b'{"status":"ok"}'  # the gate ran and produced JSON
    assert served.content_type == "application/json"


# ── I3 (4): the failure path fails closed, never upstream ─────────────────────


class _KillableFlow(_FakeFlow):
    def __init__(self, host: str, path: str) -> None:
        super().__init__(host, path)
        self.killed = False

    def kill(self) -> None:
        self.killed = True


def test_request_hook_retries_with_a_canned_response_when_the_first_refuses() -> None:
    """mitmproxy refusing one response must not leave the flow free to go upstream."""
    refused: list[Any] = []

    class _PickyResponder(proxy.BundleResponder):
        """Refuses the first response offered, the way a bad status makes mitmproxy."""

        @staticmethod
        def _make_response(served: Any) -> Any:
            if not refused:
                refused.append(served)
                raise ValueError("unacceptable response")
            return (served.status, served.body, served.headers())

    flow = _KillableFlow("gate.evil.tk", "/reg/1")
    _PickyResponder(_bundle()).request(flow)
    assert refused, "the test's first response was accepted — nothing was exercised"
    assert flow.response is not None
    _status, body, headers = flow.response
    assert body == proxy.CANNED_OK_BODY
    assert provenance_from_headers(headers)[0] is True
    assert flow.killed is False


def test_request_hook_kills_the_flow_when_no_response_can_be_built(monkeypatch: Any) -> None:
    """With no usable response factory the only fail-closed move left is to kill it."""

    def boom(_served: Any) -> Any:
        raise RuntimeError("mitmproxy unavailable")

    monkeypatch.setattr(proxy.BundleResponder, "_make_response", staticmethod(boom))
    flow = _KillableFlow("gate.evil.tk", "/reg/1")
    proxy.BundleResponder(_bundle()).request(flow)
    assert flow.response is None
    assert flow.killed is True  # never forwarded upstream


def test_request_hook_fails_closed_when_the_flow_itself_explodes() -> None:
    """Even an undecodable request gets an inert answer rather than a trip upstream."""

    class _Exploding(_KillableFlow):
        @property  # type: ignore[misc]
        def request(self) -> Any:
            raise RuntimeError("flow decode failed")

    flow = _KillableFlow.__new__(_Exploding)
    flow.response = None
    flow.killed = False
    _responder_cls = type("TestResponder", (_RecordingResponder, proxy.BundleResponder), {})
    _responder_cls(_bundle()).request(flow)
    assert flow.response is not None
    _status, body, _headers = flow.response
    assert body == proxy.CANNED_OK_BODY


# ── M4: mitmdump loads this module under nohup, so an import-time raise is silent ──


def test_build_addons_survives_an_unusable_flow_log_directory(monkeypatch: Any) -> None:
    """`FlowCaptureAddon.__init__` mkdirs. A full or read-only disk must not exit mitmdump.

    `addons = build_addons()` runs at module load, and runtime_prepare.sh starts mitmdump
    with `nohup` — a raise here kills the process silently and surfaces hours later as an
    empty flow log, the same class of failure as an unreachable proxy address. Losing
    capture is bad; losing the whole proxy means the sample also talks to nothing.
    """

    def boom(*_args: Any, **_kwargs: Any) -> Any:
        raise PermissionError("[Errno 13] mkdir: /opt/drishti/results")

    monkeypatch.setattr(proxy, "FlowCaptureAddon", boom)
    monkeypatch.delenv(proxy.BUNDLE_ENV, raising=False)
    addons = proxy.build_addons()
    assert len(addons) == 1
    assert isinstance(addons[0], proxy.BundleResponder)


# ── I1: a hostile payload-stub entry costs a route, never the proxy ───────────


def test_an_unparseable_payload_entry_yields_no_route_and_still_answers() -> None:
    bundle = C2Bundle(
        sha256="6" * 64,
        entries=(
            C2BundleEntry(
                host="gate.evil.tk",
                path_prefix="/p",
                response_kind="inert_payload_stub",
                served_body="<html>not a control response</html>",
                is_payload_url=True,
                derived_from=("ledger://x",),
            ),
        ),
    )
    responder = proxy.BundleResponder(bundle)
    assert responder.payload_targets() == frozenset()
    assert responder.plan("gate.evil.tk", "/p").body == proxy.CANNED_OK_BODY


def test_a_bundleless_responder_routes_no_payload_urls() -> None:
    assert proxy.BundleResponder(None).payload_targets() == frozenset()

"""The detonator's flow-capture addon and its pure JSONL parser.

mitmproxy is a lab extra, not a laptop dependency, so everything here runs against
plain fakes: `parse_flow_log` and `build_flow_record` are pure, and `FlowCaptureAddon`
is a dumb adapter whose `response()` hook only reads attributes off the flow object.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from drishti.contracts.dynamic_trace import CapturedFlow
from drishti.m3_dynamic.proxy import capture_addon
from drishti.m3_dynamic.proxy.capture_addon import (
    FlowCaptureAddon,
    build_flow_record,
    parse_flow_log,
    provenance_from_headers,
)

# ── the pure parser ───────────────────────────────────────────────────────────


def test_parse_flow_log_reads_jsonl() -> None:
    text = (
        '{"t_ms_epoch":1,"method":"GET","scheme":"http","host":"gate.evil.tk",'
        '"path":"/checkin","status":200,"req_body_preview":"","resp_body_preview":"ok"}\n'
    )
    flows = parse_flow_log(text)
    assert flows == [
        CapturedFlow(
            t_ms_epoch=1,
            method="GET",
            scheme="http",
            host="gate.evil.tk",
            path="/checkin",
            status=200,
            req_body_preview="",
            resp_body_preview="ok",
        )
    ]


def test_parse_flow_log_skips_blank_and_malformed_lines() -> None:
    text = '\n{"not":"a flow"}\n{bad json\n'
    assert parse_flow_log(text) == []  # tolerant: a corrupt line is dropped, not fatal


def test_parse_flow_log_keeps_good_lines_around_a_bad_one() -> None:
    good = build_flow_record(
        t_ms_epoch=7, method="GET", scheme="http", host="h", path="/", status=200
    ).model_dump_json()
    assert len(parse_flow_log(f"{good}\n{{bad\n{good}\n")) == 2


# ── provenance from the responder's headers ───────────────────────────────────


def test_provenance_reads_synthesised_and_kind() -> None:
    assert provenance_from_headers(
        {"X-DRISHTI-Synthesised": "true", "X-DRISHTI-Kind": "command_poll"}
    ) == (True, "command_poll")


def test_provenance_header_lookup_is_case_insensitive() -> None:
    assert provenance_from_headers(
        {"x-drishti-synthesised": "TRUE", "x-drishti-kind": "config"}
    ) == (True, "config")


def test_provenance_defaults_when_headers_absent() -> None:
    assert provenance_from_headers({"Content-Type": "application/json"}) == (False, None)
    assert provenance_from_headers(None) == (False, None)


def test_provenance_ignores_kind_without_synthesised() -> None:
    """A label we never earned is not a label. The contract refuses it anyway."""
    assert provenance_from_headers({"X-DRISHTI-Kind": "registration_ack"}) == (False, None)


def test_provenance_ignores_a_falsey_synthesised_header() -> None:
    assert provenance_from_headers(
        {"X-DRISHTI-Synthesised": "false", "X-DRISHTI-Kind": "config"}
    ) == (False, None)


def test_provenance_truncates_an_absurd_kind() -> None:
    """A header is sample-adjacent input; it must not blow the contract's bound."""
    synthesised, kind = provenance_from_headers(
        {"X-DRISHTI-Synthesised": "1", "X-DRISHTI-Kind": "k" * 4096}
    )
    assert synthesised is True
    assert kind == "k" * 32


def test_provenance_survives_a_headers_object_that_misbehaves() -> None:
    class Exploding:
        def items(self) -> Any:
            raise RuntimeError("header decode failed")

    assert provenance_from_headers(Exploding()) == (False, None)


# ── record building ───────────────────────────────────────────────────────────


def test_build_flow_record_redacts_previews() -> None:
    flow = build_flow_record(
        t_ms_epoch=1,
        method="POST",
        scheme="http",
        host="gate.evil.tk",
        path="/register",
        status=200,
        req_text="password=hunter2",
        resp_text="bearer abcdefghijklmnop",
    )
    assert "hunter2" not in flow.req_body_preview
    assert "[REDACTED:CREDENTIAL]" in flow.req_body_preview
    assert "[REDACTED:TOKEN]" in flow.resp_body_preview


def test_build_flow_record_strips_the_query_string() -> None:
    flow = build_flow_record(
        t_ms_epoch=1,
        method="GET",
        scheme="http",
        host="h",
        path="/gate?id=abc&otp=123456",
        status=200,
    )
    assert flow.path == "/gate"


def test_build_flow_record_stamps_provenance_from_headers() -> None:
    flow = build_flow_record(
        t_ms_epoch=1,
        method="GET",
        scheme="http",
        host="gate.evil.tk",
        path="/checkin",
        status=200,
        resp_headers={"X-DRISHTI-Synthesised": "true", "X-DRISHTI-Kind": "connectivity_ok"},
    )
    assert (flow.synthesised, flow.served_kind) == (True, "connectivity_ok")


def test_build_flow_record_leaves_an_observed_flow_unlabelled() -> None:
    flow = build_flow_record(
        t_ms_epoch=1, method="GET", scheme="http", host="h", path="/", status=200
    )
    assert (flow.synthesised, flow.served_kind) == (False, None)


def test_build_flow_record_normalises_hostile_scalars() -> None:
    """Every value here comes from a process that just ran malware. None of it is trusted."""
    flow = build_flow_record(
        t_ms_epoch=1,
        method="M" * 200,
        scheme="s" * 200,
        host="h" * 400,
        path="/" + "p" * 4000,
        status=200,
    )
    assert len(flow.method) == 16
    assert len(flow.scheme) == 8
    assert len(flow.host) == 253
    assert len(flow.path) == 512


def test_build_flow_record_fills_in_missing_method_and_scheme() -> None:
    flow = build_flow_record(t_ms_epoch=0, method="", scheme="", host="", path="", status=None)
    assert flow.method == "UNKNOWN"
    assert flow.scheme == "unknown"
    assert flow.path == "/"


def test_build_flow_record_drops_previews_rather_than_raising(monkeypatch: Any) -> None:
    """A redaction bug must cost the preview, not the flow and not the event loop."""
    monkeypatch.setattr(capture_addon, "redact_text", lambda value, **_: str(value))
    flow = build_flow_record(
        t_ms_epoch=1,
        method="POST",
        scheme="http",
        host="gate.evil.tk",
        path="/",
        status=200,
        req_text="password=hunter2",
    )
    assert flow.req_body_preview == ""
    assert flow.host == "gate.evil.tk"


# ── the addon adapter ─────────────────────────────────────────────────────────


class _Message:
    def __init__(self, text: str = "", **attrs: Any) -> None:
        self._text = text
        for key, value in attrs.items():
            setattr(self, key, value)

    def get_text(self, strict: bool = True) -> str:
        return self._text


class _Unreadable(_Message):
    def get_text(self, strict: bool = True) -> str:
        raise ValueError("body is not decodable")


def _flow(request: Any, response: Any) -> Any:
    return type("Flow", (), {"request": request, "response": response})()


def test_addon_appends_one_json_line_per_flow(tmp_path: Path) -> None:
    log = tmp_path / "flows.jsonl"
    addon = FlowCaptureAddon(log_path=str(log))
    request = _Message(
        "id=1",
        timestamp_start=1.5,
        method="POST",
        scheme="http",
        host="gate.evil.tk",
        path="/register?x=1",
    )
    response = _Message('{"status":"ok"}', status_code=200, headers={})
    addon.response(_flow(request, response))
    addon.response(_flow(request, response))

    flows = parse_flow_log(log.read_text(encoding="utf-8"))
    assert len(flows) == 2
    assert flows[0].t_ms_epoch == 1500
    assert flows[0].host == "gate.evil.tk"
    assert flows[0].path == "/register"
    assert flows[0].status == 200


def test_addon_records_a_synthesised_response(tmp_path: Path) -> None:
    log = tmp_path / "flows.jsonl"
    addon = FlowCaptureAddon(log_path=str(log))
    request = _Message(timestamp_start=2.0, method="GET", scheme="http", host="c2.tk", path="/p")
    response = _Message(
        "{}",
        status_code=200,
        headers={"X-DRISHTI-Synthesised": "true", "X-DRISHTI-Kind": "command_poll"},
    )
    addon.response(_flow(request, response))

    (flow,) = parse_flow_log(log.read_text(encoding="utf-8"))
    assert (flow.synthesised, flow.served_kind) == (True, "command_poll")


def test_addon_records_a_dead_c2_with_no_response(tmp_path: Path) -> None:
    """No answer is a finding, not a gap — the flow is still written, status None."""
    log = tmp_path / "flows.jsonl"
    addon = FlowCaptureAddon(log_path=str(log))
    request = _Message(timestamp_start=3.0, method="GET", scheme="http", host="dead.tk", path="/")
    addon.response(_flow(request, None))

    (flow,) = parse_flow_log(log.read_text(encoding="utf-8"))
    assert flow.status is None
    assert flow.host == "dead.tk"


def test_addon_yields_an_empty_preview_for_an_unreadable_body(tmp_path: Path) -> None:
    log = tmp_path / "flows.jsonl"
    addon = FlowCaptureAddon(log_path=str(log))
    request = _Unreadable(timestamp_start=4.0, method="GET", scheme="http", host="h", path="/")
    addon.response(_flow(request, _Message("ok", status_code=200, headers={})))

    (flow,) = parse_flow_log(log.read_text(encoding="utf-8"))
    assert flow.req_body_preview == ""
    assert flow.resp_body_preview == "ok"


def test_addon_never_raises_into_the_event_loop(tmp_path: Path) -> None:
    """mitmproxy runs this inline; an exception here would kill the capture, and with
    it the only record of what the sample talked to."""
    addon = FlowCaptureAddon(log_path=str(tmp_path / "flows.jsonl"))
    addon.response(object())  # no .request at all
    addon.response(None)


def test_addon_reads_the_log_path_from_the_environment(tmp_path: Path, monkeypatch: Any) -> None:
    log = tmp_path / "nested" / "flows.jsonl"
    monkeypatch.setenv("DRISHTI_FLOW_LOG", str(log))
    request = _Message(timestamp_start=5.0, method="GET", scheme="http", host="h", path="/")
    FlowCaptureAddon().response(_flow(request, _Message("", status_code=204, headers={})))
    assert len(parse_flow_log(log.read_text(encoding="utf-8"))) == 1


@pytest.mark.parametrize("body", ["x" * 900, "password=hunter2"])
def test_addon_previews_are_bounded_and_redacted(tmp_path: Path, body: str) -> None:
    log = tmp_path / "flows.jsonl"
    addon = FlowCaptureAddon(log_path=str(log))
    request = _Message(body, timestamp_start=6.0, method="POST", scheme="http", host="h", path="/")
    addon.response(_flow(request, _Message("", status_code=200, headers={})))

    (flow,) = parse_flow_log(log.read_text(encoding="utf-8"))
    assert len(flow.req_body_preview) <= 512
    assert "hunter2" not in flow.req_body_preview

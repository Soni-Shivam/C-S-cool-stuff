"""Captured proxy flows become trace flows — bounded, deduped, honestly attributed.

Three things go wrong if this lift is naive, and each has a test here.

* **Volume.** A beaconing sample in a 120s detonation emits thousands of flows. CLAUDE.md
  rule 11 is not about tidiness: one real sample produced 1,925 `Cipher.doFinal` events,
  and a row per event blows the ledger sanity band and the 12k-token prompt budget on its
  own. Flows are grouped by `(host, path, method)` with an occurrence count and capped.
* **Time base.** Hook flows carry an offset from the run's start (0…duration); captured
  flows carry wall-clock epoch milliseconds. Merging those without converting means the
  dedupe key can never collide, and the same beacon renders twice — once "observed" at
  4.2s and once "synthesised" in 2026. The lift converts before it dedupes.
* **Provenance.** `synthesised` says *we authored the response body*. It does NOT say the
  destination is ours: the sample chose to beacon at that host, and answering it does not
  make the host our infrastructure. `injected_destination` is the field that says the
  destination is ours — the sinkhole `assert_inert` rewrites URLs to, the emulator's host
  alias, anything on loopback or RFC1918, or a host that appears only in a body we wrote.
  Publishing an IOC keys on that field, never on `synthesised`.
"""

from __future__ import annotations

from drishti.contracts.dynamic_trace import DynamicTrace
from drishti.m3_dynamic.ingest import MAX_CAPTURED_FLOWS, artifact_to_trace
from tests.unit._observation_builders import START_EPOCH_MS, artifact_with, captured_flow

_HOOK = "URL.openConnection"


def _hook(url: str) -> tuple[str, str, str]:
    """The observation an APK's `URL.openConnection` hook writes for `url`."""
    return (_HOOK, "T1437", f"opened connection to={url}")


# ── the lift itself ─────────────────────────────────────────────────────────
def test_captured_flows_lift_into_network_flows() -> None:
    trace = artifact_to_trace(
        artifact_with(captured_flows=(captured_flow("gate.evil.tk", path="/api/poll"),))
    )
    hosts = {f.host for f in trace.network_flows}
    assert "gate.evil.tk" in hosts
    assert all(f.tls_intercepted is False for f in trace.network_flows), (
        "we capture cleartext HTTP and never install a system CA"
    )


def test_the_lifted_flow_keeps_what_the_proxy_saw() -> None:
    """Method, URL, status and the redacted response preview all survive."""
    trace = artifact_to_trace(
        artifact_with(
            captured_flows=(
                captured_flow(
                    "gate.evil.tk",
                    method="POST",
                    path="/api/poll",
                    status=200,
                    resp_body_preview='{"status": "ok"}',
                ),
            )
        )
    )
    (flow,) = trace.network_flows
    assert (flow.method, flow.url, flow.status) == ("POST", "http://gate.evil.tk/api/poll", 200)
    assert flow.resp_body_preview == '{"status": "ok"}'


def test_synthesised_flag_survives_ingest() -> None:
    trace = artifact_to_trace(
        artifact_with(
            captured_flows=(
                captured_flow(
                    "gate.evil.tk", synthesised=True, served_kind="command_poll", status=200
                ),
            )
        )
    )
    answered = [f for f in trace.network_flows if f.host == "gate.evil.tk"]
    assert answered and answered[0].synthesised is True


def test_ingest_is_deterministic() -> None:
    """Two ingests of one artifact must be byte-identical (no set-iteration order)."""
    artifact = artifact_with(
        _hook("http://a.example/one"),
        _hook("http://b.example/two"),
        captured_flows=(
            captured_flow("c.example", path="/three", at_ms=10),
            captured_flow("d.example", path="/four", at_ms=20),
            captured_flow("c.example", path="/three", at_ms=30),
        ),
    )
    first = artifact_to_trace(artifact).model_dump(mode="json")
    second = artifact_to_trace(artifact).model_dump(mode="json")
    assert first == second


# ── R2: one time base, so the dedupe can actually fire ──────────────────────
def test_a_captured_flow_is_stamped_in_the_runs_own_time_base() -> None:
    """`t_ms_epoch` (~1.79e12) must become an offset from the run's start, like a hook's.

    Left as an epoch, the flow renders as having happened in 2026 next to a hook event
    at 4200ms, and no dedupe key that includes time can ever collide across the two.
    """
    trace = artifact_to_trace(
        artifact_with(captured_flows=(captured_flow("gate.evil.tk", at_ms=4200),))
    )
    (flow,) = trace.network_flows
    assert flow.t_ms == 4200
    assert flow.t_ms < START_EPOCH_MS, "an epoch leaked into the trace's relative clock"


def test_a_hook_flow_and_a_captured_flow_for_one_request_collapse() -> None:
    """The proxy and the `URL.openConnection` hook see the SAME request at two layers.

    Two rows for one beacon is the bug: the report would show the sample contacting its
    C2 twice, once "observed" and once "synthesised".
    """
    trace = artifact_to_trace(
        artifact_with(
            _hook("http://gate.evil.tk/api/poll"),
            captured_flows=(
                captured_flow(
                    "gate.evil.tk",
                    method="POST",
                    path="/api/poll",
                    at_ms=4200,
                    synthesised=True,
                    served_kind="command_poll",
                ),
            ),
        )
    )
    rows = [f for f in trace.network_flows if f.host == "gate.evil.tk"]
    assert len(rows) == 1, f"one request became {len(rows)} rows"
    # The proxy's view wins: it has the real verb, the status and the body.
    assert (rows[0].method, rows[0].status) == ("POST", 200)
    assert rows[0].synthesised is True


def test_distinct_paths_on_one_host_stay_distinct() -> None:
    """Collapsing is per request, not per host — a config fetch is not the beacon."""
    trace = artifact_to_trace(
        artifact_with(
            captured_flows=(
                captured_flow("gate.evil.tk", path="/api/poll"),
                captured_flow("gate.evil.tk", path="/api/config"),
            )
        )
    )
    assert {f.url for f in trace.network_flows} == {
        "http://gate.evil.tk/api/poll",
        "http://gate.evil.tk/api/config",
    }


# ── R1: aggregate and cap (CLAUDE.md rule 11) ───────────────────────────────
def test_repeated_beacons_become_one_row_with_a_count() -> None:
    trace = artifact_to_trace(
        artifact_with(
            captured_flows=tuple(
                captured_flow("gate.evil.tk", path="/api/poll", at_ms=i * 1000) for i in range(12)
            )
        )
    )
    (flow,) = trace.network_flows
    assert flow.occurrences == 12, "the rate is a finding; it may not be discarded"
    assert flow.t_ms == 0, "the row is stamped at the FIRST time the sample went there"


def test_the_lift_is_capped_and_says_what_it_dropped() -> None:
    """Rule 11 again: the cap mirrors `MAX_OBSERVATION_GROUPS`, and a drop is disclosed."""
    trace = artifact_to_trace(
        artifact_with(
            captured_flows=tuple(
                captured_flow(f"host{i:03d}.evil.tk", path="/p")
                for i in range(MAX_CAPTURED_FLOWS * 2)
            )
        )
    )
    assert len(trace.network_flows) == MAX_CAPTURED_FLOWS
    assert any("network flow" in e for e in trace.errors), "a silent drop is a lie by omission"
    assert trace.partial is True


def test_the_cap_keeps_the_busiest_destinations() -> None:
    """If something has to go, it is the single one-off, never the 30x beacon."""
    beacons = tuple(
        captured_flow("beacon.evil.tk", path="/gate", at_ms=i * 100)
        for i in range(MAX_CAPTURED_FLOWS + 5)
    )
    singles = tuple(
        captured_flow(f"once{i:03d}.example", path="/x") for i in range(MAX_CAPTURED_FLOWS + 5)
    )
    trace = artifact_to_trace(artifact_with(captured_flows=singles + beacons))
    assert "beacon.evil.tk" in {f.host for f in trace.network_flows}


# ── R3: provenance of the DESTINATION, not of the answer ────────────────────
def test_a_host_the_sample_chose_is_not_ours_just_because_we_answered_it() -> None:
    """The sinkhole answers every unhinted host. That does not make the host ours.

    Keying IOC publication on `synthesised` empties the STIX bundle and the dossier the
    moment the proxy runs, because the proxy stamps every response it serves.
    """
    trace = artifact_to_trace(
        artifact_with(
            captured_flows=(
                captured_flow("gate.evil.tk", synthesised=True, served_kind="sinkhole", status=200),
            )
        )
    )
    (flow,) = trace.network_flows
    assert flow.synthesised is True, "we did author that response body"
    assert flow.injected_destination is False, "the sample chose that destination, not us"


def test_our_own_sinkhole_destination_is_marked_as_ours() -> None:
    """`assert_inert` rewrites every URL to `http://127.0.0.1:9/inert`.

    A sample that follows the bait fires `URL.openConnection`, and the hook path builds
    the flow with `synthesised=False` — hardcoded. Without a destination-provenance flag
    our own injected string is exported to a SOC as adversary infrastructure.
    """
    trace = artifact_to_trace(artifact_with(_hook("http://127.0.0.1:9/inert")))
    (flow,) = trace.network_flows
    assert flow.injected_destination is True


def test_the_emulators_host_alias_is_marked_as_ours() -> None:
    """`10.0.2.2` is the emulator's route to the analysis host — our proxy, not a C2."""
    trace = artifact_to_trace(artifact_with(captured_flows=(captured_flow("10.0.2.2", path="/x"),)))
    (flow,) = trace.network_flows
    assert flow.injected_destination is True


def test_a_host_named_only_in_a_body_we_wrote_is_ours() -> None:
    """Part 1 of the rule: exclude hosts that appear in a `served_body` we authored.

    If the sample went there, it went because of something WE told it, so publishing it
    as attacker infrastructure would launder our own content into intelligence.
    """
    trace = artifact_to_trace(
        artifact_with(
            captured_flows=(
                captured_flow(
                    "gate.evil.tk",
                    synthesised=True,
                    served_kind="config",
                    resp_body_preview='{"cmd": "noop", "next": "http://stage.lab.invalid/a"}',
                ),
                captured_flow("stage.lab.invalid", path="/a", at_ms=500),
            )
        )
    )
    by_host = {f.host: f for f in trace.network_flows}
    assert by_host["stage.lab.invalid"].injected_destination is True
    assert by_host["gate.evil.tk"].injected_destination is False


def test_a_host_in_a_body_the_ATTACKER_sent_is_not_ours() -> None:
    """The same body, observed rather than authored, is evidence — and stays publishable."""
    trace = artifact_to_trace(
        artifact_with(
            captured_flows=(
                captured_flow(
                    "gate.evil.tk",
                    resp_body_preview='{"next": "http://stage2.evil.tk/a"}',
                ),
                captured_flow("stage2.evil.tk", path="/a", at_ms=500),
            )
        )
    )
    by_host = {f.host: f for f in trace.network_flows}
    assert by_host["stage2.evil.tk"].injected_destination is False


def test_the_result_still_validates_as_the_contract() -> None:
    trace = artifact_to_trace(
        artifact_with(
            _hook("http://a.example/one"),
            captured_flows=(captured_flow("b.example", path="/two"),),
        )
    )
    DynamicTrace.model_validate(trace.model_dump(mode="json"))


def test_overlay_claim_is_dropped_when_the_hook_could_not_tell() -> None:
    """T1417 from a type-blind hook is not carried forward, and the drop is disclosed.

    Hooks before `m3-hooks-2.1.0` emitted T1417 on every `WindowManagerImpl.addView`
    call without reading `LayoutParams.type`. Every Activity attaches its content view
    that way, so the headline banking-trojan behaviour was asserted about 47 of 52
    captured artifacts — including the canary, which is forbidden from drawing an
    overlay. The artifact is never rewritten; we decline to draw the conclusion.
    """
    from drishti.m3_dynamic.ingest import artifact_to_trace
    from tests.unit._observation_builders import artifact_with, metadata

    overlay = ("WindowManager.addView", "T1417", "added a window over other apps")

    blind = artifact_with(overlay)
    blind = blind.model_copy(update={"metadata": metadata(hook_version="m3-hooks-2.0.0")})
    trace = artifact_to_trace(blind)
    assert not any(e.api == "WindowManager.addView" for e in trace.api_events)
    assert any("overlay observation" in e for e in trace.errors), "the drop must be disclosed"

    aware = artifact_with(overlay)
    aware = aware.model_copy(update={"metadata": metadata(hook_version="m3-hooks-2.1.0")})
    kept = artifact_to_trace(aware)
    assert any(e.api == "WindowManager.addView" for e in kept.api_events), (
        "a type-aware hook's overlay observation must survive"
    )

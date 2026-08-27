"""What may be published as adversary infrastructure, and what may never be.

A STIX bundle and a law-enforcement dossier are read by people who will act on them.
Two failures are possible and this file pins both.

**Under-publishing.** `synthesised` means *we authored the response body*. The on-VM
proxy stamps it on every response it serves, sinkhole included — so keying the exclusion
on `synthesised` means that the moment the proxy runs, the bundle contains no C2 objects
at all and the dossier's observed-infrastructure list is empty. A dead C2 the sample
beaconed to is real infrastructure; answering it does not make it ours.

**Over-publishing, which is worse.** `assert_inert` rewrites every URL-shaped value in a
response to `http://127.0.0.1:9/inert`. A sample that follows the bait fires
`URL.openConnection`, and the hook path builds that flow with `synthesised=False`. Export
it and a SOC receives *our own injected string* as adversary infrastructure — and as a
`domain-name` SDO holding an IP address, which is also a type error. `10.0.2.2`, the
emulator's alias for the analysis host, has exactly the same shape.

So publication keys on the provenance of the DESTINATION (`injected_destination`), and
the exporters re-derive that from the host themselves rather than trusting the flag:
where the two disagree the answer is *do not publish*.
"""

from __future__ import annotations

import pytest

from drishti.contracts.dynamic_trace import DynamicTrace, NetworkFlow, TraceSourceKind
from drishti.contracts.score import CompositeScore, SeverityBand
from drishti.contracts.static_report import FileMeta
from drishti.m7_report import dossier, stix


@pytest.fixture
def meta() -> FileMeta:
    return FileMeta(
        sha256="a" * 64,
        size_bytes=4_182_233,
        filename="RTO_Challan.apk",
        package="in.gov.rto.challan",
    )


@pytest.fixture
def score() -> CompositeScore:
    return CompositeScore(S=91, band=SeverityBand.CRITICAL, C=0.83, gamma=0.7)


def _trace(*flows: NetworkFlow) -> DynamicTrace:
    return DynamicTrace(
        run_id="run_1",
        source=TraceSourceKind.LIVE,
        detonated=True,
        outcome="completed",
        network_flows=flows,
    )


def _domains(bundle: dict) -> set[str]:
    return {o["value"] for o in bundle["objects"] if o["type"] == "domain-name"}


def _published(bundle: dict) -> set[str]:
    """Every value the bundle asserts as infrastructure, whatever SDO type carries it."""
    return {
        o["value"]
        for o in bundle["objects"]
        if o["type"] in {"domain-name", "ipv4-addr", "ipv6-addr"}
    }


# ── under-publishing: a synthesised ANSWER does not un-make a real C2 ───────
def test_a_host_we_answered_is_still_published_as_infrastructure(meta, score) -> None:
    """The sample chose the destination. We only chose the reply.

    This is the regression the sinkhole introduced: it answers every unhinted host, so
    keying on `synthesised` would publish nothing at all from a real detonation.
    """
    bundle = stix.build_bundle(
        meta=meta,
        score=score,
        dynamic=_trace(
            NetworkFlow(
                t_ms=10,
                method="POST",
                url="http://gate.evil.tk/api/poll",
                host="gate.evil.tk",
                synthesised=True,
            )
        ),
    )
    assert _domains(bundle) == {"gate.evil.tk"}


def test_the_dossier_still_lists_a_host_we_answered(meta, score) -> None:
    pack = dossier.build(
        meta=meta,
        score=score,
        dynamic=_trace(
            NetworkFlow(
                t_ms=10,
                method="POST",
                url="http://gate.evil.tk/api/poll",
                host="gate.evil.tk",
                synthesised=True,
            )
        ),
    )
    assert any("gate.evil.tk" in line for line in pack.indicators)


# ── over-publishing: our own destinations never leave the building ─────────
def test_a_destination_we_injected_is_never_published(meta, score) -> None:
    bundle = stix.build_bundle(
        meta=meta,
        score=score,
        dynamic=_trace(
            NetworkFlow(
                t_ms=10,
                method="GET",
                url="http://gate.evil.tk/api/poll",
                host="gate.evil.tk",
            ),
            NetworkFlow(
                t_ms=20,
                method="GET",
                url="http://stage.lab.invalid/a",
                host="stage.lab.invalid",
                injected_destination=True,
            ),
        ),
    )
    assert _published(bundle) == {"gate.evil.tk"}


def test_our_own_sinkhole_is_not_exported_as_adversary_infrastructure(meta, score) -> None:
    """The hook path hardcodes `synthesised=False`, so the flag alone cannot save us."""
    bundle = stix.build_bundle(
        meta=meta,
        score=score,
        dynamic=_trace(
            NetworkFlow(t_ms=10, method="GET", url="http://127.0.0.1:9/inert", host="127.0.0.1")
        ),
    )
    assert _published(bundle) == set()


@pytest.mark.parametrize("host", ["127.0.0.1", "10.0.2.2", "192.168.1.5", "169.254.169.254", "::1"])
def test_loopback_private_and_link_local_hosts_are_never_published(meta, score, host) -> None:
    """Including the metadata server, which the runtime VPC denies by firewall rule."""
    bundle = stix.build_bundle(
        meta=meta,
        score=score,
        dynamic=_trace(NetworkFlow(t_ms=10, method="GET", url=f"http://{host}/x", host=host)),
    )
    assert _published(bundle) == set()


def test_the_dossier_applies_the_same_guard(meta, score) -> None:
    pack = dossier.build(
        meta=meta,
        score=score,
        dynamic=_trace(
            NetworkFlow(t_ms=10, method="GET", url="http://127.0.0.1:9/inert", host="127.0.0.1"),
            NetworkFlow(t_ms=20, method="GET", url="http://10.0.2.2/x", host="10.0.2.2"),
        ),
    )
    assert pack.indicators == []


# ── type correctness: an IP is not a domain name ───────────────────────────
def test_a_routable_ip_is_published_as_an_address_not_a_domain(meta, score) -> None:
    """A recipient's tooling matches on the SDO type. `domain-name: 45.9.148.1` matches nothing.

    Not a `203.0.113.0/24` documentation address: Python classifies the documentation
    ranges as non-global, so the guard withholds them — correctly, but it would make this
    test pass for the wrong reason.
    """
    bundle = stix.build_bundle(
        meta=meta,
        score=score,
        dynamic=_trace(
            NetworkFlow(t_ms=10, method="GET", url="http://45.9.148.1/x", host="45.9.148.1")
        ),
    )
    assert _domains(bundle) == set()
    assert {o["value"] for o in bundle["objects"] if o["type"] == "ipv4-addr"} == {"45.9.148.1"}
    patterns = [o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"]
    assert any("ipv4-addr:value" in p for p in patterns)


def test_a_host_that_is_not_a_name_at_all_is_not_published(meta, score) -> None:
    """Fail toward not publishing: a single-label host is not something a SOC can block."""
    bundle = stix.build_bundle(
        meta=meta,
        score=score,
        dynamic=_trace(
            NetworkFlow(t_ms=10, method="GET", url="http://localhost/x", host="localhost")
        ),
    )
    assert _published(bundle) == set()

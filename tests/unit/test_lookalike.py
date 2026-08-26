"""The Truecaller problem: two apps, identical permissions, opposite verdicts.

Half of India has Truecaller installed. It reads SMS, reads the call log, queries
installed packages and draws overlays — exactly the capabilities an overlay banking
trojan needs. A detector that flags it is not shippable in this market.

Every test here is built around one fixture pair that differs ONLY in what the app does
with the permissions, never in which permissions it holds. If a change to
`m2_static/lookalike.py` starts separating them by permission set, these fail.
"""

from __future__ import annotations

import pytest

from drishti.contracts.static_report import (
    BenignLookalikeVerdict,
    CallPath,
    CertificateInfo,
    StaticReport,
)
from drishti.m2_static.lookalike import DUAL_USE_PERMISSIONS, assess

#: The permission set BOTH fixtures hold. This is the whole point: it is not the signal.
SHARED = (
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.READ_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_CONTACTS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.INTERNET",
)


def _cert(*, age_days: int = 2200, sha: str = "c" * 64) -> CertificateInfo:
    return CertificateInfo(
        sha256=sha,
        subject="CN=Example, O=Example, C=IN",
        issuer="CN=Example, O=Example, C=IN",
        not_before="2019-01-01T00:00:00Z",
        not_after="2049-01-01T00:00:00Z",
        age_days=age_days,
        self_signed=True,
    )


def _path(sink_id: str, entrypoint: str, *, reachable: bool = True) -> CallPath:
    return CallPath(
        sink_id=sink_id,
        sink_signature=f"L/sig/{sink_id}",
        path=("a", "b"),
        entrypoint=entrypoint,
        entrypoint_kind="receiver",
        reachable_from_lifecycle=reachable,
    )


def _report(**kwargs) -> StaticReport:
    base = dict(
        sha256="a" * 64,
        package="com.example.app",
        app_label="Example",
        version_name="1.0",
        version_code=1,
        min_sdk=26,
        target_sdk=34,
        permissions=SHARED,
        certificate=_cert(),
    )
    base.update(kwargs)
    return StaticReport(**base)


# ── the two fixtures ─────────────────────────────────────────────────────────
@pytest.fixture
def caller_id_app() -> StaticReport:
    """A Truecaller-shaped app. Privileged, and legitimately so.

    Reads SMS to classify spam LOCALLY. Draws over the dialer. Talks to the network,
    but from a different entrypoint than the one that reads messages. Carries no roster
    of banks, because it has no reason to know which bank you use.
    """
    return _report(
        package="com.truecaller",
        app_label="Caller ID and Spam Blocker",
        certificate=_cert(age_days=2500),
        call_paths=(
            _path("sms_body", "com.example.SmsClassifier.onReceive"),
            _path("overlay", "com.example.CallerIdWindow.onCallStateChanged"),
            _path("network", "com.example.SyncService.onHandleIntent"),
            _path("pkg_list", "com.example.SettingsActivity.onCreate"),
        ),
        urls=("https://api.caller-id-vendor.example/v1/lookup",),
        sink_hits=("sms_body", "overlay", "network", "pkg_list"),
    )


@pytest.fixture
def banking_trojan() -> StaticReport:
    """A challan-fraud-shaped app. The SAME permissions, used differently.

    Reads SMS and talks to the network from ONE entrypoint. Carries a roster of Indian
    banks. Knows what an OTP is. Hides its launcher icon. Freshly signed.
    """
    return _report(
        package="in.gov.rto.challan",
        app_label="RTO Challan",
        certificate=_cert(age_days=3, sha="d" * 64),
        call_paths=(
            _path("sms_body", "in.gov.rto.challan.SmsReceiver.onReceive"),
            _path("network", "in.gov.rto.challan.SmsReceiver.onReceive"),
            _path("overlay", "in.gov.rto.challan.OverlayService.onStartCommand"),
            _path("pkg_list", "in.gov.rto.challan.OverlayService.onStartCommand"),
            _path("accessibility", "in.gov.rto.challan.A11yService.onServiceConnected"),
        ),
        urls=(
            "http://challan-verify.example-c2.net/collect",
            "otp verification code net banking",
            "com.snapwork.hdfc com.csam.icici.bank.imobile net.one97.paytm",
            "setComponentEnabledSetting COMPONENT_ENABLED_STATE_DISABLED",
            "performGlobalAction",
        ),
        sink_hits=("sms_body", "network", "overlay", "pkg_list", "accessibility"),
    )


# ── the headline claim ───────────────────────────────────────────────────────
def test_identical_permissions_produce_opposite_verdicts(caller_id_app, banking_trojan) -> None:
    """The claim the whole module exists to support."""
    assert caller_id_app.permissions == banking_trojan.permissions

    benign = assess(caller_id_app)
    malicious = assess(banking_trojan)

    assert malicious.verdict is BenignLookalikeVerdict.TROJAN_SHAPE
    assert benign.verdict is not BenignLookalikeVerdict.TROJAN_SHAPE
    assert malicious.trojan_score > benign.trojan_score


def test_the_caller_id_app_is_not_flagged(caller_id_app) -> None:
    """A product that flags Truecaller is dead on arrival in India."""
    result = assess(caller_id_app)
    assert result.verdict is not BenignLookalikeVerdict.TROJAN_SHAPE
    assert result.trojan_score < 0.5


def test_the_report_names_what_it_shares_with_legitimate_apps(banking_trojan) -> None:
    """The dual-use permissions must be stated, not presented as the finding.

    Otherwise the report says "it can read your SMS!" about an app whose real problem is
    something else entirely, and a reader who knows Truecaller does the same stops
    believing the rest of the document.
    """
    result = assess(banking_trojan)
    assert set(result.shared_permissions) <= set(DUAL_USE_PERMISSIONS)
    assert len(result.shared_permissions) >= 5
    assert "permission set alone is not the finding" in result.rationale


# ── the individual discriminators ────────────────────────────────────────────
def test_the_bank_roster_is_the_strongest_signal(banking_trojan) -> None:
    """Truecaller does not ship a list of Indian bank package names. A trojan must."""
    result = assess(banking_trojan)
    roster = next(s for s in result.signals if s.id == "financial_app_roster")
    assert roster.present
    assert "com.snapwork.hdfc" in result.targeted_financial_packages


def test_sms_and_network_sharing_an_entrypoint_fires(banking_trojan) -> None:
    result = assess(banking_trojan)
    signal = next(s for s in result.signals if s.id == "sms_and_network_share_entrypoint")
    assert signal.present
    assert "SmsReceiver.onReceive" in signal.detail


def test_sms_and_network_on_separate_entrypoints_does_not_fire(caller_id_app) -> None:
    """Reading SMS and using the network is normal. Doing both on one path is not."""
    result = assess(caller_id_app)
    signal = next(s for s in result.signals if s.id == "sms_and_network_share_entrypoint")
    assert not signal.present


def test_dead_code_does_not_count(caller_id_app) -> None:
    """Unreachable paths must not create a finding.

    Library code reaches dangerous sinks constantly. Counting it is how a detector
    acquires a false-positive rate nobody can explain.
    """
    with_dead = caller_id_app.model_copy(
        update={
            "call_paths": (
                *caller_id_app.call_paths,
                _path(
                    "network",
                    "com.example.SmsClassifier.onReceive",
                    reachable=False,
                ),
            )
        }
    )
    signal = next(
        s for s in assess(with_dead).signals if s.id == "sms_and_network_share_entrypoint"
    )
    assert not signal.present


# ── honesty properties ───────────────────────────────────────────────────────
def test_it_never_returns_benign(caller_id_app) -> None:
    """`BENIGN` does not exist. The best available answer is INDETERMINATE."""
    assert not hasattr(BenignLookalikeVerdict, "BENIGN")
    assert assess(caller_id_app).verdict in {
        BenignLookalikeVerdict.INDETERMINATE,
        BenignLookalikeVerdict.LEGITIMATE_PRIVILEGED,
    }


def test_absent_signals_are_retained_not_dropped(caller_id_app) -> None:
    """ "We looked and found nothing" is a finding a reader needs."""
    result = assess(caller_id_app)
    assert any(not s.present for s in result.signals)
    roster = next(s for s in result.signals if s.id == "financial_app_roster")
    assert not roster.present
    assert "no banking or UPI package identifiers" in roster.detail


def test_a_trusted_publisher_is_about_the_signer_not_the_code(
    banking_trojan, tmp_path, monkeypatch
) -> None:
    """Publisher trust must not read as a clean bill of health."""
    import drishti.m2_static.lookalike as module

    kb = tmp_path / "kb"
    kb.mkdir()
    (kb / "known_good_publishers.txt").write_text(banking_trojan.certificate.sha256)
    (kb / "financial_packages.txt").write_text("com.snapwork.hdfc")
    monkeypatch.setattr(module, "_KB", kb)

    result = module.assess(banking_trojan)
    assert result.verdict is BenignLookalikeVerdict.LEGITIMATE_PRIVILEGED
    assert result.publisher_trusted
    assert "not a certification of the code" in result.rationale

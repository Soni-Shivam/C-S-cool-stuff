"""Shared M5 feature-extraction invariants."""

from __future__ import annotations

from drishti.contracts.static_report import CertificateInfo, PermissionCombo, Severity, StaticReport
from drishti.m5_ml.features import extract


def test_feature_extraction_is_deterministic_and_named() -> None:
    """Training and inference receive the same frozen feature map."""
    static = StaticReport(
        sha256="a" * 64,
        package="p",
        app_label="a",
        version_name="1",
        version_code=1,
        min_sdk=26,
        target_sdk=35,
        permissions=("android.permission.READ_SMS",),
        permission_combos=(
            PermissionCombo(
                rule_id="OTP_THEFT_SURFACE",
                permissions=("android.permission.READ_SMS",),
                severity=Severity.HIGH,
                description="x",
            ),
        ),
        sink_hits=("pkg_query",),
        entropy_mean=7.5,
        dex_count=2,
        certificate=CertificateInfo(
            sha256="0" * 64,
            subject="s",
            issuer="i",
            not_before="u",
            not_after="u",
            age_days=5,
            self_signed=False,
        ),
    )
    first = extract(static)
    assert first == extract(static)
    assert first.values["perm:READ_SMS"] == 1.0
    assert first.values["combo:OTP_THEFT_SURFACE"] == 1.0
    assert first.values["sink:pkg_query"] == 1.0

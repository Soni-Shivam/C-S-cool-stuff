"""Thin I/O adapter over Androguard. Isolated here so the analysis *logic*
(rules.py) stays pure and testable. Never executes the APK."""
import re

from pydantic import BaseModel, Field


class CertInfo(BaseModel):
    subject: str = ""
    issuer: str = ""
    self_signed: bool = False
    signed: bool = False


class ParsedApk(BaseModel):
    package: str = ""
    permissions: list[str] = Field(default_factory=list)
    activities: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    receivers: list[str] = Field(default_factory=list)
    providers: list[str] = Field(default_factory=list)
    exported: list[str] = Field(default_factory=list)
    strings: list[str] = Field(default_factory=list)
    cert: CertInfo = Field(default_factory=CertInfo)


_MAX_STRINGS = 50000
_EXPORTED_RE = re.compile(
    r'android:name="([^"]+)"[^>]*android:exported="true"', re.IGNORECASE
)


def parse_apk(path: str) -> ParsedApk:
    from androguard.core.apk import APK

    try:
        apk = APK(path)
    except Exception as e:  # noqa: BLE001 - normalize any parse failure
        raise ValueError(f"not a valid APK: {path} ({type(e).__name__})") from e

    parsed = ParsedApk(
        package=apk.get_package() or "",
        permissions=list(apk.get_permissions() or []),
        activities=list(apk.get_activities() or []),
        services=list(apk.get_services() or []),
        receivers=list(apk.get_receivers() or []),
        providers=list(apk.get_providers() or []),
    )

    try:
        xml = apk.get_android_manifest_axml().get_xml().decode("utf-8", "ignore")
        parsed.exported = _EXPORTED_RE.findall(xml)
    except Exception:  # noqa: BLE001
        pass

    parsed.strings = _extract_strings(apk)
    parsed.cert = _extract_cert(apk)
    return parsed


def _extract_strings(apk) -> list[str]:
    from androguard.core.dex import DEX

    out: list[str] = []
    try:
        for dex_bytes in apk.get_all_dex():
            try:
                for s in DEX(dex_bytes).get_strings():
                    out.append(s.decode("utf-8", "ignore") if isinstance(s, bytes) else str(s))
                    if len(out) >= _MAX_STRINGS:
                        return out
            except Exception:  # noqa: BLE001
                continue
    except Exception:  # noqa: BLE001
        pass
    return out


def _extract_cert(apk) -> CertInfo:
    info = CertInfo()
    try:
        info.signed = bool(apk.is_signed())
    except Exception:  # noqa: BLE001
        pass
    try:
        certs = apk.get_certificates()
        if certs:
            c = certs[0]
            info.subject = c.subject.human_friendly
            info.issuer = c.issuer.human_friendly
            info.self_signed = c.subject.native == c.issuer.native
    except Exception:  # noqa: BLE001
        pass
    return info

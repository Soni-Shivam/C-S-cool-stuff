"""Pure static-analysis logic: permission-combo risk detection, IOC extraction,
certificate heuristics. No Androguard dependency — fully unit-testable.

Permission combos and MITRE mappings follow the paper §4.2 and Table 6.
"""
import re

from pydantic import BaseModel


class PermissionCombo(BaseModel):
    id: str
    label: str
    severity: float  # 0..1 contribution to signature severity
    permissions: list[str]  # short names (last dotted segment)
    mitre: list[str]


# Ordered so that the most specific/severe combos can be surfaced first.
PERMISSION_COMBOS: list[PermissionCombo] = [
    PermissionCombo(
        id="banker_overlay_accessibility",
        label="Overlay + Accessibility abuse (classic banking-trojan pattern)",
        severity=0.95,
        permissions=["SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE"],
        mitre=["T1417", "T1516"],
    ),
    PermissionCombo(
        id="accessibility_abuse",
        label="Accessibility service abuse (screen-read / auto-click)",
        severity=0.85,
        permissions=["BIND_ACCESSIBILITY_SERVICE"],
        mitre=["T1417", "T1516"],
    ),
    PermissionCombo(
        id="otp_interception",
        label="SMS/OTP interception surface (RECEIVE_SMS + READ_SMS)",
        severity=0.8,
        permissions=["RECEIVE_SMS", "READ_SMS"],
        mitre=["T1582"],
    ),
    PermissionCombo(
        id="dropper_install",
        label="Dropper capability (installs additional packages)",
        severity=0.8,
        permissions=["REQUEST_INSTALL_PACKAGES"],
        mitre=["T1407"],
    ),
    PermissionCombo(
        id="overlay_attack",
        label="Overlay attack surface (draws over other apps)",
        severity=0.75,
        permissions=["SYSTEM_ALERT_WINDOW"],
        mitre=["T1417"],
    ),
    PermissionCombo(
        id="device_admin_persistence",
        label="Device-admin persistence",
        severity=0.7,
        permissions=["BIND_DEVICE_ADMIN"],
        mitre=["T1626"],
    ),
    PermissionCombo(
        id="sms_send_fraud",
        label="Outbound SMS (premium/fraud send)",
        severity=0.6,
        permissions=["SEND_SMS"],
        mitre=["T1582"],
    ),
    PermissionCombo(
        id="contacts_exfil",
        label="Contact-list access (exfil / spread)",
        severity=0.4,
        permissions=["READ_CONTACTS"],
        mitre=["T1409"],
    ),
]


def _short_names(perms) -> set[str]:
    return {p.split(".")[-1] for p in perms}


def detect_permission_combos(perms) -> list[PermissionCombo]:
    short = _short_names(perms)
    return [c for c in PERMISSION_COMBOS if set(c.permissions) <= short]


def signature_severity(combos: list[PermissionCombo]) -> float:
    return max((c.severity for c in combos), default=0.0)


_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_ETH_RE = re.compile(r"\b0x[0-9a-fA-F]{40}\b")
_BTC_RE = re.compile(r"\b(?:bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,39}\b")


def extract_iocs(strings) -> dict:
    urls, ips, crypto = set(), set(), set()
    for s in strings:
        if not isinstance(s, str):
            continue
        urls.update(_URL_RE.findall(s))
        ips.update(_IPV4_RE.findall(s))
        crypto.update(_ETH_RE.findall(s))
        crypto.update(_BTC_RE.findall(s))
    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
        "crypto": sorted(crypto),
    }


def analyze_certificate(subject: str, issuer: str, is_self_signed: bool,
                        package: str = "", brands=None) -> dict:
    brands = brands or []
    haystack = f"{subject} {issuer}".lower()
    pkg = package.lower()
    brand_mismatch = any(b.lower() in haystack and b.lower() not in pkg for b in brands)
    notes = []
    if is_self_signed:
        notes.append("self-signed certificate")
    if brand_mismatch:
        notes.append("certificate references a brand absent from the package name")
    return {
        "self_signed": is_self_signed,
        "brand_mismatch": brand_mismatch,
        "note": "; ".join(notes) or "no certificate anomalies",
    }

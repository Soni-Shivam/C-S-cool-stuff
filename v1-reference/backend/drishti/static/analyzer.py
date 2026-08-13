"""M2 orchestration: turn a ParsedApk into a StaticResult, writing evidence
nodes into the ledger. `analyze_parsed` is pure over its inputs (no APK I/O),
so it is fully unit-testable; `analyze` wires in the Androguard adapter + YARA."""
from pydantic import BaseModel, Field

from drishti.static.androguard_adapter import ParsedApk, parse_apk
from drishti.static.rules import (
    analyze_certificate,
    detect_permission_combos,
    extract_iocs,
    signature_severity,
)
from drishti.static.yara_scan import compile_rules, scan_bytes


class StaticResult(BaseModel):
    package: str
    permissions: list[str]
    combos: list[dict]
    iocs: dict
    cert: dict
    yara_hits: list[str] = Field(default_factory=list)
    exported: list[str] = Field(default_factory=list)
    mitre: list[str] = Field(default_factory=list)
    signature_severity: float = 0.0


# Common financial-brand tokens used for certificate impersonation heuristics.
_BRANDS = ["sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "kotak", "bank"]


def analyze_parsed(parsed: ParsedApk, bundle, led, timestamp: str,
                   yara_hits: list[str] | None = None) -> StaticResult:
    combos = detect_permission_combos(parsed.permissions)
    iocs = extract_iocs(parsed.strings)
    cert = analyze_certificate(
        parsed.cert.subject, parsed.cert.issuer, parsed.cert.self_signed,
        package=parsed.package, brands=_BRANDS,
    )
    mitre = sorted({m for c in combos for m in c.mitre})
    yara_hits = yara_hits or []

    led.append(
        "manifest", "androguard",
        f"Package {parsed.package}: {len(parsed.permissions)} permissions, "
        f"{len(parsed.exported)} exported components",
        location="AndroidManifest.xml", confidence=1.0, timestamp=timestamp,
    )
    for c in combos:
        led.append(
            "api_sink", "androguard", c.label,
            location="+".join(c.permissions), confidence=c.severity, timestamp=timestamp,
        )
    for kind, values in iocs.items():
        for v in values:
            led.append("ioc", "static", f"{kind}: {v}", location="dex-strings",
                       confidence=0.6, timestamp=timestamp)
    for hit in yara_hits:
        led.append("api_sink", "yara", f"YARA match: {hit}", location="dex",
                   confidence=0.7, timestamp=timestamp)
    if cert["self_signed"] or cert["brand_mismatch"]:
        led.append("cert", "androguard", cert["note"], location="META-INF",
                   confidence=0.7, timestamp=timestamp)

    return StaticResult(
        package=parsed.package,
        permissions=parsed.permissions,
        combos=[c.model_dump() for c in combos],
        iocs=iocs,
        cert=cert,
        yara_hits=yara_hits,
        exported=parsed.exported,
        mitre=mitre,
        signature_severity=signature_severity(combos),
    )


def analyze(bundle, led, timestamp: str) -> StaticResult:
    parsed = parse_apk(bundle.path)
    try:
        with open(bundle.path, "rb") as f:
            data = f.read()
        yara_hits = scan_bytes(data, compile_rules())
    except Exception:  # noqa: BLE001
        yara_hits = []
    return analyze_parsed(parsed, bundle, led, timestamp, yara_hits=yara_hits)

"""STIX 2.1 export. `docs/PHASE_6_REPORT_UI_DEMO.md` T6.2.

A bundle is what a CERT, an ISAC, or another bank's SOC can actually ingest. The
report persuades a human; this persuades their tooling.

**Every id is a deterministic UUIDv5**, derived from the sample hash and the object's
own identity, never from a clock or a random source. Two exports of the same job are
byte-identical, so a recipient can diff two bundles and see only what genuinely
changed — and so the scorer's purity guarantee is not quietly undone one layer up.
"""

from __future__ import annotations

import uuid
from typing import Any

from drishti.contracts.dynamic_trace import DynamicTrace
from drishti.contracts.genai_verdict import GenAIVerdict
from drishti.contracts.score import CompositeScore, SeverityBand
from drishti.contracts.static_report import FileMeta, StaticReport

#: Fixed namespace for UUIDv5 derivation. Arbitrary but frozen: changing it would
#: renumber every object in every previously exported bundle.
NAMESPACE = uuid.UUID("6ba7b812-9dad-11d1-80b4-00c04fd430c8")

#: The producer identity. Referenced by `created_by_ref` on every SDO in the bundle.
IDENTITY_KEY = "drishti-identity-v1"

SPEC_VERSION = "2.1"

#: STIX has no "unknown" confidence, and 0 means "definitely false" rather than
#: "not assessed". Bands map onto the STIX confidence scale (0-100) explicitly so a
#: recipient reads our uncertainty rather than inferring it.
_BAND_CONFIDENCE = {
    SeverityBand.CRITICAL: 90,
    SeverityBand.HIGH: 75,
    SeverityBand.MEDIUM: 50,
    SeverityBand.LOW: 25,
}


def _sdo_id(kind: str, key: str) -> str:
    """A stable STIX id for `kind` identified by `key` within this producer."""
    return f"{kind}--{uuid.uuid5(NAMESPACE, f'{kind}:{key}')}"


def _timestamp(value: str | None) -> str:
    """STIX timestamps must be RFC3339 with a Z. Fall back to the epoch, not to now().

    Using `now()` here would make the bundle non-deterministic, which is exactly the
    property this module exists to preserve.
    """
    if not value:
        return "1970-01-01T00:00:00.000Z"
    text = value.replace("+00:00", "Z")
    return text if text.endswith("Z") else f"{text}Z"


def _identity() -> dict[str, Any]:
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": _sdo_id("identity", IDENTITY_KEY),
        "created": _timestamp(None),
        "modified": _timestamp(None),
        "name": "DRISHTI Automated APK Triage",
        "identity_class": "system",
        "sectors": ["financial-services"],
    }


def build_bundle(
    *,
    meta: FileMeta,
    score: CompositeScore,
    static: StaticReport | None = None,
    genai: GenAIVerdict | None = None,
    dynamic: DynamicTrace | None = None,
) -> dict[str, Any]:
    """Assemble a STIX 2.1 bundle for one analysed sample.

    Only *verified* AI claims and *observed* network flows become STIX objects. A
    rejected claim is a thing we declined to assert; publishing it to a sharing
    partner would launder it into an assertion.
    """
    identity = _identity()
    created_by = identity["id"]
    stamp = _timestamp(dynamic.captured_at if dynamic else None)
    objects: list[dict[str, Any]] = [identity]

    # ── the file itself ──────────────────────────────────────────────────────
    file_observable: dict[str, Any] = {
        "type": "file",
        "spec_version": SPEC_VERSION,
        "id": _sdo_id("file", meta.sha256),
        "hashes": {"SHA-256": meta.sha256},
        "name": meta.filename,
        "size": meta.size_bytes,
    }
    objects.append(file_observable)

    malicious = score.band in (SeverityBand.CRITICAL, SeverityBand.HIGH)

    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": _sdo_id("indicator", meta.sha256),
        "created_by_ref": created_by,
        "created": stamp,
        "modified": stamp,
        "name": f"DRISHTI {score.band.value.upper()} — {meta.package or meta.filename}",
        "description": score.explanation or "Automated static and dynamic triage.",
        "indicator_types": ["malicious-activity"] if malicious else ["benign"],
        "pattern": f"[file:hashes.'SHA-256' = '{meta.sha256}']",
        "pattern_type": "stix",
        "valid_from": stamp,
        "confidence": _BAND_CONFIDENCE.get(score.band, 10),
        # The composite score travels with the indicator so a recipient can apply
        # their own threshold instead of inheriting ours.
        "x_drishti_score": score.S,
        "x_drishti_band": score.band.value,
        "x_drishti_confidence": score.C,
        # Non-negotiable: a bundle that hides its own caveats is worse than no bundle.
        "x_drishti_limitations": list(score.limitations),
    }
    objects.append(indicator)

    relationships: list[dict[str, Any]] = []

    def _relate(kind: str, source: str, target: str) -> None:
        relationships.append(
            {
                "type": "relationship",
                "spec_version": SPEC_VERSION,
                "id": _sdo_id("relationship", f"{kind}:{source}:{target}"),
                "created_by_ref": created_by,
                "created": stamp,
                "modified": stamp,
                "relationship_type": kind,
                "source_ref": source,
                "target_ref": target,
            }
        )

    _relate("based-on", indicator["id"], file_observable["id"])

    # ── malware SDO, only when we actually concluded malice ──────────────────
    if malicious:
        family = meta.intel.family if meta.intel and meta.intel.family else None
        malware: dict[str, Any] = {
            "type": "malware",
            "spec_version": SPEC_VERSION,
            "id": _sdo_id("malware", family or meta.sha256),
            "created_by_ref": created_by,
            "created": stamp,
            "modified": stamp,
            "name": family or f"Unattributed Android sample {meta.sha256[:12]}",
            "is_family": family is not None,
            "malware_types": ["trojan"],
            "implementation_languages": ["java"],
            "architecture_execution_envs": ["android"],
        }
        objects.append(malware)
        _relate("indicates", indicator["id"], malware["id"])

        # ── MITRE ATT&CK techniques as attack-patterns ───────────────────────
        for technique in genai.techniques if genai else ():
            technique_id = technique.technique_id
            if not technique_id:
                continue
            pattern: dict[str, Any] = {
                "type": "attack-pattern",
                "spec_version": SPEC_VERSION,
                "id": _sdo_id("attack-pattern", technique_id),
                "created_by_ref": created_by,
                "created": stamp,
                "modified": stamp,
                "name": technique.name,
                # static-only means "this code could do it", dynamic means "it did".
                # Collapsing them would overstate what was actually observed.
                "x_drishti_layer": technique.layer,
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": technique_id,
                        "url": f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/",
                    }
                ],
            }
            if not any(o["id"] == pattern["id"] for o in objects):
                objects.append(pattern)
            _relate("uses", malware["id"], pattern["id"])

    # ── C2 infrastructure, only from OBSERVED flows ──────────────────────────
    # Static URL strings are not published as infrastructure: a string in a DEX is a
    # string, and shipping it as a C2 indicator is how blocklists acquire false
    # positives that outlive the sample.
    seen_hosts: set[str] = set()
    for flow in dynamic.network_flows if dynamic else ():
        # `synthesised` means the Generative C2 served that response, not the
        # attacker. Publishing it as infrastructure would attribute our own test
        # harness to the adversary — a provenance lie that outlives the bundle.
        if flow.synthesised:
            continue
        host = flow.host
        if not host or host in seen_hosts:
            continue
        seen_hosts.add(host)
        domain = {
            "type": "domain-name",
            "spec_version": SPEC_VERSION,
            "id": _sdo_id("domain-name", host),
            "value": host,
        }
        objects.append(domain)
        c2_indicator: dict[str, Any] = {
            "type": "indicator",
            "spec_version": SPEC_VERSION,
            "id": _sdo_id("indicator", f"c2:{host}"),
            "created_by_ref": created_by,
            "created": stamp,
            "modified": stamp,
            "name": f"Contacted by {meta.package or meta.sha256[:12]}",
            "indicator_types": ["malicious-activity"] if malicious else ["anomalous-activity"],
            "pattern": f"[domain-name:value = '{host}']",
            "pattern_type": "stix",
            "valid_from": stamp,
            "x_drishti_observed_live": dynamic is not None and not dynamic.synthetic,
        }
        objects.append(c2_indicator)
        _relate("based-on", c2_indicator["id"], domain["id"])

    # ── verified claims as notes ─────────────────────────────────────────────
    for index, claim in enumerate(genai.verified_claims if genai else ()):
        text = claim.text
        if not text:
            continue
        objects.append(
            {
                "type": "note",
                "spec_version": SPEC_VERSION,
                "id": _sdo_id("note", f"{meta.sha256}:claim:{index}"),
                "created_by_ref": created_by,
                "created": stamp,
                "modified": stamp,
                "abstract": "DRISHTI verified finding",
                "content": text,
                "object_refs": [indicator["id"]],
                # The citation travels with the claim. A note a recipient cannot
                # trace back to an artefact is an opinion.
                "x_drishti_evidence_refs": list(claim.evidence_refs),
                "x_drishti_agent": claim.agent,
            }
        )

    objects.extend(relationships)

    return {
        "type": "bundle",
        "id": _sdo_id("bundle", f"{meta.sha256}:{score.S}"),
        "objects": objects,
    }

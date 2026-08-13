"""M7 campaign artifacts must hunt variants, compile, and never flag legitimate apps."""
import json
import types

import pytest

from drishti.models import DrishtiVerdict
from drishti.reporting.artifacts import (
    generate_all,
    generate_frida_script,
    generate_stix_bundle,
    generate_yara_rule,
    package_tokens,
)

#: The real generator-shuffled cluster found in the AndroZoo corpus.
CLUSTER = [
    "us.mobileandroidangryfix.mbankingfixflash",
    "au.androidanti.antimbanking.fixcambankpost",
    "com.mbankingangryboomandroid.flashangryinsta",
    "au.mbankingcamangryled.boombank",
    "eu.mbankingcamled.instacamangrypost",
]
LEGITIMATE = [
    "org.fdroid.fdroid", "com.google.android.gms", "com.bankofamerica.mobile",
    "com.icicibank.pockets", "com.whatsapp", "no.oslokommune.sykkelhotellapp",
]


def _result(package="us.mobileandroidangryfix.mbankingfixflash", observed=True):
    verdict = DrishtiVerdict(
        sha256="1e2a0086ac33c2b83369711e06e3855b0ae2cd07901cf5eb9e3da23b4712ca8f",
        threat_score=88, severity_band="Critical", confidence=0.92,
        confidence_label="High", impersonated_target="Mobile Banking Application",
        victim_profile={"language": "Unknown", "tactic": "Fake Update Lure",
                        "segment": "Mobile Banking Users"},
        adversarial_elicitation_deployed=[],
        attack_techniques=["T1582", "T1417", "T1407", "T1426"],
        iocs={}, evidence_refs=["n1", "n2"],
        summary="Banking trojan with runtime DEX loading.",
        provider="gemini", verified=True,
        dynamic_status="observed" if observed else "absent",
        dynamic_simulated=False,
    )
    ledger = [
        {"id": "n1", "type": "manifest", "content": "perms"},
        {"id": "n29", "type": "dynamic_obs",
         "content": "[OBSERVED] Local dynamic code loaded (T1407): "
                    "path=/data/user/0/pkg/cache/of87oaufaldjawdjkw.dex"},
        {"id": "n30", "type": "dynamic_obs",
         "content": "[OBSERVED] Device property read: getSimOperatorName (T1426)"},
    ] if observed else [{"id": "n1", "type": "manifest", "content": "perms"}]
    return types.SimpleNamespace(
        verdict=verdict,
        static={"permissions": ["android.permission.RECEIVE_SMS",
                                "android.permission.READ_SMS",
                                "android.permission.SEND_SMS",
                                "android.permission.SYSTEM_ALERT_WINDOW",
                                "android.permission.READ_CONTACTS"],
                "combos": [{"label": "SMS/OTP interception surface"}],
                "iocs": [{"kind": "urls", "value": "http://evil-c2.example.net/gate.php"},
                         {"kind": "urls", "value": "https://pagead2.googlesyndication.com/x"}]},
        dynamic={"package": package, "mitre_observed": ["T1407", "T1426"]},
        ledger=ledger,
    )


def test_campaign_tokens_survive_concatenation():
    """The generator concatenates tokens, so vocabulary units must be recovered."""
    tokens = package_tokens("us.mobileandroidangryfix.mbankingfixflash")
    assert "mbanking" in tokens
    assert "angry" in tokens
    assert "flash" in tokens


def test_nested_vocabulary_tokens_are_collapsed():
    """mbanking implies banking implies bank; only the longest may count."""
    tokens = package_tokens("com.mbankingcamled.x")
    assert "mbanking" in tokens
    assert "banking" not in tokens
    assert "bank" not in tokens


def test_generated_rule_matches_campaign_siblings():
    """A rule from one build must match sibling builds with different hashes and names."""
    seed = package_tokens(CLUSTER[0])[:8]
    matched = sum(1 for pkg in CLUSTER[1:]
                  if len([t for t in seed if t in pkg.lower()]) >= 2)
    assert matched >= 3, f"only {matched}/4 siblings matched; rule is hash-bound"


def test_generated_rule_does_not_match_legitimate_apps():
    """A bank trojan hunt rule must never match a bank's own application."""
    seed = package_tokens(CLUSTER[0])[:8]
    for pkg in LEGITIMATE:
        hits = [t for t in seed if t in pkg.lower()]
        assert len(hits) < 2, f"{pkg} would false-positive on {hits}"


def test_yara_rule_compiles():
    yara = pytest.importorskip("yara")
    artifact = generate_yara_rule(_result())
    yara.compile(source=artifact.content)  # raises on invalid syntax
    assert artifact.kind == "yara"
    assert artifact.evidence_refs


def test_yara_requires_zip_magic_and_two_evidence_axes():
    artifact = generate_yara_rule(_result())
    assert "uint32(0) == 0x04034b50" in artifact.content
    # Name tokens alone must not be sufficient.
    assert " and 3 of ($perm" in artifact.content


def test_frida_script_is_passive_and_covers_observed_techniques():
    artifact = generate_frida_script(_result())
    body = artifact.content
    assert "PASSIVE OBSERVER ONLY" in body
    # Techniques actually observed must be hooked.
    assert "dalvik.system.DexClassLoader" in body      # T1407
    assert "getSimOperatorName" in body                # T1426
    # It must always call through to the original implementation.
    assert "impl.apply(this, arguments)" in body
    assert "redact(" in body


def test_stix_bundle_is_valid_and_marks_observed_provenance():
    bundle = json.loads(generate_stix_bundle(_result()).content)
    assert bundle["type"] == "bundle"
    types_present = {o["type"] for o in bundle["objects"]}
    assert {"indicator", "malware", "attack-pattern", "file", "relationship"} <= types_present
    observed = [o for o in bundle["objects"] if o["type"] == "observed-data"]
    assert observed, "SHA-matched detonator output should appear as observed-data"
    assert all(o["x_drishti_provenance"] == "observed-in-isolated-detonator" for o in observed)
    for obj in bundle["objects"]:
        assert obj.get("spec_version") == "2.1" or obj["type"] == "bundle"


def test_stix_omits_observed_data_when_dynamics_absent():
    """Absent or simulated dynamics must never be published as observed-data."""
    bundle = json.loads(generate_stix_bundle(_result(observed=False)).content)
    assert not [o for o in bundle["objects"] if o["type"] == "observed-data"]


def test_stix_excludes_benign_infrastructure_hosts():
    bundle = json.loads(generate_stix_bundle(_result()).content)
    patterns = " ".join(o.get("pattern", "") for o in bundle["objects"])
    assert "evil-c2.example.net" in patterns
    assert "googlesyndication.com" not in patterns


def test_generate_all_returns_three_artifacts():
    artifacts = generate_all(_result())
    assert {a.kind for a in artifacts} == {"yara", "frida", "stix"}
    assert all(a.content and a.filename for a in artifacts)

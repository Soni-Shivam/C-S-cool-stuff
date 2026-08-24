from __future__ import annotations

from pathlib import Path

from drishti.contracts.evidence import EvidenceType
from drishti.contracts.static_report import CertificateInfo, DecompiledMethod, StaticReport
from drishti.ledger.store import LedgerStore
from drishti.m4_genai.tools import MAX_TOOL_CALLS, AnalysisToolbox, verify_transform


def _static(evidence_ref: str) -> StaticReport:
    return StaticReport(
        sha256="a" * 64,
        package="com.example",
        app_label="Example",
        version_name="1",
        version_code=1,
        min_sdk=21,
        target_sdk=35,
        certificate=CertificateInfo(
            sha256="b" * 64,
            subject="CN=Example",
            issuer="CN=Example",
            not_before="unknown",
            not_after="unknown",
            age_days=0,
            self_signed=True,
        ),
        decompiled_methods=(
            DecompiledMethod(
                signature="Lx;->a",
                body="return pm.getInstalledPackages(0);",
                evidence_ref=evidence_ref,
            ),
        ),
    )


def test_fixed_transforms_are_reproducible() -> None:
    assert verify_transform("aGVsbG8=", "base64") == "hello"
    assert verify_transform("68656c6c6f", "hex") == "hello"
    assert verify_transform("uryyb", "rot13") == "hello"
    assert verify_transform("69646d6d6e", "xor", 1) == "hello"


def test_toolbox_rejects_unknown_tools_and_enforces_budget(tmp_path: Path) -> None:
    store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    store.open("job_tools")
    evidence = store.append(
        type=EvidenceType.DECOMPILED_METHOD, source_tool="test", content={"body": "x"}
    )
    toolbox = AnalysisToolbox(_static(evidence.id), store, "job_tools")
    assert toolbox.execute("shell", {"command": "id"})["rejected"] is True
    for _ in range(MAX_TOOL_CALLS - 1):
        toolbox.execute("read_method", {"signature": "Lx;->a"})
    assert toolbox.execute("read_method", {"signature": "Lx;->a"})["rejected"] is True
    assert len(toolbox.records) == MAX_TOOL_CALLS + 1
    store.close()


def test_read_method_is_limited_to_the_workspace(tmp_path: Path) -> None:
    store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    store.open("job_tools")
    evidence = store.append(
        type=EvidenceType.DECOMPILED_METHOD, source_tool="test", content={"body": "x"}
    )
    toolbox = AnalysisToolbox(_static(evidence.id), store, "job_tools")
    result = toolbox.execute("read_method", {"signature": "Lx;->a"})
    assert result["body"].startswith("return pm")
    assert result["evidence_refs"] == [evidence.id]
    rejected = toolbox.execute("read_method", {"signature": "Lx;->missing"})
    assert rejected["rejected"] is True
    store.close()

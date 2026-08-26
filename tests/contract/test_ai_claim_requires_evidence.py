"""An AI claim without resolvable evidence cannot enter the ledger.

docs/01_DATA_CONTRACTS.md §9.3. CI gate.

CLAUDE.md rule 5: *"Don't work around it — that rejection is the product."* These
tests exist so that working around it fails the build.
"""

from __future__ import annotations

import pytest

from drishti.contracts.evidence import EvidenceType
from drishti.contracts.genai_verdict import GroundedClaim, VerifierStatus
from drishti.ledger.store import LedgerStore, UngroundedClaimError
from drishti.ledger.verifier import Verifier

JOB = "job_01932ab90e2f"


@pytest.fixture
def store(tmp_path):
    ledger = LedgerStore(tmp_path / "ledger.db", tmp_path / "key.pem")
    ledger.open(JOB)
    yield ledger
    ledger.close()


@pytest.fixture
def real_node(store):
    return store.append(
        type=EvidenceType.API_TRACE,
        source_tool="frida",
        content={"api": "SmsManager.sendTextMessage", "t_offset_ms": 4200},
        location="run#1@t=4.2s",
    )


# ── store-level refusal ──────────────────────────────────────────────────────
def test_claim_with_no_refs_is_refused(store) -> None:
    with pytest.raises(UngroundedClaimError, match="at least one evidence node"):
        store.append(
            type=EvidenceType.AI_CLAIM,
            source_tool="groq:code_interpreter",
            content={"claim": "This app steals OTPs.", "evidence_refs": []},
        )


def test_claim_with_missing_evidence_refs_key_is_refused(store) -> None:
    """Omitting the key entirely is the same failure as an empty list."""
    with pytest.raises(UngroundedClaimError):
        store.append(
            type=EvidenceType.AI_CLAIM,
            source_tool="groq:code_interpreter",
            content={"claim": "This app steals OTPs."},
        )


def test_claim_citing_a_hallucinated_id_is_refused(store) -> None:
    """The classic LLM failure: a plausible-looking id that does not exist."""
    with pytest.raises(UngroundedClaimError, match="does not exist"):
        store.append(
            type=EvidenceType.AI_CLAIM,
            source_tool="groq:code_interpreter",
            content={"claim": "It forwards SMS.", "evidence_refs": ["ev_01932deadbeef"]},
        )


def test_claim_citing_another_jobs_node_is_refused(store, tmp_path) -> None:
    """Evidence does not carry across jobs.

    Without this, one analysis could cite another's artefacts and the provenance
    trail would silently leave the job it claims to describe.
    """
    other = LedgerStore(store.db_path, tmp_path / "key.pem")
    other.open("job_someone_else")
    foreign = other.append(type=EvidenceType.API_TRACE, source_tool="frida", content={"api": "x"})
    other.close()

    with pytest.raises(UngroundedClaimError, match="does not exist"):
        store.append(
            type=EvidenceType.AI_CLAIM,
            source_tool="groq:code_interpreter",
            content={"claim": "Borrowed evidence.", "evidence_refs": [foreign.id]},
        )


def test_grounded_claim_is_accepted(store, real_node) -> None:
    node = store.append(
        type=EvidenceType.AI_CLAIM,
        source_tool="groq:code_interpreter",
        content={
            "claim": "Sends SMS to a number the user did not enter.",
            "evidence_refs": [real_node.id],
            "verifier_status": "PASS",
        },
        parents=(real_node.id,),
        confidence=0.8,
    )
    assert node.seq == 1
    assert store.verify_chain().ok is True


def test_non_ai_types_do_not_require_refs(store) -> None:
    """Only LLM-produced types carry the grounding requirement.

    An androguard fact is its own evidence; requiring it to cite something would be
    circular and would make the ledger unusable.
    """
    node = store.append(
        type=EvidenceType.MANIFEST_ENTRY,
        source_tool="androguard",
        content={"permission": "android.permission.RECEIVE_SMS"},
    )
    assert node.seq == 0


# ── verifier: partial pass, never all-or-nothing ─────────────────────────────
def test_verifier_passes_good_and_rejects_bad_independently(store, real_node) -> None:
    """Risk R4: one hallucinated citation must not void nine good claims."""
    verifier = Verifier(store, job_id=JOB)
    claims = [
        GroundedClaim(
            text=f"Grounded claim {i}",
            evidence_refs=(real_node.id,),
            agent="code_interpreter",
            verifier_status=VerifierStatus.PASS,
        )
        for i in range(9)
    ] + [
        GroundedClaim(
            text="Hallucinated citation",
            evidence_refs=("ev_01932deadbeef",),
            agent="code_interpreter",
            verifier_status=VerifierStatus.PASS,
        )
    ]

    passed, rejected = verifier.filter(claims)

    assert len(passed) == 9
    assert len(rejected) == 1
    assert rejected[0].verifier_status == VerifierStatus.REJECTED_BAD_REF


def test_verifier_statuses_are_specific(store, real_node) -> None:
    """Each rejection reason is distinguishable, so the report can explain itself."""
    verifier = Verifier(store, job_id=JOB)

    def claim(refs: tuple[str, ...]) -> GroundedClaim:
        return GroundedClaim(
            text="x", evidence_refs=refs, agent="a", verifier_status=VerifierStatus.PASS
        )

    assert verifier.check_claim(claim(())) == VerifierStatus.REJECTED_NO_EVIDENCE
    assert verifier.check_claim(claim(("ev_nope",))) == VerifierStatus.REJECTED_BAD_REF
    assert verifier.check_claim(claim((real_node.id,))) == VerifierStatus.PASS


def test_verifier_rejects_behavioural_claim_citing_only_a_certificate(store) -> None:
    """A real id is not enough — it has to be an id that supports the sentence.

    An OTP-exfil claim citing only a CERTIFICATE node is the §1.4 type-mismatch case:
    the citation is decorative, and accepting it would let the model launder an
    unsupported assertion through a valid node id.
    """
    cert = store.append(
        type=EvidenceType.CERTIFICATE,
        source_tool="androguard",
        content={"subject": "CN=Example"},
    )
    verifier = Verifier(store, job_id=JOB)
    status = verifier.check_claim(
        GroundedClaim(
            text="Forwards intercepted OTPs to a remote host.",
            evidence_refs=(cert.id,),
            agent="code_interpreter",
            verifier_status=VerifierStatus.PASS,
        )
    )
    assert status == VerifierStatus.REJECTED_TYPE_MISMATCH


def test_verifier_honours_an_explicit_allowed_type_set(store, real_node) -> None:
    verifier = Verifier(store, job_id=JOB)
    claim = GroundedClaim(
        text="x", evidence_refs=(real_node.id,), agent="a", verifier_status=VerifierStatus.PASS
    )
    assert (
        verifier.check_claim(claim, allowed_types={EvidenceType.API_TRACE}) == VerifierStatus.PASS
    )
    assert (
        verifier.check_claim(claim, allowed_types={EvidenceType.NETWORK_FLOW})
        == VerifierStatus.REJECTED_TYPE_MISMATCH
    )


def test_rejected_claims_are_retained_not_dropped(store, real_node) -> None:
    """The count of rejections drives the report's Limitations section."""
    verifier = Verifier(store, job_id=JOB)
    _, rejected = verifier.filter(
        [
            GroundedClaim(
                text="bad", evidence_refs=(), agent="a", verifier_status=VerifierStatus.PASS
            )
        ]
    )
    assert len(rejected) == 1
    assert rejected[0].text == "bad", "the claim text must survive for the report"

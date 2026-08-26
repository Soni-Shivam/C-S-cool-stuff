"""AI claims must cite real evidence, and fabricated citations must be rejected.

docs/PHASE_3_GENAI_CORE.md T3.10, CLAUDE.md rule 5.

"Every AI sentence cites a concrete artefact" is the project's central claim. It is
only true if a sentence that cites nothing, or cites something invented, is visibly
rejected — a verifier that always passes proves nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from drishti.contracts.evidence import EvidenceType
from drishti.contracts.genai_verdict import GroundedClaim, VerifierStatus
from drishti.ledger.store import LedgerStore
from drishti.ledger.verifier import Verifier
from drishti.m2_static.engine import analyse
from drishti.m4_genai.controller import build_evidence_catalogue

CANARY = Path(__file__).resolve().parents[2] / "canary" / "dist" / "canary.apk"


@pytest.fixture
def ledger(tmp_path: Path):
    store = LedgerStore(tmp_path / "l.db", tmp_path / "k.pem")
    store.open("job_claims")
    analyse(CANARY, store)
    yield store
    store.close()


def _claim(refs: tuple[str, ...]) -> GroundedClaim:
    return GroundedClaim(
        text="The app queries installed packages.",
        evidence_refs=refs,
        agent="test",
        verifier_status=VerifierStatus.PASS,
    )


def test_the_catalogue_offers_only_real_ids(ledger) -> None:
    catalogue, citable = build_evidence_catalogue(ledger, "job_claims")
    assert citable, "a real APK must yield citable evidence"
    for node_id in citable:
        assert ledger.get(node_id) is not None
        assert node_id in catalogue


def test_a_claim_citing_real_evidence_passes(ledger) -> None:
    _, citable = build_evidence_catalogue(ledger, "job_claims")
    real = next(
        n
        for n in ledger.query(job_id="job_claims")
        if n.id in citable and n.type is EvidenceType.MANIFEST_ENTRY
    )
    assert Verifier(ledger, "job_claims").check_claim(_claim((real.id,))) is VerifierStatus.PASS


def test_every_catalogue_id_can_ground_a_claim_alone(ledger) -> None:
    """The catalogue must never offer an id the verifier then refuses.

    `build_evidence_catalogue` is the list the model is *told* it may cite. If the
    verifier rejects one of those ids, the rejection is recorded against the model as
    a bad citation — blaming it for a hallucination it did not commit, and quietly
    dropping a sentence that was in fact grounded. The two sets must agree.
    """
    _, citable = build_evidence_catalogue(ledger, "job_claims")
    verifier = Verifier(ledger, "job_claims")
    offered_but_refused = {
        node_id: (ledger.get(node_id).type.value, status.value)
        for node_id in sorted(citable)
        if (status := verifier.check_claim(_claim((node_id,)))) is not VerifierStatus.PASS
    }
    assert not offered_but_refused, (
        f"the catalogue offered ids the verifier rejects: {offered_but_refused}"
    )


def test_a_hallucinated_id_is_rejected(ledger) -> None:
    """The failure mode that matters: a plausible-looking id that does not exist."""
    status = Verifier(ledger, "job_claims").check_claim(_claim(("ev_deadbeefcafe",)))
    assert status is VerifierStatus.REJECTED_BAD_REF


def test_a_claim_citing_nothing_is_rejected(ledger) -> None:
    status = Verifier(ledger, "job_claims").check_claim(_claim(()))
    assert status is VerifierStatus.REJECTED_NO_EVIDENCE


def test_one_bad_citation_does_not_sink_the_good_ones(ledger) -> None:
    """Risk R4: never all-or-nothing.

    Nine good claims and one hallucination must not produce a blank report — a blank
    report is indistinguishable from "we found nothing".
    """
    _, citable = build_evidence_catalogue(ledger, "job_claims")
    # Explicit, not `next(iter(citable))`: set iteration order over strings moves with
    # PYTHONHASHSEED, which made this test pick a different node on each interpreter
    # start and fail only on the seeds that landed on a non-behavioural node.
    good_id = next(
        n.id
        for n in ledger.query(job_id="job_claims")
        if n.id in citable and n.type is EvidenceType.MANIFEST_ENTRY
    )
    claims = [_claim((good_id,)) for _ in range(3)] + [_claim(("ev_notreal",))]
    passed, rejected = Verifier(ledger, "job_claims").filter(claims)
    assert len(passed) == 3
    assert len(rejected) == 1
    assert rejected[0].verifier_status is VerifierStatus.REJECTED_BAD_REF


def test_rejected_claims_are_retained_not_deleted(ledger) -> None:
    """The rejection count feeds the report's Limitations section."""
    passed, rejected = Verifier(ledger, "job_claims").filter([_claim(("ev_nope",))])
    assert passed == []
    assert len(rejected) == 1, "a rejected claim must survive so it can be shown as rejected"

"""Mechanical verification of AI claims against the ledger.

docs/PHASE_0_FOUNDATIONS.md T0.4.

The store refuses to *append* an ungrounded `AI_CLAIM`. This module is the layer
above: given claims an agent produced, it decides which may be asserted in a report.

**Never all-or-nothing** (risk R4). An agent that produces nine good claims and one
hallucinated citation must not lose all ten — that failure mode turns one bad
sentence into a blank report, and a blank report is indistinguishable from "we found
nothing".
"""

from __future__ import annotations

from collections.abc import Iterable

from drishti.contracts.evidence import EvidenceType
from drishti.contracts.genai_verdict import GroundedClaim, VerifierStatus
from drishti.ledger.store import LedgerStore

#: Evidence types that alone cannot support a behavioural claim.
#:
#: A claim asserting runtime behaviour that cites ONLY a certificate or file-metadata
#: node is suspicious: those nodes carry no behavioural information, so the citation
#: is decorative. This is the `REJECTED_TYPE_MISMATCH` case from §1.4 — the model
#: produced a real node id, but not one that supports what it said.
NON_BEHAVIOURAL_TYPES: frozenset[EvidenceType] = frozenset(
    {
        EvidenceType.FILE_META,
        EvidenceType.CERTIFICATE,
        EvidenceType.SPLIT_APK,
    }
)


class Verifier:
    """Checks claim citations against what is actually in a job's ledger."""

    def __init__(self, store: LedgerStore, job_id: str | None = None) -> None:
        self._store = store
        self._job_id = job_id

    def check_claim(
        self,
        claim: GroundedClaim,
        *,
        allowed_types: set[EvidenceType] | None = None,
    ) -> VerifierStatus:
        """Return the status this claim earns. Order matters: cheapest check first.

        1. no refs at all              -> REJECTED_NO_EVIDENCE
        2. a ref that does not resolve -> REJECTED_BAD_REF   (a hallucinated id)
        3. refs resolve but none is of a plausible type -> REJECTED_TYPE_MISMATCH
        4. otherwise                   -> PASS
        """
        if not claim.evidence_refs:
            return VerifierStatus.REJECTED_NO_EVIDENCE

        nodes = []
        for ref in claim.evidence_refs:
            node = self._store.get(ref)
            if node is None:
                return VerifierStatus.REJECTED_BAD_REF
            # A ref that resolves in a DIFFERENT job is still a bad ref: evidence does
            # not carry across jobs, and accepting it would let one analysis cite
            # another's artefacts.
            if self._job_id is not None and node.job_id != self._job_id:
                return VerifierStatus.REJECTED_BAD_REF
            nodes.append(node)

        permitted = allowed_types if allowed_types is not None else None
        if permitted is not None:
            if not any(n.type in permitted for n in nodes):
                return VerifierStatus.REJECTED_TYPE_MISMATCH
        elif all(n.type in NON_BEHAVIOURAL_TYPES for n in nodes):
            # Every citation is non-behavioural — nothing here supports a statement
            # about what the app does.
            return VerifierStatus.REJECTED_TYPE_MISMATCH

        return VerifierStatus.PASS

    def filter(
        self,
        claims: Iterable[GroundedClaim],
        *,
        allowed_types: set[EvidenceType] | None = None,
    ) -> tuple[list[GroundedClaim], list[GroundedClaim]]:
        """Split claims into (passed, rejected), each carrying its status.

        Both halves are returned. The rejected list is not waste — its length feeds
        the report's Limitations section, so a run where the model cited badly is
        visibly less trustworthy rather than silently shorter.
        """
        passed: list[GroundedClaim] = []
        rejected: list[GroundedClaim] = []
        for claim in claims:
            status = self.check_claim(claim, allowed_types=allowed_types)
            decided = claim.model_copy(update={"verifier_status": status})
            (passed if status == VerifierStatus.PASS else rejected).append(decided)
        return passed, rejected

/**
 * "We looked and found nothing" versus "we never looked".
 *
 * Paper §20.1: the terms that contribute nothing are labelled **ungrounded** rather
 * than left as a bare zero, because "the interface distinguishes 'we looked and found
 * nothing' from 'we never looked,' which is the distinction on which an analyst's next
 * action actually depends." A zero for R because the reputation feed said the hash is
 * clean and a zero for R because no reputation feed was ever consulted are the same
 * pixels and completely different facts.
 *
 * This decides nothing about the score. `contribution` is rendered exactly as the pure
 * scorer emitted it either way; the only thing computed here is which of two English
 * words sits beside it. The scorer stays the single source of the arithmetic
 * (`drishti/m6_score/engine.py`).
 */

import type { ScoreFactor } from '../api/types'

/**
 * True when the pipeline never obtained an input for this term.
 *
 * Read per symbol rather than with one generic rule, because each term records its
 * absence differently and a generic "is it falsy" test would call a genuine zero
 * ungrounded:
 *
 *  * `F_AI` — the scorer sets both `p_calibrated` and `behavioural_risk_B` to `null`
 *    when the classifier and the model were unusable, and to numbers otherwise. A
 *    calibrated 0.0 is a real answer and must not read as ungrounded.
 *  * `R`, `G`, `D` — grounded exactly when the term cites a ledger node. A reputation
 *    lookup that ran leaves a THREAT_INTEL node behind whatever it concluded; a
 *    signature engine that ran leaves its match. No node, no lookup.
 *
 * A term that contributed something is never ungrounded, whatever the inputs say.
 */
export function isUngrounded(factor: ScoreFactor): boolean {
  if (factor.contribution > 0) return false
  if (factor.symbol === 'F_AI') {
    const { p_calibrated: p, behavioural_risk_B: b } = factor.inputs
    return p == null && b == null
  }
  return factor.evidence_refs.length === 0
}

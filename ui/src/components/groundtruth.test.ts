/**
 * The band-vs-label mapping (contract A21).
 *
 * This is the only pure logic behind the ground-truth card, and it is the one place
 * a wrong answer would put "agreed" over a run that missed. It is tested rather than
 * eyeballed because the interesting case — MEDIUM, where the system declines to
 * decide — is exactly the one a careless reading collapses onto the wrong side.
 */

import { describe, expect, it } from 'vitest'
import { agreement } from './GroundTruthCard'

describe('agreement', () => {
  it('counts a flagged band on a malicious sample as agreement', () => {
    expect(agreement('CRITICAL', 1)).toBe('agreed')
    expect(agreement('HIGH', 1)).toBe('agreed')
  })

  it('counts a cleared band on a benign sample as agreement', () => {
    expect(agreement('LOW', 0)).toBe('agreed')
  })

  it('reports a miss in both directions', () => {
    // The false negative: real malware that scored as clean.
    expect(agreement('LOW', 1)).toBe('disagreed')
    // The false positive: a benign app the system flagged.
    expect(agreement('HIGH', 0)).toBe('disagreed')
    expect(agreement('CRITICAL', 0)).toBe('disagreed')
  })

  it('treats MEDIUM as undecided rather than forcing it onto a side', () => {
    // MEDIUM means "a human should look". Scoring it as a hit or a miss would
    // punish the calibration for being honest about its own uncertainty.
    expect(agreement('MEDIUM', 1)).toBe('inconclusive')
    expect(agreement('MEDIUM', 0)).toBe('inconclusive')
  })

  it('has nothing to compare for an unlabelled sample', () => {
    // Our own canary is inert by construction, which is a different kind of fact
    // from "VirusTotal saw nothing", and it is not scored against either.
    expect(agreement('LOW', null)).toBe('unlabelled')
    expect(agreement('CRITICAL', null)).toBe('unlabelled')
  })
})

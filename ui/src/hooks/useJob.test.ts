/**
 * Tests for the stage-event merge.
 *
 * The hook itself needs a DOM, an EventSource and a running API to exercise, so
 * the part worth protecting is pulled out as a pure function and tested here. It
 * carries two claims a screenshot cannot check: that a job selected by hand shows
 * the timings the stream never delivered for it, and that a transition arriving
 * twice — live over SSE and again in the refetched `stage_history` — is drawn
 * once. Both were bugs; the second is the one a fix for the first would
 * reintroduce.
 */

import { describe, expect, it } from 'vitest'
import { mergeStageEvents } from './useJob'
import type { StageEvent } from '../api/types'

const event = (
  stage: StageEvent['stage'],
  status: string,
  at: string,
  duration_ms: number | null = null,
): StageEvent => ({ stage, status, at, duration_ms, message: null, ledger_seq: null })

const STARTED = event('static', 'started', '2026-08-26T10:00:00Z')
const COMPLETED = event('static', 'completed', '2026-08-26T10:00:04Z', 4000)

describe('mergeStageEvents', () => {
  it('adopts history for a job whose stream delivered nothing', () => {
    // Selecting a finished job by hand: `stream()` has no queued events left, so
    // `stage_history` is the only place its durations can come from.
    const merged = mergeStageEvents([], [STARTED, COMPLETED])
    expect(merged).toEqual([STARTED, COMPLETED])
    expect(merged.map((e) => e.duration_ms)).toEqual([null, 4000])
  })

  it('does not duplicate an event that arrived over the stream first', () => {
    const merged = mergeStageEvents([STARTED], [STARTED, COMPLETED])
    expect(merged).toEqual([STARTED, COMPLETED])
  })

  it('keeps two transitions of the same stage that differ in status', () => {
    // `started` and `completed` are the same stage at different times. Keying on
    // the stage alone would collapse them and lose the duration.
    expect(mergeStageEvents([], [STARTED, COMPLETED])).toHaveLength(2)
  })

  it('returns the identical array when nothing is new', () => {
    // Referential stability: a poll that learned nothing must not re-render the
    // stage strip.
    const known = [STARTED, COMPLETED]
    expect(mergeStageEvents(known, [STARTED, COMPLETED])).toBe(known)
  })

  it('appends in first-seen order', () => {
    const later = event('ml', 'completed', '2026-08-26T10:00:09Z', 900)
    expect(mergeStageEvents([COMPLETED], [STARTED, later])).toEqual([COMPLETED, STARTED, later])
  })
})

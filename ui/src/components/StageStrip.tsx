/**
 * The pipeline stage strip.
 *
 * PHASE_6 T6.4 asks for this specifically because it "makes the '<5 min
 * preliminary, deep analysis async' claim visible rather than asserted": the
 * preliminary verdict lands at SCORE_PRELIM, and everything to its right is the
 * asynchronous deep analysis continuing after the analyst already has a verdict.
 * The marker below is drawn from `PIPELINE_ORDER`, so it cannot drift from the
 * pipeline's real stage list.
 *
 * FRONTIER and SANDBOX_2 are conditional (they run only when pass 1 stalled), so
 * they are drawn dimmed-with-a-dashed-border until they actually fire — showing
 * them as "skipped=failed" would misread a healthy run.
 */

import { CONDITIONAL_STAGES, PIPELINE_ORDER, STAGE_LABELS } from '../api/types'
import type { JobStage, StageEvent } from '../api/types'

type StageState = 'done' | 'active' | 'failed' | 'skipped' | 'waiting'

function stateFor(
  stage: JobStage,
  byStage: Map<JobStage, StageEvent[]>,
  current: JobStage | undefined,
): StageState {
  const events = byStage.get(stage) ?? []
  if (events.some((e) => e.status === 'failed' || e.status === 'error')) return 'failed'
  if (events.some((e) => e.status === 'completed' || e.status === 'done' || e.status === 'ok'))
    return 'done'
  if (stage === current) return 'active'
  if (events.length > 0) return 'active'
  // Past its turn but never seen: a conditional stage that did not need to run.
  const currentIndex = current ? PIPELINE_ORDER.indexOf(current) : -1
  const index = PIPELINE_ORDER.indexOf(stage)
  if (currentIndex > index || current === 'done') {
    return CONDITIONAL_STAGES.has(stage) ? 'skipped' : 'done'
  }
  return 'waiting'
}

const TONE: Record<StageState, string> = {
  done: 'border-good/50 bg-good/10 text-good',
  active: 'border-accent bg-accent-soft text-accent',
  failed: 'border-bad/60 bg-bad/10 text-bad',
  skipped: 'border-dashed border-line text-dim',
  waiting: 'border-line text-dim',
}

export function StageStrip({ events, current }: { events: StageEvent[]; current: JobStage | undefined }) {
  const byStage = new Map<JobStage, StageEvent[]>()
  for (const event of events) {
    byStage.set(event.stage, [...(byStage.get(event.stage) ?? []), event])
  }

  return (
    <div className="flex shrink-0 items-stretch gap-1 overflow-x-auto border-b border-line bg-panel px-5 py-2">
      {PIPELINE_ORDER.map((stage) => {
        const state = stateFor(stage, byStage, current)
        const duration = (byStage.get(stage) ?? []).find((e) => e.duration_ms != null)?.duration_ms
        const isVerdict = stage === 'score_prelim'
        return (
          <div key={stage} className="flex items-center gap-1">
            <div
              title={state === 'skipped' ? 'conditional stage — not needed for this run' : state}
              className={`min-w-fit rounded border px-2 py-1 text-[11px] leading-tight whitespace-nowrap transition-colors ${TONE[state]}`}
            >
              <div className="font-medium">{STAGE_LABELS[stage]}</div>
              <div className="font-mono text-[10px] opacity-70">
                {duration != null ? `${duration} ms` : state === 'skipped' ? 'not run' : '—'}
              </div>
            </div>
            {isVerdict && (
              <span
                className="mx-1 self-center border-l border-dashed border-accent/50 pl-1 text-[10px] tracking-wider text-accent/80"
                title="Everything to the right runs asynchronously, after the analyst already has a verdict"
              >
                VERDICT ▸ async
              </span>
            )}
          </div>
        )
      })}
    </div>
  )
}

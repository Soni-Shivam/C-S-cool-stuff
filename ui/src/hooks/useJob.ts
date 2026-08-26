/**
 * Job state, driven by the SSE stage stream.
 *
 * The stream is the source of truth for *progress*; the REST job object is the
 * source of truth for *content* (it carries `preliminary` and `final`). So a
 * stage event triggers a job refetch rather than being trusted to reconstruct the
 * whole object client-side — which would drift the moment a contract field lands.
 *
 * The stream is not, however, the source of truth for a job's *history*. It
 * replays nothing: `JobRunner.stream()` hands out whatever is still in the job's
 * queue, so a run that finished before this hook subscribed delivers no events at
 * all. `Job.stage_history` is the durable record of the same transitions, and it
 * is merged in on every refetch — that is what puts stage durations on screen for
 * a job selected by hand rather than followed live.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { getJob } from '../api/client'
import type { Job, StageEvent } from '../api/types'

/**
 * Two events describe the same transition when they agree on stage, status and
 * timestamp. A key is needed because the same transition reaches this hook twice
 * — once live over SSE, and again inside the `stage_history` of the refetch that
 * event triggered — and a transition recorded twice draws a stage that looks like
 * it ran twice.
 */
function eventKey(event: StageEvent): string {
  return `${event.stage}|${event.status}|${event.at}`
}

/** `incoming` merged into what is already known, in first-seen order. */
export function mergeStageEvents(
  known: StageEvent[],
  incoming: readonly StageEvent[],
): StageEvent[] {
  const seen = new Set(known.map(eventKey))
  const merged = [...known]
  for (const event of incoming) {
    const key = eventKey(event)
    if (seen.has(key)) continue
    seen.add(key)
    merged.push(event)
  }
  // Returning the identical array when nothing was new keeps `events`
  // referentially stable, so a poll that learned nothing does not re-render the
  // stage strip on every tick.
  return merged.length === known.length ? known : merged
}

export interface JobState {
  job: Job | null
  events: StageEvent[]
  streaming: boolean
  error: string | null
  /** Bumps on every stage transition. Artefact hooks watch it to know when to refetch. */
  revision: number
  refresh: () => void
}

export function useJob(jobId: string | null): JobState {
  const [job, setJob] = useState<Job | null>(null)
  const [events, setEvents] = useState<StageEvent[]>([])
  const [streaming, setStreaming] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [revision, setRevision] = useState(0)
  const sourceRef = useRef<EventSource | null>(null)
  // Bumped every time the selected job changes. A fetch records the value it was
  // issued under and drops its response if the selection has moved on since —
  // otherwise a `getJob` for the job the operator just left resolves late and
  // repaints the header and stage strip with it, which is exactly what read on
  // screen as the view flipping between two runs.
  const selection = useRef(0)

  const refresh = useCallback(() => {
    if (!jobId) return
    const issuedFor = selection.current
    getJob(jobId)
      .then((next) => {
        if (selection.current !== issuedFor) return
        setJob(next)
        // The durable history, merged with whatever the stream already delivered.
        // For a job selected by hand this is the only source of its timings.
        setEvents((prev) => mergeStageEvents(prev, next.stage_history))
        setError(null)
      })
      .catch((exc: unknown) => {
        if (selection.current !== issuedFor) return
        setError(exc instanceof Error ? exc.message : String(exc))
      })
  }, [jobId])

  useEffect(() => {
    selection.current += 1
    setJob(null)
    setEvents([])
    setError(null)
    setRevision(0)
    if (!jobId) return

    refresh()

    const source = new EventSource(`/api/jobs/${jobId}/events`)
    sourceRef.current = source
    setStreaming(true)

    source.addEventListener('stage', (raw) => {
      const event = JSON.parse((raw as MessageEvent).data) as StageEvent
      // Merged rather than appended: the refetch below carries this same event in
      // `stage_history`, and whichever arrives second must not duplicate it.
      setEvents((prev) => mergeStageEvents(prev, [event]))
      setRevision((n) => n + 1)
      refresh()
    })

    source.addEventListener('done', () => {
      setStreaming(false)
      setRevision((n) => n + 1)
      refresh()
      source.close()
    })

    source.onerror = () => {
      // A closed stream after `done` is normal; only report while still open.
      if (source.readyState === EventSource.CLOSED) setStreaming(false)
    }

    return () => {
      source.close()
      sourceRef.current = null
      setStreaming(false)
    }
  }, [jobId, refresh])

  // A finished job is not streaming, whatever the EventSource is doing. Opening the
  // stream sets `streaming` true, but a job that completed BEFORE we subscribed already
  // had its `done` sentinel consumed by the original stream, so no `done` ever arrives
  // and the badge sits on "running" forever. Selecting any past run therefore claimed it
  // was still in progress — a false statement on the demo screen, and the same class of
  // bug as a panel showing another job's data.
  const terminal = job?.stage === 'done' || job?.stage === 'failed'

  return { job, events, streaming: streaming && !terminal, error, revision, refresh }
}

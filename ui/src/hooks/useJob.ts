/**
 * Job state, driven by the SSE stage stream.
 *
 * The stream is the source of truth for *progress*; the REST job object is the
 * source of truth for *content* (it carries `preliminary` and `final`). So a
 * stage event triggers a job refetch rather than being trusted to reconstruct the
 * whole object client-side — which would drift the moment a contract field lands.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import { getJob } from '../api/client'
import type { Job, StageEvent } from '../api/types'

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

  const refresh = useCallback(() => {
    if (!jobId) return
    getJob(jobId)
      .then((next) => {
        setJob(next)
        setError(null)
      })
      .catch((exc: unknown) => setError(exc instanceof Error ? exc.message : String(exc)))
  }, [jobId])

  useEffect(() => {
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
      setEvents((prev) => [...prev, event])
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

  return { job, events, streaming, error, revision, refresh }
}

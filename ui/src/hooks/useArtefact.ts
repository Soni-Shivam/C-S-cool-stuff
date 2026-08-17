/**
 * Load one per-job artefact and reload it when the pipeline moves.
 *
 * `revision` comes from the SSE stage stream, so a panel fills in as its stage
 * lands instead of on a timer. A pending artefact stays pending — this hook never
 * substitutes a default value for one that has not been produced.
 */

import { useCallback, useEffect, useState } from 'react'
import type { Artefact } from '../api/client'

export function useArtefact<T>(
  jobId: string | null,
  load: (jobId: string) => Promise<Artefact<T>>,
  revision: number,
): { artefact: Artefact<T> | null; reload: () => void } {
  const [artefact, setArtefact] = useState<Artefact<T> | null>(null)

  const reload = useCallback(() => {
    if (!jobId) {
      setArtefact(null)
      return
    }
    let cancelled = false
    load(jobId).then((next) => {
      if (!cancelled) setArtefact(next)
    })
    return () => {
      cancelled = true
    }
    // `load` is a module-level function reference in every call site.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId])

  useEffect(() => {
    reload()
  }, [reload, revision])

  return { artefact, reload }
}

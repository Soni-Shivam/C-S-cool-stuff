/**
 * Load one per-job artefact and reload it when the pipeline moves.
 *
 * `revision` comes from the SSE stage stream, so a panel fills in as its stage
 * lands instead of on a timer. A pending artefact stays pending — this hook never
 * substitutes a default value for one that has not been produced.
 *
 * Every fetch is issued under a generation number and its response is dropped if
 * a newer fetch was issued in the meantime. That is not defensive coding: eight
 * of these hooks run per job, a new submission can change the selection while all
 * eight are in flight, and a response that lands late writes the *previous* job's
 * numbers into a panel the shell is rendering as the current one. With several
 * jobs arriving in a demo the effect is a dashboard that appears to flip back and
 * forth between two runs.
 */

import { useCallback, useEffect, useRef, useState } from 'react'
import type { Artefact } from '../api/client'

export function useArtefact<T>(
  jobId: string | null,
  load: (jobId: string) => Promise<Artefact<T>>,
  revision: number,
): { artefact: Artefact<T> | null; reload: () => void } {
  const [artefact, setArtefact] = useState<Artefact<T> | null>(null)
  // `reload()` bumps this instead of fetching directly, so that every fetch —
  // the one a stage transition triggers and the one a caller asks for — goes
  // through the single effect below, which is the only place that knows how to
  // discard a response that arrived too late.
  const [nonce, setNonce] = useState(0)
  const generation = useRef(0)

  const reload = useCallback(() => setNonce((n) => n + 1), [])

  // Kept separate from the fetch below because only a change of *job* invalidates
  // what is on screen. Dropping the old job's value here rather than leaving it
  // until its replacement lands is what stops one panel showing job A beside a
  // panel already showing job B. A revision bump is the same job moving forward,
  // and blanking every panel on each stage transition would strobe the dashboard.
  useEffect(() => {
    setArtefact(null)
  }, [jobId])

  useEffect(() => {
    if (!jobId) return
    const issued = (generation.current += 1)
    void load(jobId).then((next) => {
      // Superseded — by another job, or by a later fetch for this one that came
      // back first. Either way this response is no longer what the shell is
      // rendering, and writing it would be a lie about which run is on screen.
      if (generation.current !== issued) return
      setArtefact(next)
    })
    // `load` is a module-level function reference in every call site.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId, revision, nonce])

  return { artefact, reload }
}

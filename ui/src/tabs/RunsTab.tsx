/**
 * Runs: every job this instance has analysed, as a table an analyst can work.
 *
 * The header strip was doing two jobs that want opposite things. The live beat — a phone
 * submits an APK and you watch it arrive — wants to be small, ambient and show only the
 * newest. Review — "the run from twenty minutes ago", "which of last night's forty-eight
 * came back HIGH" — wants a table, sorting and all of them. Cramming both into one strip
 * is why it truncated to six, and why unchecking follow left you stranded.
 *
 * So the strip keeps the live beat and this is the history. That also fixes the
 * truncation structurally rather than by raising a limit: the strip no longer pretends
 * to be history, so it has nothing to hide.
 *
 * `GET /api/jobs` carries identity and `stage_history` but **no score** — verified
 * against the running API rather than assumed. Scores are therefore fetched per row,
 * lazily, and a row renders complete without one. Extending the frozen route (T0.6) to
 * carry a score would have been the other option and a worse one.
 */

import { useEffect, useMemo, useState } from 'react'
import { getScore, listJobs } from '../api/client'
import type { CompositeScore, Job } from '../api/types'
import { CopyButton } from '../components/Analyst'
import { matches, summarise } from '../components/analyst'
import { BAND_CLASS, Empty, Panel, SectionHead } from '../components/primitives'

type SortKey = 'time' | 'score'

/** Wall-clock for the run, summed from the stage history already on the wire. */
function duration(job: Job): number | null {
  const total = (job.stage_history ?? []).reduce((sum, event) => sum + (event.duration_ms ?? 0), 0)
  return total > 0 ? total : null
}

function seconds(ms: number | null): string {
  if (ms === null) return '—'
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`
}

function when(iso: string | null | undefined): string {
  if (!iso) return '—'
  const at = new Date(iso)
  return Number.isNaN(at.getTime()) ? '—' : at.toLocaleString()
}

export function RunsTab({
  currentJobId,
  onSelectJob,
}: {
  currentJobId: string | null
  onSelectJob: (jobId: string) => void
}) {
  const [jobs, setJobs] = useState<Job[]>([])
  const [scores, setScores] = useState<Record<string, CompositeScore | null>>({})
  const [query, setQuery] = useState('')
  const [sort, setSort] = useState<SortKey>('time')
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    listJobs()
      .then((next) => {
        if (!cancelled) setJobs(next)
      })
      .catch(() => undefined)
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  // Scores are not in the job list, so they arrive per row. Guarded by `cancelled` for
  // the same reason every other fetch in this app now is: a late response must never
  // paint a view the user has already left.
  useEffect(() => {
    let cancelled = false
    const pending = jobs.filter((job) => job.stage === 'done' && !(job.id in scores))
    for (const job of pending.slice(0, 60)) {
      getScore(job.id)
        .then((result) => {
          // `getScore` returns the artefact envelope: a job can legitimately have no
          // score yet, and "pending" is not "zero". Only a ready value becomes a score.
          const score = result.state === 'ready' ? result.value : null
          if (!cancelled) setScores((prev) => ({ ...prev, [job.id]: score }))
        })
        .catch(() => {
          if (!cancelled) setScores((prev) => ({ ...prev, [job.id]: null }))
        })
    }
    return () => {
      cancelled = true
    }
  }, [jobs, scores])

  const visible = useMemo(() => {
    const filtered = jobs.filter((job) =>
      matches([job.filename ?? '', job.sha256 ?? '', job.id, job.stage ?? ''], query),
    )
    const ordered = [...filtered]
    if (sort === 'score') {
      // Unscored rows sort last rather than as zero — "not scored" is not "scored 0",
      // and letting them sink to the bottom of a descending list says that.
      ordered.sort((a, b) => (scores[b.id]?.S ?? -1) - (scores[a.id]?.S ?? -1))
    }
    return ordered
  }, [jobs, query, sort, scores])

  return (
    <div className="space-y-5">
      <SectionHead
        eyebrow="Runs"
        title="Every sample this instance has analysed"
        lede="The header strip follows the phone; this is the history. Scores are fetched per row because GET /api/jobs carries identity and timings but not a verdict."
      />

      <Panel
        title={`Runs (${summarise(visible.length, jobs.length)})`}
        right={
          <div className="flex items-center gap-2">
            <input
              type="search"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="filter by name, hash or stage…"
              data-analyst-filter
              className="w-60 rounded-full border border-line-bright bg-ground-2 px-3 py-1.5 text-xs text-fg transition-colors placeholder:text-muted hover:border-v400 focus:border-v400 focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setSort(sort === 'time' ? 'score' : 'time')}
              className="rounded-full border border-line-bright bg-ground-2 px-3 py-1.5 text-xs text-muted transition-colors hover:border-v400 hover:text-fg"
            >
              sort: {sort === 'time' ? 'newest' : 'score'}
            </button>
          </div>
        }
      >
        {loading ? (
          <Empty>Loading runs…</Empty>
        ) : jobs.length === 0 ? (
          <Empty>Nothing analysed yet. Drop an APK in the header to start.</Empty>
        ) : visible.length === 0 ? (
          <Empty>
            No runs match “{query}”. {jobs.length} recorded.
          </Empty>
        ) : (
          <div className="max-h-[34rem] overflow-auto">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-ground-1 text-muted">
                <tr>
                  <th className="py-1.5 pr-3 font-medium">when</th>
                  <th className="py-1.5 pr-3 font-medium">sample</th>
                  <th className="py-1.5 pr-3 font-medium">stage</th>
                  <th className="py-1.5 pr-3 font-medium">score</th>
                  <th className="py-1.5 pr-3 font-medium">took</th>
                  <th className="py-1.5 font-medium">sha256</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((job) => {
                  const score = scores[job.id]
                  const active = job.id === currentJobId
                  return (
                    <tr
                      key={job.id}
                      onClick={() => onSelectJob(job.id)}
                      className={`cursor-pointer border-t border-line-soft transition-colors hover:bg-white/[0.04] ${
                        active ? 'bg-v500/[0.10]' : ''
                      }`}
                    >
                      <td className="py-1.5 pr-3 whitespace-nowrap text-muted">
                        {when(job.created_at)}
                      </td>
                      <td className="max-w-[18rem] py-1.5 pr-3 truncate font-mono text-fg">
                        {job.filename ?? job.id}
                      </td>
                      <td className="py-1.5 pr-3 text-muted">{job.stage}</td>
                      <td className="py-1.5 pr-3">
                        {score ? (
                          <span className={`font-mono ${BAND_CLASS[score.band]}`}>
                            {score.S} {score.band}
                          </span>
                        ) : (
                          <span className="text-dim">—</span>
                        )}
                      </td>
                      <td className="py-1.5 pr-3 font-mono text-muted">
                        {seconds(duration(job))}
                      </td>
                      <td className="py-1.5">
                        <span
                          className="inline-flex items-center gap-1.5"
                          onClick={(e) => e.stopPropagation()}
                        >
                          <span className="font-mono text-dim">
                            {(job.sha256 ?? '').slice(0, 12) || '—'}
                          </span>
                          {job.sha256 ? <CopyButton value={job.sha256} label="copy" /> : null}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </div>
  )
}

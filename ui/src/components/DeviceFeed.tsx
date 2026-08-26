/**
 * The live device feed — the dashboard's half of the on-stage demo.
 *
 * During the live demo nobody touches this browser. An APK lands on a phone, DRISHTI
 * Shield uploads it, and the job appears here on its own. That is the whole reason
 * this strip exists: a dashboard the presenter has to drive by hand would not
 * demonstrate anything the phone did not already show.
 *
 * It polls `GET /api/jobs` rather than holding a socket. The job it needs to notice
 * is created by a different client entirely, so there is no stream to subscribe to at
 * the moment it matters, and a one-second poll is well inside the latency the beat
 * can absorb.
 *
 * "Follow the phone" is on by default and is a real toggle: an operator inspecting an
 * older job mid-demo must not have the view yanked out from under them by the next
 * submission.
 */

import { useEffect, useRef, useState } from 'react'
import { Smartphone, Radio } from 'lucide-react'
import { listJobs } from '../api/client'
import type { Job } from '../api/types'

const POLL_MS = 1000

export function DeviceFeed({
  currentJobId,
  onSelectJob,
}: {
  currentJobId: string | null
  onSelectJob: (jobId: string) => void
}) {
  const [jobs, setJobs] = useState<Job[]>([])
  const [follow, setFollow] = useState(true)
  const [reachable, setReachable] = useState(true)
  // Which job id we have already auto-followed, so toggling `follow` back on does
  // not re-hijack the view to a job the operator deliberately navigated away from.
  const followed = useRef<string | null>(null)

  useEffect(() => {
    let cancelled = false
    const tick = async () => {
      try {
        const next = await listJobs()
        if (cancelled) return
        setReachable(true)
        setJobs(next)
        const newest = next[0]
        if (follow && newest && followed.current !== newest.id && newest.id !== currentJobId) {
          followed.current = newest.id
          onSelectJob(newest.id)
        }
      } catch {
        if (!cancelled) setReachable(false)
      }
    }
    void tick()
    const timer = window.setInterval(() => void tick(), POLL_MS)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [follow, currentJobId, onSelectJob])

  const newest = jobs[0]
  const live = newest != null && newest.stage !== 'done' && newest.stage !== 'failed'

  return (
    <div className="flex shrink-0 items-center gap-3 overflow-x-auto border-b border-line bg-ground-2 px-4 py-2 text-xs">
      <span className="flex shrink-0 items-center gap-1.5 font-medium text-muted">
        {live ? (
          <Radio size={14} strokeWidth={2} className="animate-pulse text-accent" />
        ) : (
          <Smartphone size={14} strokeWidth={1.8} />
        )}
        Device feed
      </span>

      {!reachable && <span className="text-danger">API unreachable</span>}

      {reachable && jobs.length === 0 && (
        <span className="text-dim">
          No submissions yet — waiting for DRISHTI Shield to upload an APK
        </span>
      )}

      <div className="flex min-w-0 items-center gap-1.5">
        {jobs.slice(0, 6).map((job) => {
          const selected = job.id === currentJobId
          const score = job.final ?? job.preliminary
          return (
            <button
              key={job.id}
              type="button"
              onClick={() => {
                // An explicit click is also a decision to stop being dragged around.
                followed.current = job.id
                onSelectJob(job.id)
              }}
              title={`${job.filename} · ${job.sha256.slice(0, 16)}… · ${job.stage}`}
              className={`flex shrink-0 items-center gap-2 rounded border px-2 py-1 transition-colors ${
                selected
                  ? 'border-accent/40 bg-accent-soft text-accent'
                  : 'border-line bg-ground-1 text-muted hover:text-fg'
              }`}
            >
              <span className="max-w-36 truncate font-medium">{job.filename}</span>
              <span className="font-mono text-dim">{job.stage}</span>
              {score && (
                <span
                  className={
                    score.band === 'CRITICAL' || score.band === 'HIGH'
                      ? 'font-semibold text-danger'
                      : 'text-dim'
                  }
                >
                  {score.S}
                </span>
              )}
            </button>
          )
        })}
      </div>

      <label className="ml-auto flex shrink-0 cursor-pointer items-center gap-1.5 text-muted">
        <input
          type="checkbox"
          checked={follow}
          onChange={(event) => setFollow(event.target.checked)}
          className="accent-accent"
        />
        Follow the phone
      </label>
    </div>
  )
}

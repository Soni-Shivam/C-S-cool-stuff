/**
 * Top bar: identity, the drop target, and the job's live state.
 *
 * The drop target is in the header rather than in a modal because on stage the
 * upload IS the opening move — it has to be reachable in one gesture with a file
 * already dragged from the desktop.
 */

import { Upload } from 'lucide-react'
import { useCallback, useRef, useState } from 'react'
import { submitApk } from '../api/client'
import type { Job } from '../api/types'

export function Header({
  job,
  streaming,
  onJobCreated,
  version,
}: {
  job: Job | null
  streaming: boolean
  onJobCreated: (jobId: string) => void
  version: string | null
}) {
  const [dragging, setDragging] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const input = useRef<HTMLInputElement>(null)

  const upload = useCallback(
    async (file: File | undefined) => {
      if (!file) return
      setBusy(true)
      setError(null)
      try {
        onJobCreated(await submitApk(file))
      } catch (exc) {
        setError(exc instanceof Error ? exc.message : String(exc))
      } finally {
        setBusy(false)
      }
    },
    [onJobCreated],
  )

  return (
    <header className="flex min-w-0 shrink-0 items-center gap-2 border-b border-line bg-panel px-3 py-3 sm:gap-4 sm:px-5">
      <div className="flex shrink-0 items-baseline gap-2">
        <span className="text-lg font-bold tracking-[0.2em] text-fg">DRISHTI</span>
        <span className="hidden text-xs text-muted sm:inline">APK triage</span>
        {version && <span className="hidden font-mono text-[11px] text-dim lg:inline">v{version}</span>}
      </div>

      <div
        onDragOver={(e) => {
          e.preventDefault()
          setDragging(true)
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault()
          setDragging(false)
          void upload(e.dataTransfer.files[0])
        }}
        onClick={() => input.current?.click()}
        className={`flex min-w-0 flex-1 cursor-pointer items-center justify-center gap-2 rounded border border-dashed px-2 py-2 text-center text-sm transition-colors sm:px-4 ${
          dragging
            ? 'border-accent bg-accent-soft text-accent'
            : 'border-line hover:border-accent/60 text-muted'
        }`}
      >
        <Upload size={15} className="shrink-0" />
        <span className="sm:hidden">{busy ? 'Uploading' : 'APK'}</span>
        <span className="hidden truncate sm:inline">
          {busy ? 'uploading…' : 'drop APK here, or click to choose'}
        </span>
        <input
          ref={input}
          type="file"
          accept=".apk,.apks,.xapk,application/vnd.android.package-archive"
          className="hidden"
          onChange={(e) => void upload(e.target.files?.[0])}
        />
      </div>

      {error && <span className="max-w-64 truncate text-xs text-bad">{error}</span>}

      {job && (
        <div className="flex min-w-0 shrink-0 items-center gap-3">
          <div className="hidden text-right md:block">
            <div className="font-mono text-xs text-fg">{job.id}</div>
            <div className="max-w-56 truncate font-mono text-[11px] text-muted" title={job.filename}>
              {job.filename}
            </div>
          </div>
          <span
            className={`flex items-center gap-1.5 rounded border px-2 py-1 text-[11px] font-medium ${
              job.stage === 'failed'
                ? 'border-bad/40 bg-bad/10 text-bad'
                : streaming
                  ? 'border-accent/40 bg-accent-soft text-accent'
                  : 'border-good/40 bg-good/10 text-good'
            }`}
          >
            <span className={`h-1.5 w-1.5 rounded-full bg-current ${streaming ? 'pulse' : ''}`} />
            {job.stage === 'failed' ? 'failed' : streaming ? 'running' : job.stage}
          </span>
        </div>
      )}
    </header>
  )
}

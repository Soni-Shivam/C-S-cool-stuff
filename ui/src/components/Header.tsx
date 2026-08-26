/**
 * Top bar: identity, the drop target, and the job's live state.
 *
 * The drop target is in the header rather than in a modal because on stage the
 * upload IS the opening move — it has to be reachable in one gesture with a file
 * already dragged from the desktop. While the upload is in flight the logo
 * spinner replaces the icon, so the app's one loading language starts at the very
 * first interaction.
 */

import { Upload } from 'lucide-react'
import { useCallback, useRef, useState } from 'react'
import { submitApk } from '../api/client'
import type { Job } from '../api/types'
import { LogoLockup, LogoSpinner } from './Logo'

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
    <header className="glass flex min-w-0 shrink-0 items-center gap-3 border-b border-line px-4 py-3 sm:gap-5 sm:px-6">
      <LogoLockup version={version} />

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
        className={`flex min-w-0 flex-1 cursor-pointer items-center justify-center gap-2.5 rounded-full border border-dashed px-3 py-2.5 text-center text-sm transition-all duration-300 sm:px-5 ${
          dragging
            ? 'border-v400 bg-v500/15 text-v200 shadow-[0_0_34px_-6px_rgba(168,85,247,0.75)]'
            : 'border-line-bright text-muted hover:border-v500/70 hover:text-v300'
        }`}
      >
        {busy ? <LogoSpinner size="xs" /> : <Upload size={15} className="shrink-0" />}
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
            <div
              className="max-w-56 truncate font-mono text-[11px] text-dim"
              title={job.filename}
            >
              {job.filename}
            </div>
          </div>
          <span
            className={`flex items-center gap-2 rounded-full border px-3 py-1.5 text-[11px] font-medium ${
              job.stage === 'failed'
                ? 'border-bad/45 bg-bad/10 text-bad'
                : streaming
                  ? 'border-v500/50 bg-v500/15 text-v300'
                  : 'border-good/45 bg-good/10 text-good'
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

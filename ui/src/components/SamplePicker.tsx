/**
 * Run a sample whose true nature is already known (contract A21).
 *
 * Uploading whatever APK is to hand makes a demonstration only as good as that file.
 * These samples sit on the analysis VM with their corpus label attached, so the
 * verdict can be put next to the truth and be seen to be right — or wrong, which the
 * comparison renders just as plainly.
 *
 * **The label is shown here and never sent back.** Pressing Run posts an id; the VM
 * starts the same pipeline an upload starts. `label` and `vt_detection` are
 * VirusTotal-derived, and a scoring run that could see them would be scoring its own
 * answer key. That the picker knows the answer and the analysis does not is the
 * entire point of putting the two side by side afterwards.
 *
 * The picker renders nothing when the catalogue is empty, which is the normal state
 * on a laptop: no samples are staged there, and a button that cannot work is worse
 * than no button.
 */

import { FlaskConical, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { analyseSample, listSamples } from '../api/client'
import type { SampleEntry } from '../api/types'
import { LogoSpinner } from './Logo'

/** The label as a reader's word plus the icon that carries it at a glance. */
export function groundTruth(entry: SampleEntry): {
  word: string
  detail: string
  tone: 'bad' | 'good' | 'neutral'
} {
  if (entry.label === 1) {
    return {
      word: 'malicious',
      detail: entry.vt_detection ? `${entry.vt_detection} VirusTotal detections` : 'corpus label',
      tone: 'bad',
    }
  }
  if (entry.label === 0) {
    return { word: 'benign', detail: 'no VirusTotal detections', tone: 'good' }
  }
  return { word: 'unlabelled', detail: 'our own inert probe app', tone: 'neutral' }
}

const TONE: Record<'bad' | 'good' | 'neutral', string> = {
  bad: 'border-bad/40 bg-bad/10 text-bad',
  good: 'border-ok/40 bg-ok/10 text-ok',
  neutral: 'border-line-bright bg-ground-2 text-muted',
}

function Icon({ tone }: { tone: 'bad' | 'good' | 'neutral' }) {
  const size = 13
  if (tone === 'bad') return <ShieldAlert size={size} />
  if (tone === 'good') return <ShieldCheck size={size} />
  return <ShieldQuestion size={size} />
}

function kb(bytes: number): string {
  return bytes >= 1024 * 1024
    ? `${(bytes / 1024 / 1024).toFixed(1)} MB`
    : `${Math.round(bytes / 1024)} KB`
}

export function SamplePicker({ onJobCreated }: { onJobCreated: (jobId: string) => void }) {
  const [samples, setSamples] = useState<SampleEntry[]>([])
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const box = useRef<HTMLDivElement>(null)

  useEffect(() => {
    // A failure here is not worth a banner: the catalogue is an affordance, and the
    // drop target beside it still works. It logs and the picker stays hidden.
    void listSamples()
      .then(setSamples)
      .catch(() => setSamples([]))
  }, [])

  useEffect(() => {
    if (!open) return
    const close = (event: MouseEvent) => {
      if (box.current && !box.current.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [open])

  if (samples.length === 0) return null

  const run = async (entry: SampleEntry) => {
    setBusy(entry.id)
    setError(null)
    try {
      onJobCreated(await analyseSample(entry.id))
      setOpen(false)
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setBusy(null)
    }
  }

  return (
    <div ref={box} className="relative shrink-0">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-2 rounded-full border border-line-bright px-3 py-2.5 text-sm text-muted transition-colors hover:border-v500/70 hover:text-v300"
        title="Run a sample whose true nature is already known"
      >
        <FlaskConical size={15} className="shrink-0" />
        <span className="hidden lg:inline">known samples</span>
      </button>

      {open && (
        <div className="shadow-card absolute right-0 z-50 mt-2 w-[min(30rem,calc(100vw-2rem))] overflow-hidden rounded-[var(--radius-card)] border border-line bg-ground-1">
          <div className="border-b border-line-soft px-4 py-3">
            <div className="text-sm font-semibold text-fg">Samples staged on the analysis VM</div>
            <p className="mt-1 text-xs leading-relaxed text-muted">
              Their nature is already known, so you can check the verdict against it. The
              label below is shown to you and is never sent to the analysis — the run sees
              exactly what an upload would.
            </p>
          </div>

          <ul className="max-h-[26rem] divide-y divide-line-soft overflow-auto">
            {samples.map((entry) => {
              const truth = groundTruth(entry)
              return (
                <li
                  key={entry.id}
                  className="flex items-center justify-between gap-3 px-4 py-2.5 hover:bg-ground-2/60"
                >
                  <div className="min-w-0">
                    <div className="truncate font-mono text-[12px] text-fg">{entry.package}</div>
                    <div className="mt-0.5 flex items-center gap-2">
                      <span
                        className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] ${TONE[truth.tone]}`}
                      >
                        <Icon tone={truth.tone} />
                        {truth.word}
                      </span>
                      <span className="truncate text-[11px] text-dim">
                        {truth.detail} · {kb(entry.size_bytes)}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => void run(entry)}
                    disabled={busy !== null}
                    className="shrink-0 rounded border border-accent/50 bg-accent-soft px-3 py-1.5 text-xs text-accent hover:bg-accent/20 disabled:opacity-50"
                  >
                    {busy === entry.id ? <LogoSpinner size="xs" /> : 'Run'}
                  </button>
                </li>
              )
            })}
          </ul>

          {error && <div className="border-t border-line-soft px-4 py-2 text-xs text-bad">{error}</div>}
        </div>
      )}
    </div>
  )
}

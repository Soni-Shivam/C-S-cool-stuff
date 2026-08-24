/**
 * Shared display primitives.
 *
 * `ArtefactGate` is the important one. Every panel in this app renders through it,
 * so the 404/501 distinction the API makes reaches the screen intact: a stage that
 * has not run says so, and a feature that does not exist in this build names the
 * task that will build it. Neither is ever drawn as an empty result.
 */

import type { ReactNode } from 'react'
import type { Artefact } from '../api/client'
import type { AnalyserResult, SeverityBand } from '../api/types'

export function Panel({
  title,
  subtitle,
  right,
  children,
  className = '',
}: {
  title?: string
  subtitle?: string
  right?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`rounded-lg border border-line bg-panel ${className}`}>
      {(title || right) && (
        <header className="flex items-baseline justify-between gap-3 border-b border-line-soft px-4 py-2.5">
          <div>
            {title && <h3 className="text-sm font-semibold tracking-wide text-fg">{title}</h3>}
            {subtitle && <p className="mt-0.5 text-xs text-muted">{subtitle}</p>}
          </div>
          {right}
        </header>
      )}
      <div className="p-4">{children}</div>
    </section>
  )
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="text-sm text-muted italic">{children}</p>
}

/**
 * Render an artefact, or the honest reason it is not here yet.
 *
 * Note there is no "loading -> render zeros" path. `null` means the request is in
 * flight; a produced-but-empty artefact is the panel's own business.
 */
export function ArtefactGate<T>({
  artefact,
  children,
}: {
  artefact: Artefact<T> | null
  children: (value: T) => ReactNode
}) {
  if (artefact === null) {
    return <p className="text-sm text-muted">Loading…</p>
  }
  if (artefact.state === 'pending') {
    return (
      <div className="rounded border border-line-soft bg-panel-2 px-3 py-2.5 text-sm text-muted">
        Not produced yet — the pipeline is at <span className="font-mono text-fg">{artefact.stage}</span>.
      </div>
    )
  }
  if (artefact.state === 'unavailable') {
    return (
      <div className="rounded border border-warn/30 bg-warn/5 px-3 py-2.5 text-sm">
        <span className="text-warn">Not available in this build.</span>{' '}
        <span className="text-muted">
          {artefact.what} lands in <span className="font-mono text-fg">{artefact.task}</span>.
        </span>
      </div>
    )
  }
  if (artefact.state === 'error') {
    return (
      <div className="rounded border border-bad/40 bg-bad/5 px-3 py-2.5 text-sm text-bad">
        {artefact.message}
      </div>
    )
  }
  return <>{children(artefact.value)}</>
}

/**
 * `partial` + `errors` from `AnalyserResult`, surfaced wherever a module degraded.
 *
 * 00_GUIDING_MAP §9.2 makes degradation a data property so it survives to the UI.
 * It only survives if something draws it, which is this.
 */
export function DegradedNotice({ result }: { result: AnalyserResult }) {
  if (!result.partial && result.errors.length === 0) return null
  return (
    <div className="mb-3 rounded border border-warn/30 bg-warn/5 px-3 py-2 text-xs">
      <span className="font-semibold text-warn">
        {result.partial ? 'Partial result' : 'Completed with errors'}
      </span>
      <ul className="mt-1 space-y-0.5 text-muted">
        {result.errors.map((error, i) => (
          <li key={i} className="max-w-full break-all font-mono">
            {error}
          </li>
        ))}
      </ul>
    </div>
  )
}

export const BAND_CLASS: Record<SeverityBand, string> = {
  CRITICAL: 'text-critical',
  HIGH: 'text-high',
  MEDIUM: 'text-medium',
  LOW: 'text-low',
}

export const BAND_STROKE: Record<SeverityBand, string> = {
  CRITICAL: 'var(--color-critical)',
  HIGH: 'var(--color-high)',
  MEDIUM: 'var(--color-medium)',
  LOW: 'var(--color-low)',
}

export function Tag({
  tone = 'neutral',
  children,
  title,
}: {
  tone?: 'neutral' | 'good' | 'bad' | 'warn' | 'accent'
  children: ReactNode
  title?: string
}) {
  const tones = {
    neutral: 'border-line bg-panel-2 text-muted',
    good: 'border-good/40 bg-good/10 text-good',
    bad: 'border-bad/40 bg-bad/10 text-bad',
    warn: 'border-warn/40 bg-warn/10 text-warn',
    accent: 'border-accent/40 bg-accent-soft text-accent',
  }
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium ${tones[tone]}`}
    >
      {children}
    </span>
  )
}

export function KeyValue({ pairs }: { pairs: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
      {pairs.map(([key, value], i) => (
        <div key={i} className="contents">
          <dt className="text-muted">{key}</dt>
          <dd className="font-mono text-fg break-all">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

/** Monospaced JSON, for raw ledger content and anything sample-derived. */
export function Raw({ value }: { value: unknown }) {
  return (
    <pre className="max-h-80 overflow-auto rounded bg-ink p-3 font-mono text-xs leading-relaxed text-muted">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

export function Bar({ fraction, color }: { fraction: number; color: string }) {
  const pct = Math.max(0, Math.min(1, fraction)) * 100
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-line-soft">
      <div
        className="h-full rounded-full transition-[width] duration-500"
        style={{ width: `${pct}%`, background: color }}
      />
    </div>
  )
}

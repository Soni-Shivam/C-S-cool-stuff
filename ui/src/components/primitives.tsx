/**
 * Shared display primitives and the card tier system.
 *
 * The deck this UI is themed after has three card tiers — violet gradient, lilac
 * wash, and white — layered over a dark indigo ground. They are used here with a
 * rule: the light tiers carry *summary* surfaces (a verdict, a headline number, a
 * conclusion) and the dark tiers carry *working* surfaces (code, tables, graphs,
 * logs). Reversing that would look like the slides and be unreadable at hour
 * three of a triage.
 *
 * `ArtefactGate` remains the important one. Every panel in this app renders
 * through it, so the 404/501 distinction the API makes reaches the screen intact:
 * a stage that has not run says so, and a feature that does not exist in this
 * build names the task that will build it. Neither is ever drawn as an empty
 * result, and neither is ever drawn as a zero.
 */

import type { CSSProperties, ReactNode } from 'react'
import type { Artefact } from '../api/client'
import type { AnalyserResult, SeverityBand } from '../api/types'
import { LogoSpinner } from './Logo'

/* ─── card tiers ─────────────────────────────────────────────────────────── */

/** The working surface: dark, bordered, wide radius. The default everywhere. */
export function Panel({
  title,
  subtitle,
  right,
  children,
  className = '',
  bodyClass = 'p-4',
  style,
}: {
  title?: ReactNode
  subtitle?: ReactNode
  right?: ReactNode
  children: ReactNode
  className?: string
  bodyClass?: string
  style?: CSSProperties
}) {
  return (
    <section
      className={`shadow-card overflow-hidden rounded-[var(--radius-card)] border border-line bg-ground-1/80 backdrop-blur-sm ${className}`}
      style={style}
    >
      {(title || right) && (
        <header className="flex items-start justify-between gap-3 border-b border-line-soft px-5 py-3.5">
          <div className="min-w-0">
            {title && (
              <h3 className="font-display truncate text-[15px] font-semibold tracking-tight text-fg">
                {title}
              </h3>
            )}
            {subtitle && <p className="mt-1 text-xs leading-relaxed text-muted">{subtitle}</p>}
          </div>
          {right && <div className="shrink-0">{right}</div>}
        </header>
      )}
      <div className={bodyClass}>{children}</div>
    </section>
  )
}

/** Tier 1 — the violet gradient card. For the single most important claim on a view. */
export function GradientCard({
  children,
  className = '',
  deep = false,
  style,
}: {
  children: ReactNode
  className?: string
  deep?: boolean
  style?: CSSProperties
}) {
  return (
    <section
      className={`shadow-lift relative overflow-hidden rounded-[var(--radius-card)] ${
        deep ? 'grad-violet-deep' : 'grad-violet'
      } text-white ${className}`}
      style={style}
    >
      {/* A soft specular sweep, matching the deck's card highlight. */}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-0"
        style={{
          background:
            'radial-gradient(28rem 18rem at 88% -12%, rgba(255,255,255,0.24), transparent 62%)',
        }}
      />
      <div className="relative">{children}</div>
    </section>
  )
}

/** Tier 2 — the lilac wash card. Dark text on a pale violet-to-white gradient. */
export function WashCard({
  children,
  className = '',
  style,
}: {
  children: ReactNode
  className?: string
  style?: CSSProperties
}) {
  return (
    <section
      className={`shadow-card grad-wash overflow-hidden rounded-[var(--radius-card)] text-ink ${className}`}
      style={style}
    >
      {children}
    </section>
  )
}

/** Tier 3 — the plain white card. */
export function WhiteCard({
  children,
  className = '',
  style,
}: {
  children: ReactNode
  className?: string
  style?: CSSProperties
}) {
  return (
    <section
      className={`shadow-card overflow-hidden rounded-[var(--radius-card)] bg-white text-ink ${className}`}
      style={style}
    >
      {children}
    </section>
  )
}

/** The `01`–`08` circle from the deck's contents slide. */
export function NumberBadge({
  n,
  active = false,
  size = 36,
}: {
  n: number
  active?: boolean
  size?: number
}) {
  return (
    <span
      className={`font-display inline-flex shrink-0 items-center justify-center rounded-full border font-semibold tabular-nums transition-all duration-300 ${
        active
          ? 'border-transparent bg-white text-ink shadow-[0_0_20px_-2px_rgba(192,132,252,0.9)]'
          : 'border-line-bright bg-ground-2 text-muted group-hover:border-v400 group-hover:text-v300'
      }`}
      style={{ width: size, height: size, fontSize: size * 0.34 }}
    >
      {String(n).padStart(2, '0')}
    </span>
  )
}

/** The deck's headline treatment: very large, very tight, small muted lede under it. */
export function SectionHead({
  eyebrow,
  title,
  lede,
  right,
}: {
  eyebrow?: string
  title: ReactNode
  lede?: ReactNode
  right?: ReactNode
}) {
  return (
    <div className="anim-rise flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
      <div className="min-w-0">
        {eyebrow && <div className="eyebrow mb-2">{eyebrow}</div>}
        <h2 className="display text-[clamp(1.9rem,3.4vw,2.9rem)] text-fg">{title}</h2>
        {lede && <p className="mt-2.5 max-w-2xl text-sm leading-relaxed text-muted">{lede}</p>}
      </div>
      {right && <div className="flex shrink-0 flex-wrap items-center gap-2">{right}</div>}
    </div>
  )
}

/** A headline number. `tone` picks the card tier, so importance and colour agree. */
export function StatTile({
  value,
  label,
  hint,
  tone = 'dark',
  className = '',
}: {
  value: ReactNode
  label: ReactNode
  hint?: ReactNode
  tone?: 'gradient' | 'wash' | 'white' | 'dark'
  className?: string
}) {
  const body = (
    <div className="px-5 py-4">
      <div className="display text-[clamp(1.6rem,2.6vw,2.3rem)] tabular-nums">{value}</div>
      <div
        className={`mt-1.5 text-[11px] font-medium tracking-[0.14em] uppercase ${
          tone === 'gradient' ? 'text-white/75' : tone === 'dark' ? 'text-dim' : 'text-ink-muted'
        }`}
      >
        {label}
      </div>
      {hint && (
        <div
          className={`mt-2 text-xs leading-relaxed ${
            tone === 'gradient' ? 'text-white/80' : tone === 'dark' ? 'text-muted' : 'text-ink-muted'
          }`}
        >
          {hint}
        </div>
      )}
    </div>
  )
  if (tone === 'gradient') return <GradientCard className={className}>{body}</GradientCard>
  if (tone === 'wash') return <WashCard className={className}>{body}</WashCard>
  if (tone === 'white') return <WhiteCard className={className}>{body}</WhiteCard>
  return (
    <div
      className={`shadow-card rounded-[var(--radius-tile)] border border-line bg-ground-1/80 ${className}`}
    >
      {body}
    </div>
  )
}

/* ─── states ─────────────────────────────────────────────────────────────── */

export function Empty({ children }: { children: ReactNode }) {
  return <p className="text-sm leading-relaxed text-muted italic">{children}</p>
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
    return (
      <div className="flex items-center justify-center py-8">
        <LogoSpinner size="md" label="Loading…" />
      </div>
    )
  }
  if (artefact.state === 'pending') {
    return (
      <div className="flex items-center gap-3 rounded-[var(--radius-tile)] border border-line bg-ground-2/70 px-4 py-3.5 text-sm text-muted">
        <LogoSpinner size="sm" />
        <span>
          Not produced yet — the pipeline is at{' '}
          <span className="font-mono text-v300">{artefact.stage}</span>.
        </span>
      </div>
    )
  }
  if (artefact.state === 'unavailable') {
    return (
      <div className="rounded-[var(--radius-tile)] border border-warn/30 bg-warn/[0.07] px-4 py-3.5 text-sm">
        <span className="font-medium text-warn">Not available in this build.</span>{' '}
        <span className="text-muted">
          {artefact.what} lands in <span className="font-mono text-fg">{artefact.task}</span>.
        </span>
      </div>
    )
  }
  if (artefact.state === 'error') {
    return (
      <div className="rounded-[var(--radius-tile)] border border-bad/40 bg-bad/[0.08] px-4 py-3.5 text-sm text-bad">
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
    <div className="mb-3 rounded-[var(--radius-tile)] border border-warn/30 bg-warn/[0.07] px-4 py-3 text-xs">
      <span className="font-semibold text-warn">
        {result.partial ? 'Partial result' : 'Completed with errors'}
      </span>
      <ul className="mt-1.5 space-y-1 text-muted">
        {result.errors.map((error, i) => (
          <li key={i} className="max-w-full font-mono break-all">
            {error}
          </li>
        ))}
      </ul>
    </div>
  )
}

/* ─── severity ───────────────────────────────────────────────────────────── */

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

export type Tone = 'neutral' | 'good' | 'bad' | 'warn' | 'accent' | 'solid'

const TONES: Record<Tone, string> = {
  neutral: 'border-line-bright bg-ground-2 text-muted',
  good: 'border-good/40 bg-good/10 text-good',
  bad: 'border-bad/45 bg-bad/10 text-bad',
  warn: 'border-warn/40 bg-warn/10 text-warn',
  accent: 'border-v500/45 bg-v500/15 text-v300',
  solid: 'border-transparent text-white [background-image:var(--grad-violet)]',
}

export function Tag({
  tone = 'neutral',
  children,
  title,
  className = '',
}: {
  tone?: Tone
  children: ReactNode
  title?: string
  className?: string
}) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-medium whitespace-nowrap ${TONES[tone]} ${className}`}
    >
      {children}
    </span>
  )
}

/**
 * `count(1, 'edge')` -> `1 edge`.
 *
 * Small, but these counts sit in the headline chips of every view, and "1 edges"
 * on a projector is the kind of thing a reviewer reads as carelessness about the
 * numbers underneath it.
 */
export function count(n: number, singular: string, many = `${singular}s`): string {
  return `${n} ${plural(n, singular, many)}`
}

/** Just the noun, agreeing with `n`. For a `StatTile`, whose value is separate. */
export function plural(n: number, singular: string, many = `${singular}s`): string {
  return n === 1 ? singular : many
}

export function KeyValue({ pairs }: { pairs: [string, ReactNode][] }) {
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-5 gap-y-2 text-sm">
      {pairs.map(([key, value], i) => (
        <div key={i} className="contents">
          <dt className="text-muted">{key}</dt>
          <dd className="font-mono break-all text-fg">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

/** Monospaced JSON, for raw ledger content and anything sample-derived. */
export function Raw({ value }: { value: unknown }) {
  return (
    <pre className="max-h-80 overflow-auto rounded-[var(--radius-tile)] border border-line-soft bg-ground p-3.5 font-mono text-xs leading-relaxed text-muted">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

export function Bar({
  fraction,
  color = 'var(--grad-violet)',
  height = 6,
}: {
  fraction: number
  color?: string
  height?: number
}) {
  const pct = Math.max(0, Math.min(1, fraction)) * 100
  const gradient = color.startsWith('linear-') || color.startsWith('radial-')
  return (
    <div
      className="w-full overflow-hidden rounded-full bg-ground-3"
      style={{ height }}
      role="presentation"
    >
      <div
        className="h-full rounded-full transition-[width] duration-700 ease-[var(--ease-out-soft)]"
        style={{
          width: `${pct}%`,
          ...(gradient ? { backgroundImage: color } : { background: color }),
        }}
      />
    </div>
  )
}

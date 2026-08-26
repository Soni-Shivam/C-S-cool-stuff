/**
 * The mark, the lockup, and the app's one and only loading indicator.
 *
 * Every wait in DRISHTI is drawn with the logo: an artefact that has not been
 * produced, a stage still running, the graph laying out, the report rendering.
 * That is a deliberate constraint rather than decoration — one shape means a
 * viewer three metres from a projector learns "violet eye floating = the system
 * is working" exactly once, and it reads the same at 16px in a table cell and at
 * 108px in an empty pane.
 */

import type { CSSProperties, ReactNode } from 'react'

const SIZES = { xs: 16, sm: 22, md: 44, lg: 108 } as const
export type LogoSize = keyof typeof SIZES

export function LogoMark({
  size = 'md',
  float = false,
  className = '',
  style,
}: {
  size?: LogoSize | number
  float?: boolean
  className?: string
  style?: CSSProperties
}) {
  const px = typeof size === 'number' ? size : SIZES[size]
  return (
    <img
      src="/logo.png"
      alt=""
      aria-hidden
      draggable={false}
      width={px}
      height={px}
      className={`${float ? 'anim-float' : ''} select-none ${className}`}
      style={{ width: px, height: px, ...style }}
    />
  )
}

/** Mark + wordmark, the deck's top-left lockup. */
export function LogoLockup({ version }: { version?: string | null }) {
  return (
    <div className="flex shrink-0 items-center gap-2.5">
      <span className="relative flex items-center justify-center">
        <span
          aria-hidden
          className="absolute inset-0 rounded-full blur-md"
          style={{ background: 'var(--grad-arc)', opacity: 0.55 }}
        />
        <LogoMark size={30} className="relative" />
      </span>
      <span className="flex min-w-0 flex-col leading-none">
        <span className="display text-[19px] tracking-[0.14em] text-fg">DRISHTI</span>
        <span className="mt-1 hidden text-[10px] tracking-[0.16em] text-dim uppercase sm:block">
          APK triage{version ? ` · v${version}` : ''}
        </span>
      </span>
    </div>
  )
}

/**
 * The loading state.
 *
 * `lg` and `md` get the full treatment — a breathing violet halo behind the
 * floating mark and a conic ring sweeping around it. `sm` and `xs` drop the ring,
 * because at 22px a rotating stroke reads as a rendering artefact rather than
 * as progress.
 */
export function LogoSpinner({
  size = 'md',
  label,
  className = '',
}: {
  size?: LogoSize
  label?: ReactNode
  className?: string
}) {
  const px = SIZES[size]
  const ring = size === 'md' || size === 'lg'
  const box = ring ? Math.round(px * 1.85) : px

  return (
    <div
      className={`flex items-center gap-3 ${size === 'lg' ? 'flex-col gap-4' : ''} ${className}`}
      role="status"
    >
      <span
        className="relative inline-flex shrink-0 items-center justify-center"
        style={{ width: box, height: box }}
      >
        <span
          aria-hidden
          className="anim-breathe absolute rounded-full blur-lg"
          style={{ inset: '8%', background: 'var(--grad-arc)' }}
        />
        {ring && (
          <span
            aria-hidden
            className="anim-sweep absolute inset-0 rounded-full"
            style={{
              background:
                'conic-gradient(from 0deg, rgba(192,132,252,0) 0deg, rgba(192,132,252,0) 190deg, #c084fc 320deg, #e23fd8 360deg)',
              WebkitMask: 'radial-gradient(farthest-side, transparent calc(100% - 2.5px), #000 0)',
              mask: 'radial-gradient(farthest-side, transparent calc(100% - 2.5px), #000 0)',
            }}
          />
        )}
        <LogoMark size={px} float className="relative" />
      </span>
      {label !== undefined && (
        <span
          className={
            size === 'lg'
              ? 'text-center text-sm text-muted'
              : 'text-sm text-muted'
          }
        >
          {label}
        </span>
      )}
    </div>
  )
}

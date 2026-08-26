/**
 * The opening animation: the eye opens, the room lights up, the shell arrives.
 *
 * It runs once per browser session, not once per mount — a tab refresh mid-demo
 * must not cost two seconds again — and any click or keypress skips it. Under
 * `prefers-reduced-motion` the CSS reset in index.css collapses every duration,
 * so the sequence resolves immediately and this component is effectively a
 * one-frame flash rather than something to sit through.
 *
 * Nothing behind it is blocked: `App` mounts the real shell underneath from the
 * first frame, so the API calls a run needs are already in flight while this
 * plays.
 */

import { useEffect, useRef, useState } from 'react'
import { LogoMark } from './Logo'

const SESSION_KEY = 'drishti.booted'
const HOLD_MS = 1850
const FADE_MS = 480

export function playedThisSession(): boolean {
  try {
    return window.sessionStorage.getItem(SESSION_KEY) === '1'
  } catch {
    // Private-mode storage denial must not cost the app its opening.
    return false
  }
}

export function BootSequence({ onDone }: { onDone: () => void }) {
  const [leaving, setLeaving] = useState(false)
  const finished = useRef(false)

  useEffect(() => {
    const finish = () => {
      if (finished.current) return
      finished.current = true
      try {
        window.sessionStorage.setItem(SESSION_KEY, '1')
      } catch {
        /* nothing to do; the sequence simply replays next session */
      }
      setLeaving(true)
      window.setTimeout(onDone, FADE_MS)
    }

    const hold = window.setTimeout(finish, HOLD_MS)
    window.addEventListener('pointerdown', finish)
    window.addEventListener('keydown', finish)
    return () => {
      window.clearTimeout(hold)
      window.removeEventListener('pointerdown', finish)
      window.removeEventListener('keydown', finish)
    }
  }, [onDone])

  return (
    <div
      className="fixed inset-0 z-[100] flex flex-col items-center justify-center bg-ground transition-opacity"
      style={{
        opacity: leaving ? 0 : 1,
        transitionDuration: `${FADE_MS}ms`,
        transitionTimingFunction: 'var(--ease-out-soft)',
      }}
      aria-hidden
    >
      {/* The bloom arrives with the iris rather than being there from frame one,
          so the screen genuinely goes from dark to lit. */}
      <div
        className="absolute inset-0"
        style={{
          background:
            'radial-gradient(38rem 38rem at 50% 46%, rgba(139,61,238,0.34), transparent 66%)',
          animation: 'drishti-iris 1.1s var(--ease-out-soft) 0.12s both',
        }}
      />

      <div className="relative flex flex-col items-center">
        <div className="relative flex h-40 w-40 items-center justify-center">
          {[0, 0.22, 0.44].map((delay) => (
            <span
              key={delay}
              className="absolute inset-0 rounded-full border"
              style={{
                borderColor: 'rgba(192,132,252,0.55)',
                animation: `drishti-ring-out 1.5s var(--ease-out-soft) ${0.35 + delay}s both`,
              }}
            />
          ))}
          <LogoMark
            size={132}
            style={{ animation: 'drishti-iris 0.95s var(--ease-out-soft) 0.1s both' }}
          />
        </div>

        <div
          className="display mt-7 text-[38px] text-fg sm:text-[52px]"
          style={{
            letterSpacing: '0.34em',
            textIndent: '0.34em',
            animation: 'drishti-rise 0.7s var(--ease-out-soft) 0.62s both',
          }}
        >
          DRISHTI
        </div>

        <div
          className="mt-4 flex items-center gap-3 text-[11px] tracking-[0.24em] text-muted uppercase"
          style={{ animation: 'drishti-rise 0.7s var(--ease-out-soft) 0.92s both' }}
        >
          <span className="h-px w-8" style={{ background: 'var(--grad-violet)' }} />
          Android malware triage
          <span className="h-px w-8" style={{ background: 'var(--grad-violet)' }} />
        </div>
      </div>

      <div
        className="absolute bottom-8 text-[10px] tracking-[0.2em] text-dim uppercase"
        style={{ animation: 'drishti-rise 0.6s var(--ease-out-soft) 1.35s both' }}
      >
        press any key to skip
      </div>
    </div>
  )
}

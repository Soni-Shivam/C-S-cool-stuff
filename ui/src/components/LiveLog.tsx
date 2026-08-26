/**
 * The always-visible live log.
 *
 * 00_GUIDING_MAP §9.7 / PHASE_6 T6.4: on stage this is what shows the frontier
 * reasoning in real time, so it is monospaced, readable at three metres, and
 * follows the tail unless the operator has scrolled up to read something — an
 * auto-scroll that fights the user is worse than none.
 */

import { useEffect, useRef, useState } from 'react'
import { useLogs } from '../hooks/useLogs'
import { LogoSpinner } from './Logo'

const LEVEL_CLASS: Record<string, string> = {
  error: 'text-bad',
  critical: 'text-bad',
  warning: 'text-warn',
  warn: 'text-warn',
  info: 'text-muted',
  debug: 'text-dim',
}

export function LiveLog() {
  const { lines, connected } = useLogs()
  const [follow, setFollow] = useState(true)
  const box = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight
  }, [lines, follow])

  return (
    <div className="glass flex h-32 shrink-0 flex-col border-t border-line sm:h-44">
      <div className="flex items-center gap-3 border-b border-line-soft px-5 py-2">
        <span className="eyebrow">Live log</span>
        <span
          className={`flex items-center gap-1.5 text-[11px] ${connected ? 'text-good' : 'text-dim'}`}
        >
          <span className={`h-1.5 w-1.5 rounded-full bg-current ${connected ? 'pulse' : ''}`} />
          {connected ? 'streaming' : 'disconnected'}
        </span>
        <span className="flex-1" />
        <label className="flex cursor-pointer items-center gap-1.5 text-[11px] text-muted">
          <input
            type="checkbox"
            checked={follow}
            onChange={(e) => setFollow(e.target.checked)}
            className="accent-[var(--color-accent)]"
          />
          follow tail
        </label>
      </div>
      <div
        ref={box}
        onWheel={(e) => {
          if (e.deltaY < 0) setFollow(false)
        }}
        className="flex-1 overflow-auto px-5 py-2.5 font-mono text-[12px] leading-relaxed"
      >
        {lines.length === 0 ? (
          <div className="flex items-center gap-3 py-2">
            <LogoSpinner size="xs" />
            <span className="text-dim italic">waiting for log output…</span>
          </div>
        ) : (
          lines.map((line) => (
            <div key={line.seq} className="whitespace-pre-wrap">
              {line.at && <span className="text-dim">{line.at.slice(11, 23)} </span>}
              <span className={LEVEL_CLASS[line.level ?? 'info'] ?? 'text-muted'}>{line.event}</span>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

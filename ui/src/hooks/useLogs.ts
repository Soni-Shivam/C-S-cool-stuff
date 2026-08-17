/**
 * The live log panel's feed. `GET /api/logs/stream`.
 *
 * Two things here are demo requirements, not preferences (PHASE_6 T6.4):
 *
 *  * **Throttled render (~150 ms).** structlog can emit faster than React can
 *    paint; re-rendering per line turns the log into a strobe on a projector.
 *    Lines are buffered and flushed on an interval instead.
 *  * **Bounded history.** An unbounded array is a memory leak on a long
 *    detonation, and nobody scrolls back 10,000 lines on stage.
 */

import { useEffect, useRef, useState } from 'react'

const FLUSH_MS = 150
const MAX_LINES = 500

export interface LogLine {
  seq: number
  at: string | null
  level: string | null
  event: string
  raw: string
}

/** structlog writes JSON. Fall back to the raw text rather than dropping a line. */
function parseLine(raw: string, seq: number): LogLine {
  try {
    const parsed = JSON.parse(raw) as Record<string, unknown>
    const { event, level, timestamp, ...rest } = parsed
    const extras = Object.entries(rest)
      .filter(([key]) => key !== 'logger')
      .map(([key, value]) => `${key}=${typeof value === 'string' ? value : JSON.stringify(value)}`)
      .join(' ')
    return {
      seq,
      at: typeof timestamp === 'string' ? timestamp : null,
      level: typeof level === 'string' ? level : null,
      event: [typeof event === 'string' ? event : raw, extras].filter(Boolean).join('  '),
      raw,
    }
  } catch {
    return { seq, at: null, level: null, event: raw, raw }
  }
}

export function useLogs(enabled = true): { lines: LogLine[]; connected: boolean } {
  const [lines, setLines] = useState<LogLine[]>([])
  const [connected, setConnected] = useState(false)
  const buffer = useRef<LogLine[]>([])
  const seq = useRef(0)

  useEffect(() => {
    if (!enabled) return
    const source = new EventSource('/api/logs/stream')

    source.addEventListener('log', (raw) => {
      buffer.current.push(parseLine((raw as MessageEvent).data, seq.current++))
    })
    source.onopen = () => setConnected(true)
    source.onerror = () => setConnected(false)

    const timer = window.setInterval(() => {
      if (buffer.current.length === 0) return
      const batch = buffer.current
      buffer.current = []
      setLines((prev) => [...prev, ...batch].slice(-MAX_LINES))
    }, FLUSH_MS)

    return () => {
      window.clearInterval(timer)
      source.close()
      setConnected(false)
    }
  }, [enabled])

  return { lines, connected }
}

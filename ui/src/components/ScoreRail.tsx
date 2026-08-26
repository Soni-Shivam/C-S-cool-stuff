/**
 * The left rail: score ring, band, confidence, and the factor breakdown.
 *
 * PHASE_0 T0.8: "the score ring animates when it changes from preliminary to
 * final (judges *see* the deep analysis land), and the factor breakdown is always
 * visible — it is the answer to 'how did you get 92?'".
 *
 * Two things this component refuses to do, both from CLAUDE.md:
 *  * It never computes S, C, or any contribution. Every number is rendered from
 *    `CompositeScore` exactly as the pure scorer emitted it. The formula lives in
 *    `m6_score/engine.py` and nowhere else — a second implementation here would be
 *    a second answer to "how did you get 92?".
 *  * `limitations` is displayed verbatim, not summarised. It is generated from
 *    real flags and is the honest half of the verdict.
 */

import { useEffect, useRef, useState } from 'react'
import { EvidenceChips } from './Evidence'
import { LogoSpinner } from './Logo'
import { BAND_CLASS, BAND_STROKE, Bar } from './primitives'
import { isUngrounded } from '../lib/grounding'
import type { CompositeScore, ScoreFactor } from '../api/types'

const RADIUS = 52
const CIRCUMFERENCE = 2 * Math.PI * RADIUS

function Ring({ score, flash }: { score: CompositeScore; flash: boolean }) {
  const offset = CIRCUMFERENCE * (1 - Math.max(0, Math.min(100, score.S)) / 100)
  return (
    <div className={`relative mx-auto h-36 w-36 ${flash ? 'pulse' : ''}`}>
      {/* A band-coloured bloom behind the ring, so the verdict reads as a light
          source at three metres rather than as a thin coloured line. */}
      <div
        aria-hidden
        className="absolute inset-4 rounded-full blur-2xl"
        style={{ background: BAND_STROKE[score.band], opacity: 0.28 }}
      />
      <svg viewBox="0 0 120 120" className="relative h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={RADIUS} fill="none" stroke="var(--color-ground-3)" strokeWidth="9" />
        <circle
          cx="60"
          cy="60"
          r={RADIUS}
          fill="none"
          stroke={BAND_STROKE[score.band]}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={CIRCUMFERENCE}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 900ms cubic-bezier(.22,1,.36,1), stroke 500ms' }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={`display text-[44px] tabular-nums ${BAND_CLASS[score.band]}`}>
          {score.S}
        </span>
        <span className="mt-1 text-[10px] tracking-[0.2em] text-dim">/ 100</span>
      </div>
    </div>
  )
}

function Factor({ factor }: { factor: ScoreFactor }) {
  // Max possible contribution for this term is its own weight, so the bar shows
  // "how much of this factor's budget was spent" rather than a share of 100.
  const fraction = factor.weight > 0 ? factor.contribution / factor.weight : 0
  // Paper §20.1: a term that contributed nothing because nothing fed it is labelled,
  // not left as a bare zero. The number itself is untouched — only its caption.
  const ungrounded = isUngrounded(factor)

  return (
    <li className="space-y-1">
      <div className="flex items-baseline justify-between gap-2">
        <span className="font-mono text-xs text-fg">{factor.symbol}</span>
        <span className="flex-1 truncate text-[11px] text-muted" title={factor.label}>
          {factor.label}
        </span>
        <span
          className={`font-mono text-xs tabular-nums ${ungrounded ? 'text-dim' : 'text-fg'}`}
        >
          {(factor.contribution * 100).toFixed(1)}
        </span>
      </div>
      <Bar fraction={fraction} />
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[10px] text-dim">
        <span className="font-mono">
          raw {factor.raw.toFixed(3)} × w {factor.weight}
        </span>
        {ungrounded ? (
          <span
            className="rounded border border-warn/40 bg-warn/10 px-1 py-px text-[10px] font-medium text-warn"
            title="Nothing fed this term. This zero means we never looked, not that we looked and found nothing."
          >
            ungrounded — not measured
          </span>
        ) : (
          <EvidenceChips refs={factor.evidence_refs} max={4} />
        )}
      </div>
    </li>
  )
}

export function ScoreRail({ score, isFinal }: { score: CompositeScore; isFinal: boolean }) {
  const [flash, setFlash] = useState(false)
  const previous = useRef<number | null>(null)

  useEffect(() => {
    const changed = previous.current !== null && previous.current !== score.S
    // Recorded on every pass, not only on the quiet one. When the update sat inside
    // the `else`, the ref froze at the score the ring first rendered with, so a
    // later return to that value read as "unchanged" and the ring stayed still
    // through a transition the audience was told to watch for.
    previous.current = score.S
    if (!changed) return
    setFlash(true)
    const timer = window.setTimeout(() => setFlash(false), 1600)
    return () => window.clearTimeout(timer)
  }, [score.S])

  return (
    <div className="space-y-5">
      <Ring score={score} flash={flash} />

      <div className="text-center">
        <div className={`display text-xl tracking-[0.18em] ${BAND_CLASS[score.band]}`}>
          {score.band}
        </div>
        <div className="mt-1.5 text-xs text-muted">
          confidence <span className="font-mono text-fg">{score.C.toFixed(2)}</span>
          <span className="mx-1.5 text-line-bright">·</span>γ{' '}
          <span className="font-mono text-fg">{score.gamma.toFixed(2)}</span>
        </div>
      </div>

      {isFinal ? (
        <div className="rounded-full border border-good/45 bg-good/10 px-3 py-1.5 text-center text-[11px] font-medium text-good">
          final verdict
        </div>
      ) : (
        <div className="grad-violet flex items-center justify-center gap-2 rounded-full px-3 py-1.5 text-center text-[11px] font-medium text-white shadow-[0_0_26px_-6px_rgba(168,85,247,0.9)]">
          <LogoSpinner size="xs" />
          preliminary — deep analysis running
        </div>
      )}

      {(score.override_applied || score.requires_human_review || score.anomaly_escalated) && (
        <div className="space-y-1.5 text-[11px]">
          {score.override_applied && (
            <div className="rounded-lg border border-bad/40 bg-bad/10 px-2.5 py-1.5 text-bad">
              override: <span className="font-mono">{score.override_applied}</span>
            </div>
          )}
          {score.anomaly_escalated && (
            <div className="rounded-lg border border-warn/40 bg-warn/10 px-2.5 py-1.5 text-warn">
              anomaly escalator raised the band
            </div>
          )}
          {score.requires_human_review && (
            <div className="rounded-lg border border-warn/40 bg-warn/10 px-2.5 py-1.5 text-warn">
              human review required
            </div>
          )}
        </div>
      )}

      <div>
        <h4 className="eyebrow mb-2.5">Factors</h4>
        <ul className="space-y-3">
          {score.factors.map((factor) => (
            <Factor key={factor.symbol} factor={factor} />
          ))}
        </ul>
      </div>

      {score.limitations.length > 0 && (
        <div>
          <h4 className="eyebrow mb-2">Limitations</h4>
          <ul className="space-y-1.5 text-[11px] leading-relaxed text-muted">
            {score.limitations.map((limitation, i) => (
              <li key={i} className="rounded-r-md border-l-2 border-warn/50 bg-warn/[0.06] py-1 pl-2.5">
                {limitation}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

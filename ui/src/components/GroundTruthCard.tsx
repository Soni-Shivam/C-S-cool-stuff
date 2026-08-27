/**
 * The verdict, next to the truth (contract A21).
 *
 * This is the only screen in the product that can say whether DRISHTI was *right*,
 * and it can say so only for the staged samples, whose nature was known before the
 * run. The job is matched to its catalogue entry by sha256 — the hash the pipeline
 * computed from the bytes it analysed, against the hash the catalogue computed from
 * the bytes on disk. Nothing is threaded through the job for this, so there is no
 * path by which the label could have reached the analysis.
 *
 * **Disagreement renders as disagreement.** A card that could only report success
 * would be worth nothing; the interesting run is the one where the band and the label
 * part company, and it is drawn in the same size and colour weight as agreement.
 *
 * **It is not a benchmark, and it says so.** Eight hand-picked samples do not measure
 * accuracy, and CLAUDE.md requires any metric on screen to trace to a measurement in
 * STATUS.md. So this reports one run at a time and never accumulates a score.
 */

import type { SampleEntry } from '../api/types'
import type { SeverityBand } from '../api/types'
import { groundTruth } from './SamplePicker'

/**
 * Whether a band and a corpus label tell the same story.
 *
 * The mapping is deliberately coarse and stated here rather than inferred: CRITICAL
 * and HIGH read as "this is malware", LOW reads as "this is not", and MEDIUM is
 * neither — an honest triage system is allowed to be undecided, and scoring that as a
 * miss would punish the calibration for being truthful. MEDIUM is exactly the band
 * whose meaning is "a human should look", so it is reported as its own outcome rather
 * than forced onto one side.
 */
export function agreement(
  band: SeverityBand,
  label: 0 | 1 | null,
): 'agreed' | 'disagreed' | 'inconclusive' | 'unlabelled' {
  if (label === null) return 'unlabelled'
  const flagged = band === 'CRITICAL' || band === 'HIGH'
  const cleared = band === 'LOW'
  if (!flagged && !cleared) return 'inconclusive'
  return flagged === (label === 1) ? 'agreed' : 'disagreed'
}

const VERDICT: Record<
  'agreed' | 'disagreed' | 'inconclusive' | 'unlabelled',
  { text: string; className: string }
> = {
  agreed: {
    text: 'agreed with ground truth',
    className: 'border-ok/40 bg-ok/10 text-ok',
  },
  disagreed: {
    text: 'DISAGREED with ground truth',
    className: 'border-bad/50 bg-bad/10 text-bad',
  },
  inconclusive: {
    text: 'landed mid-band — neither flagged nor cleared',
    className: 'border-warn/40 bg-warn/10 text-warn',
  },
  unlabelled: {
    text: 'no corpus label to compare against',
    className: 'border-line-bright bg-ground-2 text-muted',
  },
}

export function GroundTruthCard({
  sample,
  band,
  score,
}: {
  sample: SampleEntry
  band: SeverityBand
  score: number
}) {
  const truth = groundTruth(sample)
  const outcome = agreement(band, sample.label)
  const verdict = VERDICT[outcome]

  return (
    <section
      className={`overflow-hidden rounded-[var(--radius-card)] border ${verdict.className.split(' ')[0]} bg-ground-1/80`}
    >
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line-soft px-5 py-3">
        <div>
          <h3 className="font-display text-[15px] font-semibold tracking-tight text-fg">
            Checked against known ground truth
          </h3>
          <p className="mt-0.5 font-mono text-[11px] text-dim">{sample.package}</p>
        </div>
        <span
          className={`rounded-full border px-3 py-1 text-[11px] font-semibold ${verdict.className}`}
        >
          {verdict.text}
        </span>
      </div>

      <div className="grid gap-px bg-line-soft sm:grid-cols-2">
        <div className="bg-ground-1 px-5 py-3.5">
          <div className="text-[10px] tracking-widest text-dim uppercase">DRISHTI said</div>
          <div className="mt-1 text-lg font-semibold text-fg">
            {band} <span className="text-sm font-normal text-muted">· {score}/100</span>
          </div>
        </div>
        <div className="bg-ground-1 px-5 py-3.5">
          <div className="text-[10px] tracking-widest text-dim uppercase">Ground truth</div>
          <div className="mt-1 text-lg font-semibold text-fg">
            {truth.word} <span className="text-sm font-normal text-muted">· {truth.detail}</span>
          </div>
        </div>
      </div>

      <p className="border-t border-line-soft px-5 py-2.5 text-[11px] leading-relaxed text-muted">
        The label was never sent to the analysis — this run saw exactly what an upload of
        the same file would have seen. One sample is not a measurement: these are a
        handful of staged samples for checking behaviour, not a benchmark, and no
        accuracy figure is derived from them.
      </p>
    </section>
  )
}

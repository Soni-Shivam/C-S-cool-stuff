/**
 * The shared `Verdict`, rendered.
 *
 * This is the analyst portal's view of the one object every surface consumes —
 * `drishti/contracts/verdict.py`, contract addendum A15, served by
 * `GET /api/jobs/{id}/verdict`. The type it renders is generated from that pydantic
 * model (`ui/src/api/verdict.gen.ts`), so this component cannot drift from the phone
 * screen's view of the same sample without a red contract test.
 *
 * Nothing here computes. No band, no score, no provenance, no action — every value is
 * displayed exactly as `build_verdict()` projected it. The dashboard consumes verdicts;
 * it does not produce them.
 *
 * Three honesty rules shape the layout rather than decorate it:
 *
 *  1. **Confidence sits beside the score, always.** Not in a tooltip, not below the
 *     fold. A high score with low confidence must read as exactly that, so when the two
 *     disagree the panel says so in a sentence instead of leaving the reader to notice.
 *  2. **The provenance badge is the second thing on the card.** `STATIC_ONLY` is drawn
 *     in red as NO TRACE, because a score computed without ever executing the sample is
 *     a different kind of claim from one that watched it run.
 *  3. **A field the pipeline could not populate says so.** "not determined" and
 *     "none found" are different strings and are never collapsed.
 */

import { EvidenceChips } from './Evidence'
import { VerdictProvenanceBadge } from './ProvenanceBadge'
import { BAND_CLASS, Bar, Tag } from './primitives'
import type { Verdict } from '../api/verdict.gen'

const ACTION_COPY: Record<Verdict['recommended_action'], { tone: string; blurb: string }> = {
  BLOCK: {
    tone: 'border-critical/50 bg-critical/10 text-critical',
    blurb: 'Tell the user not to install it.',
  },
  REVIEW: {
    tone: 'border-medium/50 bg-medium/10 text-medium',
    blurb: 'Safety could not be confirmed either way. A human decides.',
  },
  MONITOR: {
    tone: 'border-low/50 bg-low/10 text-low',
    blurb: 'Nothing actionable found. Not the same as proven clean.',
  },
}

/** A value the pipeline may not have produced. Absence is stated, never blanked. */
function Field({
  label,
  value,
  absent,
}: {
  label: string
  value: string | null
  absent: string
}) {
  return (
    <div>
      <div className="eyebrow">{label}</div>
      {value ? (
        <div className="mt-0.5 text-sm text-fg">{value}</div>
      ) : (
        <div className="mt-0.5 text-sm text-muted italic" title="The pipeline produced no value for this field">
          {absent}
        </div>
      )}
    </div>
  )
}

export function VerdictHeadline({ verdict }: { verdict: Verdict }) {
  const action = ACTION_COPY[verdict.recommended_action]
  // The one comparison this component makes, and it is a display decision, not a
  // scoring one: when a loud score rests on thin evidence, say so in words. Both
  // numbers are the scorer's own (S and C); nothing is recomputed.
  const loudButThin = verdict.threat_score >= 40 && verdict.confidence < 0.5

  return (
    <div className="shadow-lift relative overflow-hidden rounded-[var(--radius-card)] border border-line bg-ground-1/85 p-6 backdrop-blur-sm sm:p-7">
      {/* A violet wash across the top edge, so the card reads as the primary
          surface of the view without tinting the colour-coded values inside it. */}
      <span
        aria-hidden
        className="pointer-events-none absolute inset-x-0 top-0 h-32"
        style={{
          background:
            'radial-gradient(36rem 10rem at 22% -40%, rgba(139,61,238,0.36), transparent 70%)',
        }}
      />
      <div className="relative flex flex-wrap items-start gap-x-8 gap-y-5">
        {/* score + confidence, side by side, one never without the other */}
        <div className="flex items-end gap-5">
          <div>
            <div className="eyebrow">Threat score</div>
            <div className="flex items-baseline gap-2">
              <span className={`display text-[clamp(3rem,5vw,4.2rem)] tabular-nums ${BAND_CLASS[verdict.severity_band]}`}>
                {verdict.threat_score}
              </span>
              <span className={`display text-xl tracking-[0.18em] ${BAND_CLASS[verdict.severity_band]}`}>
                {verdict.severity_band}
              </span>
            </div>
          </div>

          <div className="min-w-[9rem] pb-2">
            <div className="eyebrow">Confidence</div>
            <div className="font-mono text-2xl tabular-nums text-fg">
              {verdict.confidence.toFixed(2)}
            </div>
            <div className="mt-1.5">
              <Bar
                fraction={verdict.confidence}
                color={verdict.confidence < 0.5 ? 'var(--color-warn)' : 'var(--color-accent-strong)'}
              />
            </div>
          </div>
        </div>

        <div className="space-y-2">
          <VerdictProvenanceBadge provenance={verdict.provenance} />
          <div className={`inline-flex flex-col rounded-xl border px-3.5 py-2 ${action.tone}`}>
            <span className="text-sm font-semibold tracking-wide">
              {verdict.recommended_action}
            </span>
            <span className="text-[11px] opacity-80">{action.blurb}</span>
          </div>
        </div>
      </div>

      {loudButThin && (
        <p className="mt-5 rounded-[var(--radius-tile)] border border-warn/40 bg-warn/[0.07] px-4 py-3 text-sm leading-relaxed text-warn">
          <strong>{verdict.severity_band}</strong> at confidence{' '}
          <strong>{verdict.confidence.toFixed(2)}</strong> — an actionable band resting on thin
          evidence. Treat it as a lead to investigate, not a finding to act on.
        </p>
      )}

      <p className="mt-6 border-l-2 border-v500 pl-4 text-[clamp(1rem,1.5vw,1.2rem)] leading-relaxed text-fg">
        {verdict.consumer_summary}
      </p>
      <p className="mt-1 pl-3 text-[11px] text-dim">
        The plain-language sentence the phone shows its user. Templated from grounded
        findings in Python — not written by a model.
      </p>

      <div className="mt-5 grid gap-4 border-t border-line-soft pt-4 sm:grid-cols-2 lg:grid-cols-4">
        <Field
          label="Impersonates"
          value={verdict.impersonated_target}
          absent="no brand identified"
        />
        <Field
          label="Victim language"
          value={verdict.victim_profile.language}
          absent="not determined"
        />
        <Field label="Tactic" value={verdict.victim_profile.tactic} absent="not determined" />
        <Field label="Segment" value={verdict.victim_profile.segment} absent="not determined" />
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <div>
          <div className="eyebrow">Behaviours detected</div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {verdict.behaviors_detected.length === 0 ? (
              <span className="text-sm text-muted italic">
                no behaviour asserted by the model
              </span>
            ) : (
              verdict.behaviors_detected.map((name) => (
                <Tag key={name} tone="bad">
                  {name.replace(/_/g, ' ')}
                </Tag>
              ))
            )}
          </div>
        </div>
        <div>
          <div className="eyebrow">ATT&amp;CK techniques</div>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {verdict.attack_techniques.length === 0 ? (
              <span className="text-sm text-muted italic">none mapped</span>
            ) : (
              verdict.attack_techniques.map((id) => (
                <Tag key={id} tone="accent">
                  {id}
                </Tag>
              ))
            )}
          </div>
        </div>
      </div>

      <div className="mt-4 border-t border-line-soft pt-3">
        <div className="eyebrow mb-2">
          Evidence behind this verdict
        </div>
        <EvidenceChips refs={verdict.evidence_refs} max={8} />
      </div>

      {verdict.limitations.length > 0 && (
        <div className="mt-5 rounded-[var(--radius-tile)] border border-warn/25 bg-warn/[0.07] px-4 py-3">
          <div className="eyebrow text-warn">
            What this analysis could not do
          </div>
          <ul className="mt-1.5 space-y-1 text-xs text-muted">
            {verdict.limitations.map((limitation, i) => (
              <li key={i} className="border-l-2 border-warn/40 pl-2">
                {limitation}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

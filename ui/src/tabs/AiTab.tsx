/**
 * AI: grounded claims, rejected-claim badge, MITRE grid, victim profile, ML.
 *
 * The rejected-claim count is the headline number on this tab, not a footnote.
 * CLAUDE.md rule 5: "`ledger.append()` rejects an AI_CLAIM with empty or
 * unresolvable `evidence_refs`. Don't work around it — that rejection is the
 * product." A tab that showed only surviving claims would hide the mechanism that
 * makes the surviving ones worth anything.
 *
 * The claim text itself is model output about sample-derived content, so it is
 * rendered as text by React (escaped by construction) and never as markup.
 */

import type { Artefact } from '../api/client'
import { EvidenceChips } from '../components/Evidence'
import { ArtefactGate, DegradedNotice, Empty, Panel, Tag } from '../components/primitives'
import type { GenAIVerdict, MLPrediction, VerifierStatus } from '../api/types'

const VERIFIER_TONE: Record<VerifierStatus, 'good' | 'bad' | 'warn'> = {
  pass: 'good',
  rejected: 'bad',
  unverified: 'warn',
}

export function AiTab({
  genai,
  ml,
}: {
  genai: Artefact<GenAIVerdict> | null
  ml: Artefact<MLPrediction> | null
}) {
  return (
    <div className="space-y-4">
      <ArtefactGate artefact={genai}>
        {(verdict) => {
          const rejected = verdict.claims.filter((c) => c.verifier_status === 'rejected').length
          const unverified = verdict.claims.filter((c) => c.verifier_status === 'unverified').length
          return (
            <div className="space-y-4">
              <DegradedNotice result={verdict} />

              <Panel
                title="Summary"
                right={
                  <div className="flex flex-wrap items-center gap-2">
                    <Tag tone={rejected > 0 ? 'bad' : 'good'}>{rejected} rejected</Tag>
                    {unverified > 0 && <Tag tone="warn">{unverified} unverified</Tag>}
                    <Tag>{verdict.llm_calls} LLM calls</Tag>
                    <Tag tone={verdict.provider === 'mock' ? 'warn' : 'neutral'}>
                      provider: {verdict.provider}
                    </Tag>
                  </div>
                }
              >
                <p className="text-base leading-relaxed text-fg">
                  {verdict.summary || <Empty>The model returned no summary.</Empty>}
                </p>
                {verdict.provider === 'mock' && (
                  <p className="mt-2 text-xs text-warn">
                    The mock provider produced this. No model was called; nothing here is a model inference.
                  </p>
                )}
              </Panel>

              <Panel
                title={`Grounded claims (${verdict.claims.length})`}
                subtitle="Every claim cites the ledger nodes it rests on — click a chip to open the node"
              >
                {verdict.claims.length === 0 ? (
                  <Empty>No claims were emitted.</Empty>
                ) : (
                  <ul className="space-y-2.5">
                    {verdict.claims.map((claim, i) => (
                      <li
                        key={i}
                        className={`rounded border p-2.5 ${
                          claim.verifier_status === 'rejected'
                            ? 'border-bad/40 bg-bad/5'
                            : 'border-line-soft bg-panel-2'
                        }`}
                      >
                        <div className="flex items-start gap-2">
                          <Tag tone={VERIFIER_TONE[claim.verifier_status]}>{claim.verifier_status}</Tag>
                          <span className="text-[11px] text-muted">{claim.agent}</span>
                        </div>
                        <p
                          className={`mt-1.5 text-sm ${
                            claim.verifier_status === 'rejected' ? 'text-muted line-through' : 'text-fg'
                          }`}
                        >
                          {claim.text}
                        </p>
                        <div className="mt-1.5">
                          <EvidenceChips refs={claim.evidence_refs} label="evidence:" />
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>

              <div className="grid gap-4 xl:grid-cols-2">
                <Panel title={`MITRE ATT&CK for Mobile (${verdict.techniques.length})`}>
                  {verdict.techniques.length === 0 ? (
                    <Empty>No technique mapped.</Empty>
                  ) : (
                    <div className="grid gap-2 sm:grid-cols-2">
                      {verdict.techniques.map((technique) => (
                        <div
                          key={technique.technique_id}
                          className="rounded border border-line-soft bg-panel-2 p-2"
                        >
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs text-accent">{technique.technique_id}</span>
                            <Tag>{technique.layer}</Tag>
                          </div>
                          <div className="mt-0.5 text-sm text-fg">{technique.name}</div>
                          <div className="text-[11px] text-muted">{technique.tactic}</div>
                          <div className="mt-1">
                            <EvidenceChips refs={technique.evidence_refs} />
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </Panel>

                <Panel title="Victim profile & impersonation">
                  {verdict.victim ? (
                    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
                      {(
                        [
                          ['impersonates', verdict.victim.impersonated_target ?? '—'],
                          ['language', verdict.victim.language ?? '—'],
                          ['tactic', verdict.victim.tactic ?? '—'],
                          ['segment', verdict.victim.segment ?? '—'],
                          ['confidence', verdict.victim.confidence.toFixed(2)],
                        ] as [string, string][]
                      ).map(([key, text]) => (
                        <div key={key} className="contents">
                          <dt className="text-muted">{key}</dt>
                          <dd className="text-fg">{text}</dd>
                        </div>
                      ))}
                    </dl>
                  ) : (
                    <Empty>No victim profile — the Social-Engineering Analyst agent lands in T3.8.</Empty>
                  )}

                  <div className="mt-3 border-t border-line-soft pt-3">
                    {verdict.impersonation ? (
                      <div className="text-sm">
                        <div className="flex items-center gap-2">
                          <Tag tone={verdict.impersonation.similarity >= verdict.impersonation.threshold ? 'bad' : 'neutral'}>
                            {verdict.impersonation.method}
                          </Tag>
                          <span className="font-mono text-xs text-fg">
                            similarity {verdict.impersonation.similarity.toFixed(3)} / threshold{' '}
                            {verdict.impersonation.threshold.toFixed(3)}
                          </span>
                        </div>
                        <div className="mt-1 text-muted">
                          brand: {verdict.impersonation.matched_brand ?? 'no match'}
                        </div>
                      </div>
                    ) : (
                      <Empty>No vision impersonation check — the VLM sub-agent lands in T3.9.</Empty>
                    )}
                  </div>
                </Panel>
              </div>
            </div>
          )
        }}
      </ArtefactGate>

      <Panel
        title="ML prediction"
        subtitle="P_cal feeds F_AI. An uncalibrated probability would break the noisy-OR fusion."
      >
        <ArtefactGate artefact={ml}>
          {(prediction) => (
            <div className="space-y-3">
              <DegradedNotice result={prediction} />
              <div className="flex flex-wrap items-center gap-2">
                <Tag tone="accent">P_cal {prediction.p_calibrated.toFixed(3)}</Tag>
                <Tag>raw {prediction.p_malicious_raw.toFixed(3)}</Tag>
                <Tag tone={prediction.anomaly_escalate ? 'bad' : 'neutral'}>
                  anomaly {prediction.anomaly_score.toFixed(3)}
                  {prediction.anomaly_escalate && ' — escalated'}
                </Tag>
                <Tag tone={prediction.model_version === 'stub' ? 'warn' : 'neutral'}>
                  model {prediction.model_version}
                </Tag>
                <Tag tone={prediction.feature_schema_version === 'stub' ? 'warn' : 'neutral'}>
                  features {prediction.feature_schema_version}
                </Tag>
              </div>

              {Object.keys(prediction.labels).length > 0 && (
                <div>
                  <h4 className="mb-1 text-[11px] tracking-widest text-muted">
                    MULTI-LABEL (independent sigmoids)
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(prediction.labels).map(([label, probability]) => (
                      <Tag key={label}>
                        {label} {probability.toFixed(2)}
                      </Tag>
                    ))}
                  </div>
                </div>
              )}

              {prediction.top_features.length > 0 ? (
                <div>
                  <h4 className="mb-1 text-[11px] tracking-widest text-muted">TOP SHAP CONTRIBUTIONS</h4>
                  <ul className="space-y-1">
                    {prediction.top_features.map((feature) => (
                      <li key={feature.feature} className="flex items-center gap-2 text-xs">
                        <span className={feature.direction === '+' ? 'text-bad' : 'text-good'}>
                          {feature.direction}
                        </span>
                        <span className="flex-1 font-mono break-all text-fg">{feature.feature}</span>
                        <span className="font-mono text-muted">
                          v {feature.value} · shap {feature.shap.toFixed(4)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <Empty>No SHAP attributions — explanations land in T2.6.</Empty>
              )}

              <EvidenceChips refs={prediction.ledger_refs} label="ledger:" />
            </div>
          )}
        </ArtefactGate>
      </Panel>
    </div>
  )
}

/**
 * Overview: the verdict sentence, behaviour chips, top findings, proposed actions.
 *
 * The confirm buttons are the human-in-the-loop gate. `POST .../confirm` writes an
 * ANALYST_ACTION ledger node and returns the action marked confirmed — it does NOT
 * execute anything, and the button copy says so, because "DRISHTI is decision
 * support, not autonomous enforcement" (paper §11) is a claim the UI can quietly
 * break by looking like a Block button.
 */

import { useState } from 'react'
import { confirmAction } from '../api/client'
import type { Artefact } from '../api/client'
import { EvidenceChips } from '../components/Evidence'
import { ProvenanceBadge } from '../components/ProvenanceBadge'
import {
  ArtefactGate,
  Empty,
  GradientCard,
  KeyValue,
  Panel,
  SectionHead,
  Tag,
} from '../components/primitives'
import type {
  CompositeScore,
  DynamicTrace,
  FileMeta,
  GenAIVerdict,
  ProposedAction,
} from '../api/types'

function ActionRow({ jobId, action }: { jobId: string; action: ProposedAction }) {
  const [confirmed, setConfirmed] = useState<ProposedAction | null>(
    action.confirmed_by ? action : null,
  )
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const confirm = async () => {
    const analyst = window.prompt('Confirm as (analyst name) — recorded in the ledger:')
    if (!analyst?.trim()) return
    setBusy(true)
    setError(null)
    try {
      setConfirmed(await confirmAction(jobId, action.action, analyst.trim()))
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : String(exc))
    } finally {
      setBusy(false)
    }
  }

  return (
    <li className="flex flex-wrap items-start gap-3 border-b border-line-soft py-3 last:border-0">
      <div className="flex-1">
        <div className="font-mono text-sm text-v300">{action.action}</div>
        <div className="mt-0.5 text-xs leading-relaxed text-muted">{action.rationale}</div>
        {error && <div className="mt-1 text-xs text-bad">{error}</div>}
      </div>
      {confirmed?.confirmed_by ? (
        <Tag tone="good" title={`Recorded at ${confirmed.confirmed_at ?? 'unknown time'}`}>
          confirmed by {confirmed.confirmed_by}
        </Tag>
      ) : (
        <button
          type="button"
          onClick={() => void confirm()}
          disabled={busy}
          title="Records a human confirmation in the ledger. Nothing is executed."
          className="shrink-0 rounded-full border border-v500/50 bg-v500/15 px-3 py-1.5 text-[11px] text-v300 transition-colors hover:border-v400 hover:bg-v500/25 disabled:opacity-50"
        >
          {busy ? 'recording…' : 'confirm (records only)'}
        </button>
      )}
    </li>
  )
}

export function OverviewTab({
  jobId,
  score,
  genai,
  ingest,
  dynamic,
}: {
  jobId: string
  score: Artefact<CompositeScore> | null
  genai: Artefact<GenAIVerdict> | null
  ingest: Artefact<FileMeta> | null
  dynamic: Artefact<DynamicTrace> | null
}) {
  return (
    <div className="space-y-5">
      <SectionHead
        eyebrow="Investigation"
        title="Verdict"
        lede="The sentence below is the scorer's own explanation, rendered verbatim. Every number behind it is traceable to a ledger node through the chips."
      />

      <ArtefactGate artefact={score}>
        {(value) => (
          <GradientCard>
            <div className="px-6 py-6 sm:px-8 sm:py-7">
              <p className="text-[clamp(1rem,1.6vw,1.28rem)] leading-relaxed font-medium text-white">
                {value.explanation || 'The scorer produced no explanation for this run.'}
              </p>
              {/* Provenance and evidence chips sit on a dark inset rather than
                  straight on the gradient: their colours are load-bearing (green
                  means live, red means synthetic) and those readings only hold
                  against the dark ground they were chosen for. */}
              <div className="mt-5 flex flex-wrap items-center gap-2 rounded-[16px] bg-ground/70 px-4 py-3">
                {dynamic?.state === 'ready' && <ProvenanceBadge trace={dynamic.value} />}
                <EvidenceChips refs={value.ledger_refs} label="score nodes:" />
              </div>
            </div>
          </GradientCard>
        )}
      </ArtefactGate>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Sample">
          <ArtefactGate artefact={ingest}>
            {(meta) => (
              <div className="space-y-4">
                <KeyValue
                  pairs={[
                    ['sha256', meta.sha256],
                    ['package', meta.package ?? '—'],
                    ['label', meta.app_label ?? '—'],
                    ['version', `${meta.version_name ?? '—'} (${meta.version_code ?? '—'})`],
                    ['sdk', `min ${meta.min_sdk ?? '—'} / target ${meta.target_sdk ?? '—'}`],
                    ['size', `${meta.size_bytes.toLocaleString()} bytes`],
                  ]}
                />
                <div className="flex flex-wrap gap-2">
                  {meta.is_split && (
                    <Tag tone="warn">split APK ({meta.split_names.length} parts)</Tag>
                  )}
                  {meta.dedupe_hit && <Tag>seen before</Tag>}
                  {meta.intel?.known_bad_hash && <Tag tone="bad">known-bad hash</Tag>}
                  {meta.intel && meta.intel.source !== 'none' && (
                    <Tag title={`verdict: ${meta.intel.verdict}`}>intel: {meta.intel.source}</Tag>
                  )}
                  {meta.intel?.label_derived && (
                    <Tag
                      tone="warn"
                      title="Label-derived reputation must not feed R — evaluation would be circular"
                    >
                      label-derived
                    </Tag>
                  )}
                </div>
              </div>
            )}
          </ArtefactGate>
        </Panel>

        <Panel
          title="Behaviours"
          subtitle="Enumerated by the model; B is computed from a weight table in Python"
        >
          <ArtefactGate artefact={genai}>
            {(verdict) => {
              const positive = Object.entries(verdict.behaviours).filter(([, on]) => on)
              return (
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-1.5">
                    {positive.length === 0 ? (
                      <Empty>No behaviour flags set.</Empty>
                    ) : (
                      positive.map(([name]) => (
                        <Tag key={name} tone="bad">
                          {name}
                        </Tag>
                      ))
                    )}
                  </div>
                  <div className="text-xs leading-relaxed text-muted">
                    B ={' '}
                    <span className="font-mono text-fg">
                      {verdict.behavioural_risk_B.toFixed(3)}
                    </span>
                    {verdict.B_rationale && <span className="ml-2">{verdict.B_rationale}</span>}
                  </div>
                  {verdict.disagreement_flag && (
                    <div className="rounded-[var(--radius-tile)] border border-warn/40 bg-warn/10 px-3 py-2 text-xs leading-relaxed text-warn">
                      Detector disagreement: {verdict.disagreement_note ?? 'flagged, no note'} — this
                      lowers C and never silently alters S.
                    </div>
                  )}
                </div>
              )
            }}
          </ArtefactGate>
        </Panel>
      </div>

      <Panel
        title="Proposed actions"
        subtitle="Recommendations only — confirming records an ANALYST_ACTION node, it executes nothing"
      >
        <ArtefactGate artefact={score}>
          {(value) =>
            value.actions_proposed.length === 0 ? (
              <Empty>No actions proposed.</Empty>
            ) : (
              <ul>
                {value.actions_proposed.map((action) => (
                  <ActionRow key={action.action} jobId={jobId} action={action} />
                ))}
              </ul>
            )
          }
        </ArtefactGate>
      </Panel>
    </div>
  )
}

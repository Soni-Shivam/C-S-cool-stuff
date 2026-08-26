/**
 * Overview: the shared `Verdict`, then the sample, behaviours and proposed actions.
 *
 * The card at the top is `GET /api/jobs/{id}/verdict` — the one object the consumer
 * phone screen, this portal and the demo scripts all read (contract A15). Rendering it
 * here rather than assembling an equivalent view out of `score` + `genai` + `dynamic`
 * is the point: if the analyst and the victim are ever shown different verdicts for the
 * same APK, it will be because someone built a second projection, so this tab does not
 * have one.
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
import { VerdictHeadline } from '../components/VerdictHeadline'
import {
  ArtefactGate,
  Empty,
  KeyValue,
  Panel,
  SectionHead,
  Tag,
  WashCard,
} from '../components/primitives'
import type {
  CompositeScore,
  FileMeta,
  GenAIVerdict,
  ProposedAction,
  StaticReport,
} from '../api/types'
import type { Verdict } from '../api/verdict.gen'

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
  verdict,
  score,
  genai,
  ingest,
  staticReport,
}: {
  jobId: string
  verdict: Artefact<Verdict> | null
  score: Artefact<CompositeScore> | null
  genai: Artefact<GenAIVerdict> | null
  ingest: Artefact<FileMeta> | null
  staticReport: Artefact<StaticReport> | null
}) {
  // One line, on the tab everyone actually looks at. The full A13 breakdown lives on
  // the Static tab; this is the sentence that stops a reader concluding "it flagged
  // an app for reading SMS" before they get there.
  const lookalike =
    staticReport?.state === 'ready' ? staticReport.value.lookalike : null

  return (
    <div className="space-y-5">
      <SectionHead
        eyebrow="Investigation"
        title="Verdict"
        lede="This is GET /api/jobs/{id}/verdict — the one projection the consumer phone screen, this portal and the demo scripts all read. Rendering it here rather than assembling an equivalent out of score + genai + dynamic is the point: two surfaces can only disagree about a sample if someone builds a second projection."
      />

      <ArtefactGate artefact={verdict}>{(value) => <VerdictHeadline verdict={value} />}</ArtefactGate>

      {/* Directly under the verdict, before any table. Several of the rules behind
          a permission finding fire on apps nobody would call malicious, and a
          reader who meets the detail first has already drawn a conclusion. */}
      {lookalike && lookalike.shared_permissions.length > 0 && (
        <WashCard>
          <div className="px-6 py-5">
            <h3 className="font-display text-lg font-semibold tracking-tight">
              Shared with apps you trust
            </h3>
            <p className="mt-2 text-sm leading-relaxed text-ink-muted">
              This sample holds{' '}
              <span className="font-semibold text-ink">{lookalike.shared_permissions.length}</span>{' '}
              dual-use permission{lookalike.shared_permissions.length === 1 ? '' : 's'} that
              caller-ID, SMS-backup and anti-spam apps hold too — Truecaller reads your SMS as
              well. The permission set is not the finding.
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-1.5">
              {lookalike.shared_permissions.map((permission) => (
                <span
                  key={permission}
                  title={permission}
                  className="rounded-md bg-ground/10 px-2 py-0.5 font-mono text-[10px] text-ink-muted"
                >
                  {permission.split('.').pop()}
                </span>
              ))}
              <span
                className={`rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${
                  lookalike.verdict === 'trojan_shape'
                    ? 'border-bad/50 bg-bad/10 text-bad'
                    : 'border-ink/20 bg-ground/5 text-ink-muted'
                }`}
              >
                {lookalike.verdict.replace(/_/g, ' ')} · trojan-shape{' '}
                {lookalike.trojan_score.toFixed(2)}
              </span>
            </div>
            <p className="mt-3 text-xs text-ink-muted">
              Open <span className="font-medium text-ink">04 Static</span> for the signal-by-signal
              breakdown of what does, and does not, separate it from them.
            </p>
          </div>
        </WashCard>
      )}

      <Panel
        title="How the scorer explained it"
        subtitle="CompositeScore.explanation — the analyst-facing wording behind the verdict above"
      >
        <ArtefactGate artefact={score}>
          {(value) => (
            <div className="space-y-3">
              <p className="text-base leading-relaxed text-fg">
                {value.explanation || (
                  <Empty>The scorer produced no explanation for this run.</Empty>
                )}
              </p>
              <div className="flex flex-wrap items-center gap-2">
                <EvidenceChips refs={value.ledger_refs} label="score nodes:" />
              </div>
            </div>
          )}
        </ArtefactGate>
      </Panel>

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
          {/* `ai` rather than `verdict`: the outer prop of that name is the shared
              A15 projection, and shadowing it here reads as if the two were the
              same object. They are not. */}
          <ArtefactGate artefact={genai}>
            {(ai) => {
              const positive = Object.entries(ai.behaviours).filter(([, on]) => on)
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
                    B = <span className="font-mono text-fg">{ai.behavioural_risk_B.toFixed(3)}</span>
                    {ai.B_rationale && <span className="ml-2">{ai.B_rationale}</span>}
                  </div>
                  {ai.disagreement_flag && (
                    <div className="rounded-[var(--radius-tile)] border border-warn/40 bg-warn/10 px-3 py-2 text-xs leading-relaxed text-warn">
                      Detector disagreement: {ai.disagreement_note ?? 'flagged, no note'} — this
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

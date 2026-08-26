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
import { ArtefactGate, Empty, Panel, Tag } from '../components/primitives'
import type {
  CompositeScore,
  DynamicTrace,
  FileMeta,
  GenAIVerdict,
  ProposedAction,
  StaticReport,
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
    <li className="flex items-start gap-3 border-b border-line-soft py-2 last:border-0">
      <div className="flex-1">
        <div className="font-mono text-sm text-fg">{action.action}</div>
        <div className="text-xs text-muted">{action.rationale}</div>
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
          className="rounded border border-accent/50 bg-accent-soft px-2 py-1 text-[11px] text-accent hover:bg-accent/20 disabled:opacity-50"
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
  staticReport,
}: {
  jobId: string
  score: Artefact<CompositeScore> | null
  genai: Artefact<GenAIVerdict> | null
  ingest: Artefact<FileMeta> | null
  dynamic: Artefact<DynamicTrace> | null
  staticReport: Artefact<StaticReport> | null
}) {
  // One line, on the tab everyone actually looks at. The full A13 breakdown lives on
  // the Static tab; this is the sentence that stops a reader concluding "it flagged
  // an app for reading SMS" before they get there.
  const lookalike =
    staticReport?.state === 'ready' ? staticReport.value.lookalike : null
  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Panel title="Verdict" className="xl:col-span-2">
        <ArtefactGate artefact={score}>
          {(value) => (
            <div className="space-y-3">
              <p className="text-base leading-relaxed text-fg">
                {value.explanation || <Empty>The scorer produced no explanation for this run.</Empty>}
              </p>
              <div className="flex flex-wrap items-center gap-2">
                {dynamic?.state === 'ready' && <ProvenanceBadge trace={dynamic.value} />}
                <EvidenceChips refs={value.ledger_refs} label="score nodes:" />
              </div>
            </div>
          )}
        </ArtefactGate>
      </Panel>

      {lookalike && lookalike.shared_permissions.length > 0 && (
        <Panel title="Shared with apps you trust" className="xl:col-span-2">
          <p className="text-sm text-fg">
            This sample holds{' '}
            <span className="font-semibold">{lookalike.shared_permissions.length}</span>{' '}
            dual-use permission
            {lookalike.shared_permissions.length === 1 ? '' : 's'} that caller-ID, SMS-backup
            and anti-spam apps hold too — Truecaller reads your SMS as well. The permission
            set is not the finding.
          </p>
          <div className="mt-2 flex flex-wrap items-center gap-1">
            {lookalike.shared_permissions.map((permission) => (
              <span
                key={permission}
                title={permission}
                className="rounded bg-ink px-1.5 py-0.5 font-mono text-[10px] text-muted"
              >
                {permission.split('.').pop()}
              </span>
            ))}
            <Tag tone={lookalike.verdict === 'trojan_shape' ? 'bad' : 'neutral'}>
              {lookalike.verdict.replace(/_/g, ' ')} · trojan-shape{' '}
              {lookalike.trojan_score.toFixed(2)}
            </Tag>
          </div>
          <p className="mt-2 text-xs text-muted">
            Open the <span className="text-fg">Static</span> tab for the signal-by-signal
            breakdown of what does, and does not, separate it from them.
          </p>
        </Panel>
      )}

      <Panel title="Sample">
        <ArtefactGate artefact={ingest}>
          {(meta) => (
            <div className="space-y-3">
              <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
                {(
                  [
                    ['sha256', meta.sha256],
                    ['package', meta.package ?? '—'],
                    ['label', meta.app_label ?? '—'],
                    ['version', `${meta.version_name ?? '—'} (${meta.version_code ?? '—'})`],
                    ['sdk', `min ${meta.min_sdk ?? '—'} / target ${meta.target_sdk ?? '—'}`],
                    ['size', `${meta.size_bytes.toLocaleString()} bytes`],
                  ] as [string, string][]
                ).map(([key, value]) => (
                  <div key={key} className="contents">
                    <dt className="text-muted">{key}</dt>
                    <dd className="font-mono break-all text-fg">{value}</dd>
                  </div>
                ))}
              </dl>
              <div className="flex flex-wrap gap-2">
                {meta.is_split && <Tag tone="warn">split APK ({meta.split_names.length} parts)</Tag>}
                {meta.dedupe_hit && <Tag>seen before</Tag>}
                {meta.intel?.known_bad_hash && <Tag tone="bad">known-bad hash</Tag>}
                {meta.intel && meta.intel.source !== 'none' && (
                  <Tag title={`verdict: ${meta.intel.verdict}`}>intel: {meta.intel.source}</Tag>
                )}
                {meta.intel?.label_derived && (
                  <Tag tone="warn" title="Label-derived reputation must not feed R — evaluation would be circular">
                    label-derived
                  </Tag>
                )}
              </div>
            </div>
          )}
        </ArtefactGate>
      </Panel>

      <Panel title="Behaviours" subtitle="Enumerated by the model; B is computed from a weight table in Python">
        <ArtefactGate artefact={genai}>
          {(verdict) => {
            const positive = Object.entries(verdict.behaviours).filter(([, on]) => on)
            return (
              <div className="space-y-3">
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
                <div className="text-xs text-muted">
                  B = <span className="font-mono text-fg">{verdict.behavioural_risk_B.toFixed(3)}</span>
                  {verdict.B_rationale && <span className="ml-2">{verdict.B_rationale}</span>}
                </div>
                {verdict.disagreement_flag && (
                  <div className="rounded border border-warn/40 bg-warn/10 px-2 py-1.5 text-xs text-warn">
                    Detector disagreement: {verdict.disagreement_note ?? 'flagged, no note'} — this lowers
                    C and never silently alters S.
                  </div>
                )}
              </div>
            )
          }}
        </ArtefactGate>
      </Panel>

      <Panel
        title="Proposed actions"
        subtitle="Recommendations only — confirming records an ANALYST_ACTION node, it executes nothing"
        className="xl:col-span-2"
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

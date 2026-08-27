/**
 * Agents & orchestration: who acted, what they produced, and what was refused.
 *
 * A cyber-security analyst inheriting this verdict needs to answer "which parts of
 * this were decided by a model, and can I see it work?" before they trust any of it.
 * Every row here is derived from the job's own `GenAIVerdict` and ledger — an agent
 * that did not run is drawn as `not run`, never omitted, because a missing row and a
 * silent failure look identical once the panel is scrolled past.
 *
 * Two rules this view exists to make visible:
 *   - the model never emits the score; it emits enumerated booleans and Python
 *     computes B from a weight table;
 *   - a claim whose evidence cannot be resolved is REFUSED, and the refusal is the
 *     product. Rejected claims are shown, struck through, never dropped.
 */

import type { Artefact } from '../api/client'
import type { GenAIVerdict, EvidenceNode } from '../api/types'
import { ArtefactGate, Empty, KeyValue, Panel, Tag, count } from '../components/primitives'

/** One agent's contribution, derived only from what the verdict actually carries. */
type AgentRow = {
  name: string
  role: string
  /** What it produced, in the analyst's words. Empty string when it did not run. */
  produced: string
  ran: boolean
  /** Ledger ids this agent's output is anchored to. */
  refs: number
}

function buildRows(v: GenAIVerdict): AgentRow[] {
  const claimsBy = (agent: string) => v.claims.filter((c) => c.agent === agent)
  const checklist = claimsBy('behaviour_checklist')
  const interpClaims = v.interpretations.flatMap((i) => i.claims)

  return [
    {
      name: 'behaviour_checklist',
      role: 'Enumerates the behaviour booleans. Python turns them into B.',
      produced: checklist.length ? count(checklist.length, 'grounded claim') : '',
      ran: checklist.length > 0,
      refs: checklist.reduce((n, c) => n + c.evidence_refs.length, 0),
    },
    {
      name: 'code_interpreter',
      role: 'Reads sink-reachable method bodies and explains them.',
      produced: v.interpretations.length
        ? `${count(v.interpretations.length, 'method')} interpreted`
        : '',
      ran: v.interpretations.length > 0,
      refs: interpClaims.reduce((n, c) => n + c.evidence_refs.length, 0),
    },
    {
      name: 'technique_mapper',
      role: 'Maps observed capability onto ATT&CK.',
      produced: v.techniques.length ? `${count(v.techniques.length, 'technique')} mapped` : '',
      ran: v.techniques.length > 0,
      refs: v.techniques.reduce((n, t) => n + t.evidence_refs.length, 0),
    },
    {
      name: 'social_engineering',
      role: 'Infers who the lure targets, and in what language.',
      produced: v.victim ? 'victim profile built' : '',
      ran: Boolean(v.victim),
      refs: 0,
    },
    {
      name: 'vision',
      role: 'Compares the icon against known brands.',
      produced: v.impersonation ? 'icon compared' : '',
      ran: Boolean(v.impersonation),
      refs: 0,
    },
    {
      name: 'adversarial_elicitor',
      role: 'Answers an environment probe so a stalled sample proceeds.',
      produced: v.elicitation_deployed.length
        ? count(v.elicitation_deployed.length, 'morph')
        : '',
      ran: v.elicitation_deployed.length > 0,
      refs: 0,
    },
  ]
}

/** Module-level steps, straight from the ledger's own `source_tool` values. */
function orchestrationSteps(ledger: EvidenceNode[]) {
  const seen = new Map<string, { tool: string; seq: number; nodes: number }>()
  for (const n of ledger) {
    const cur = seen.get(n.source_tool)
    if (cur) cur.nodes += 1
    else seen.set(n.source_tool, { tool: n.source_tool, seq: n.seq, nodes: 1 })
  }
  return [...seen.values()].sort((a, b) => a.seq - b.seq)
}

export function AgentsTab({
  genai,
  ledger,
}: {
  genai: Artefact<GenAIVerdict> | null
  ledger: EvidenceNode[]
}) {
  return (
    <ArtefactGate artefact={genai}>
      {(verdict) => <AgentsView verdict={verdict} ledger={ledger} />}
    </ArtefactGate>
  )
}

function AgentsView({ verdict, ledger }: { verdict: GenAIVerdict; ledger: EvidenceNode[] }) {
  const rows = buildRows(verdict)
  const rejected = verdict.claims.filter((c) => c.verifier_status !== 'PASS')
  const steps = orchestrationSteps(ledger)
  const budget = 25

  return (
    <div className="space-y-4">
      <Panel
        title="Orchestrator"
        subtitle="What the controller dispatched for this sample, and what it spent doing it"
        right={
          <div className="flex items-center gap-2">
            <Tag>{verdict.provider}</Tag>
            <Tag tone={verdict.llm_calls > budget ? 'bad' : 'good'}>
              {verdict.llm_calls}/{budget} LLM calls
            </Tag>
            {verdict.partial && <Tag tone="warn">partial</Tag>}
          </div>
        }
      >
        <KeyValue
          pairs={[
            ['Agents dispatched', `${rows.filter((r) => r.ran).length} of ${rows.length}`],
            ['Grounded claims kept', String(verdict.claims.length - rejected.length)],
            [
              'Claims refused',
              rejected.length ? (
                <span className="text-bad">{rejected.length}</span>
              ) : (
                '0'
              ),
            ],
            ['Tool calls', String(verdict.tool_calls.length)],
            ['Wall clock', `${verdict.duration_ms} ms`],
          ]}
        />
        {verdict.errors.length > 0 && (
          <ul className="mt-3 space-y-1 border-t border-line-soft pt-3 text-xs text-muted">
            {verdict.errors.map((e, i) => (
              <li key={i}>· {e}</li>
            ))}
          </ul>
        )}
        <p className="mt-3 text-[11px] leading-relaxed text-dim">
          The model never emits the score. It answers enumerated behaviour booleans and
          Python computes <span className="font-mono">B</span> from a fixed weight table.
        </p>
      </Panel>

      <Panel
        title="Agents"
        subtitle="One row per agent. An agent that did not run says so rather than being omitted."
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="text-[11px] tracking-wide text-dim uppercase">
              <tr>
                <th className="py-2 pr-4">Agent</th>
                <th className="py-2 pr-4">What it does</th>
                <th className="py-2 pr-4">Produced</th>
                <th className="py-2">Evidence</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.name} className="border-t border-line-soft align-top">
                  <td className="py-2.5 pr-4 font-mono text-[11px] whitespace-nowrap">
                    {r.name}
                  </td>
                  <td className="py-2.5 pr-4 text-muted">{r.role}</td>
                  <td className="py-2.5 pr-4">
                    {r.ran ? (
                      <Tag tone="good">{r.produced}</Tag>
                    ) : (
                      <Tag>not run</Tag>
                    )}
                  </td>
                  <td className="py-2.5 text-muted tabular-nums">
                    {r.refs > 0 ? `${r.refs} refs` : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>

      <Panel
        title={`Refused claims (${rejected.length})`}
        subtitle="A claim whose evidence does not resolve is refused. The refusal is the product, so it is shown rather than dropped."
      >
        {rejected.length === 0 ? (
          <Empty>
            Every claim the model made resolved to a real ledger node, so none were
            refused on this sample.
          </Empty>
        ) : (
          <ul className="space-y-2">
            {rejected.map((c, i) => (
              <li key={i} className="rounded-[var(--radius-tile)] border border-bad/30 p-3">
                <div className="mb-1 flex items-center gap-2">
                  <Tag tone="bad">{c.verifier_status}</Tag>
                  <span className="text-[11px] text-muted">{c.agent}</span>
                </div>
                <p className="text-muted line-through">{c.text}</p>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel
        title="Tool calls"
        subtitle="Every tool the model was allowed to call, with the outcome the harness recorded"
      >
        {verdict.tool_calls.length === 0 ? (
          <Empty>
            No tool calls on this sample. The agents answered from the evidence
            catalogue they were given, without asking for more.
          </Empty>
        ) : (
          <ul className="space-y-2">
            {verdict.tool_calls.map((t) => (
              <li
                key={t.id}
                className="flex items-start justify-between gap-3 rounded-[var(--radius-tile)] border border-line p-3"
              >
                <div className="min-w-0">
                  <div className="mb-1 flex items-center gap-2">
                    <span className="font-mono text-[11px]">{t.name}</span>
                    <Tag tone={t.status === 'ok' ? 'good' : t.status === 'rejected' ? 'warn' : 'bad'}>
                      {t.status}
                    </Tag>
                  </div>
                  <p className="text-muted">{t.result_summary || '—'}</p>
                </div>
                <span className="shrink-0 text-[11px] text-dim tabular-nums">{t.duration_ms} ms</span>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel
        title="Pipeline order"
        subtitle="Read from the ledger's own source_tool values, in the sequence they were written"
      >
        <ol className="space-y-1.5">
          {steps.map((s) => (
            <li key={s.tool} className="flex items-center gap-3 text-xs">
              <span className="w-10 shrink-0 text-right font-mono text-[11px] text-dim tabular-nums">
                {s.seq}
              </span>
              <span className="font-mono text-[11px]">{s.tool}</span>
              <span className="text-dim">{count(s.nodes, 'node')}</span>
            </li>
          ))}
        </ol>
      </Panel>
    </div>
  )
}

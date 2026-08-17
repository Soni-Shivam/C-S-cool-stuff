/**
 * Frontier: what the sample demanded, what we synthesised, and what changed.
 *
 * The before/after diff is the centrepiece (PHASE_6 T6.4), and it is reconstructed
 * from the ledger rather than from a dedicated endpoint: the pipeline appends an
 * API_TRACE node per sandbox pass carrying that pass's stage, outcome and counts,
 * so pass 1 versus pass 2 is a fact already recorded in the chain. Reading it from
 * the ledger rather than from a UI-side cache is also the point — the same source
 * an auditor would use.
 *
 * If the morph plan was produced by a stub generator, this tab says so in the
 * heading rather than presenting a stubbed plan as GenAI synthesis. That is the
 * difference between demonstrating the architecture and overclaiming the frontier.
 */

import type { Artefact } from '../api/client'
import { EvidenceChips } from '../components/Evidence'
import { ArtefactGate, Empty, Panel, Raw, Tag } from '../components/primitives'
import type { DynamicTrace, EvidenceNode } from '../api/types'

function passNode(nodes: EvidenceNode[], stage: string): EvidenceNode | undefined {
  return nodes.find((node) => node.type === 'api_trace' && node.content.stage === stage)
}

function Delta({ label, before, after }: { label: string; before: unknown; after: unknown }) {
  const changed = JSON.stringify(before) !== JSON.stringify(after)
  const render = (value: unknown) =>
    value === undefined ? '—' : typeof value === 'boolean' ? String(value) : String(value)
  return (
    <tr className="border-t border-line-soft">
      <td className="py-1.5 pr-3 text-muted">{label}</td>
      <td className="py-1.5 pr-3 font-mono text-fg">{render(before)}</td>
      <td className="py-1.5 pr-3 text-dim">→</td>
      <td className={`py-1.5 font-mono ${changed ? 'text-good' : 'text-muted'}`}>{render(after)}</td>
    </tr>
  )
}

export function FrontierTab({
  nodes,
  dynamic,
}: {
  nodes: EvidenceNode[]
  dynamic: Artefact<DynamicTrace> | null
}) {
  const morphNodes = nodes.filter((node) => node.type === 'morph_action')
  const c2Nodes = nodes.filter((node) => node.type === 'generative_c2')
  const pass1 = passNode(nodes, 'sandbox_pass1')
  const pass2 = passNode(nodes, 'sandbox_pass2')
  const stubbed = morphNodes.some((node) => node.source_tool.endsWith(':stub'))

  return (
    <div className="space-y-4">
      {morphNodes.length === 0 && (
        <div className="rounded border border-line bg-panel px-4 py-3 text-sm text-muted">
          The frontier did not run for this job. It runs only when pass 1 did not detonate{' '}
          <em>and</em> pass 1 recorded an evasion observation — morphing without an observation would
          be a guess, not a response.
        </div>
      )}

      {stubbed && (
        <div className="rounded border border-warn/40 bg-warn/5 px-4 py-3 text-sm text-warn">
          This plan came from the <span className="font-mono">stub</span> generator. It is derived from
          real pass-1 observations, but no model synthesised it and no morph was applied to a device —
          the LLM-generated plan and the applicator land in P5 (T5.1–T5.3).
        </div>
      )}

      <Panel
        title="1 · What the sample demanded"
        subtitle="Evasion observations from pass 1 — the justification for every morph below"
      >
        <ArtefactGate artefact={dynamic}>
          {(trace) =>
            trace.evasion_observations.length === 0 ? (
              <Empty>No environment probe was observed.</Empty>
            ) : (
              <ul className="space-y-2">
                {trace.evasion_observations.map((observation, i) => (
                  <li key={i} className="rounded border border-line-soft bg-panel-2 p-2.5 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <Tag tone="warn">{observation.result}</Tag>
                      <span className="text-muted">{observation.probe_kind}</span>
                      <span className="font-mono break-all text-fg">{observation.queried}</span>
                    </div>
                    {observation.inferred_requirement && (
                      <div className="mt-1 text-xs text-muted">
                        inferred requirement: {observation.inferred_requirement}
                      </div>
                    )}
                  </li>
                ))}
              </ul>
            )
          }
        </ArtefactGate>
      </Panel>

      <Panel
        title="2 · What we synthesised"
        subtitle="Morphs change what the sample observes about its environment. They never add capability to it."
      >
        {morphNodes.length === 0 ? (
          <Empty>No morph plan was generated.</Empty>
        ) : (
          <ul className="space-y-2">
            {morphNodes.map((node) => (
              <li key={node.id} className="rounded border border-line-soft bg-panel-2 p-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-accent">{String(node.content.plan_id ?? node.id)}</span>
                  <Tag>{node.source_tool}</Tag>
                  <Tag tone={node.content.human_reviewed ? 'good' : 'warn'}>
                    {node.content.human_reviewed ? 'human reviewed' : 'not human reviewed'}
                  </Tag>
                  <EvidenceChips refs={[node.id]} />
                </div>
                <div className="mt-2">
                  <Raw value={node.content} />
                </div>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="3 · Generative C2" subtitle="Synthesised responses served to a dead or geo-fenced C2">
        {c2Nodes.length === 0 ? (
          <Empty>
            No Generative C2 exchange. Emulation lands in P5 (T5.4); until then no synthesised response
            has ever been served to a sample.
          </Empty>
        ) : (
          <ul className="space-y-2">
            {c2Nodes.map((node) => (
              <li key={node.id} className="rounded border border-line-soft bg-panel-2 p-2.5">
                <Raw value={node.content} />
              </li>
            ))}
          </ul>
        )}
      </Panel>

      <Panel title="4 · Before / after" subtitle="Pass 1 versus pass 2, read from the ledger">
        {!pass1 ? (
          <Empty>No sandbox pass was recorded.</Empty>
        ) : !pass2 ? (
          <Empty>Only one pass ran — there is nothing to diff.</Empty>
        ) : (
          <table className="w-full text-left text-sm">
            <thead className="text-[11px] tracking-widest text-muted">
              <tr>
                <th className="pb-1 font-medium"></th>
                <th className="pb-1 font-medium">PASS 1</th>
                <th></th>
                <th className="pb-1 font-medium">PASS 2 (morphed)</th>
              </tr>
            </thead>
            <tbody>
              <Delta label="detonated" before={pass1.content.detonated} after={pass2.content.detonated} />
              <Delta label="outcome" before={pass1.content.outcome} after={pass2.content.outcome} />
              <Delta label="api events" before={pass1.content.api_events} after={pass2.content.api_events} />
              <Delta
                label="evasion observations"
                before={pass1.content.evasion_observations}
                after={pass2.content.evasion_observations}
              />
              <Delta label="synthetic" before={pass1.content.synthetic} after={pass2.content.synthetic} />
            </tbody>
          </table>
        )}
      </Panel>

      <ArtefactGate artefact={dynamic}>
        {(trace) =>
          trace.morphs_applied.length > 0 ? (
            <Panel title="Morphs applied to the latest trace">
              <div className="flex flex-wrap gap-1.5">
                {trace.morphs_applied.map((morph) => (
                  <Tag key={morph} tone="accent">
                    {morph}
                  </Tag>
                ))}
              </div>
            </Panel>
          ) : (
            <></>
          )
        }
      </ArtefactGate>
    </div>
  )
}

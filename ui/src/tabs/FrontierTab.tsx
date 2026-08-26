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
import { ArtefactGate, count, Empty, Panel, Raw, SectionHead, Tag } from '../components/primitives'
import type { DynamicTrace, EvidenceNode } from '../api/types'
import type { Verdict } from '../api/verdict.gen'

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
  verdict,
}: {
  nodes: EvidenceNode[]
  dynamic: Artefact<DynamicTrace> | null
  verdict: Artefact<Verdict> | null
}) {
  const morphNodes = nodes.filter((node) => node.type === 'morph_action')
  const c2Nodes = nodes.filter((node) => node.type === 'generative_c2')
  const pass1 = passNode(nodes, 'sandbox_pass1')
  const pass2 = passNode(nodes, 'sandbox_pass2')
  const stubbed = morphNodes.some((node) => node.source_tool.endsWith(':stub'))

  return (
    <div className="space-y-5">
      <SectionHead
        eyebrow="Frontier"
        title="Answering an evasive sample"
        lede="When pass 1 stalls on an environment check, the frontier synthesises what the sample demanded to see and runs it again. Everything below is reconstructed from the ledger, not from a UI-side cache."
        right={
          <>
            <Tag tone={morphNodes.length > 0 ? 'accent' : 'neutral'}>
              {count(morphNodes.length, 'morph action')}
            </Tag>
            {stubbed && <Tag tone="warn">stub generator</Tag>}
          </>
        }
      />

      <ArtefactGate artefact={verdict}>
        {(value) => (
          <Panel
            title="0 · Adversarial elicitation deployed"
            subtitle="verdict.adversarial_elicitation_deployed — what the elicitor actually put in front of this sample"
          >
            {value.adversarial_elicitation_deployed.length === 0 ? (
              <Empty>
                Nothing was elicited for this sample. The frontier runs only when a pass
                stalled with an observed environment probe to answer, so an empty list here
                means the branch never fired — not that it fired and found nothing.
              </Empty>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {value.adversarial_elicitation_deployed.map((item) => (
                  <Tag key={item} tone="accent">
                    {item}
                  </Tag>
                ))}
              </div>
            )}
          </Panel>
        )}
      </ArtefactGate>

      {morphNodes.length === 0 && (
        <div className="rounded-[var(--radius-card)] border border-line bg-ground-1/70 px-5 py-4 text-sm leading-relaxed text-muted">
          The frontier did not run for this job. It runs only when pass 1 did not detonate{' '}
          <em>and</em> pass 1 recorded an evasion observation — morphing without an observation would
          be a guess, not a response.
        </div>
      )}

      {stubbed && (
        <div className="rounded border border-warn/40 bg-warn/5 px-4 py-3 text-sm text-warn">
          This plan came from the <span className="font-mono">stub</span> generator in{' '}
          <span className="font-mono">pipeline.py</span>, not from the Adversarial Elicitor. It is
          derived from real pass-1 observations, but no model synthesised it and no morph was
          applied to a device. The elicitor and the JIT applicator do exist —{' '}
          <span className="font-mono">m4_genai/agents/adversarial_elicitor.py</span> and{' '}
          <span className="font-mono">m3_dynamic/morph.py</span> — this pipeline path simply does
          not call them.
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
                  <li key={i} className="rounded-[var(--radius-tile)] border border-line-soft bg-ground-2/60 p-2.5 text-sm">
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
              <li key={node.id} className="rounded-[var(--radius-tile)] border border-line-soft bg-ground-2/60 p-2.5">
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
            No Generative C2 exchange for this job. The emulation is built
            (<span className="font-mono">m3_dynamic/generative_c2.py</span>, behind its inertness
            gate) but it only serves a response to a sample that is actually running, and nothing
            detonated here. No synthesised response was served.
          </Empty>
        ) : (
          <ul className="space-y-2">
            {c2Nodes.map((node) => (
              <li key={node.id} className="rounded-[var(--radius-tile)] border border-line-soft bg-ground-2/60 p-2.5">
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

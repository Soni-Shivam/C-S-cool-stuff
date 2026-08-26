/**
 * Code-Graph RAG Navigation.
 *
 * This view answers the question a reviewer actually has about an LLM-assisted
 * analysis: *what did the model get to look at, and what did it conclude from
 * exactly that?*
 *
 * The graph is the call graph M2 walked backward from each sink. On top of it,
 * three retrieval facts are drawn from data the pipeline already records:
 *
 *   which methods had a body recovered      `StaticReport.decompiled_methods`
 *   which of those the model interpreted    `GenAIVerdict.interpretations`
 *   what each tool call actually reached    `GenAIVerdict.tool_calls`
 *
 * Selecting a tool call replays its retrieval across the graph, one node at a
 * time, so the audit trail in `tool_calls` becomes something you watch rather
 * than something you read. Methods the run never retrieved stay hollow and
 * dashed — that gap is the most important thing on the screen, because a claim
 * about one of those nodes could not have been grounded.
 */

import { useEffect, useMemo, useState } from 'react'
import {
  Braces,
  CheckCircle2,
  CircleDashed,
  GitBranch,
  Play,
  Square,
  Target,
  Wrench,
  XCircle,
} from 'lucide-react'
import type { Artefact } from '../api/client'
import type { EvidenceNode, GenAIVerdict, StaticReport } from '../api/types'
import { EvidenceChips } from '../components/Evidence'
import { LogoSpinner } from '../components/Logo'
import {
  ArtefactGate,
  count,
  plural,
  DegradedNotice,
  Empty,
  Panel,
  SectionHead,
  StatTile,
  Tag,
} from '../components/primitives'
import { GraphCanvas } from '../graph/GraphCanvas'
import { buildGraph, nodesOnPath, nodesTouchedBy } from '../graph/layout'
import type { CodeGraph, GraphNode } from '../graph/layout'

const REPLAY_MS = 420

export function CodeGraphTab({
  report,
  genai,
  ledger,
}: {
  report: Artefact<StaticReport> | null
  genai: Artefact<GenAIVerdict> | null
  ledger: EvidenceNode[]
}) {
  return (
    <ArtefactGate artefact={report}>
      {(staticReport) => (
        <Workspace
          report={staticReport}
          /* The static graph exists before the GenAI stage finishes; showing it
             with every node still un-interpreted beats an empty pane. */
          verdict={genai?.state === 'ready' ? genai.value : null}
          genaiPending={genai === null || genai.state === 'pending'}
          ledger={ledger}
        />
      )}
    </ArtefactGate>
  )
}

function Workspace({
  report,
  verdict,
  genaiPending,
  ledger,
}: {
  report: StaticReport
  verdict: GenAIVerdict | null
  genaiPending: boolean
  ledger: EvidenceNode[]
}) {
  const graph = useMemo(() => buildGraph(report, verdict), [report, verdict])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [pathFilter, setPathFilter] = useState<number | null>(null)
  const [replayCall, setReplayCall] = useState<string | null>(null)
  const [step, setStep] = useState(0)

  const calls = verdict?.tool_calls ?? []
  const replayOrder = useMemo(() => {
    const call = calls.find((candidate) => candidate.id === replayCall)
    return call ? nodesTouchedBy(call, graph) : []
  }, [calls, replayCall, graph])

  useEffect(() => {
    if (replayCall === null || step >= replayOrder.length) return
    const timer = window.setTimeout(() => setStep((n) => n + 1), REPLAY_MS)
    return () => window.clearTimeout(timer)
  }, [replayCall, step, replayOrder.length])

  const reached = useMemo(() => new Set(replayOrder.slice(0, step)), [replayOrder, step])
  const focus = useMemo(
    () => (pathFilter === null ? null : new Set(nodesOnPath(graph, pathFilter))),
    [graph, pathFilter],
  )

  const selected = selectedId ? (graph.byId.get(selectedId) ?? null) : null
  const retrieved = graph.nodes.length - graph.unretrievedCount
  const interpreted = graph.nodes.filter((node) => node.retrieval === 'interpreted').length

  const startReplay = (id: string) => {
    setReplayCall(id)
    setStep(0)
  }

  if (graph.nodes.length === 0) {
    return (
      <div className="space-y-5">
        <DegradedNotice result={report} />
        <SectionHead
          eyebrow="Code-graph RAG"
          title="No sink-reachable call path"
          lede="The backward traversal from every known sink returned nothing for this sample, so there is no code graph to navigate. Static findings and the ledger remain valid; this run simply cannot support code-level model claims."
        />
      </div>
    )
  }

  return (
    <div className="space-y-5">
      <DegradedNotice result={report} />
      {verdict && <DegradedNotice result={verdict} />}

      <SectionHead
        eyebrow="Code-graph RAG navigation"
        title="What the model was allowed to see"
        lede="Every edge below is a call the static analyser actually walked, backward from a sink to a lifecycle entrypoint. Fill shows how far retrieval got: hollow means no body was ever recovered, so nothing said about that method could have been grounded."
        right={
          <>
            <Tag tone="accent">
              {count(graph.nodes.length, 'method')} · {count(graph.edges.length, 'edge')}
            </Tag>
            <Tag tone={graph.unretrievedCount === 0 ? 'good' : 'warn'}>
              {retrieved}/{graph.nodes.length} retrieved
            </Tag>
            {genaiPending && (
              <Tag tone="neutral">
                <LogoSpinner size="xs" /> interpretation running
              </Tag>
            )}
          </>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatTile
          tone="gradient"
          value={graph.paths.length}
          label={plural(graph.paths.length, 'sink path')}
          hint="Distinct chains from a lifecycle entrypoint to a dangerous API, found by walking the call graph backward from each sink."
        />
        <StatTile
          tone="wash"
          value={interpreted}
          label={`${plural(interpreted, 'method')} interpreted`}
          hint="Bodies the model produced a validated, evidence-bearing reading for."
        />
        <StatTile
          value={graph.unretrievedCount}
          label="never retrieved"
          hint="On a sink path, but no body was recovered. Ungroundable by construction."
        />
        <StatTile
          value={calls.length}
          label={plural(calls.length, 'retrieval tool call')}
          hint={
            calls.length === 0
              ? 'No model tool call was made in this run.'
              : 'Each one is replayable across the graph below.'
          }
        />
      </div>

      <Legend />

      <div className="grid min-h-[600px] gap-4 2xl:grid-cols-[minmax(0,1fr)_400px]">
        <Panel
          title="Call graph"
          subtitle="Columns are call depth: lifecycle entrypoints on the left, sinks on the right."
          bodyClass="p-0"
          right={
            <PathFilter graph={graph} value={pathFilter} onChange={setPathFilter} />
          }
          className="flex min-h-[420px] flex-col"
        >
          <div className="h-[clamp(360px,52vh,660px)]">
            <GraphCanvas
              graph={graph}
              selectedId={selectedId}
              focus={focus}
              reached={reached}
              onSelect={setSelectedId}
            />
          </div>
        </Panel>

        <Inspector node={selected} ledger={ledger} />
      </div>

      <RetrievalTimeline
        graph={graph}
        verdict={verdict}
        activeId={replayCall}
        step={step}
        touched={replayOrder}
        onPlay={startReplay}
        onStop={() => {
          setReplayCall(null)
          setStep(0)
        }}
        onSelectNode={setSelectedId}
      />
    </div>
  )
}

/* ─── legend ─────────────────────────────────────────────────────────────── */

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-[var(--radius-tile)] border border-line bg-ground-1/70 px-5 py-3.5 text-xs text-muted">
      <span className="eyebrow">Retrieval</span>
      <Swatch
        label="interpreted"
        hint="body recovered and read by the model"
        style={{ backgroundImage: 'var(--grad-violet)', border: '1px solid transparent' }}
      />
      <Swatch
        label="decompiled"
        hint="body recovered, no model reading"
        style={{
          background: 'var(--color-ground-3)',
          border: '1px solid var(--color-v600)',
        }}
      />
      <Swatch
        label="never retrieved"
        hint="on a sink path, no body recovered — ungroundable"
        style={{ border: '1px dashed var(--color-line-bright)' }}
      />
      <span className="hidden h-4 w-px bg-line lg:block" />
      <span className="eyebrow">Role</span>
      <span className="flex items-center gap-2">
        <span className="h-2.5 w-2.5 rounded-sm bg-v300" /> entrypoint
      </span>
      <span className="flex items-center gap-2">
        <span className="h-2.5 w-2.5 rounded-full bg-critical" /> sink
      </span>
      <span className="flex items-center gap-2">
        <span className="h-px w-6 border-t border-dashed border-v500" /> call cycle
      </span>
    </div>
  )
}

function Swatch({
  label,
  hint,
  style,
}: {
  label: string
  hint: string
  style: React.CSSProperties
}) {
  return (
    <span className="flex items-center gap-2" title={hint}>
      <span className="h-4 w-7 rounded-[5px]" style={style} />
      {label}
    </span>
  )
}

/* ─── path filter ────────────────────────────────────────────────────────── */

function PathFilter({
  graph,
  value,
  onChange,
}: {
  graph: CodeGraph
  value: number | null
  onChange: (index: number | null) => void
}) {
  return (
    <div className="flex flex-wrap items-center justify-end gap-1.5">
      <button
        type="button"
        onClick={() => onChange(null)}
        className={chipClass(value === null)}
        title="Show every path"
      >
        all
      </button>
      {graph.paths.map((path, index) => (
        <button
          key={`${path.sink_id}-${index}`}
          type="button"
          onClick={() => onChange(value === index ? null : index)}
          className={chipClass(value === index)}
          title={`${path.entrypoint_kind} entrypoint → ${path.sink_signature} (${path.path.length} hops)`}
        >
          {String(index + 1).padStart(2, '0')}
        </button>
      ))}
    </div>
  )
}

function chipClass(active: boolean): string {
  return `rounded-full border px-2.5 py-0.5 font-mono text-[11px] transition-colors ${
    active
      ? 'border-transparent bg-white text-ink'
      : 'border-line-bright bg-ground-2 text-muted hover:border-v400 hover:text-v300'
  }`
}

/* ─── inspector ──────────────────────────────────────────────────────────── */

type Pane = 'code' | 'reasoning' | 'evidence'

function Inspector({ node, ledger }: { node: GraphNode | null; ledger: EvidenceNode[] }) {
  const [pane, setPane] = useState<Pane>('code')

  if (!node) {
    return (
      <Panel title="Inspector" className="flex min-h-[320px] flex-col">
        <div className="flex flex-1 flex-col items-center justify-center gap-4 py-10 text-center">
          <Target size={26} className="text-dim" />
          <Empty>Select a method in the graph to read its recovered body, the model's grounded reading of it, and the ledger nodes both are anchored to.</Empty>
        </div>
      </Panel>
    )
  }

  const cited = new Set(node.interpretation?.cited_lines ?? [])
  const panes: [Pane, string, boolean][] = [
    ['code', 'Code', node.decompiled !== null],
    ['reasoning', 'Reasoning', node.interpretation !== null],
    ['evidence', 'Evidence', node.evidenceRefs.length > 0],
  ]

  return (
    <Panel
      title={node.label}
      subtitle={node.owner || undefined}
      bodyClass="p-0"
      className="flex min-h-[320px] flex-col"
      right={
        <div className="flex flex-wrap justify-end gap-1.5">
          {node.isEntrypoint && <Tag tone="accent">entrypoint</Tag>}
          {node.isSink && <Tag tone="bad">sink</Tag>}
          <Tag tone={node.retrieval === 'interpreted' ? 'solid' : node.retrieval === 'decompiled' ? 'accent' : 'warn'}>
            {node.retrieval}
          </Tag>
        </div>
      }
    >
      <div className="flex gap-1 border-b border-line-soft px-3 pt-2">
        {panes.map(([key, label, available]) => (
          <button
            key={key}
            type="button"
            onClick={() => setPane(key)}
            className={`relative px-3 py-2 text-xs transition-colors ${
              pane === key ? 'text-fg' : available ? 'text-muted hover:text-fg' : 'text-dim'
            }`}
          >
            {label}
            {!available && <span className="ml-1.5 text-[9px] text-dim">—</span>}
            {pane === key && (
              <span
                className="absolute inset-x-2 -bottom-px h-0.5 rounded-full"
                style={{ backgroundImage: 'var(--grad-violet)' }}
              />
            )}
          </button>
        ))}
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {pane === 'code' &&
          (node.decompiled ? (
            <>
              <div className="border-b border-line-soft px-4 py-2 text-[10px] text-dim">
                Sample-derived text, rendered inert
                {node.decompiled.truncated && ' · truncated by the extractor'}
              </div>
              <pre className="bg-ground p-3 font-mono text-[12px] leading-6">
                {node.decompiled.body.split('\n').map((line, index) => {
                  const number = node.decompiled!.line_start + index
                  const hot = cited.has(number)
                  return (
                    <div
                      key={number}
                      className={`grid grid-cols-[2.6rem_1fr] ${hot ? 'bg-v500/20' : ''}`}
                    >
                      <span className={hot ? 'text-v300' : 'text-dim'}>{number}</span>
                      <code className="break-words whitespace-pre-wrap text-fg">{line || ' '}</code>
                    </div>
                  )
                })}
              </pre>
            </>
          ) : (
            <div className="p-4">
              <Empty>
                No body was recovered for this method. It sits on a sink path, but the bounded
                decompiler never reached it — so no model claim about it could be grounded, and
                none was accepted.
              </Empty>
            </div>
          ))}

        {pane === 'reasoning' &&
          (node.interpretation ? (
            <div className="space-y-4 p-4">
              <div>
                <div className="flex items-center gap-2">
                  <Braces size={14} className="text-v300" />
                  <Tag tone={node.interpretation.insufficient_evidence ? 'warn' : 'good'}>
                    {node.interpretation.confidence} confidence
                  </Tag>
                  {node.interpretation.insufficient_evidence && (
                    <Tag tone="warn">insufficient evidence</Tag>
                  )}
                </div>
                <p className="mt-2.5 text-sm leading-relaxed text-fg">
                  {node.interpretation.summary}
                </p>
              </div>
              <div className="space-y-2.5">
                {node.interpretation.claims.map((claim, index) => (
                  <div
                    key={index}
                    className={`rounded-r-lg border-l-2 bg-ground-2/60 py-2 pl-3 ${
                      claim.verifier_status === 'PASS' ? 'border-good' : 'border-bad'
                    }`}
                  >
                    <div className="flex items-center gap-1.5 text-[10px]">
                      {claim.verifier_status === 'PASS' ? (
                        <CheckCircle2 size={12} className="text-good" />
                      ) : (
                        <XCircle size={12} className="text-bad" />
                      )}
                      <span className="font-mono text-muted">{claim.verifier_status}</span>
                    </div>
                    <p className="mt-1 text-xs leading-relaxed text-fg">{claim.text}</p>
                    <div className="mt-1.5">
                      <EvidenceChips refs={claim.evidence_refs} />
                    </div>
                  </div>
                ))}
              </div>
              {Object.keys(node.interpretation.renamed_symbols).length > 0 && (
                <div>
                  <div className="eyebrow mb-2">Suggested names</div>
                  {Object.entries(node.interpretation.renamed_symbols).map(([from, to]) => (
                    <div key={from} className="mb-1.5 text-[11px]">
                      <div className="truncate font-mono text-dim" title={from}>
                        {from}
                      </div>
                      <div className="font-mono text-v300">↳ {to}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="p-4">
              <Empty>
                No validated model interpretation exists for this method in this run.
              </Empty>
            </div>
          ))}

        {pane === 'evidence' && <Lineage node={node} ledger={ledger} />}
      </div>
    </Panel>
  )
}

/* ─── ledger lineage ─────────────────────────────────────────────────────── */

/**
 * Walk `parents` up from the node's own grounding refs.
 *
 * This is the provenance the ledger already stores; drawing it here means
 * "grounded in evidence" can be inspected rather than taken on faith. Depth is
 * capped so a deep chain cannot push the pane off the screen.
 */
function Lineage({ node, ledger }: { node: GraphNode; ledger: EvidenceNode[] }) {
  const byId = useMemo(() => new Map(ledger.map((entry) => [entry.id, entry])), [ledger])

  const levels = useMemo(() => {
    const out: EvidenceNode[][] = []
    const seen = new Set<string>()
    let frontier = node.evidenceRefs
      .map((id) => byId.get(id))
      .filter((entry): entry is EvidenceNode => entry !== undefined)
    for (let depth = 0; depth < 4 && frontier.length > 0; depth += 1) {
      const level = frontier.filter((entry) => !seen.has(entry.id))
      if (level.length === 0) break
      level.forEach((entry) => seen.add(entry.id))
      out.push(level)
      frontier = level
        .flatMap((entry) => entry.parents)
        .map((id) => byId.get(id))
        .filter((entry): entry is EvidenceNode => entry !== undefined)
    }
    return out
  }, [node, byId])

  if (node.evidenceRefs.length === 0) {
    return (
      <div className="p-4">
        <Empty>
          This method is cited by no ledger node. Nothing about it is grounded, which is why the
          graph draws it hollow.
        </Empty>
      </div>
    )
  }

  return (
    <div className="space-y-4 p-4">
      <div>
        <div className="eyebrow mb-2">Grounded in</div>
        <EvidenceChips refs={node.evidenceRefs} max={8} />
      </div>

      {levels.length === 0 ? (
        <Empty>
          The ledger for this job has not loaded, so the lineage behind those refs cannot be shown
          yet.
        </Empty>
      ) : (
        <div>
          <div className="eyebrow mb-2">Provenance</div>
          <ol className="space-y-2">
            {levels.map((level, depth) => (
              <li key={depth} className="flex gap-3">
                <span className="mt-1 font-mono text-[10px] text-dim">
                  {depth === 0 ? 'cited' : `−${depth}`}
                </span>
                <div className="min-w-0 flex-1 space-y-1.5">
                  {level.map((entry) => (
                    <div
                      key={entry.id}
                      className="rounded-lg border border-line-soft bg-ground-2/60 px-2.5 py-1.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate font-mono text-[11px] text-v300">
                          {entry.type}
                        </span>
                        <span className="shrink-0 font-mono text-[10px] text-dim">
                          #{entry.seq}
                        </span>
                      </div>
                      <div className="mt-0.5 truncate text-[10px] text-muted" title={entry.source_tool}>
                        {entry.source_tool}
                      </div>
                    </div>
                  ))}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  )
}

/* ─── retrieval timeline ─────────────────────────────────────────────────── */

function RetrievalTimeline({
  graph,
  verdict,
  activeId,
  step,
  touched,
  onPlay,
  onStop,
  onSelectNode,
}: {
  graph: CodeGraph
  verdict: GenAIVerdict | null
  activeId: string | null
  step: number
  touched: string[]
  onPlay: (id: string) => void
  onStop: () => void
  onSelectNode: (id: string) => void
}) {
  const calls = verdict?.tool_calls ?? []

  return (
    <Panel
      title="Retrieval trail"
      subtitle="Every tool call the model was permitted to make, in order. Play one to watch it light up the methods it actually reached."
      right={<Wrench size={15} className="text-v300" />}
    >
      {calls.length === 0 ? (
        <Empty>
          {verdict
            ? 'No model tool call was made in this run, so nothing was retrieved beyond what the static stage had already selected.'
            : 'The GenAI stage has not produced a verdict yet.'}
        </Empty>
      ) : (
        <div className="space-y-2.5">
          {calls.map((call, index) => {
            const active = call.id === activeId
            const reach = active ? touched : nodesTouchedBy(call, graph)
            return (
              <div
                key={call.id}
                className={`rounded-[var(--radius-tile)] border px-3.5 py-3 transition-colors ${
                  active ? 'border-v500 bg-v500/[0.09]' : 'border-line-soft bg-ground-2/50'
                }`}
              >
                <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
                  <span className="font-mono text-[10px] text-dim">
                    {String(index + 1).padStart(2, '0')}
                  </span>
                  <span className="font-mono text-xs text-fg">{call.name}</span>
                  <Tag tone={call.status === 'ok' ? 'good' : call.status === 'rejected' ? 'warn' : 'bad'}>
                    {call.status}
                  </Tag>
                  <span className="font-mono text-[10px] text-dim">{call.duration_ms} ms</span>
                  <span className="flex-1" />
                  {reach.length === 0 ? (
                    <span className="flex items-center gap-1.5 text-[11px] text-dim">
                      <CircleDashed size={12} /> reached no method in this graph
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => (active ? onStop() : onPlay(call.id))}
                      className="flex items-center gap-1.5 rounded-full border border-line-bright bg-ground-2 px-2.5 py-1 text-[11px] text-muted transition-colors hover:border-v400 hover:text-v300"
                    >
                      {active ? <Square size={11} /> : <Play size={11} />}
                      {active ? `${Math.min(step, reach.length)}/${reach.length}` : `replay ${reach.length}`}
                    </button>
                  )}
                </div>

                <p className="mt-1.5 text-xs leading-relaxed text-muted">{call.result_summary}</p>

                {reach.length > 0 && (
                  <div className="mt-2 flex flex-wrap items-center gap-1.5">
                    <GitBranch size={11} className="text-dim" />
                    {reach.map((id, position) => {
                      const lit = active && position < step
                      return (
                        <button
                          key={id}
                          type="button"
                          onClick={() => onSelectNode(id)}
                          className={`rounded-full border px-2 py-0.5 font-mono text-[10px] transition-colors ${
                            lit
                              ? 'border-magenta bg-magenta/15 text-magenta'
                              : 'border-line-bright bg-ground-2 text-muted hover:border-v400 hover:text-v300'
                          }`}
                          title={id}
                        >
                          {graph.byId.get(id)?.label ?? id}
                        </button>
                      )
                    })}
                  </div>
                )}

                <div className="mt-2">
                  <EvidenceChips refs={call.evidence_refs} max={4} />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </Panel>
  )
}

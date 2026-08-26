import { Braces, CheckCircle2, Link2, Wrench, XCircle } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import type { Artefact } from '../api/client'
import type { GenAIVerdict, StaticReport } from '../api/types'
import { EvidenceChips } from '../components/Evidence'
import {
  ArtefactGate,
  count,
  DegradedNotice,
  Empty,
  Panel,
  SectionHead,
  Tag,
} from '../components/primitives'
import { AiTab } from './AiTab'
import type { MLPrediction } from '../api/types'

function shortSignature(signature: string): string {
  const method = signature.split(';->').at(-1) ?? signature
  const owner = signature.split('/').at(-1)?.split(';')[0] ?? ''
  return owner ? `${owner}.${method}` : method
}

export function ReverseEngineeringTab({
  report,
  genai,
  ml,
}: {
  report: Artefact<StaticReport> | null
  genai: Artefact<GenAIVerdict> | null
  ml: Artefact<MLPrediction> | null
}) {
  return (
    <div className="space-y-4">
      <ArtefactGate artefact={report}>
        {(staticReport) => (
          <ArtefactGate artefact={genai}>
            {(verdict) => <Workspace report={staticReport} verdict={verdict} />}
          </ArtefactGate>
        )}
      </ArtefactGate>
      <AiTab genai={genai} ml={ml} />
    </div>
  )
}

function Workspace({ report, verdict }: { report: StaticReport; verdict: GenAIVerdict }) {
  const initial = new URLSearchParams(window.location.search).get('method')
  const [signature, setSignature] = useState(
    initial && report.decompiled_methods.some((method) => method.signature === initial)
      ? initial
      : report.decompiled_methods[0]?.signature ?? '',
  )
  const method = report.decompiled_methods.find((item) => item.signature === signature)
  const interpretation = verdict.interpretations.find((item) => item.method_signature === signature)
  const cited = useMemo(() => new Set(interpretation?.cited_lines ?? []), [interpretation])

  useEffect(() => {
    const url = new URL(window.location.href)
    if (signature) url.searchParams.set('method', signature)
    else url.searchParams.delete('method')
    window.history.replaceState({}, '', url)
  }, [signature])

  return (
    <div className="space-y-5">
      <DegradedNotice result={report} />
      <DegradedNotice result={verdict} />
      <SectionHead
        eyebrow="Reverse engineering"
        title="Code, reasoning, evidence"
        lede="Sink-reachable method bodies beside the model's reading of them and the ledger nodes both are anchored to. For the same material as a navigable graph, see view 02."
        right={
          <>
            <Tag tone="accent">{count(report.decompiled_methods.length, 'method')} recovered</Tag>
            <Tag tone={verdict.tool_calls.some((call) => call.status !== 'ok') ? 'warn' : 'good'}>
              {count(verdict.tool_calls.length, 'audited tool call')}
            </Tag>
            <Tag>{verdict.provider}</Tag>
          </>
        }
      />

      {report.decompiled_methods.length === 0 ? (
        <div className="rounded-[var(--radius-card)] border border-line bg-ground-1/70 px-6 py-7">
          <Empty>
            No sink-reachable method body was recovered. The graph and static findings remain valid,
            but this run cannot support code-level model claims.
          </Empty>
        </div>
      ) : (
        <div className="shadow-card grid min-h-[540px] overflow-hidden rounded-[var(--radius-card)] border border-line bg-ground-1/70 xl:grid-cols-[260px_minmax(360px,1fr)_340px]">
          <section className="border-b border-line xl:border-r xl:border-b-0">
            <header className="eyebrow border-b border-line-soft px-4 py-3">
              SINK PATH METHODS
            </header>
            <div className="max-h-52 overflow-auto p-2 xl:max-h-[500px]">
              {report.decompiled_methods.map((item) => {
                const selected = item.signature === signature
                const reasoning = verdict.interpretations.find(
                  (candidate) => candidate.method_signature === item.signature,
                )
                return (
                  <button
                    key={item.signature}
                    type="button"
                    onClick={() => setSignature(item.signature)}
                    className={`mb-1 w-full border-l-2 px-2.5 py-2 text-left transition-colors ${
                      selected
                        ? 'border-v400 bg-v500/15 text-fg'
                        : 'border-transparent text-muted hover:bg-ground-2 hover:text-fg'
                    }`}
                    title={item.signature}
                  >
                    <div className="truncate font-mono text-xs">{shortSignature(item.signature)}</div>
                    <div className="mt-1 flex items-center gap-2 text-[10px]">
                      <span>{item.line_end - item.line_start + 1} lines</span>
                      <span>path {item.call_path_indexes.map((index) => index + 1).join(', ')}</span>
                      {reasoning && <span className="text-good">interpreted</span>}
                    </div>
                  </button>
                )
              })}
            </div>
          </section>

          <section className="min-w-0 border-b border-line xl:border-r xl:border-b-0">
            <header className="flex min-w-0 items-center justify-between gap-3 overflow-hidden border-b border-line-soft px-3 py-2.5">
              <div className="min-w-0">
                <div className="truncate font-mono text-xs text-fg" title={signature}>
                  {signature}
                </div>
                <div className="mt-0.5 text-[10px] text-muted">Sample-derived text, rendered inert</div>
              </div>
              {method && <EvidenceChips refs={[method.evidence_ref]} max={1} />}
            </header>
            <pre className="max-h-[470px] overflow-auto bg-ground p-3 font-mono text-[12px] leading-6">
              {method?.body.split('\n').map((line, index) => {
                const number = method.line_start + index
                return (
                  <div
                    key={number}
                    className={`grid grid-cols-[3rem_1fr] ${cited.has(number) ? 'bg-accent/15' : ''}`}
                  >
                    <span className={cited.has(number) ? 'text-accent' : 'text-dim'}>{number}</span>
                    <code className="whitespace-pre-wrap break-words text-fg">{line || ' '}</code>
                  </div>
                )
              })}
            </pre>
          </section>

          <section className="min-w-0">
            <header className="eyebrow border-b border-line-soft px-4 py-3">
              GROUNDED REASONING
            </header>
            <div className="max-h-[500px] space-y-4 overflow-auto p-3">
              {!interpretation ? (
                <Empty>No validated model interpretation was produced for this method.</Empty>
              ) : (
                <>
                  <div>
                    <div className="flex items-center gap-2">
                      <Braces size={14} className="text-accent" />
                      <Tag tone={interpretation.insufficient_evidence ? 'warn' : 'good'}>
                        {interpretation.confidence} confidence
                      </Tag>
                    </div>
                    <p className="mt-2 text-sm leading-relaxed text-fg">{interpretation.summary}</p>
                  </div>
                  <div className="space-y-2">
                    {interpretation.claims.map((claim, index) => (
                      <div
                        key={index}
                        className={`border-l-2 pl-3 ${
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
                        <div className="mt-1.5"><EvidenceChips refs={claim.evidence_refs} /></div>
                      </div>
                    ))}
                  </div>
                  {Object.keys(interpretation.renamed_symbols).length > 0 && (
                    <div>
                      <div className="mb-1.5 text-[10px] font-semibold tracking-widest text-muted">
                        SUGGESTED NAMES
                      </div>
                      {Object.entries(interpretation.renamed_symbols).map(([from, to]) => (
                        <div key={from} className="mb-1 text-[11px]">
                          <div className="truncate font-mono text-dim" title={from}>{from}</div>
                          <div className="font-mono text-accent">{to}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </div>
          </section>
        </div>
      )}

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="Deterministically verified strings" right={<Link2 size={15} className="text-accent" />}>
          {verdict.verified_strings.length === 0 ? (
            <Empty>No model-proposed decoding was reproduced by the fixed evaluator.</Empty>
          ) : (
            <div className="space-y-3">
              {verdict.verified_strings.map((item, index) => (
                <div key={index} className="border-b border-line-soft pb-3 last:border-0 last:pb-0">
                  <div className="flex items-center gap-2">
                    <Tag tone={item.verified ? 'good' : 'bad'}>{item.verified ? 'verified' : 'rejected'}</Tag>
                    <span className="font-mono text-xs text-accent">{item.transform}</span>
                  </div>
                  <div className="mt-2 grid gap-1 font-mono text-xs">
                    <div className="break-all text-dim">{item.ciphertext}</div>
                    <div className="break-all text-fg">{item.plaintext}</div>
                  </div>
                  <div className="mt-1.5"><EvidenceChips refs={item.evidence_refs} /></div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        <Panel title="Model tool activity" right={<Wrench size={15} className="text-accent" />}>
          {verdict.tool_calls.length === 0 ? (
            <Empty>No model tool call was made in this run.</Empty>
          ) : (
            <div className="max-h-72 space-y-2 overflow-auto">
              {verdict.tool_calls.map((call) => (
                <div key={call.id} className="flex items-start gap-3 border-b border-line-soft pb-2 last:border-0">
                  <Tag tone={call.status === 'ok' ? 'good' : call.status === 'rejected' ? 'warn' : 'bad'}>
                    {call.status}
                  </Tag>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs text-fg">{call.name}</span>
                      <span className="font-mono text-[10px] text-dim">{call.duration_ms} ms</span>
                    </div>
                    <p className="mt-0.5 text-xs text-muted">{call.result_summary}</p>
                    <div className="mt-1"><EvidenceChips refs={call.evidence_refs} max={3} /></div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </div>
    </div>
  )
}

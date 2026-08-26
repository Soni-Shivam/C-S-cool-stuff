/**
 * Sandbox: outcome, provenance, API timeline, network, drops, evasion.
 *
 * The outcome banner is the honesty-critical part. CLAUDE.md: "A sample that
 * produced no observations is `inconclusive`, never benign. Environment-aware
 * stalling looks identical to a clean app if you let it." So `outcome` is rendered
 * literally from the trace and an `inconclusive` run gets an explicit sentence
 * saying it is not a clean bill of health — the one reading a viewer would
 * otherwise supply for themselves.
 *
 * The API timeline is a horizontal track rather than a table on T6.4's advice: a
 * reader needs to see clustering in time, which a table cannot show.
 */

import type { Artefact } from '../api/client'
import { ProvenanceBadge, VerdictProvenanceBadge } from '../components/ProvenanceBadge'
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
import type { ApiEvent, DynamicTrace, TraceOutcome } from '../api/types'
import type { Verdict } from '../api/verdict.gen'

const OUTCOME_TONE: Record<TraceOutcome, 'good' | 'warn' | 'bad'> = {
  completed: 'good',
  inconclusive: 'warn',
  failed: 'bad',
  timeout: 'warn',
  crashed: 'bad',
}

function Timeline({ events }: { events: ApiEvent[] }) {
  if (events.length === 0) return <Empty>No API events recorded.</Empty>
  const span = Math.max(1, ...events.map((e) => e.t_ms))

  return (
    <div className="space-y-2">
      <div className="relative h-10 overflow-hidden rounded-[var(--radius-tile)] border border-line-soft bg-ground">
        {events.map((event, i) => (
          <span
            key={i}
            title={`${event.t_ms} ms · ${event.api}${event.count > 1 ? ` ×${event.count}` : ''}`}
            className="absolute top-0 h-full w-0.5 bg-v400/70 transition-colors hover:bg-magenta"
            style={{ left: `${(event.t_ms / span) * 98}%` }}
          />
        ))}
        <span className="absolute right-1 bottom-0 font-mono text-[10px] text-dim">{span} ms</span>
      </div>
      <div className="max-h-72 overflow-auto">
        <table className="w-full text-left text-xs">
          <thead className="sticky top-0 bg-ground-1 text-muted">
            <tr>
              <th className="py-1 pr-2 font-medium">t</th>
              <th className="py-1 pr-2 font-medium">api</th>
              <th className="py-1 pr-2 font-medium">args</th>
              <th className="py-1 font-medium">×</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event, i) => (
              <tr key={i} className="border-t border-line-soft align-top">
                <td className="py-1 pr-2 font-mono text-dim">{event.t_ms}</td>
                <td className="py-1 pr-2 font-mono break-all text-fg">{event.api}</td>
                <td className="py-1 pr-2 font-mono break-all text-muted">{event.args.join(', ')}</td>
                <td className="py-1 font-mono text-muted">{event.count > 1 ? event.count : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

/** The `[synthesised]` marker `build_verdict()` appends to a capture it did not observe. */
const SYNTHESISED = '  [synthesised]'

/**
 * `verdict.dynamic_trace` — what the sandbox contributed to the shared verdict.
 *
 * Three states, kept distinct on purpose:
 *
 *   null            nothing ever ran this sample. There is no trace, and the panel says
 *                   that rather than drawing three empty lists.
 *   detonated=false the sample was put in front of a sandbox and did not detonate.
 *   detonated=true  it ran. The lists may still be empty, and an empty list here is a
 *                   real observation — "it ran and did nothing we could see" — which is
 *                   NOT a clean bill of health, because that is also what an
 *                   environment-aware sample looks like.
 */
function VerdictTracePanel({ verdict }: { verdict: Verdict }) {
  const trace = verdict.dynamic_trace

  if (trace === null) {
    return (
      <Panel title="Sandbox contribution to the verdict">
        <div className="space-y-2">
          <VerdictProvenanceBadge provenance={verdict.provenance} withBlurb />
          <p className="rounded border border-bad/30 bg-bad/5 px-3 py-2.5 text-sm text-fg">
            <strong className="text-bad">Not yet detonated.</strong> No trace source produced
            anything for this sample, so no runtime behaviour contributed to the verdict —
            every finding on this job was read out of the file. This is not evidence that the
            app is inert; it is the absence of evidence either way.
          </p>
        </div>
      </Panel>
    )
  }

  const lists: [string, string[], string][] = [
    ['API calls', trace.api_calls, 'Hooked API names only — arguments are withheld, they can carry a victim OTP'],
    ['Decrypted strings', trace.decrypted_strings, 'Recovered before encryption, redacted on the way into the verdict'],
    ['Network captures', trace.network_captures, 'Method and host'],
  ]

  return (
    <Panel
      title="Sandbox contribution to the verdict"
      subtitle="Read from the shared Verdict (contract A15) — the same three lists the phone screen sees"
      right={<VerdictProvenanceBadge provenance={verdict.provenance} />}
    >
      <div className="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <Tag tone={trace.detonated ? 'bad' : 'warn'}>
            {trace.detonated ? 'detonated' : 'did not detonate'}
          </Tag>
          {trace.detonated &&
            trace.api_calls.length === 0 &&
            trace.decrypted_strings.length === 0 &&
            trace.network_captures.length === 0 && (
              <span className="text-xs text-warn">
                It ran and produced nothing observable — silence is not innocence.
              </span>
            )}
        </div>

        <div className="grid gap-4 lg:grid-cols-3">
          {lists.map(([label, values, note]) => (
            <div key={label}>
              <div className="text-[10px] tracking-widest text-dim uppercase">
                {label} ({values.length})
              </div>
              <p className="mt-0.5 text-[11px] text-dim">{note}</p>
              {values.length === 0 ? (
                <p className="mt-1.5 text-sm text-muted italic">none recorded</p>
              ) : (
                <ul className="mt-1.5 max-h-56 space-y-1 overflow-auto font-mono text-[11px] break-all text-muted">
                  {values.map((value, i) => {
                    const synthesised = value.endsWith(SYNTHESISED)
                    return (
                      <li key={i} className="flex flex-wrap items-center gap-1.5">
                        <span>{synthesised ? value.slice(0, -SYNTHESISED.length) : value}</span>
                        {synthesised && (
                          <Tag
                            tone="warn"
                            title="Our own Generative C2 served this response. It is not attacker infrastructure and must never be reported as such."
                          >
                            synthesised by us
                          </Tag>
                        )}
                      </li>
                    )
                  })}
                </ul>
              )}
            </div>
          ))}
        </div>
      </div>
    </Panel>
  )
}

export function SandboxTab({
  dynamic,
  verdict,
}: {
  dynamic: Artefact<DynamicTrace> | null
  verdict: Artefact<Verdict> | null
}) {
  return (
    <div className="space-y-4">
      <ArtefactGate artefact={verdict}>
        {(value) => <VerdictTracePanel verdict={value} />}
      </ArtefactGate>

      <ArtefactGate artefact={dynamic}>
      {(trace) => (
        <div className="space-y-5">
          <DegradedNotice result={trace} />

          <SectionHead
            eyebrow="Dynamic analysis"
            title="What the sample did"
            lede="Behaviour observed while the package ran under instrumentation. Provenance is read from the trace itself — a replayed capture and a live detonation are never presented as the same thing."
            right={<ProvenanceBadge trace={trace} />}
          />

          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile
              tone="gradient"
              value={trace.api_events.length}
              label={plural(trace.api_events.length, 'API event group')}
              hint="Aggregated by (technique, hook) before reaching the ledger or a prompt."
            />
            <StatTile
              tone="wash"
              value={trace.network_flows.length}
              label={plural(trace.network_flows.length, 'network flow')}
              hint={`${count(trace.decrypted_blobs.length, 'decrypted blob')} recovered before encryption`}
            />
            <StatTile
              value={trace.dex_loads.length}
              label={plural(trace.dex_loads.length, 'dex load')}
              hint={`${count(trace.file_writes.length, 'file write')} observed`}
            />
            <StatTile
              value={trace.evasion_observations.length}
              label={plural(trace.evasion_observations.length, 'evasion probe')}
              hint={
                trace.evasion_observations.length === 0
                  ? 'The sample made no environment probe that the harness recognised.'
                  : 'Environment questions the sample asked before deciding what to do.'
              }
            />
          </div>

          <div className="grid gap-4 xl:grid-cols-2">
            <Panel title="Outcome">
              <div className="flex flex-wrap items-center gap-2">
                <Tag tone={OUTCOME_TONE[trace.outcome]}>{trace.outcome}</Tag>
                <Tag tone={trace.detonated ? 'bad' : 'neutral'}>
                  {trace.detonated ? 'detonated' : 'did not detonate'}
                </Tag>
              </div>
              {trace.detonation_reason && (
                <p className="mt-2 text-sm text-muted">
                  rule fired: <span className="font-mono text-fg">{trace.detonation_reason}</span>
                </p>
              )}
              {trace.outcome === 'inconclusive' && (
                <p className="mt-2 rounded-[var(--radius-tile)] border border-warn/30 bg-warn/[0.07] px-2.5 py-2 text-xs text-warn">
                  Inconclusive is <strong>not</strong> a clean result. Environment-aware stalling is
                  indistinguishable from a benign app without further interrogation.
                </p>
              )}
            </Panel>

            <Panel title="Provenance">
              <ProvenanceBadge trace={trace} detailed />
            </Panel>
          </div>

          <Panel title={`API timeline (${trace.api_events.length} deduplicated events)`}>
            <Timeline events={trace.api_events} />
          </Panel>

          <div className="grid gap-4 xl:grid-cols-2">
            <Panel title={`Network flows (${trace.network_flows.length})`}>
              {trace.network_flows.length === 0 ? (
                <Empty>No flow captured.</Empty>
              ) : (
                <ul className="max-h-72 space-y-2 overflow-auto">
                  {trace.network_flows.map((flow, i) => (
                    <li key={i} className="rounded-[var(--radius-tile)] border border-line-soft bg-ground-2/60 p-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-xs text-fg">{flow.method}</span>
                        <span className="font-mono text-[11px] break-all text-muted">{flow.url}</span>
                        {flow.status != null && <Tag>{flow.status}</Tag>}
                        {flow.synthesised && (
                          <Tag tone="warn" title="We served this response from the Generative C2 — not real attacker infrastructure">
                            synthesised response
                          </Tag>
                        )}
                        {flow.tls_intercepted && <Tag tone="accent">TLS intercepted</Tag>}
                      </div>
                      {flow.req_body_preview && (
                        <pre className="mt-1 overflow-auto rounded bg-ground p-1.5 font-mono text-[10px] text-muted">
                          {flow.req_body_preview}
                        </pre>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title={`Evasion observations (${trace.evasion_observations.length})`}>
              {trace.evasion_observations.length === 0 ? (
                <Empty>No probe → miss → stall pattern observed.</Empty>
              ) : (
                <ul className="max-h-72 space-y-2 overflow-auto">
                  {trace.evasion_observations.map((observation, i) => (
                    <li key={i} className="rounded-[var(--radius-tile)] border border-line-soft bg-ground-2/60 p-2 text-xs">
                      <div className="flex flex-wrap items-center gap-2">
                        <Tag tone={observation.result === 'MISS' ? 'warn' : 'bad'}>{observation.result}</Tag>
                        <span className="text-muted">{observation.probe_kind}</span>
                        <span className="font-mono break-all text-fg">{observation.queried}</span>
                        <span className="font-mono text-dim">@{observation.t_ms} ms</span>
                      </div>
                      {observation.followed_by_stall && (
                        <div className="mt-1 text-warn">
                          followed by stall
                          {observation.stall_duration_ms != null && ` (${observation.stall_duration_ms} ms)`}
                        </div>
                      )}
                      {observation.inferred_requirement && (
                        <div className="mt-0.5 text-muted">→ {observation.inferred_requirement}</div>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>

          <div className="grid gap-4 xl:grid-cols-3">
            <Panel title={`Decrypted blobs (${trace.decrypted_blobs.length})`} subtitle="Cipher.doFinal, pre-encryption">
              {trace.decrypted_blobs.length === 0 ? (
                <Empty>none</Empty>
              ) : (
                <ul className="max-h-56 space-y-1.5 overflow-auto text-xs">
                  {trace.decrypted_blobs.map((blob, i) => (
                    <li key={i} className="rounded bg-ground-2 p-1.5">
                      <div className="flex flex-wrap gap-1.5">
                        {blob.algorithm && <Tag>{blob.algorithm}</Tag>}
                        <Tag>{blob.length_bytes} B</Tag>
                        {blob.occurrences > 1 && <Tag>×{blob.occurrences}</Tag>}
                        {blob.contains_dex_magic && <Tag tone="bad">DEX magic</Tag>}
                        {blob.contains_url && <Tag tone="warn">URL</Tag>}
                      </div>
                      <pre className="mt-1 overflow-auto font-mono text-[10px] text-muted">
                        {blob.plaintext_preview}
                      </pre>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title={`Dex loads (${trace.dex_loads.length})`} subtitle="T1407 — code static analysis never saw">
              {trace.dex_loads.length === 0 ? (
                <Empty>none</Empty>
              ) : (
                <ul className="max-h-56 space-y-1.5 overflow-auto text-xs">
                  {trace.dex_loads.map((load, i) => (
                    <li key={i} className="rounded bg-ground-2 p-1.5">
                      <div className="font-mono break-all text-fg">{load.loader}</div>
                      <div className="font-mono break-all text-muted">{load.path ?? '—'}</div>
                      {!load.in_original_apk && <Tag tone="bad">not in original APK</Tag>}
                    </li>
                  ))}
                </ul>
              )}
            </Panel>

            <Panel title={`File writes (${trace.file_writes.length})`}>
              {trace.file_writes.length === 0 ? (
                <Empty>none</Empty>
              ) : (
                <ul className="max-h-56 space-y-1 overflow-auto font-mono text-[11px] break-all text-muted">
                  {trace.file_writes.map((write, i) => (
                    <li key={i}>
                      {write.path}
                      {write.is_executable_content && <span className="ml-1 text-bad">[exec]</span>}
                      {write.deleted_after && <span className="ml-1 text-warn">[deleted]</span>}
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>

          {trace.screenshots.length > 0 && (
            <Panel title={`Screenshots (${trace.screenshots.length})`}>
              <ul className="space-y-0.5 font-mono text-[11px] break-all text-muted">
                {trace.screenshots.map((path) => (
                  <li key={path}>{path}</li>
                ))}
              </ul>
            </Panel>
          )}
        </div>
      )}
      </ArtefactGate>
    </div>
  )
}

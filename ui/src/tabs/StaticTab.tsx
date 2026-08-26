/**
 * Static: permissions and combos, components, certificate, packing, call paths.
 *
 * Two judgement calls encoded here, both from the contracts' own docstrings:
 *
 *  * `self_signed` is shown greyed and labelled a non-signal. Every Android APK is
 *    self-signed, so drawing it in red would be a 100% false-positive indicator on
 *    the busiest card in the tab.
 *  * A call path with `reachable_from_lifecycle === false` is dimmed and marked
 *    "not reachable". Dead library code reaches dangerous sinks constantly, and a
 *    tree that treats it identically to a live path overstates the finding.
 */

import { useState } from 'react'
import type { Artefact } from '../api/client'
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
import type { CallPath, Severity, StaticReport } from '../api/types'

const SEVERITY_TONE: Record<Severity, 'bad' | 'warn' | 'neutral'> = {
  critical: 'bad',
  high: 'bad',
  medium: 'warn',
  low: 'neutral',
}

function CallPathRow({ path }: { path: CallPath }) {
  const [open, setOpen] = useState(false)
  return (
    <li className={`border-b border-line-soft py-2 last:border-0 ${path.reachable_from_lifecycle ? '' : 'opacity-55'}`}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-start gap-2 text-left"
      >
        <span className="mt-0.5 text-dim">{open ? '▾' : '▸'}</span>
        <span className="flex-1">
          <span className="font-mono text-xs break-all text-fg">{path.sink_signature}</span>
          <span className="mt-0.5 block text-[11px] text-muted">
            entry <span className="font-mono">{path.entrypoint}</span> ({path.entrypoint_kind}) ·{' '}
            {path.path.length} frames
          </span>
        </span>
        {path.reachable_from_lifecycle ? (
          <Tag tone="bad">reachable</Tag>
        ) : (
          <Tag title="Sink is present but no lifecycle entrypoint reaches it — dead code does not score">
            not reachable
          </Tag>
        )}
      </button>
      {open && (
        <ol className="mt-2 ml-5 space-y-0.5 border-l border-line pl-3">
          {path.path.map((frame, i) => (
            <li key={i} className="font-mono text-[11px] break-all text-muted">
              {frame}
            </li>
          ))}
        </ol>
      )}
    </li>
  )
}

export function StaticTab({ report }: { report: Artefact<StaticReport> | null }) {
  return (
    <ArtefactGate artefact={report}>
      {(value) => {
        const inCombo = new Set(value.permission_combos.flatMap((combo) => combo.permissions))
        return (
          <div className="space-y-5">
            <DegradedNotice result={value} />

            <SectionHead
              eyebrow="Static analysis"
              title="What the package declares"
              lede="Manifest, certificate, packing and reachability — everything recoverable without running a line of the sample's code."
              right={
                <>
                  <Tag tone="accent">{count(value.permissions.length, 'permission')}</Tag>
                  <Tag tone={value.permission_combos.length > 0 ? 'bad' : 'good'}>
                    {count(value.permission_combos.length, 'risky combination')}
                  </Tag>
                  <Tag>{count(value.components.length, 'component')}</Tag>
                </>
              }
            />

            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
              <StatTile
                tone="gradient"
                value={value.call_paths.length}
                label={plural(value.call_paths.length, 'sink path')}
                hint={`${count(value.sink_hits.length, 'distinct sink')} reached`}
              />
              <StatTile
                tone="wash"
                value={value.exported_unprotected.length}
                label="exported, unguarded"
                hint="Components any other app on the device can start."
              />
              <StatTile
                value={value.entropy_mean.toFixed(2)}
                label="mean entropy"
                hint={`${value.dex_count} dex · ${value.reflection_count} reflection sites`}
              />
              <StatTile
                value={value.packer_hints.length + value.dcl_indicators.length}
                label="packing / DCL hints"
                hint={
                  value.packer_hints.length + value.dcl_indicators.length === 0
                    ? 'No packer or dynamic-code-loading indicator matched.'
                    : [...value.packer_hints, ...value.dcl_indicators].join(', ')
                }
              />
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              <Panel
                title="Permission combinations"
                subtitle="A combination is the signal — a single permission is weak"
              >
                {value.permission_combos.length === 0 ? (
                  <Empty>No high-risk combination matched.</Empty>
                ) : (
                  <ul className="space-y-2.5">
                    {value.permission_combos.map((combo) => (
                      <li key={combo.rule_id} className="rounded-[var(--radius-tile)] border border-line-soft bg-ground-2/60 p-2.5">
                        <div className="flex items-center gap-2">
                          <Tag tone={SEVERITY_TONE[combo.severity]}>{combo.severity}</Tag>
                          <span className="font-mono text-[11px] text-muted">{combo.rule_id}</span>
                          {combo.mitre && <Tag tone="accent">{combo.mitre}</Tag>}
                        </div>
                        <p className="mt-1.5 text-sm text-fg">{combo.description}</p>
                        <div className="mt-1.5 flex flex-wrap gap-1">
                          {combo.permissions.map((permission) => (
                            <span
                              key={permission}
                              className="rounded-md bg-ground px-2 py-0.5 font-mono text-[10px] text-muted"
                            >
                              {permission}
                            </span>
                          ))}
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>

              <Panel title="Certificate">
                <div className="space-y-2.5">
                  <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
                    {(
                      [
                        ['subject', value.certificate.subject],
                        ['issuer', value.certificate.issuer],
                        ['valid from', value.certificate.not_before],
                        ['age', `${value.certificate.age_days} days`],
                        ['sha256', value.certificate.sha256],
                      ] as [string, string][]
                    ).map(([key, text]) => (
                      <div key={key} className="contents">
                        <dt className="text-muted">{key}</dt>
                        <dd className="font-mono break-all text-fg">{text}</dd>
                      </div>
                    ))}
                  </dl>
                  <div className="flex flex-wrap gap-2">
                    {value.certificate.brand_mismatch && (
                      <Tag tone="bad">
                        brand mismatch{value.certificate.brand_claimed && `: claims ${value.certificate.brand_claimed}`}
                      </Tag>
                    )}
                    {value.certificate.known_bad_reuse && <Tag tone="bad">reused by known-bad samples</Tag>}
                    {value.certificate.debug_cert && <Tag tone="warn">debug certificate</Tag>}
                    {value.certificate.self_signed && (
                      <Tag title="Every Android APK is self-signed — this is not a risk signal">
                        self-signed (non-signal)
                      </Tag>
                    )}
                  </div>
                </div>
              </Panel>

              <Panel title="Packing & code loading">
                <div className="flex flex-wrap gap-2">
                  <Tag title="Mean Shannon entropy across archive entries">
                    entropy {value.entropy_mean.toFixed(2)}
                  </Tag>
                  <Tag>{value.dex_count} dex</Tag>
                  <Tag>{value.reflection_count} reflection sites</Tag>
                  {value.packer_hints.map((hint) => (
                    <Tag key={hint} tone="bad">
                      packer: {hint}
                    </Tag>
                  ))}
                  {value.dcl_indicators.map((indicator) => (
                    <Tag key={indicator} tone="warn">
                      DCL: {indicator}
                    </Tag>
                  ))}
                  {value.native_libs.map((lib) => (
                    <Tag key={lib}>{lib}</Tag>
                  ))}
                </div>
                {value.deep_link_schemes.length > 0 && (
                  <div className="mt-3">
                    <h4 className="eyebrow mb-2">Deep link schemes</h4>
                    <div className="flex flex-wrap gap-1">
                      {value.deep_link_schemes.map((scheme) => (
                        <span key={scheme} className="font-mono text-[11px] text-fg">
                          {scheme}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </Panel>

              <Panel title="Over-privilege & drift">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <h4 className="eyebrow mb-2">Declared, not used</h4>
                    {value.declared_not_used.length === 0 ? (
                      <Empty>none</Empty>
                    ) : (
                      <ul className="space-y-0.5 font-mono text-[11px] text-warn">
                        {value.declared_not_used.map((permission) => (
                          <li key={permission}>{permission}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                  <div>
                    <h4 className="eyebrow mb-2">Used, not declared</h4>
                    {value.used_not_declared.length === 0 ? (
                      <Empty>none</Empty>
                    ) : (
                      <ul className="space-y-0.5 font-mono text-[11px] text-bad">
                        {value.used_not_declared.map((permission) => (
                          <li key={permission}>{permission}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              </Panel>
            </div>

            <Panel
              title="Call paths to dangerous sinks"
              subtitle={`${value.call_paths.length} paths · ${value.sink_hits.length} distinct sinks hit`}
            >
              {value.call_paths.length === 0 ? (
                <Empty>No source-to-sink path was recovered.</Empty>
              ) : (
                <ul>
                  {value.call_paths.map((path, i) => (
                    <CallPathRow key={`${path.sink_id}-${i}`} path={path} />
                  ))}
                </ul>
              )}
            </Panel>

            <div className="grid gap-4 xl:grid-cols-2">
              <Panel title={`Components (${value.components.length})`}>
                <div className="max-h-72 overflow-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="sticky top-0 bg-ground-1 text-muted">
                      <tr>
                        <th className="py-1 pr-2 font-medium">name</th>
                        <th className="py-1 pr-2 font-medium">kind</th>
                        <th className="py-1 font-medium">exported</th>
                      </tr>
                    </thead>
                    <tbody>
                      {value.components.map((component) => (
                        <tr key={`${component.kind}:${component.name}`} className="border-t border-line-soft">
                          <td className="py-1 pr-2 font-mono break-all text-fg">{component.name}</td>
                          <td className="py-1 pr-2 text-muted">{component.kind}</td>
                          <td className="py-1">
                            {component.exported ? (
                              component.permission ? (
                                <Tag tone="warn">exported, guarded</Tag>
                              ) : (
                                <Tag tone="bad">exported, unguarded</Tag>
                              )
                            ) : (
                              <span className="text-dim">no</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>

              <Panel title={`Permissions (${value.permissions.length})`}>
                <div className="flex max-h-72 flex-wrap gap-1 overflow-auto">
                  {value.permissions.map((permission) => (
                    <span
                      key={permission}
                      className={`rounded px-1.5 py-0.5 font-mono text-[11px] ${
                        inCombo.has(permission)
                          ? 'bg-bad/15 text-bad ring-1 ring-bad/40'
                          : 'bg-ground-2 text-muted'
                      }`}
                      title={inCombo.has(permission) ? 'part of a matched high-risk combination' : undefined}
                    >
                      {permission}
                    </span>
                  ))}
                </div>
              </Panel>
            </div>

            <div className="grid gap-4 xl:grid-cols-2">
              <Panel title={`URLs (${value.urls.length})`} subtitle="Defanged — sample-derived, never rendered as links">
                {value.urls.length === 0 ? (
                  <Empty>none extracted</Empty>
                ) : (
                  <ul className="max-h-56 space-y-0.5 overflow-auto font-mono text-[11px] break-all text-muted">
                    {value.urls.map((url) => (
                      <li key={url}>{url}</li>
                    ))}
                  </ul>
                )}
              </Panel>

              <Panel
                title={`Hypotheses (${value.hypotheses.length})`}
                subtitle="The static → dynamic bridge: what the sandbox is told to watch"
              >
                {value.hypotheses.length === 0 ? (
                  <Empty>none derived</Empty>
                ) : (
                  <ul className="max-h-56 space-y-2 overflow-auto">
                    {value.hypotheses.map((hypothesis) => (
                      <li key={hypothesis.id} className="rounded-[var(--radius-tile)] border border-line-soft bg-ground-2/60 p-2">
                        <div className="flex items-center gap-2">
                          <Tag tone="accent">{hypothesis.kind}</Tag>
                          <span className="text-[11px] text-muted">priority {hypothesis.priority}</span>
                        </div>
                        <p className="mt-1 text-xs text-fg">{hypothesis.statement}</p>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
            </div>
          </div>
        )
      }}
    </ArtefactGate>
  )
}

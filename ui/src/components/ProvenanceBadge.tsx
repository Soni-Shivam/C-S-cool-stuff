/**
 * The replay-vs-live badge.
 *
 * CLAUDE.md, honesty requirements: "**Replay vs. live is read from the trace, not
 * from a config.** A trace carries the image version, VM instance id, and run
 * timestamp it was produced by; the UI badge is derived from those. Replaying a
 * real captured trace is legitimate and must be disclosed on screen; presenting it
 * as live is not."
 *
 * This component therefore takes a `DynamicTrace` and nothing else. There is no
 * prop for "mode", no read of settings, and no way for a caller to tell it what to
 * say. Four states, in decreasing order of evidentiary weight:
 *
 *   LIVE      source=live      — detonated on a real VM; shows image + instance id
 *   REPLAY    source=replay, synthetic=false — a real captured trace, replayed
 *   SYNTHETIC synthetic=true   — hand-authored fixture; no sample ever ran
 *   NO TRACE  source=unavailable — nothing observed the sample at all
 */

import { Tag } from './primitives'
import type { DynamicTrace } from '../api/types'

export type Provenance = 'live' | 'replay' | 'synthetic' | 'none'

export function provenanceOf(trace: DynamicTrace): Provenance {
  if (trace.source === 'unavailable') return 'none'
  if (trace.synthetic) return 'synthetic'
  return trace.source === 'live' ? 'live' : 'replay'
}

const COPY: Record<Provenance, { label: string; tone: 'good' | 'warn' | 'bad' | 'neutral'; blurb: string }> =
  {
    live: {
      label: 'LIVE DETONATION',
      tone: 'good',
      blurb: 'Observed on a sealed detonator VM.',
    },
    replay: {
      label: 'REPLAY — real captured trace',
      tone: 'warn',
      blurb: 'A previously captured real run, replayed. Not executed now.',
    },
    synthetic: {
      label: 'SYNTHETIC — hand-authored fixture',
      tone: 'bad',
      blurb: 'No sample was executed. Nothing here is an observation of this APK.',
    },
    none: {
      label: 'NO TRACE',
      tone: 'bad',
      blurb: 'No trace source could produce anything; the sample was not observed.',
    },
  }

export function ProvenanceBadge({ trace, detailed = false }: { trace: DynamicTrace; detailed?: boolean }) {
  const kind = provenanceOf(trace)
  const copy = COPY[kind]

  if (!detailed) {
    return (
      <Tag tone={copy.tone} title={copy.blurb}>
        {copy.label}
      </Tag>
    )
  }

  // Only fields the trace actually carries are shown. A missing image version is
  // rendered as "not recorded", never filled in from anywhere else.
  const rows: [string, string][] = [
    ['source', trace.source],
    ['run id', trace.run_id],
    ['emulator image', trace.emulator_image ?? 'not recorded'],
    ['vm instance', trace.vm_instance_id ?? 'not recorded'],
    ['harness', trace.harness_version ?? 'not recorded'],
    ['captured at', trace.captured_at ?? 'not recorded'],
  ]

  return (
    <div className="rounded-[var(--radius-tile)] border border-line bg-ground-2/60 p-3">
      <div className="flex flex-wrap items-center gap-2">
        <Tag tone={copy.tone}>{copy.label}</Tag>
        <Tag tone={trace.containment_verified ? 'good' : 'bad'}>
          {trace.containment_verified ? 'containment verified' : 'containment NOT verified'}
        </Tag>
      </div>
      <p className="mt-2 text-xs text-muted">{copy.blurb}</p>
      <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
        {rows.map(([key, value]) => (
          <div key={key} className="contents">
            <dt className="text-muted">{key}</dt>
            <dd className="font-mono break-all text-fg">{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

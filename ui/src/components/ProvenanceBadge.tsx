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
import type { Verdict } from '../api/verdict.gen'

/**
 * The same badge, read off the shared `Verdict` instead of off a raw trace.
 *
 * `Verdict.provenance` is computed by `build_verdict()` in
 * `drishti/contracts/verdict.py` from the trace itself — `STATIC_ONLY` when nothing
 * detonated, `REPLAY` when the trace was a fixture or carried `synthetic`, `LIVE`
 * only for a real run. This component takes that string and nothing else. There is
 * deliberately no prop, setting, or query parameter that can change what it says:
 * a route that could tell the badge "call this live" would defeat the field.
 */
const VERDICT_COPY: Record<
  Verdict['provenance'],
  { label: string; tone: 'good' | 'warn' | 'bad'; blurb: string }
> = {
  LIVE: {
    label: 'LIVE DETONATION',
    tone: 'good',
    blurb: 'This sample was executed on a sealed detonator VM and observed there.',
  },
  REPLAY: {
    label: 'REPLAY — not executed now',
    tone: 'warn',
    blurb:
      'The behaviour below came from a stored trace, not from a run that happened just now.',
  },
  STATIC_ONLY: {
    label: 'NO TRACE — STATIC ONLY',
    tone: 'bad',
    blurb:
      'Nothing executed this sample. Every finding below was read out of the file, never observed.',
  },
}

export function VerdictProvenanceBadge({
  provenance,
  withBlurb = false,
}: {
  provenance: Verdict['provenance']
  withBlurb?: boolean
}) {
  const copy = VERDICT_COPY[provenance]
  // STATIC_ONLY gets the heavier treatment rather than a quiet grey chip: it is the
  // state in which the dynamic half of the system contributed nothing, and a reader
  // skimming a score needs to see that before they act on it.
  const emphatic = provenance === 'STATIC_ONLY'

  return (
    <span className="inline-flex flex-wrap items-center gap-2">
      <span
        title={copy.blurb}
        className={`inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-[11px] font-semibold tracking-wide ${
          emphatic
            ? 'border-bad bg-bad/15 text-bad'
            : copy.tone === 'good'
              ? 'border-good/50 bg-good/10 text-good'
              : 'border-warn/50 bg-warn/10 text-warn'
        }`}
      >
        <span
          aria-hidden
          className={`h-1.5 w-1.5 rounded-full ${
            emphatic ? 'bg-bad' : copy.tone === 'good' ? 'bg-good' : 'bg-warn'
          }`}
        />
        {copy.label}
      </span>
      {withBlurb && <span className="text-xs text-muted">{copy.blurb}</span>}
    </span>
  )
}

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

/**
 * Tests for the code-graph layout.
 *
 * These exist because the module makes claims a screenshot cannot check. The only
 * real sample available on a developer machine is the canary, whose call graph is
 * two nodes on one path — it exercises none of the layering, ordering or cycle
 * handling below. Rather than eyeball a trivial graph and call the algorithm
 * verified, the interesting shapes are constructed here directly.
 *
 * The determinism test is the load-bearing one. "Same run, same picture" is what
 * makes a graph screenshot usable as evidence in a report, and a barycentre sweep
 * with an unstable tie-break would quietly break it.
 */

import { describe, expect, it } from 'vitest'
import { buildGraph, nodesTouchedBy, shortLabel, splitSignature } from './layout'
import type {
  CallPath,
  CodeInterpretation,
  DecompiledMethod,
  GenAIVerdict,
  StaticReport,
  ToolCallRecord,
} from '../api/types'

const sig = (owner: string, member: string) => `Lcom/x/${owner};->${member}()V`

const ENTRY = sig('MainActivity', 'onCreate')
const MID = sig('Loader', 'prepare')
const OTHER = sig('Worker', 'run')
const SINK = sig('Sms', 'sendTextMessage')
const SINK2 = sig('Net', 'openConnection')

function path(over: Partial<CallPath> & { path: string[] }): CallPath {
  return {
    sink_id: over.path[over.path.length - 1],
    sink_signature: over.path[over.path.length - 1],
    entrypoint: over.path[0],
    entrypoint_kind: 'lifecycle',
    reachable_from_lifecycle: true,
    ...over,
  }
}

function report(paths: CallPath[], decompiled: DecompiledMethod[] = []): StaticReport {
  return {
    errors: [],
    partial: false,
    duration_ms: 1,
    sha256: 'a'.repeat(64),
    package: 'com.x',
    app_label: 'X',
    version_name: '1.0',
    version_code: 1,
    min_sdk: 21,
    target_sdk: 34,
    permissions: [],
    permission_combos: [],
    components: [],
    exported_unprotected: [],
    deep_link_schemes: [],
    certificate: {
      sha256: 'b'.repeat(64),
      subject: 'CN=x',
      issuer: 'CN=x',
      not_before: '2020-01-01',
      not_after: '2050-01-01',
      age_days: 1,
      self_signed: true,
      known_bad_reuse: false,
      brand_mismatch: false,
      brand_claimed: null,
      debug_cert: false,
    },
    declared_not_used: [],
    used_not_declared: [],
    native_libs: [],
    dex_count: 1,
    entropy_mean: 0,
    packer_hints: [],
    dcl_indicators: [],
    reflection_count: 0,
    urls: [],
    crypto_constants: [],
    call_paths: paths,
    decompiled_methods: decompiled,
    sink_hits: [],
    hypotheses: [],
    ledger_refs: [],
  }
}

function method(signature: string, evidenceRef: string): DecompiledMethod {
  return {
    signature,
    body: 'line one\nline two',
    line_start: 1,
    line_end: 2,
    call_path_indexes: [0],
    evidence_ref: evidenceRef,
    truncated: false,
  }
}

function interpretation(signature: string): CodeInterpretation {
  return {
    method_signature: signature,
    summary: 'does a thing',
    claims: [
      {
        text: 'a claim',
        evidence_refs: ['ev_claim'],
        agent: 'reader',
        verifier_status: 'PASS',
      },
    ],
    renamed_symbols: {},
    confidence: 'medium',
    insufficient_evidence: false,
    cited_lines: [1],
  }
}

function verdict(over: Partial<GenAIVerdict> = {}): GenAIVerdict {
  return {
    errors: [],
    partial: false,
    duration_ms: 1,
    summary: '',
    claims: [],
    behavioural_risk_B: 0,
    B_rationale: '',
    behaviours: {},
    techniques: [],
    victim: null,
    impersonation: null,
    interpretations: [],
    tool_calls: [],
    verified_strings: [],
    elicitation_deployed: [],
    disagreement_flag: false,
    disagreement_note: null,
    llm_calls: 0,
    provider: 'test',
    ledger_refs: [],
    ...over,
  }
}

function toolCall(over: Partial<ToolCallRecord> = {}): ToolCallRecord {
  return {
    id: 'call_1',
    name: 'read_method',
    arguments: {},
    status: 'ok',
    result_summary: '',
    evidence_refs: [],
    duration_ms: 1,
    ...over,
  }
}

describe('splitSignature / shortLabel', () => {
  it('unpacks a smali signature', () => {
    expect(splitSignature(SINK)).toEqual({
      owner: 'com.x.Sms',
      member: 'sendTextMessage()V',
    })
    expect(shortLabel(SINK)).toBe('Sms.sendTextMessage')
  })

  it('passes an unrecognised signature through rather than mangling it', () => {
    expect(shortLabel('not a signature')).toBe('not a signature')
  })
})

describe('buildGraph', () => {
  it('derives every edge from a recorded call path and no others', () => {
    const graph = buildGraph(report([path({ path: [ENTRY, MID, SINK] })]), null)

    expect(graph.nodes.map((node) => node.id)).toEqual([ENTRY, MID, SINK])
    expect(graph.edges.map((edge) => [edge.from, edge.to])).toEqual([
      [ENTRY, MID],
      [MID, SINK],
    ])
  })

  it('layers nodes by longest path, so every forward edge points right', () => {
    // A short path and a long one converge on the same sink: the sink must sit
    // in the deeper column, or the edge from Worker would point backwards.
    const graph = buildGraph(
      report([
        path({ path: [ENTRY, SINK] }),
        path({ path: [ENTRY, MID, OTHER, SINK] }),
      ]),
      null,
    )

    expect(graph.byId.get(ENTRY)!.depth).toBe(0)
    expect(graph.byId.get(SINK)!.depth).toBe(3)
    for (const edge of graph.edges) {
      expect(graph.byId.get(edge.to)!.depth).toBeGreaterThan(graph.byId.get(edge.from)!.depth)
      expect(edge.back).toBe(false)
    }
  })

  it('marks a call cycle as a back edge instead of failing to lay out', () => {
    const graph = buildGraph(
      report([path({ path: [ENTRY, MID, OTHER] }), path({ path: [OTHER, MID, SINK] })]),
      null,
    )

    const cycle = graph.edges.find((edge) => edge.from === OTHER && edge.to === MID)
    expect(cycle?.back).toBe(true)
    expect(graph.nodes.every((node) => Number.isFinite(node.x) && Number.isFinite(node.y))).toBe(
      true,
    )
  })

  it('is deterministic: the same report lays out identically every time', () => {
    const input = report([
      path({ path: [ENTRY, MID, SINK] }),
      path({ path: [OTHER, MID, SINK2] }),
      path({ path: [ENTRY, OTHER, SINK2] }),
    ])
    const a = buildGraph(input, null)
    const b = buildGraph(input, null)

    const positions = (graph: typeof a) => graph.nodes.map((n) => [n.id, n.x, n.y])
    expect(positions(a)).toEqual(positions(b))
  })

  it('separates unretrieved, decompiled and interpreted methods', () => {
    const graph = buildGraph(
      report([path({ path: [ENTRY, MID, SINK] })], [method(ENTRY, 'ev_1'), method(MID, 'ev_2')]),
      verdict({ interpretations: [interpretation(MID)] }),
    )

    expect(graph.byId.get(ENTRY)!.retrieval).toBe('decompiled')
    expect(graph.byId.get(MID)!.retrieval).toBe('interpreted')
    expect(graph.byId.get(SINK)!.retrieval).toBe('unretrieved')
    expect(graph.unretrievedCount).toBe(1)
  })

  it('treats a missing verdict as nothing interpreted rather than as an error', () => {
    const graph = buildGraph(report([path({ path: [ENTRY, SINK] })], [method(ENTRY, 'ev_1')]), null)
    expect(graph.nodes.every((node) => node.retrieval !== 'interpreted')).toBe(true)
  })

  it('collects grounding refs from the body node and every claim', () => {
    const graph = buildGraph(
      report([path({ path: [ENTRY, SINK] })], [method(ENTRY, 'ev_body')]),
      verdict({ interpretations: [interpretation(ENTRY)] }),
    )
    expect(graph.byId.get(ENTRY)!.evidenceRefs).toEqual(['ev_body', 'ev_claim'])
  })

  it('returns an empty graph for a report with no call paths', () => {
    const graph = buildGraph(report([]), null)
    expect(graph.nodes).toEqual([])
    expect(graph.width).toBe(0)
  })
})

describe('nodesTouchedBy', () => {
  const graph = buildGraph(
    report([path({ path: [ENTRY, MID, SINK] })], [method(MID, 'ev_mid')]),
    verdict(),
  )

  it('matches a signature nested anywhere in the validated arguments', () => {
    const call = toolCall({ arguments: { targets: [{ signature: MID }] } })
    expect(nodesTouchedBy(call, graph)).toEqual([MID])
  })

  it('matches through a shared evidence ref', () => {
    expect(nodesTouchedBy(toolCall({ evidence_refs: ['ev_mid'] }), graph)).toEqual([MID])
  })

  it('reports no reach rather than guessing at a near-miss name', () => {
    const call = toolCall({ arguments: { signature: 'Lcom/x/Loader;->prepareOther()V' } })
    expect(nodesTouchedBy(call, graph)).toEqual([])
  })

  it('returns hits in graph order so a replay always animates the same way', () => {
    const call = toolCall({ arguments: { a: SINK, b: ENTRY, c: MID } })
    expect(nodesTouchedBy(call, graph)).toEqual([ENTRY, MID, SINK])
  })
})

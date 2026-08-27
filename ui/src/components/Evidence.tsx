/**
 * Evidence chips — the click path that makes the central claim checkable.
 *
 * PHASE_6 T6.4: "Every evidence chip is a link. Test the click path
 * upload -> score -> factor -> ML -> SHAP -> permission combo -> manifest line.
 * If any hop is broken, the central claim of the project is unverifiable on stage."
 *
 * So a chip is not decoration. It jumps to the Ledger tab with that node selected
 * and expanded. A ref the ledger cannot resolve renders as a visibly broken chip
 * rather than a dead-but-pretty one — an unresolvable reference is exactly the
 * thing `ledger.append()` exists to reject, and hiding it here would undo that.
 */

import { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { getEvidenceNode } from '../api/client'
import type { Artefact } from '../api/client'
import type { EvidenceNode } from '../api/types'
import { stageLabel } from './primitives'

export interface EvidenceNav {
  /** Jump to the Ledger tab, select `nodeId`, expand it. */
  showEvidence: (nodeId: string) => void
  /** Node ids known to exist for this job, for rendering unresolvable refs honestly. */
  knownIds: ReadonlySet<string>
}

export const EvidenceNavContext = createContext<EvidenceNav>({
  showEvidence: () => {},
  knownIds: new Set(),
})

export const useEvidenceNav = () => useContext(EvidenceNavContext)

/** Trim `ev_01932abc…` to something readable without losing identity. */
function shortId(id: string): string {
  return id.length > 14 ? `${id.slice(0, 12)}…` : id
}

export function EvidenceChip({ nodeId }: { nodeId: string }) {
  const { showEvidence, knownIds } = useEvidenceNav()
  // An empty knownIds means the ledger has not loaded yet — assume resolvable
  // rather than flashing every chip red on first paint.
  const resolvable = knownIds.size === 0 || knownIds.has(nodeId)

  return (
    <button
      type="button"
      onClick={() => showEvidence(nodeId)}
      title={resolvable ? `Open evidence ${nodeId}` : `${nodeId} is not in this job's ledger`}
      className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[11px] transition-all duration-200 ${
        resolvable
          ? 'border-v500/45 bg-v500/12 text-v300 hover:border-v400 hover:bg-v500/25 hover:shadow-[0_0_16px_-4px_rgba(168,85,247,0.9)]'
          : 'border-bad/50 bg-bad/10 text-bad line-through'
      }`}
    >
      {shortId(nodeId)}
    </button>
  )
}

/**
 * A capped chip list.
 *
 * A factor can cite twenty nodes, and twenty chips in the 256px score rail push the
 * D factor off the bottom of the screen — on a projector that means a judge never
 * sees the fourth term of the formula. The cap is display-only: every ref stays one
 * click away, and the count is always shown so nothing is silently dropped.
 */
export function EvidenceChips({
  refs,
  label,
  max = 6,
}: {
  refs: string[]
  label?: string
  max?: number
}) {
  const [expanded, setExpanded] = useState(false)

  // One chip per distinct node. A node cited twice is still one piece of evidence, and
  // two chips reading `ev_402b7878…` side by side look like the list rendered twice.
  // The producers are expected to send a unique list; this makes the display true
  // regardless of which one slips.
  const unique = useMemo(() => [...new Set(refs)], [refs])

  if (unique.length === 0) {
    return (
      <span className="text-[11px] text-muted italic" title="No evidence node cited">
        ungrounded
      </span>
    )
  }

  const shown = expanded ? unique : unique.slice(0, max)
  const hidden = unique.length - shown.length

  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {label && <span className="text-[11px] text-muted">{label}</span>}
      {shown.map((ref) => (
        <EvidenceChip key={ref} nodeId={ref} />
      ))}
      {hidden > 0 && (
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="rounded-full border border-line-bright bg-ground-2 px-2 py-0.5 text-[11px] text-muted transition-colors hover:border-v400 hover:text-v300"
        >
          +{hidden} more
        </button>
      )}
      {expanded && unique.length > max && (
        <button
          type="button"
          onClick={() => setExpanded(false)}
          className="rounded-full border border-line-bright bg-ground-2 px-2 py-0.5 text-[11px] text-muted transition-colors hover:border-v400 hover:text-v300"
        >
          show fewer
        </button>
      )}
    </span>
  )
}

/**
 * The authoritative end of the click path: `GET /api/evidence/{node_id}`.
 *
 * The ledger table renders from the job's node list, which is a *listing* — filtered,
 * capped, and fetched at some earlier moment. Resolving a chip against that list alone
 * means a reference the API can serve perfectly well shows up as unresolvable because
 * the browser happened not to have it. So the selected chip is resolved against the
 * drilldown route itself, which is the same answer an auditor with `curl` would get.
 *
 * A 404 here is a real finding and is displayed as one. `ledger.append()` refuses to
 * write a claim whose evidence does not resolve; if one is nonetheless cited on screen
 * and does not resolve, the interface must say so rather than quietly render nothing.
 */
export function EvidenceResolution({ nodeId }: { nodeId: string }) {
  const [state, setState] = useState<Artefact<EvidenceNode> | null>(null)

  useEffect(() => {
    let live = true
    setState(null)
    void getEvidenceNode(nodeId).then((result) => {
      if (live) setState(result)
    })
    return () => {
      live = false
    }
  }, [nodeId])

  if (state === null) {
    return <p className="text-sm text-muted">Resolving {nodeId}…</p>
  }

  if (state.state !== 'ready') {
    const detail =
      state.state === 'error'
        ? state.message
        : state.state === 'pending'
          ? `the pipeline is still at ${stageLabel(state.stage)}`
          : `${state.what} is not part of this build`
    return (
      <div className="rounded border border-bad/40 bg-bad/5 px-3 py-2.5 text-sm">
        <span className="text-bad">
          <span className="font-mono">{nodeId}</span> does not resolve.
        </span>{' '}
        <span className="text-muted">{detail}</span>
        <p className="mt-1 text-[11px] text-dim">
          A cited reference that the ledger cannot serve is a defect in the claim, not in the
          view. Reported here rather than hidden.
        </p>
      </div>
    )
  }

  const node = state.value
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-xs text-accent">{node.id}</span>
        <span className="rounded border border-line bg-ground-2 px-1.5 py-0.5 font-mono text-[11px] text-muted">
          {node.type}
        </span>
        <span className="text-[11px] text-muted">
          seq {node.seq} · {node.source_tool} · confidence {node.confidence.toFixed(2)}
        </span>
      </div>
      {node.location && (
        <div className="font-mono text-[11px] break-all text-muted">{node.location}</div>
      )}
      <pre className="max-h-64 overflow-auto rounded bg-ground p-3 font-mono text-xs leading-relaxed text-muted">
        {JSON.stringify(node.content, null, 2)}
      </pre>
      <div className="font-mono text-[10px] break-all text-dim">
        node_hash {node.node_hash}
      </div>
    </div>
  )
}

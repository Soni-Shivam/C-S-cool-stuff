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

import { createContext, useContext, useState } from 'react'

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
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 font-mono text-[11px] transition-colors ${
        resolvable
          ? 'border-accent/40 bg-accent-soft text-accent hover:border-accent hover:bg-accent/20'
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

  if (refs.length === 0) {
    return (
      <span className="text-[11px] text-muted italic" title="No evidence node cited">
        ungrounded
      </span>
    )
  }

  const shown = expanded ? refs : refs.slice(0, max)
  const hidden = refs.length - shown.length

  return (
    <span className="inline-flex flex-wrap items-center gap-1">
      {label && <span className="text-[11px] text-muted">{label}</span>}
      {shown.map((ref, i) => (
        <EvidenceChip key={`${ref}-${i}`} nodeId={ref} />
      ))}
      {hidden > 0 && (
        <button
          type="button"
          onClick={() => setExpanded(true)}
          className="rounded border border-line px-1.5 py-0.5 text-[11px] text-muted hover:border-accent/60 hover:text-accent"
        >
          +{hidden} more
        </button>
      )}
      {expanded && refs.length > max && (
        <button
          type="button"
          onClick={() => setExpanded(false)}
          className="rounded border border-line px-1.5 py-0.5 text-[11px] text-muted hover:border-accent/60 hover:text-accent"
        >
          show fewer
        </button>
      )}
    </span>
  )
}

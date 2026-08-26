/**
 * The two affordances an analyst reaches for constantly, and the app had neither.
 *
 * **Filtering.** `LedgerTab` already proved the pattern — chips and selects that narrow a
 * list — but nothing else used it, and the screen where an analyst actually works
 * (Static) renders 122 components, 50 permissions and 100 URLs as one unbroken wall. The
 * answer to "is READ_SMS declared?" was to scroll.
 *
 * **Copying.** There was no copy control anywhere in the app. An analyst's next action is
 * always to paste somewhere else — the sha256 into VirusTotal, the C2 host into a
 * blocklist, the evidence id into a ticket — and the only way to do it was to select
 * monospace text out of a `break-all` blob by hand.
 *
 * The counting rule is the one honesty property here: whenever a filter hides rows, the
 * total is shown beside the count. "12 permissions" and "12 of 122 permissions" are
 * different claims, and a filtered list that reads like a complete one is the
 * list-shaped version of the reporting bugs this project keeps finding.
 */

import { type ReactNode, useMemo, useState } from 'react'
import { matches, summarise } from './analyst'
import { Empty } from './primitives'

/**
 * Copy one value to the clipboard, confirming that it happened.
 *
 * The confirmation matters more than it looks: a copy control that gives no feedback
 * gets pressed twice, and the second press is how someone ends up pasting the wrong
 * thing into a ticket. Failure is reported too — `navigator.clipboard` rejects outright
 * on an insecure origin, and silently doing nothing would be indistinguishable from
 * success.
 */
export function CopyButton({
  value,
  label = 'copy',
  title,
}: {
  value: string
  label?: string
  title?: string
}) {
  const [state, setState] = useState<'idle' | 'done' | 'failed'>('idle')

  async function copy() {
    try {
      await navigator.clipboard.writeText(value)
      setState('done')
    } catch {
      setState('failed')
    }
    window.setTimeout(() => setState('idle'), 1400)
  }

  return (
    <button
      type="button"
      onClick={copy}
      title={title ?? `Copy ${label}`}
      disabled={!value}
      className="shrink-0 rounded-full border border-line-bright bg-ground-2 px-2 py-0.5 font-sans text-[10px] tracking-wide text-muted transition-colors hover:border-v400 hover:text-fg disabled:opacity-40"
    >
      {state === 'done' ? 'copied' : state === 'failed' ? 'blocked' : label}
    </button>
  )
}

/** A value shown with a copy control beside it, for anything worth taking away. */
export function Copyable({
  value,
  className = '',
  children,
}: {
  value: string
  className?: string
  children?: ReactNode
}) {
  return (
    <span className={`inline-flex items-center gap-1.5 ${className}`}>
      <span className="min-w-0 break-all">{children ?? value}</span>
      <CopyButton value={value} />
    </span>
  )
}

export interface FilterableListProps<T> {
  items: readonly T[]
  /** Everything the filter should search for one row. */
  searchable: (item: T) => string | string[]
  children: (item: T, index: number) => ReactNode
  /** What one row is called, for the placeholder and the empty state. */
  noun: string
  /** Below this many rows a search box is noise rather than help. */
  threshold?: number
  /** Rendered as the row container. Defaults to a plain wrapper. */
  className?: string
}

/**
 * A list that can be searched once it is long enough to need it.
 *
 * The threshold exists so a three-item list does not sprout a search box. Below it this
 * renders exactly what a bare `.map()` would, which is why it is safe to apply
 * everywhere rather than only where the data happens to be dense today — a sample with
 * four permissions and one with fifty take the same code path.
 */
export function FilterableList<T>({
  items,
  searchable,
  children,
  noun,
  threshold = 8,
  className = '',
}: FilterableListProps<T>) {
  const [query, setQuery] = useState('')
  const visible = useMemo(
    () => (query ? items.filter((item) => matches(searchable(item), query)) : items),
    // `searchable` is typically an inline arrow and would change identity every render;
    // the filter depends on the items and the query, which is what this tracks.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [items, query],
  )

  if (items.length === 0) return <Empty>No {noun} recorded.</Empty>

  return (
    <div>
      {items.length >= threshold && (
        <div className="mb-2 flex items-center gap-2">
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder={`filter ${noun}…`}
            data-analyst-filter
            className="min-w-0 flex-1 rounded-full border border-line-bright bg-ground-2 px-3 py-1.5 text-xs text-fg transition-colors placeholder:text-muted hover:border-v400 focus:border-v400 focus:outline-none"
          />
          <span className="shrink-0 font-mono text-[10px] text-muted">
            {summarise(visible.length, items.length)}
          </span>
        </div>
      )}
      {visible.length === 0 ? (
        <Empty>
          No {noun} match “{query}”. {items.length} recorded.
        </Empty>
      ) : (
        <div className={className}>{visible.map((item, i) => children(item, i))}</div>
      )}
    </div>
  )
}

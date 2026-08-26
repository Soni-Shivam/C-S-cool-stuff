/**
 * The pure half of the analyst affordances: matching, counting, and IOC collection.
 *
 * Kept out of the components so it can be tested directly. The UI suite runs in the
 * `node` environment with no DOM, and these are the parts where being wrong actually
 * costs something — a filter that silently hides rows, or a copied indicator list with a
 * blank line in it that someone pastes into a blocklist.
 */

/** Fold a haystack for comparison: lowercase, and separators removed. */
function fold(text: string): string {
  return text.toLowerCase().replace(/[\s._/\-:]+/g, '')
}

/**
 * Does `value` match what the analyst typed?
 *
 * Separator-insensitive on purpose. An analyst types `read_sms`, `READ_SMS` and
 * `read sms` for the same thing, and a filter that only honours one of them is a filter
 * they stop trusting. An empty query matches everything, so an unfiltered list is the
 * full list rather than nothing.
 */
export function matches(value: string | readonly string[], query: string): boolean {
  const needle = fold(query)
  if (!needle) return true
  const fields = Array.isArray(value) ? value : [value as string]
  return fields.some((field) => fold(String(field ?? '')).includes(needle))
}

/**
 * Describe how much of a list is on screen.
 *
 * "12 permissions" and "12 of 122 permissions" are different claims, and showing the
 * first while a filter hides 110 rows is the list-shaped version of the reporting bugs
 * this project keeps finding. The total is always stated when anything is hidden.
 */
export function summarise(shown: number, total: number): string {
  if (total === 0) return 'none'
  if (shown === total) return String(total)
  if (shown === 0) return `no matches in ${total}`
  return `showing ${shown} of ${total}`
}

export interface IocSource {
  sha256: string | null
  packageName: string | null
  hosts: readonly string[]
  urls: readonly string[]
}

/**
 * Every indicator from one job, one per line, prefixed by kind.
 *
 * This exists to be pasted somewhere consequential — a blocklist, a SIEM rule, a ticket
 * — so it emits nothing it cannot fill. A `host:` line with an empty host would be
 * silently accepted by most of those places and match nothing, or worse, everything.
 * Sorted within each kind so two copies of the same job compare equal in a diff.
 */
export function collectIocs(source: IocSource): string {
  const lines: string[] = []
  const clean = (value: string | null | undefined): string => String(value ?? '').trim()

  const sha = clean(source.sha256)
  if (sha) lines.push(`sha256:${sha}`)

  const pkg = clean(source.packageName)
  if (pkg) lines.push(`package:${pkg}`)

  const uniq = (values: readonly string[]): string[] =>
    [...new Set(values.map(clean).filter(Boolean))].sort()

  for (const host of uniq(source.hosts)) lines.push(`host:${host}`)
  for (const url of uniq(source.urls)) lines.push(`url:${url}`)

  return lines.join('\n')
}

/**
 * The shell: header, stage strip, numbered navigation, content, score rail, log.
 *
 * The four regions from PHASE_0 T0.8 are all still here; what changed is that the
 * view list is drawn as the deck's numbered arc — eight circles riding a violet
 * curve — instead of an icon strip. The numbers are not decoration: they give a
 * presenter something to say out loud ("everything in 02 comes from 04") and they
 * survive the rail collapsing to 72px on a narrow screen, which icons alone did
 * not.
 *
 * All artefact loading is hoisted here so that a stage transition refetches once
 * and every view sees the same snapshot. Views are mounted on demand but their
 * data is not — switching views mid-run must never show an older picture of the
 * job than the one beside it.
 *
 * `showEvidence` is the click path: any chip anywhere jumps to the Ledger view
 * with that node selected. It lives at this level because it crosses views, which
 * is the whole point of it.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  getDynamic,
  getGenai,
  getHealth,
  getIngest,
  getLedger,
  getMl,
  getScore,
  getStatic,
  getVerdict,
} from './api/client'
import { BootSequence, playedThisSession } from './components/BootSequence'
import { DeviceFeed } from './components/DeviceFeed'
import { EvidenceNavContext } from './components/Evidence'
import { Header } from './components/Header'
import { LiveLog } from './components/LiveLog'
import { LogoSpinner } from './components/Logo'
import { NumberBadge, Panel } from './components/primitives'
import { ScoreRail } from './components/ScoreRail'
import { StageStrip } from './components/StageStrip'
import { useArtefact } from './hooks/useArtefact'
import { useJob } from './hooks/useJob'
import { CodeGraphTab } from './tabs/CodeGraphTab'
import { FrontierTab } from './tabs/FrontierTab'
import { LedgerTab } from './tabs/LedgerTab'
import { OverviewTab } from './tabs/OverviewTab'
import { ReportTab } from './tabs/ReportTab'
import { ReverseEngineeringTab } from './tabs/ReverseEngineeringTab'
import { SandboxTab } from './tabs/SandboxTab'
import { StaticTab } from './tabs/StaticTab'

const TABS = [
  { name: 'Overview', slug: 'overview' },
  { name: 'Code Graph', slug: 'code-graph' },
  { name: 'Reverse Engineering', slug: 'reverse-engineering' },
  { name: 'Static', slug: 'static' },
  { name: 'Sandbox', slug: 'sandbox' },
  { name: 'Frontier', slug: 'frontier' },
  { name: 'Ledger', slug: 'ledger' },
  { name: 'Report', slug: 'report' },
] as const
type Tab = (typeof TABS)[number]['name']

function initialTab(): Tab {
  const slug = new URLSearchParams(window.location.search).get('view')
  return TABS.find((item) => item.slug === slug)?.name ?? 'Overview'
}

/* The numbered rail, laid out from one set of constants so the arc drawn behind
   the badges actually passes through them. Getting these out of sync is how the
   arc ends up as a stray diagonal down the edge of the pane. */
const BADGE = 38
const ROW_STRIDE = 56 // badge + the button's py-1.5 above and below + gap-1.5
const ROW_TOP = 6 // the button's own top padding
const BADGE_LEFT = 4 // the button's pl-1

/** How far item `i` of `n` bows out from the rail, tracing the deck's arc. */
function bow(index: number, count: number): number {
  return Math.sin(((index + 0.5) / count) * Math.PI) * 13
}

function badgeCentre(index: number, count: number): { x: number; y: number } {
  return {
    x: BADGE_LEFT + bow(index, count) + BADGE / 2,
    y: ROW_TOP + BADGE / 2 + index * ROW_STRIDE,
  }
}

/** A smooth path through the badge centres, via quadratics about their midpoints. */
function arcThroughBadges(count: number): string {
  const points = Array.from({ length: count }, (_, i) => badgeCentre(i, count))
  if (points.length < 2) return ''
  let d = `M ${points[0].x} ${points[0].y}`
  for (let i = 1; i < points.length - 1; i += 1) {
    const midX = (points[i].x + points[i + 1].x) / 2
    const midY = (points[i].y + points[i + 1].y) / 2
    d += ` Q ${points[i].x} ${points[i].y}, ${midX} ${midY}`
  }
  const last = points[points.length - 1]
  return `${d} T ${last.x} ${last.y}`
}

export default function App() {
  const params = new URLSearchParams(window.location.search)
  const [jobId, setJobId] = useState<string | null>(params.get('job'))
  const [tab, setTab] = useState<Tab>(initialTab)
  const [selectedNode, setSelectedNode] = useState<string | null>(params.get('node'))
  const [version, setVersion] = useState<string | null>(null)
  const [booting, setBooting] = useState(() => !playedThisSession())

  const { job, events, streaming, error, revision } = useJob(jobId)

  const ingest = useArtefact(jobId, getIngest, revision).artefact
  const staticReport = useArtefact(jobId, getStatic, revision).artefact
  const ml = useArtefact(jobId, getMl, revision).artefact
  const genai = useArtefact(jobId, getGenai, revision).artefact
  const dynamic = useArtefact(jobId, getDynamic, revision).artefact
  const score = useArtefact(jobId, getScore, revision).artefact
  const ledger = useArtefact(jobId, (id) => getLedger(id), revision).artefact
  // The shared projection (contract A15). Fetched alongside the raw artefacts rather
  // than derived from them: the Verdict every surface reads must be the one the server
  // built, not one this app assembled from the same parts and hoped matched.
  const verdict = useArtefact(jobId, getVerdict, revision).artefact

  useEffect(() => {
    void getHealth()
      .then((health) => setVersion(health.version))
      .catch(() => setVersion(null))
  }, [])

  const nodes = useMemo(() => (ledger?.state === 'ready' ? ledger.value : []), [ledger])
  const knownIds = useMemo(() => new Set(nodes.map((node) => node.id)), [nodes])

  const showEvidence = useCallback((nodeId: string) => {
    setSelectedNode(nodeId)
    setTab('Ledger')
    const url = new URL(window.location.href)
    url.searchParams.set('view', 'ledger')
    url.searchParams.set('node', nodeId)
    window.history.pushState({}, '', url)
  }, [])

  const selectTab = useCallback((name: Tab) => {
    setTab(name)
    const item = TABS.find((candidate) => candidate.name === name)
    const url = new URL(window.location.href)
    if (item) url.searchParams.set('view', item.slug)
    if (name !== 'Ledger') url.searchParams.delete('node')
    window.history.pushState({}, '', url)
  }, [])

  const selectJob = useCallback((id: string) => {
    setJobId(id)
    setTab('Overview')
    setSelectedNode(null)
    const url = new URL(window.location.href)
    url.searchParams.set('job', id)
    url.searchParams.set('view', 'overview')
    url.searchParams.delete('node')
    url.searchParams.delete('method')
    window.history.pushState({}, '', url)
  }, [])

  useEffect(() => {
    const restore = () => {
      const query = new URLSearchParams(window.location.search)
      setJobId(query.get('job'))
      setTab(initialTab())
      setSelectedNode(query.get('node'))
    }
    window.addEventListener('popstate', restore)
    return () => window.removeEventListener('popstate', restore)
  }, [])

  const nav = useMemo(() => ({ showEvidence, knownIds }), [showEvidence, knownIds])

  const currentScore = score?.state === 'ready' ? score.value : null
  const isFinal = job?.final != null
  const activeIndex = TABS.findIndex((item) => item.name === tab)

  return (
    <EvidenceNavContext.Provider value={nav}>
      {booting && <BootSequence onDone={() => setBooting(false)} />}

      <div className="flex h-full min-w-0 flex-col overflow-hidden">
        <Header job={job} streaming={streaming} onJobCreated={selectJob} version={version} />
        <DeviceFeed currentJobId={jobId} onSelectJob={selectJob} />
        {job && <StageStrip events={events} current={job.stage} />}

        <main className="flex min-h-0 flex-1">
          <aside className="relative w-[74px] shrink-0 overflow-x-hidden overflow-y-auto border-r border-line bg-ground-1/60 py-5 backdrop-blur-sm xl:w-[248px]">
            {/* The violet field the arc separates, as on the contents slide. */}
            <div
              aria-hidden
              className="pointer-events-none absolute inset-y-0 -left-10 w-40 opacity-70"
              style={{
                background:
                  'radial-gradient(closest-side, rgba(139,61,238,0.28), transparent 100%)',
              }}
            />

            <nav className="relative px-2.5 xl:px-4" aria-label="Investigation views">
              <div className="relative flex flex-col gap-1.5">
                {/* The arc the numbers ride. Its geometry is derived from the same
                    constants that position the badges, so the two cannot drift. */}
                <svg
                  aria-hidden
                  className="pointer-events-none absolute top-0 left-0 overflow-visible"
                  width={80}
                  height={ROW_TOP * 2 + TABS.length * ROW_STRIDE}
                >
                  <defs>
                    <linearGradient id="rail-arc" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="#7b3fe4" stopOpacity="0" />
                      <stop offset="22%" stopColor="#a855f7" stopOpacity="0.9" />
                      <stop offset="78%" stopColor="#c084fc" stopOpacity="0.9" />
                      <stop offset="100%" stopColor="#7b3fe4" stopOpacity="0" />
                    </linearGradient>
                  </defs>
                  <path
                    d={arcThroughBadges(TABS.length)}
                    fill="none"
                    stroke="url(#rail-arc)"
                    strokeWidth={1.5}
                    strokeLinecap="round"
                  />
                </svg>

                {TABS.map((item, index) => {
                  const active = item.name === tab
                  return (
                    <button
                      key={item.name}
                      type="button"
                      onClick={() => selectTab(item.name)}
                      title={item.name}
                      aria-current={active ? 'page' : undefined}
                      className="group relative flex items-center gap-3.5 rounded-full py-1.5 pr-2 pl-1 text-left transition-all duration-300 hover:bg-white/[0.04]"
                      style={{ marginLeft: bow(index, TABS.length) }}
                    >
                      <NumberBadge n={index + 1} active={active} size={BADGE} />
                      <span
                        className={`hidden truncate text-sm transition-colors xl:block ${
                          active ? 'font-medium text-fg' : 'text-muted group-hover:text-fg'
                        }`}
                      >
                        {item.name}
                      </span>
                    </button>
                  )
                })}
              </div>
            </nav>
          </aside>

          <section className="flex min-w-0 flex-1 flex-col">
            <div className="flex h-11 shrink-0 items-center gap-2.5 border-b border-line bg-ground-1/40 px-5 text-xs backdrop-blur-sm">
              <span className="text-dim">Investigation</span>
              <span className="text-line-bright">/</span>
              <span className="font-mono text-[11px] text-v400">
                {String(activeIndex + 1).padStart(2, '0')}
              </span>
              <span className="font-medium text-fg">{tab}</span>
              {job && (
                <span
                  className="ml-auto hidden truncate font-mono text-dim md:block"
                  title={job.sha256}
                >
                  {job.sha256.slice(0, 16)}…
                </span>
              )}
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto p-5">
              {error && (
                <div className="mb-4 rounded-[var(--radius-tile)] border border-bad/40 bg-bad/[0.08] px-4 py-3 text-sm text-bad">
                  {error}
                </div>
              )}
              {job?.error && (
                <div className="mb-4 rounded-[var(--radius-tile)] border border-bad/40 bg-bad/[0.08] px-4 py-3 text-sm text-bad">
                  Job failed: {job.error}
                </div>
              )}

              {!jobId ? (
                <Welcome />
              ) : (
                <>
                  {tab === 'Overview' && (
                    <OverviewTab
                      jobId={jobId}
                      verdict={verdict}
                      score={score}
                      genai={genai}
                      ingest={ingest}
                      staticReport={staticReport}
                    />
                  )}
                  {tab === 'Code Graph' && (
                    <CodeGraphTab report={staticReport} genai={genai} ledger={nodes} />
                  )}
                  {tab === 'Reverse Engineering' && (
                    <ReverseEngineeringTab report={staticReport} genai={genai} ml={ml} />
                  )}
                  {tab === 'Static' && <StaticTab report={staticReport} />}
                  {tab === 'Sandbox' && <SandboxTab dynamic={dynamic} verdict={verdict} />}
                  {tab === 'Frontier' && (
                    <FrontierTab nodes={nodes} dynamic={dynamic} verdict={verdict} />
                  )}
                  {tab === 'Ledger' && (
                    <LedgerTab
                      jobId={jobId}
                      nodes={nodes}
                      selectedId={selectedNode}
                      onSelect={setSelectedNode}
                    />
                  )}
                  {tab === 'Report' && <ReportTab jobId={jobId} revision={revision} />}
                </>
              )}
            </div>
          </section>

          <aside className="hidden w-[272px] shrink-0 overflow-y-auto border-l border-line bg-ground-1/60 p-5 backdrop-blur-sm 2xl:block">
            {currentScore ? (
              <ScoreRail score={currentScore} isFinal={isFinal} />
            ) : jobId ? (
              <div className="flex flex-col items-center gap-4 pt-10">
                <LogoSpinner size="lg" label="Waiting for the preliminary verdict…" />
              </div>
            ) : (
              <p className="text-sm text-muted">No investigation loaded.</p>
            )}
          </aside>
        </main>

        <LiveLog />
      </div>
    </EvidenceNavContext.Provider>
  )
}

/** The idle state. On stage this is the first thing on the projector. */
function Welcome() {
  return (
    <div className="anim-rise mx-auto max-w-4xl space-y-6 pt-6">
      <div>
        <div className="eyebrow mb-3">Android malware triage</div>
        <h1 className="display text-[clamp(2.4rem,6vw,4.6rem)] text-fg">
          Drop an APK to
          <br />
          open an investigation.
        </h1>
        <p className="mt-5 max-w-2xl text-sm leading-relaxed text-muted">
          The preliminary verdict lands as soon as the file has been read, classified and reasoned
          over; everything after it — sandbox passes, frontier probes, the full model reading —
          continues asynchronously while you already have a score to act on. Every number on every
          screen is
          traceable to a node in an append-only evidence ledger, and anything that could not be
          grounded is shown as ungrounded rather than quietly dropped.
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Panel title="Grounded by construction">
          <p className="text-sm leading-relaxed text-muted">
            The model emits enumerated behaviour booleans and evidence-bearing claims. It never
            emits the score — that is computed in pure Python from a weight table.
          </p>
        </Panel>
        <Panel title="Provenance on screen">
          <p className="text-sm leading-relaxed text-muted">
            Live detonation, replayed real trace, and hand-authored fixture are read from the trace
            itself and badged distinctly. A run that observed nothing is inconclusive, never benign.
          </p>
        </Panel>
        <Panel title="Retrieval you can audit">
          <p className="text-sm leading-relaxed text-muted">
            View <span className="font-mono text-v300">02</span> replays every tool call across the
            call graph, so what the model was allowed to read is visible next to what it concluded.
          </p>
        </Panel>
      </div>
    </div>
  )
}

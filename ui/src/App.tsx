/**
 * The four regions from PHASE_0 T0.8: header, score rail, tabbed content, live log.
 *
 * All artefact loading is hoisted here so that a stage transition refetches once and
 * every tab sees the same snapshot. Tabs are kept mounted-on-demand but their data
 * is not — switching tabs mid-run must never show an older view of the job than the
 * one beside it.
 *
 * `showEvidence` is the click path: any chip anywhere jumps to the Ledger tab with
 * that node selected. It lives at this level because it crosses tabs, which is the
 * whole point of it.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity,
  BookOpenCheck,
  Boxes,
  FileText,
  FlaskConical,
  LayoutDashboard,
  Network,
} from 'lucide-react'
import {
  getDynamic,
  getGenai,
  getHealth,
  getIngest,
  getLedger,
  getMl,
  getScore,
  getStatic,
} from './api/client'
import { DeviceFeed } from './components/DeviceFeed'
import { Header } from './components/Header'
import { LiveLog } from './components/LiveLog'
import { ScoreRail } from './components/ScoreRail'
import { StageStrip } from './components/StageStrip'
import { EvidenceNavContext } from './components/Evidence'
import { Panel } from './components/primitives'
import { useArtefact } from './hooks/useArtefact'
import { useJob } from './hooks/useJob'
import { FrontierTab } from './tabs/FrontierTab'
import { LedgerTab } from './tabs/LedgerTab'
import { OverviewTab } from './tabs/OverviewTab'
import { ReportTab } from './tabs/ReportTab'
import { ReverseEngineeringTab } from './tabs/ReverseEngineeringTab'
import { SandboxTab } from './tabs/SandboxTab'
import { StaticTab } from './tabs/StaticTab'

const TABS = [
  { name: 'Overview', slug: 'overview', icon: LayoutDashboard },
  { name: 'Reverse Engineering', slug: 'reverse-engineering', icon: BookOpenCheck },
  { name: 'Static', slug: 'static', icon: Boxes },
  { name: 'Sandbox', slug: 'sandbox', icon: Activity },
  { name: 'Frontier', slug: 'frontier', icon: FlaskConical },
  { name: 'Ledger', slug: 'ledger', icon: Network },
  { name: 'Report', slug: 'report', icon: FileText },
] as const
type Tab = (typeof TABS)[number]['name']

function initialTab(): Tab {
  const slug = new URLSearchParams(window.location.search).get('view')
  return TABS.find((item) => item.slug === slug)?.name ?? 'Overview'
}

export default function App() {
  const params = new URLSearchParams(window.location.search)
  const [jobId, setJobId] = useState<string | null>(params.get('job'))
  const [tab, setTab] = useState<Tab>(initialTab)
  const [selectedNode, setSelectedNode] = useState<string | null>(params.get('node'))
  const [version, setVersion] = useState<string | null>(null)

  const { job, events, streaming, error, revision } = useJob(jobId)

  const ingest = useArtefact(jobId, getIngest, revision).artefact
  const staticReport = useArtefact(jobId, getStatic, revision).artefact
  const ml = useArtefact(jobId, getMl, revision).artefact
  const genai = useArtefact(jobId, getGenai, revision).artefact
  const dynamic = useArtefact(jobId, getDynamic, revision).artefact
  const score = useArtefact(jobId, getScore, revision).artefact
  const ledger = useArtefact(jobId, (id) => getLedger(id), revision).artefact

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

  return (
    <EvidenceNavContext.Provider value={nav}>
      <div className="flex h-full min-w-0 flex-col overflow-hidden bg-ink">
        <Header job={job} streaming={streaming} onJobCreated={selectJob} version={version} />
        <DeviceFeed currentJobId={jobId} onSelectJob={selectJob} />
        {job && <StageStrip events={events} current={job.stage} />}

        <main className="flex min-h-0 flex-1">
          <aside className="w-16 shrink-0 overflow-y-auto border-r border-line bg-panel px-2 py-3 lg:w-52">
            <nav className="space-y-1" aria-label="Investigation views">
              {TABS.map(({ name, icon: Icon }) => (
                <button
                  key={name}
                  type="button"
                  onClick={() => selectTab(name)}
                  title={name}
                  className={`flex h-10 w-full items-center gap-3 border-l-2 px-3 text-sm transition-colors ${
                    tab === name
                      ? 'border-accent bg-accent-soft text-accent'
                      : 'border-transparent text-muted hover:bg-panel-2 hover:text-fg'
                  }`}
                >
                  <Icon size={17} strokeWidth={1.8} className="shrink-0" />
                  <span className="hidden truncate lg:block">{name}</span>
                </button>
              ))}
            </nav>
          </aside>

          <section className="flex min-w-0 flex-1 flex-col">
            <div className="flex h-10 shrink-0 items-center gap-2 border-b border-line bg-panel px-4 text-xs">
              <span className="text-muted">Investigation</span>
              <span className="text-dim">/</span>
              <span className="font-medium text-fg">{tab}</span>
              {job && <span className="ml-auto hidden font-mono text-dim md:block">{job.sha256.slice(0, 16)}…</span>}
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto p-4">
              {error && (
                <div className="mb-4 rounded border border-bad/40 bg-bad/5 px-3 py-2 text-sm text-bad">
                  {error}
                </div>
              )}
              {job?.error && (
                <div className="mb-4 rounded border border-bad/40 bg-bad/5 px-3 py-2 text-sm text-bad">
                  Job failed: {job.error}
                </div>
              )}

              {!jobId ? (
                <Panel title="No job loaded">
                  <p className="text-sm text-muted">
                    Drop an APK in the header to start a run. The preliminary verdict appears at
                    SCORE_PRELIM; everything after it continues asynchronously.
                  </p>
                </Panel>
              ) : (
                <>
                  {tab === 'Overview' && (
                    <OverviewTab
                      jobId={jobId}
                      score={score}
                      genai={genai}
                      ingest={ingest}
                      dynamic={dynamic}
                    />
                  )}
                  {tab === 'Static' && <StaticTab report={staticReport} />}
                  {tab === 'Reverse Engineering' && (
                    <ReverseEngineeringTab report={staticReport} genai={genai} ml={ml} />
                  )}
                  {tab === 'Sandbox' && <SandboxTab dynamic={dynamic} />}
                  {tab === 'Frontier' && <FrontierTab nodes={nodes} dynamic={dynamic} />}
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

          <aside className="hidden w-60 shrink-0 overflow-y-auto border-l border-line bg-panel p-4 xl:block">
            {currentScore ? (
              <ScoreRail score={currentScore} isFinal={isFinal} />
            ) : (
              <p className="text-sm text-muted">
                {jobId ? 'Waiting for the preliminary verdict…' : 'No investigation loaded.'}
              </p>
            )}
          </aside>
        </main>

        <LiveLog />
      </div>
    </EvidenceNavContext.Provider>
  )
}

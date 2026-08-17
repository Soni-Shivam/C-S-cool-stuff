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
  getDynamic,
  getGenai,
  getHealth,
  getIngest,
  getLedger,
  getMl,
  getScore,
  getStatic,
} from './api/client'
import { Header } from './components/Header'
import { LiveLog } from './components/LiveLog'
import { ScoreRail } from './components/ScoreRail'
import { StageStrip } from './components/StageStrip'
import { EvidenceNavContext } from './components/Evidence'
import { Panel } from './components/primitives'
import { useArtefact } from './hooks/useArtefact'
import { useJob } from './hooks/useJob'
import { AiTab } from './tabs/AiTab'
import { FrontierTab } from './tabs/FrontierTab'
import { LedgerTab } from './tabs/LedgerTab'
import { OverviewTab } from './tabs/OverviewTab'
import { ReportTab } from './tabs/ReportTab'
import { SandboxTab } from './tabs/SandboxTab'
import { StaticTab } from './tabs/StaticTab'

const TABS = ['Overview', 'Static', 'AI', 'Sandbox', 'Frontier', 'Ledger', 'Report'] as const
type Tab = (typeof TABS)[number]

export default function App() {
  const [jobId, setJobId] = useState<string | null>(null)
  const [tab, setTab] = useState<Tab>('Overview')
  const [selectedNode, setSelectedNode] = useState<string | null>(null)
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
  }, [])

  const nav = useMemo(() => ({ showEvidence, knownIds }), [showEvidence, knownIds])

  const currentScore = score?.state === 'ready' ? score.value : null
  const isFinal = job?.final != null

  return (
    <EvidenceNavContext.Provider value={nav}>
      <div className="flex h-full flex-col bg-ink">
        <Header job={job} streaming={streaming} onJobCreated={setJobId} version={version} />
        {job && <StageStrip events={events} current={job.stage} />}

        <main className="flex min-h-0 flex-1">
          <aside className="w-64 shrink-0 overflow-y-auto border-r border-line bg-panel p-4">
            {currentScore ? (
              <ScoreRail score={currentScore} isFinal={isFinal} />
            ) : (
              <p className="text-sm text-muted">
                {jobId ? 'Waiting for the preliminary verdict…' : 'No job yet. Drop an APK above.'}
              </p>
            )}
          </aside>

          <section className="flex min-w-0 flex-1 flex-col">
            <nav className="flex shrink-0 gap-1 border-b border-line bg-panel px-4">
              {TABS.map((name) => (
                <button
                  key={name}
                  type="button"
                  onClick={() => setTab(name)}
                  className={`border-b-2 px-3 py-2 text-sm transition-colors ${
                    tab === name
                      ? 'border-accent text-accent'
                      : 'border-transparent text-muted hover:text-fg'
                  }`}
                >
                  {name}
                </button>
              ))}
            </nav>

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
                  {tab === 'AI' && <AiTab genai={genai} ml={ml} />}
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
        </main>

        <LiveLog />
      </div>
    </EvidenceNavContext.Provider>
  )
}

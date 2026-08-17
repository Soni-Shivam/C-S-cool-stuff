/**
 * Report: the HTML report and the exportable artefacts.
 *
 * All three of report.html, YARA and STIX return **501 with the owning task id**
 * today (T6.3, T6.1, T6.2). This tab therefore mostly renders those 501s — which is
 * the correct thing to render. A placeholder report that looked like a real one is
 * exactly what `drishti/api/routes/artifacts.py` refuses to serve, and the UI has
 * no business inventing one on the client instead.
 *
 * The ledger export is real and downloads today, so it is not lumped in with them.
 */

import { useEffect, useState } from 'react'
import type { Artefact } from '../api/client'
import { getReportHtml, getStix, getYara, ledgerExportUrl } from '../api/client'
import { ArtefactGate, Panel } from '../components/primitives'

function Unbuilt({ artefact }: { artefact: Artefact<unknown> | null }) {
  return (
    <ArtefactGate artefact={artefact}>
      {(value) => (
        <pre className="max-h-96 overflow-auto rounded bg-ink p-3 font-mono text-xs text-muted">
          {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
        </pre>
      )}
    </ArtefactGate>
  )
}

export function ReportTab({ jobId, revision }: { jobId: string; revision: number }) {
  const [report, setReport] = useState<Artefact<string> | null>(null)
  const [yara, setYara] = useState<Artefact<string> | null>(null)
  const [stix, setStix] = useState<Artefact<unknown> | null>(null)

  useEffect(() => {
    void getReportHtml(jobId).then(setReport)
    void getYara(jobId).then(setYara)
    void getStix(jobId).then(setStix)
  }, [jobId, revision])

  return (
    <div className="space-y-4">
      <Panel title="Investigation report" subtitle="GET /api/jobs/{job}/report.html">
        {report?.state === 'ready' ? (
          // Sandboxed: the report embeds sample-derived strings, and this is the one
          // place they are rendered as markup rather than as text.
          <iframe
            title="DRISHTI report"
            srcDoc={report.value}
            sandbox=""
            className="h-[32rem] w-full rounded border border-line bg-white"
          />
        ) : (
          <Unbuilt artefact={report} />
        )}
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="YARA rules" subtitle="GET /api/jobs/{job}/artifacts/yara">
          <Unbuilt artefact={yara} />
        </Panel>

        <Panel title="STIX 2.1 bundle" subtitle="GET /api/jobs/{job}/artifacts/stix">
          <Unbuilt artefact={stix} />
        </Panel>
      </div>

      <Panel title="Downloads" subtitle="Only what exists is offered — an unbuilt export is not a button">
        <div className="flex flex-wrap gap-2">
          <a
            href={ledgerExportUrl(jobId)}
            download={`${jobId}-ledger.json`}
            className="rounded border border-accent/50 bg-accent-soft px-3 py-1.5 text-sm text-accent hover:bg-accent/20"
          >
            Evidence ledger (JSON)
          </a>
          <span
            className="cursor-not-allowed rounded border border-line px-3 py-1.5 text-sm text-dim"
            title="T6.3"
          >
            HTML report — T6.3
          </span>
          <span className="cursor-not-allowed rounded border border-line px-3 py-1.5 text-sm text-dim" title="T6.1">
            YARA — T6.1
          </span>
          <span className="cursor-not-allowed rounded border border-line px-3 py-1.5 text-sm text-dim" title="T6.2">
            STIX — T6.2
          </span>
        </div>
      </Panel>
    </div>
  )
}

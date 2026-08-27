/**
 * Report: the HTML report, the machine-readable exports, and the complaint package.
 *
 * Everything on this view can also be taken in one archive — `bundle.zip`, assembled
 * server-side from the same bytes these panels render, with a manifest that hashes each
 * entry and records whether the evidence chain verified when it was built. The sample is
 * never in it.
 *
 * All four routes are implemented — report.html (T6.3), YARA (T6.1), STIX (T6.2) and
 * the dossier (contract A12). This tab previously stated they were unbuilt and offered
 * dead buttons labelled with their task ids, which was true when it was written and had
 * quietly become false. Understating what exists is the same defect as overstating it:
 * both leave the screen saying something the system does not.
 *
 * What the tab still refuses to invent is unchanged. Every panel renders through
 * `ArtefactGate`, so a job that has not reached `ingest`/`score` shows 404-pending and a
 * genuinely unbuilt feature would show its 501 and its owning task — never a plausible
 * placeholder.
 *
 * **The complaint package is generated, never filed.** India's National Cyber Crime
 * Reporting Portal has no public submission API; `submission_is_manual` is always true
 * and there is no control here that submits anything. The button says "download", the
 * portal is a link a human follows, and nothing in this product tells a user their
 * complaint has been lodged.
 */

import { useEffect, useState } from 'react'
import type { Artefact } from '../api/client'
import { CopyButton } from '../components/Analyst'
import { collectIocs } from '../components/analyst'
import {
  exportUrls,
  getDossier,
  getReportHtml,
  getStix,
  getYara,
  ledgerExportUrl,
} from '../api/client'
import { ArtefactGate, Panel, SectionHead, Tag } from '../components/primitives'
import type { Dossier } from '../api/types'

function Payload({ artefact }: { artefact: Artefact<unknown> | null }) {
  return (
    <ArtefactGate artefact={artefact}>
      {(value) => (
        <pre className="max-h-96 overflow-auto rounded-[var(--radius-tile)] border border-line-soft bg-ground p-3.5 font-mono text-xs text-muted">
          {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
        </pre>
      )}
    </ArtefactGate>
  )
}

function Download({ href, name, children }: { href: string; name: string; children: string }) {
  return (
    <a
      href={href}
      download={name}
      className="rounded border border-accent/50 bg-accent-soft px-3 py-1.5 text-sm text-accent hover:bg-accent/20"
    >
      {children}
    </a>
  )
}

/**
 * The whole case in one archive.
 *
 * Separate links are fine while a job is on screen and useless six weeks later, when
 * the question is "is this everything, and was the evidence intact when it was taken".
 * The archive answers that from its `MANIFEST.json`: a SHA-256 per entry, the chain
 * verification as read at build time, and any export that failed named with its reason.
 *
 * The sample is not in it, and the button says so — an APK never leaves the analysis
 * project, and a download control is not an exception to that.
 */
function CaseFileDownload({ jobId, href }: { jobId: string; href: string }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-[var(--radius-tile)] border border-accent/40 bg-accent-soft px-4 py-3">
      <div className="min-w-0">
        <div className="text-sm font-semibold text-fg">Keep the whole case file</div>
        <p className="mt-0.5 text-xs leading-relaxed text-muted">
          Report, complaint package, YARA, STIX, the evidence ledger and the verdict, plus a
          manifest hashing every entry and recording whether the chain verified. The analysed
          APK is not included.
        </p>
      </div>
      <a
        href={href}
        download={`${jobId}-case-file.zip`}
        className="shrink-0 rounded bg-accent px-4 py-2 text-sm font-semibold text-ground hover:bg-accent/85"
      >
        Download case file (ZIP)
      </a>
    </div>
  )
}

function ComplaintPackage({ dossier }: { dossier: Dossier }) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Tag tone={dossier.reportable ? 'bad' : 'neutral'}>
          {dossier.reportable ? 'meets the reporting threshold' : 'below the reporting threshold'}
        </Tag>
        <span className="text-xs text-muted">{dossier.reason}</span>
      </div>

      <p className="rounded border border-warn/30 bg-warn/5 px-3 py-2 text-sm text-warn">
        Nothing is filed by this system. The portal has no submission API, so this package
        is written for a person to attach to a complaint they raise themselves at{' '}
        <span className="font-mono">{dossier.portal_url}</span> or on{' '}
        <span className="font-mono">{dossier.helpline}</span>. The sample itself never
        leaves the analysis project — this is hashes and derived facts.
      </p>

      <p className="text-sm text-fg">{dossier.summary}</p>

      <div className="grid gap-4 lg:grid-cols-2">
        <div>
          <div className="text-[10px] tracking-widest text-dim uppercase">
            Indicators ({dossier.indicators.length})
          </div>
          {dossier.indicators.length === 0 ? (
            <p className="mt-1 text-sm text-muted italic">
              none — only observed infrastructure is listed, never a flow our own
              Generative C2 synthesised
            </p>
          ) : (
            <ul className="mt-1 space-y-0.5 font-mono text-[11px] break-all text-muted">
              {dossier.indicators.map((indicator) => (
                <li key={indicator}>{indicator}</li>
              ))}
            </ul>
          )}
        </div>
        <div>
          <div className="text-[10px] tracking-widest text-dim uppercase">
            Caveats ({dossier.caveats.length})
          </div>
          <ul className="mt-1 space-y-1 text-xs text-muted">
            {dossier.caveats.map((caveat, i) => (
              <li key={i} className="border-l-2 border-warn/40 pl-2">
                {caveat}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <pre className="max-h-72 overflow-auto rounded bg-ground p-3 font-mono text-xs leading-relaxed text-muted">
        {dossier.text}
      </pre>
    </div>
  )
}

export function ReportTab({
  jobId,
  revision,
  sha256,
  packageName,
  urls: sampleUrls,
  hosts,
}: {
  jobId: string
  revision: number
  sha256?: string | null
  packageName?: string | null
  urls?: readonly string[]
  hosts?: readonly string[]
}) {
  const [report, setReport] = useState<Artefact<string> | null>(null)
  const [yara, setYara] = useState<Artefact<string> | null>(null)
  const [stix, setStix] = useState<Artefact<unknown> | null>(null)
  const [dossier, setDossier] = useState<Artefact<Dossier> | null>(null)
  const urls = exportUrls(jobId)
  // Everything an analyst pastes elsewhere, in one place. The exports beside it are
  // files for a SIEM; this is for the ticket, the blocklist and the chat message, which
  // is where most of this actually goes first.
  const iocs = collectIocs({
    sha256: sha256 ?? null,
    packageName: packageName ?? null,
    hosts: hosts ?? [],
    urls: sampleUrls ?? [],
  })

  // A change of job invalidates what is already rendered, not just what is in
  // flight — otherwise the previous run's report sits here under the new run's
  // heading until its replacement lands.
  useEffect(() => {
    setReport(null)
    setYara(null)
    setStix(null)
    setDossier(null)
  }, [jobId])

  // These four are fetched here rather than through `useArtefact`, so they need
  // the same late-response guard it applies: this component stays mounted across
  // a change of job, and a response for the job the operator left would otherwise
  // land in a panel the shell is rendering as the current one.
  useEffect(() => {
    let current = true
    void getReportHtml(jobId).then((next) => current && setReport(next))
    void getYara(jobId).then((next) => current && setYara(next))
    void getStix(jobId).then((next) => current && setStix(next))
    void getDossier(jobId).then((next) => current && setDossier(next))
    return () => {
      current = false
    }
  }, [jobId, revision])

  return (
    <div className="space-y-5">
      <SectionHead
        eyebrow="Deliverables"
        title="Report and exports"
        lede="Report, YARA, STIX and the complaint dossier are all implemented and download today, individually or as one case-file archive with a manifest. The complaint package is generated, never filed — India's cyber-crime portal has no submission API, so nothing on this screen tells a user their complaint has been lodged."
      />

      <Panel
        title="Indicators"
        subtitle="Hash, package and every host and URL the sample referenced — one per line, prefixed by kind"
        right={<CopyButton value={iocs} label="copy all IOCs" />}
      >
        {iocs ? (
          <pre className="max-h-40 overflow-auto font-mono text-[11px] break-all whitespace-pre-wrap text-muted">
            {iocs}
          </pre>
        ) : (
          <p className="text-xs text-muted">
            No indicators recovered for this sample. Nothing is emitted rather than a
            prefixed line with nothing after it — a blank entry pasted into a blocklist
            matches nothing, or everything.
          </p>
        )}
      </Panel>

      <Panel
        title="Investigation report"
        subtitle="GET /api/jobs/{job}/report.html — self-contained, no external assets"
        right={
          report?.state === 'ready' ? (
            <Download href={urls.report} name={`${jobId}-report.html`}>
              Download report
            </Download>
          ) : undefined
        }
      >
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
          <Payload artefact={report} />
        )}
      </Panel>

      <Panel
        title="Complaint package"
        subtitle="GET /api/jobs/{job}/artifacts/dossier — generated for a human to file. This system files nothing."
      >
        <ArtefactGate artefact={dossier}>{(value) => <ComplaintPackage dossier={value} />}</ArtefactGate>
      </Panel>

      <div className="grid gap-4 xl:grid-cols-2">
        <Panel title="YARA rule" subtitle="GET /api/jobs/{job}/artifacts/yara — keyed on repack-resistant artefacts, never the hash">
          <Payload artefact={yara} />
        </Panel>

        <Panel title="STIX 2.1 bundle" subtitle="GET /api/jobs/{job}/artifacts/stix — deterministic; two exports of one job are byte-identical">
          <Payload artefact={stix} />
        </Panel>
      </div>

      <Panel title="Downloads" subtitle="Only what this build actually serves is offered — an unbuilt export is not a button">
        <CaseFileDownload jobId={jobId} href={urls.bundle} />
        <div className="mt-4 text-[10px] tracking-widest text-dim uppercase">
          or take one file at a time
        </div>
        <div className="mt-2 flex flex-wrap gap-2">
          <Download href={ledgerExportUrl(jobId)} name={`${jobId}-ledger.json`}>
            Evidence ledger (JSON)
          </Download>
          <Download href={urls.report} name={`${jobId}-report.html`}>
            Investigation report (HTML)
          </Download>
          <Download href={urls.dossier} name={`${jobId}-complaint-package.json`}>
            Complaint package (JSON)
          </Download>
          <Download href={urls.yara} name={`${jobId}.yar`}>
            YARA rule
          </Download>
          <Download href={urls.stix} name={`${jobId}-stix.json`}>
            STIX 2.1 bundle
          </Download>
        </div>
      </Panel>
    </div>
  )
}

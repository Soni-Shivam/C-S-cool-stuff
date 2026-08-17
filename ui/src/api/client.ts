/**
 * The only place that talks to the API.
 *
 * The whole file exists to preserve one distinction the backend was careful to
 * make (`drishti/api/deps.py`) and which a naive `fetch(...).then(r => r.json())`
 * would destroy:
 *
 *   404 + {reason: "not_produced_yet", stage} -> the pipeline has not got there yet
 *   501 + {reason: "not_implemented", task}   -> this feature does not exist in this build
 *
 * Collapsing them into "error" would make a permanently-missing feature look like
 * a slow one, which is precisely the dishonesty the 501 convention was added to
 * prevent. `Artefact<T>` carries the difference all the way to the component.
 */

import type {
  ChainVerification,
  CompositeScore,
  DynamicTrace,
  EvidenceNode,
  EvidenceTypeName,
  FileMeta,
  GenAIVerdict,
  Job,
  MLPrediction,
  ProposedAction,
  StaticReport,
} from './types'

export type Artefact<T> =
  | { state: 'ready'; value: T }
  | { state: 'pending'; stage: string }
  | { state: 'unavailable'; what: string; task: string }
  | { state: 'error'; message: string }

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message)
  }
}

/** Pull a message out of FastAPI's `detail`, which is a string OR an object. */
function detailMessage(body: unknown, fallback: string): string {
  if (body && typeof body === 'object' && 'detail' in body) {
    const detail = (body as { detail: unknown }).detail
    if (typeof detail === 'string') return detail
    if (detail && typeof detail === 'object') return JSON.stringify(detail)
  }
  return fallback
}

async function parseJson(response: Response): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    return null
  }
}

/** A plain request that must succeed. Use for actions, not for artefacts. */
async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, init)
  const body = await parseJson(response)
  if (!response.ok) {
    throw new ApiError(detailMessage(body, `${response.status} ${response.statusText}`), response.status)
  }
  return body as T
}

/**
 * Fetch a per-job artefact, mapping the two "not available" conventions onto
 * `Artefact<T>` rather than throwing. Nothing here invents a value for a missing
 * artefact: a stage that has not run renders as pending, never as zero.
 */
async function artefact<T>(path: string): Promise<Artefact<T>> {
  let response: Response
  try {
    response = await fetch(path)
  } catch (exc) {
    return { state: 'error', message: exc instanceof Error ? exc.message : String(exc) }
  }
  const body = await parseJson(response)

  if (response.ok) return { state: 'ready', value: body as T }

  const detail =
    body && typeof body === 'object' && 'detail' in body
      ? ((body as { detail: unknown }).detail as Record<string, unknown> | string)
      : undefined

  if (response.status === 404 && detail && typeof detail === 'object') {
    return { state: 'pending', stage: String(detail.stage ?? 'unknown') }
  }
  if (response.status === 501 && detail && typeof detail === 'object') {
    return {
      state: 'unavailable',
      what: String(detail.what ?? 'this feature'),
      task: String(detail.task ?? '?'),
    }
  }
  return { state: 'error', message: detailMessage(body, `${response.status} ${response.statusText}`) }
}

// ─── jobs ────────────────────────────────────────────────────────────────────

export async function submitApk(file: File): Promise<string> {
  const form = new FormData()
  form.append('apk', file)
  const body = await request<{ job_id: string }>('/api/jobs', { method: 'POST', body: form })
  return body.job_id
}

export const getJob = (jobId: string) => request<Job>(`/api/jobs/${jobId}`)

export const getHealth = () => request<{ status: string; version: string }>('/api/health')

// ─── per-job artefacts ───────────────────────────────────────────────────────

export const getIngest = (jobId: string) => artefact<FileMeta>(`/api/jobs/${jobId}/ingest`)
export const getStatic = (jobId: string) => artefact<StaticReport>(`/api/jobs/${jobId}/static`)
export const getMl = (jobId: string) => artefact<MLPrediction>(`/api/jobs/${jobId}/ml`)
export const getGenai = (jobId: string) => artefact<GenAIVerdict>(`/api/jobs/${jobId}/genai`)
export const getDynamic = (jobId: string) => artefact<DynamicTrace>(`/api/jobs/${jobId}/dynamic`)
export const getScore = (jobId: string) => artefact<CompositeScore>(`/api/jobs/${jobId}/score`)

// ─── ledger ──────────────────────────────────────────────────────────────────

export function getLedger(
  jobId: string,
  opts: { type?: EvidenceTypeName; sourceTool?: string; sinceSeq?: number } = {},
): Promise<Artefact<EvidenceNode[]>> {
  const query = new URLSearchParams()
  if (opts.type) query.set('type', opts.type)
  if (opts.sourceTool) query.set('source_tool', opts.sourceTool)
  if (opts.sinceSeq) query.set('since_seq', String(opts.sinceSeq))
  const suffix = query.toString() ? `?${query}` : ''
  return artefact<EvidenceNode[]>(`/api/jobs/${jobId}/ledger${suffix}`)
}

/**
 * Verify a job's chain.
 *
 * A broken chain is **200 with ok:false**, not an HTTP error — the backend is
 * explicit that a successful report about a bad state is not a failed request.
 * So this uses `request`, and a red banner comes from `ok === false`.
 */
export const verifyLedger = (jobId: string) =>
  request<ChainVerification>(`/api/jobs/${jobId}/ledger/verify`)

export const getEvidenceNode = (nodeId: string) => artefact<EvidenceNode>(`/api/evidence/${nodeId}`)

export const ledgerExportUrl = (jobId: string) => `/api/jobs/${jobId}/ledger/export`

// ─── artefacts / actions ─────────────────────────────────────────────────────

export const getReportHtml = (jobId: string) => artefact<string>(`/api/jobs/${jobId}/report.html`)
export const getYara = (jobId: string) => artefact<string>(`/api/jobs/${jobId}/artifacts/yara`)
export const getStix = (jobId: string) => artefact<unknown>(`/api/jobs/${jobId}/artifacts/stix`)

export const confirmAction = (jobId: string, action: string, confirmedBy: string) =>
  request<ProposedAction>(`/api/jobs/${jobId}/actions/${action}/confirm`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ confirmed_by: confirmedBy }),
  })

/**
 * TypeScript mirrors of `drishti/contracts/`.
 *
 * Hand-written rather than generated, deliberately: the generator would need a
 * build step on the Python side that nothing else needs, and the route surface is
 * frozen (docs/PHASE_0_FOUNDATIONS.md T0.6) so these do not chase daily changes.
 *
 * The rule when editing: a field here must exist in the pydantic model. The UI
 * never invents a field, and never displays a number the API did not send —
 * CLAUDE.md's honesty requirements are enforced by what this file does NOT contain.
 */

// ─── §7 job ──────────────────────────────────────────────────────────────────

export type JobStage =
  | 'queued'
  | 'ingest'
  | 'static'
  | 'ml'
  | 'genai_static'
  | 'score_prelim'
  | 'sandbox_pass1'
  | 'frontier'
  | 'sandbox_pass2'
  | 'genai_full'
  | 'score_final'
  | 'report'
  | 'done'
  | 'failed'

/** Canonical order, mirroring `contracts/job.py:PIPELINE_ORDER`. */
export const PIPELINE_ORDER: JobStage[] = [
  'ingest',
  'static',
  'ml',
  'genai_static',
  'score_prelim',
  'sandbox_pass1',
  'frontier',
  'sandbox_pass2',
  'genai_full',
  'score_final',
  'report',
]

/** FRONTIER and SANDBOX_2 are conditional — they run only when pass 1 stalled. */
export const CONDITIONAL_STAGES: ReadonlySet<JobStage> = new Set<JobStage>([
  'frontier',
  'sandbox_pass2',
])

export const STAGE_LABELS: Record<JobStage, string> = {
  queued: 'Queued',
  ingest: 'Ingest',
  static: 'Static',
  ml: 'ML',
  genai_static: 'GenAI (static)',
  score_prelim: 'Score (prelim)',
  sandbox_pass1: 'Sandbox 1',
  frontier: 'Frontier',
  sandbox_pass2: 'Sandbox 2',
  genai_full: 'GenAI (full)',
  score_final: 'Score (final)',
  report: 'Report',
  done: 'Done',
  failed: 'Failed',
}

export interface StageEvent {
  stage: JobStage
  status: string
  at: string
  duration_ms: number | null
  message: string | null
  ledger_seq: number | null
}

export interface Job {
  id: string
  sha256: string
  filename: string
  stage: JobStage
  created_at: string
  stage_history: StageEvent[]
  preliminary: CompositeScore | null
  final: CompositeScore | null
  error: string | null
}

// ─── §0 degradation ──────────────────────────────────────────────────────────

export interface AnalyserResult {
  errors: string[]
  partial: boolean
  duration_ms: number
}

// ─── §5 / §6 ML and score ────────────────────────────────────────────────────

// Re-exported from the generated binding rather than restated here. `SeverityBand` is
// the one enum this file shares with `Verdict`, and two hand-kept copies of it would be
// the drift contract A15 forbids.
import type { SeverityBand } from './verdict.gen'
export type { SeverityBand }

export interface FeatureAttribution {
  feature: string
  value: number
  shap: number
  direction: '+' | '-'
}

export interface MLPrediction extends AnalyserResult {
  p_malicious_raw: number
  p_calibrated: number
  labels: Record<string, number>
  top_features: FeatureAttribution[]
  anomaly_score: number
  anomaly_escalate: boolean
  model_version: string
  feature_schema_version: string
  ledger_refs: string[]
}

export type FactorSymbol = 'R' | 'F_AI' | 'G' | 'D'

export interface ScoreFactor {
  symbol: FactorSymbol
  label: string
  raw: number
  weight: number
  contribution: number
  inputs: Record<string, unknown>
  evidence_refs: string[]
}

export type ActionName =
  | 'block'
  | 'quarantine'
  | 'notify_customers'
  | 'push_ioc'
  | 'fast_track_analyst'
  | 'analyst_review'
  | 'monitor'
  | 'log'

export interface ProposedAction {
  action: ActionName
  rationale: string
  requires_confirmation: boolean
  confirmed_by: string | null
  confirmed_at: string | null
}

export interface CompositeScore {
  S: number
  band: SeverityBand
  C: number
  gamma: number
  factors: ScoreFactor[]
  override_applied: string | null
  requires_human_review: boolean
  anomaly_escalated: boolean
  actions_proposed: ProposedAction[]
  explanation: string
  limitations: string[]
  ledger_refs: string[]
}

// ─── §1 evidence ledger ──────────────────────────────────────────────────────

export type EvidenceTypeName =
  | 'file_meta'
  | 'split_apk'
  | 'threat_intel'
  | 'manifest_entry'
  | 'permission_combo'
  | 'certificate'
  | 'string_const'
  | 'code_method'
  | 'decompiled_method'
  | 'deobfuscated_string'
  | 'call_path'
  | 'sink_hit'
  | 'overprivilege'
  | 'api_trace'
  | 'network_flow'
  | 'decrypted_blob'
  | 'file_write'
  | 'dex_load'
  | 'screenshot'
  | 'evasion_check'
  | 'morph_action'
  | 'generative_c2'
  | 'detonation'
  | 'ai_claim'
  | 'ai_hypothesis'
  | 'technique_map'
  | 'vision_match'
  | 'ai_tool_call'
  | 'report_generated'
  | 'ml_prediction'
  | 'anomaly_signal'
  | 'score_factor'
  | 'error'
  | 'analyst_action'

export interface EvidenceNode {
  id: string
  job_id: string
  seq: number
  type: EvidenceTypeName
  source_tool: string
  content: Record<string, unknown>
  location: string | null
  confidence: number
  parents: string[]
  timestamp: string
  prev_hash: string
  node_hash: string
  signature: string
}

export interface ChainVerification {
  ok: boolean
  node_count: number
  first_bad_seq: number | null
  reason: string | null
}

// ─── §2 ingest + static ──────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type ComponentKind = 'activity' | 'service' | 'receiver' | 'provider'

export interface Component {
  name: string
  kind: ComponentKind
  exported: boolean
  permission: string | null
  intent_filters: string[]
}

export interface PermissionCombo {
  rule_id: string
  permissions: string[]
  severity: Severity
  description: string
  mitre: string | null
}

export interface CertificateInfo {
  sha256: string
  subject: string
  issuer: string
  not_before: string
  not_after: string
  age_days: number
  self_signed: boolean
  known_bad_reuse: boolean
  brand_mismatch: boolean
  brand_claimed: string | null
  debug_cert: boolean
}

export interface CallPath {
  sink_id: string
  sink_signature: string
  path: string[]
  entrypoint: string
  entrypoint_kind: string
  reachable_from_lifecycle: boolean
}

export interface DecompiledMethod {
  signature: string
  body: string
  line_start: number
  line_end: number
  call_path_indexes: number[]
  evidence_ref: string
  truncated: boolean
}

export type HypothesisKind =
  | 'secondary_payload'
  | 'otp_exfil'
  | 'overlay_attack'
  | 'accessibility_abuse'
  | 'target_app_probe'
  | 'c2_beacon'
  | 'logic_bomb'
  | 'clipboard_swap'

export interface Hypothesis {
  id: string
  kind: HypothesisKind
  statement: string
  target_methods: string[]
  target_apis: string[]
  suggested_probe: Record<string, unknown>
  priority: number
  evidence_refs: string[]
}

export interface ThreatIntel extends AnalyserResult {
  sha256: string
  known_bad_hash: boolean
  detections: number | null
  total_engines: number | null
  source: string
  verdict: 'confirmed_bad' | 'suspected_bad' | 'grey' | 'unknown'
  family: string | null
  c2_domains: string[]
  label_derived: boolean
}

export interface FileMeta extends AnalyserResult {
  sha256: string
  size_bytes: number
  filename: string
  package: string | null
  app_label: string | null
  version_name: string | null
  version_code: number | null
  min_sdk: number | null
  target_sdk: number | null
  is_split: boolean
  split_names: string[]
  dedupe_hit: boolean
  intel: ThreatIntel | null
  ledger_refs: string[]
}

export type BenignLookalikeVerdict = 'trojan_shape' | 'legitimate_privileged' | 'indeterminate'

/** One discriminator from `m2_static/lookalike.py`, and whether it fired. */
export interface LookalikeSignal {
  id: string
  present: boolean
  weight: number
  detail: string
  evidence_refs: string[]
}

/**
 * Contract A13. Why this app is, or is not, the trojan its permissions would allow.
 *
 * `shared_permissions` is the half that matters to a reader: the capabilities this
 * sample holds in common with Truecaller, SMS-backup tools and anti-spam apps. The
 * panel leads with it, because a report that presents a dual-use permission as though
 * it were itself the finding is a report that flags Truecaller.
 *
 * There is no `benign` verdict. `indeterminate` is the best available.
 */
export interface LookalikeAssessment {
  verdict: BenignLookalikeVerdict
  trojan_score: number
  signals: LookalikeSignal[]
  shared_permissions: string[]
  targeted_financial_packages: string[]
  publisher_trusted: boolean
  rationale: string
}

export interface StaticReport extends AnalyserResult {
  sha256: string
  package: string
  app_label: string
  version_name: string
  version_code: number
  min_sdk: number
  target_sdk: number
  permissions: string[]
  permission_combos: PermissionCombo[]
  components: Component[]
  exported_unprotected: Component[]
  deep_link_schemes: string[]
  certificate: CertificateInfo
  declared_not_used: string[]
  used_not_declared: string[]
  native_libs: string[]
  dex_count: number
  entropy_mean: number
  packer_hints: string[]
  dcl_indicators: string[]
  reflection_count: number
  urls: string[]
  crypto_constants: string[]
  call_paths: CallPath[]
  decompiled_methods: DecompiledMethod[]
  sink_hits: string[]
  hypotheses: Hypothesis[]
  lookalike: LookalikeAssessment | null
  ledger_refs: string[]
}

// ─── §3 dynamic ──────────────────────────────────────────────────────────────

export type TraceSourceKind = 'live' | 'replay' | 'unavailable'

export interface ApiEvent {
  t_ms: number
  api: string
  args: string[]
  retval: string | null
  thread: string
  stack: string[]
  count: number
}

export interface NetworkFlow {
  t_ms: number
  method: string
  url: string
  host: string
  req_headers: Record<string, unknown>
  req_body_preview: string
  req_body_sha256: string | null
  status: number | null
  resp_body_preview: string | null
  /** True when DRISHTI authored the RESPONSE BODY — not a statement about the destination. */
  synthesised: boolean
  tls_intercepted: boolean
  /** True when the DESTINATION is DRISHTI's own (sinkhole, proxy, a host we named). Never an IOC. */
  injected_destination: boolean
  /** Requests to this (host, path, method) folded into this row. */
  occurrences: number
}

export interface DecryptedBlob {
  t_ms: number
  algorithm: string | null
  plaintext_preview: string
  plaintext_sha256: string | null
  length_bytes: number
  contains_url: boolean
  contains_dex_magic: boolean
  occurrences: number
}

export interface DexLoadEvent {
  t_ms: number
  loader: string
  path: string | null
  sha256: string | null
  size_bytes: number | null
  in_original_apk: boolean
  dumped_to: string | null
}

export interface FileWrite {
  t_ms: number
  path: string
  size_bytes: number | null
  sha256: string | null
  is_executable_content: boolean
  deleted_after: boolean
}

export interface EvasionObservation {
  probe_kind: string
  queried: string
  result: 'HIT' | 'MISS'
  t_ms: number
  followed_by_stall: boolean
  stall_duration_ms: number | null
  inferred_requirement: string | null
  stack: string[]
}

export type TraceOutcome = 'completed' | 'inconclusive' | 'failed' | 'timeout' | 'crashed'

export interface DynamicTrace extends AnalyserResult {
  run_id: string
  source: TraceSourceKind
  detonated: boolean
  detonation_reason: string | null
  outcome: TraceOutcome
  api_events: ApiEvent[]
  network_flows: NetworkFlow[]
  decrypted_blobs: DecryptedBlob[]
  dex_loads: DexLoadEvent[]
  file_writes: FileWrite[]
  evasion_observations: EvasionObservation[]
  screenshots: string[]
  morphs_applied: string[]
  ledger_refs: string[]
  emulator_image: string | null
  vm_instance_id: string | null
  harness_version: string | null
  containment_verified: boolean
  captured_at: string | null
  synthetic: boolean
}

// ─── A12 reporting dossier ───────────────────────────────────────────────────

/**
 * The complaint package for a cyber cell or a bank fraud desk. Mirrors the response of
 * `GET /api/jobs/{job}/artifacts/dossier` (`drishti/m7_report/dossier.py`).
 *
 * `submission_is_manual` is always `true` and there is no code path that can set it
 * false: India's National Cyber Crime Reporting Portal has no public submission API.
 * Nothing in this product files a complaint. The UI generates a package a human files,
 * and must never offer a control that reads as "report to cyber cell".
 */
export interface Dossier {
  sha256: string
  reportable: boolean
  reason: string
  summary: string
  facts: Record<string, string | number | boolean | null>
  indicators: string[]
  techniques: string[]
  caveats: string[]
  portal_url: string
  helpline: string
  submission_is_manual: boolean
  text: string
}

// ─── §4 GenAI verdict ────────────────────────────────────────────────────────

export type VerifierStatus =
  | 'PASS'
  | 'REJECTED_NO_EVIDENCE'
  | 'REJECTED_BAD_REF'
  | 'REJECTED_TYPE_MISMATCH'

export interface GroundedClaim {
  text: string
  evidence_refs: string[]
  agent: string
  verifier_status: VerifierStatus
}

export interface CodeInterpretation {
  method_signature: string
  summary: string
  claims: GroundedClaim[]
  renamed_symbols: Record<string, string>
  confidence: 'high' | 'medium' | 'low'
  insufficient_evidence: boolean
  cited_lines: number[]
}

export interface ToolCallRecord {
  id: string
  name: string
  arguments: Record<string, unknown>
  status: 'ok' | 'rejected' | 'error'
  result_summary: string
  evidence_refs: string[]
  duration_ms: number
}

export interface VerifiedString {
  ciphertext: string
  transform: string
  plaintext: string
  verified: boolean
  reason: string
  evidence_refs: string[]
}

export interface TechniqueMapping {
  technique_id: string
  name: string
  tactic: string
  layer: 'static' | 'dynamic' | 'both'
  evidence_refs: string[]
}

export interface VictimProfile {
  language: string | null
  tactic: string | null
  segment: string | null
  impersonated_target: string | null
  confidence: number
  evidence_refs: string[]
}

export interface VisionMatch {
  matched_brand: string | null
  similarity: number
  threshold: number
  method: 'vlm' | 'perceptual_hash'
  icon_path: string | null
  screenshot_path: string | null
  evidence_refs: string[]
}

export interface GenAIVerdict extends AnalyserResult {
  summary: string
  claims: GroundedClaim[]
  behavioural_risk_B: number
  B_rationale: string
  behaviours: Record<string, boolean>
  techniques: TechniqueMapping[]
  victim: VictimProfile | null
  impersonation: VisionMatch | null
  interpretations: CodeInterpretation[]
  tool_calls: ToolCallRecord[]
  verified_strings: VerifiedString[]
  elicitation_deployed: string[]
  disagreement_flag: boolean
  disagreement_note: string | null
  llm_calls: number
  provider: string
  ledger_refs: string[]
}

/**
 * GENERATED FILE — DO NOT EDIT.
 *
 * Emitted from `drishti/contracts/verdict.py` by `ui/scripts/gen_verdict_types.py`.
 * `drishti/contracts/verdict.py` is the single source of truth for this shape
 * (contract addendum A15); a hand-maintained copy of it here would be exactly the
 * drift that contract exists to prevent, so this file is generated and a contract
 * test fails when it no longer matches the model.
 *
 * Regenerate:  python ui/scripts/gen_verdict_types.py
 */


/**
 * What the sandbox actually observed. `null` on the parent until a run happens.
 *
 * `detonated=True` with three empty lists is a real and important state: the app ran
 * and did nothing observable. It is NOT the same as never having run, which is why
 * this object exists rather than the fields being optional on the parent.
 */
export interface DynamicTraceView {
  detonated: boolean
  api_calls: string[]
  decrypted_strings: string[]
  network_captures: string[]
}

export type SeverityBand = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

/**
 * The social-engineering read, flattened for display.
 */
export interface VictimProfileView {
  language: string | null
  tactic: string | null
  segment: string | null
}

/**
 * The flat, cross-surface view of one analysed APK.
 *
 * Consumed by the consumer warning screen, the analyst portal, and the demo scripts.
 * Produced only by `build_verdict()`.
 */
export interface Verdict {
  sha256: string
  package_name: string
  threat_score: number
  severity_band: SeverityBand
  confidence: number
  provenance: 'STATIC_ONLY' | 'REPLAY' | 'LIVE'
  impersonated_target: string | null
  victim_profile: VictimProfileView
  behaviors_detected: string[]
  attack_techniques: string[]
  evidence_refs: string[]
  consumer_summary: string
  recommended_action: 'BLOCK' | 'REVIEW' | 'MONITOR'
  dynamic_trace: DynamicTraceView | null
  adversarial_elicitation_deployed: string[]
  limitations: string[]
}

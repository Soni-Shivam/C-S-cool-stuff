package in.drishti.client.model

import com.google.gson.annotations.SerializedName

data class Accepted(val analysis_id: String, val state: String)
data class JobStatus(
    val analysis_id: String,
    val state: String,
    val sha256: String? = null,
    val error: String? = null,
)
data class Confidence(val value: Double, val label: String)
data class Provenance(
    val static_analysis: String,
    val ml_model_version: String,
    val gemini_status: String,
    val dynamic_status: String,
    val notice: String,
)
data class CitedStatement(val text: String, val evidence_refs: List<String> = emptyList())
data class Capability(
    val capability_id: String,
    val text: String,
    val permissions: List<String> = emptyList(),
    val mitre_techniques: List<String> = emptyList(),
    val evidence_refs: List<String> = emptyList(),
)
data class Indicator(val kind: String, val value: String, val evidence_refs: List<String>)
data class Evidence(
    val id: String,
    val type: String,
    val source: String,
    val statement: String,
    val location: String? = null,
    val confidence: Double,
    val provenance: String,
)
data class AnalysisReport(
    val analysis_id: String,
    val sha256: String,
    val threat_score: Int,
    val severity: String,
    val confidence: Confidence,
    val provenance: Provenance,
    val genai_summary: CitedStatement,
    val potential_consequences: List<CitedStatement> = emptyList(),
    val suspicious_permissions: List<String> = emptyList(),
    val suspicious_capabilities: List<Capability> = emptyList(),
    val mitre_mobile_techniques: List<CitedStatement> = emptyList(),
    val iocs: List<Indicator> = emptyList(),
    val evidence: List<Evidence> = emptyList(),
    val safety_notice: String,
)

package in.drishti.client

import com.google.gson.Gson
import in.drishti.client.model.AnalysisReport
import org.junit.Assert.assertEquals
import org.junit.Test

class ApiParsingTest {
    @Test fun `report provenance parses all explicit modes`() {
        val json = """{
          "analysis_id":"id","sha256":"${"a".repeat(64)}","threat_score":71,
          "severity":"High","confidence":{"value":0.82,"label":"High"},
          "provenance":{"static_analysis":"completed","ml_model_version":"m1","gemini_status":"live","dynamic_status":"observed","notice":"SHA matched"},
          "genai_summary":{"text":"Observed artifact was available","evidence_refs":["n2"]},
          "potential_consequences":[],"suspicious_permissions":[],"suspicious_capabilities":[],
          "mitre_mobile_techniques":[],"iocs":[],"evidence":[],"safety_notice":"User controls install"
        }"""
        val report = Gson().fromJson(json, AnalysisReport::class.java)
        assertEquals("observed", report.provenance.dynamic_status)
        assertEquals("live", report.provenance.gemini_status)
        assertEquals(71, report.threat_score)
    }
}

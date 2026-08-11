package in.drishti.client

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import in.drishti.client.model.AnalysisReport

private val Navy = Color(0xFF13233F)
private val Blue = Color(0xFF2357D9)
private val Pale = Color(0xFFF4F7FD)
private val Warning = Color(0xFFFFF1D6)

@Composable
fun DrishtiApp(
    state: UiState,
    onConfigure: (String, String) -> Unit,
    onPick: () -> Unit,
    onRetry: () -> Unit,
    onDelete: () -> Unit,
    onSettings: () -> Unit,
    onInstall: (UiState.Complete) -> Unit,
) {
    when (state) {
        UiState.Configure -> ConfigurationScreen(onConfigure)
        UiState.Select -> SelectionScreen(onPick, onSettings)
        is UiState.Preparing -> ProgressScreen("Preparing ${state.name}", null, "Copying only this URI into private cache…")
        is UiState.Uploading -> ProgressScreen("Uploading for analysis", state.progress / 100f, "SHA-256\n${state.sha256}")
        is UiState.Analyzing -> ProgressScreen("Analysis ${state.serverState}", null, "Static analysis, trained ML, and grounded reasoning are running.")
        is UiState.Complete -> VerdictScreen(state, onDelete, onInstall)
        is UiState.Error -> ErrorScreen(state.message, onRetry, onSettings)
    }
}

@Composable
private fun Header(kicker: String, title: String, subtitle: String) {
    Column(Modifier.fillMaxWidth().background(Navy).padding(24.dp)) {
        Text(kicker.uppercase(), color = Color(0xFF9AB6FF), style = MaterialTheme.typography.labelMedium)
        Spacer(Modifier.height(8.dp))
        Text(title, color = Color.White, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(6.dp))
        Text(subtitle, color = Color(0xFFD7E1F8), style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun ConfigurationScreen(onConfigure: (String, String) -> Unit) {
    var url by remember { mutableStateOf("http://10.0.2.2:8000/") }
    var token by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize().background(Pale)) {
        Header("Pre-install protection", "Connect DRISHTI", "Configure the analysis service before selecting an APK.")
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Text("Your APK is uploaded only when you explicitly select or share it.")
            OutlinedTextField(url, { url = it }, label = { Text("Backend URL") }, modifier = Modifier.fillMaxWidth())
            OutlinedTextField(token, { token = it }, label = { Text("Demo API token") }, modifier = Modifier.fillMaxWidth())
            Button({ onConfigure(url, token) }, enabled = token.isNotBlank(), modifier = Modifier.fillMaxWidth()) { Text("Save and continue") }
        }
    }
}

@Composable
private fun SelectionScreen(onPick: () -> Unit, onSettings: () -> Unit) {
    Column(Modifier.fillMaxSize().background(Pale)) {
        Header("DRISHTI", "Check before you install", "Select an APK with Android’s document picker, or share a download to DRISHTI.")
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(16.dp)) {
            Card(colors = CardDefaults.cardColors(containerColor = Color.White)) {
                Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("What happens", fontWeight = FontWeight.Bold)
                    Text("1  You choose one APK\n2  DRISHTI analyzes it without installing it\n3  You review evidence and decide")
                    Text("Real malware must never be installed on a physical demo phone.", color = Color(0xFF9C2F20), fontWeight = FontWeight.SemiBold)
                }
            }
            Button(onPick, modifier = Modifier.fillMaxWidth()) { Text("Select APK") }
            TextButton(onSettings, modifier = Modifier.align(Alignment.CenterHorizontally)) { Text("Backend settings") }
        }
    }
}

@Composable
private fun ProgressScreen(title: String, progress: Float?, detail: String) {
    Column(Modifier.fillMaxSize().background(Pale), horizontalAlignment = Alignment.CenterHorizontally) {
        Header("Analysis in progress", title, "You may leave DRISHTI open; a notification appears when the report is ready.")
        Spacer(Modifier.height(56.dp))
        if (progress == null) CircularProgressIndicator(color = Blue) else LinearProgressIndicator({ progress }, Modifier.fillMaxWidth().padding(horizontal = 40.dp))
        Text(detail, Modifier.padding(28.dp), style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun VerdictScreen(complete: UiState.Complete, onDelete: () -> Unit, onInstall: (UiState.Complete) -> Unit) {
    val report = complete.report
    var showEvidence by remember { mutableStateOf(false) }
    var acknowledge by remember { mutableStateOf(false) }
    if (acknowledge) AlertDialog(
        onDismissRequest = { acknowledge = false },
        title = { Text("Continue to Android installer?") },
        text = { Text("I understand DRISHTI is decision support, this app may be risky, and Android—not DRISHTI—controls the final installation approval.") },
        confirmButton = { Button({ acknowledge = false; onInstall(complete) }) { Text("I understand—continue") } },
        dismissButton = { TextButton({ acknowledge = false }) { Text("Cancel") } },
    )
    LazyColumn(Modifier.fillMaxSize().background(Pale)) {
        item { Header(report.severity, "${report.threat_score} / 100", "Threat score • ${report.confidence.label} confidence (${String.format("%.0f", report.confidence.value * 100)}%)") }
        if (report.provenance.gemini_status == "mock" || report.provenance.dynamic_status != "observed") {
            item {
                Card(Modifier.fillMaxWidth().padding(16.dp), colors = CardDefaults.cardColors(containerColor = Warning)) {
                    Column(Modifier.padding(16.dp)) {
                        if (report.provenance.gemini_status == "mock") Text("Gemini is mocked", fontWeight = FontWeight.Bold)
                        Text(report.provenance.notice)
                    }
                }
            }
        }
        item { ReportSection("Verified summary") { Text(report.genai_summary.text) } }
        item { ReportSection("Potential consequences") { report.potential_consequences.forEach { Text("• ${it.text}", Modifier.padding(vertical = 3.dp)) } } }
        item { ReportSection("Suspicious capabilities") { report.suspicious_capabilities.forEach { Text(it.text, fontWeight = FontWeight.SemiBold); Text(it.permissions.joinToString(), style = MaterialTheme.typography.bodySmall) } } }
        item { ReportSection("MITRE Mobile") { Text(report.mitre_mobile_techniques.joinToString { it.text }.ifBlank { "No evidence-backed technique mapping." }) } }
        item { ReportSection("Indicators") { report.iocs.forEach { Text("${it.kind}: ${it.value}", maxLines = 2, overflow = TextOverflow.Ellipsis) } } }
        item { ReportSection("Provenance") { Text("ML: ${report.provenance.ml_model_version}\nGemini: ${report.provenance.gemini_status}\nDynamic: ${report.provenance.dynamic_status}\nSHA-256: ${report.sha256}") } }
        item {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton({ showEvidence = !showEvidence }, Modifier.fillMaxWidth()) { Text(if (showEvidence) "Hide evidence" else "Evidence details (${report.evidence.size})") }
                if (showEvidence) report.evidence.forEach { EvidenceRow(it.id, it.provenance, it.statement) }
                Button(onDelete, Modifier.fillMaxWidth()) { Text("Delete / Cancel") }
                OutlinedButton({ acknowledge = true }, Modifier.fillMaxWidth()) { Text("Continue to system installer") }
                Text(report.safety_notice, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
private fun ReportSection(title: String, content: @Composable () -> Unit) {
    Card(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 6.dp), colors = CardDefaults.cardColors(containerColor = Color.White)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) { Text(title, fontWeight = FontWeight.Bold); HorizontalDivider(); content() }
    }
}

@Composable
private fun EvidenceRow(id: String, provenance: String, statement: String) {
    Column(Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Text("$id • $provenance", color = Blue, style = MaterialTheme.typography.labelMedium)
        Text(statement, style = MaterialTheme.typography.bodySmall)
    }
}

@Composable
private fun ErrorScreen(message: String, onRetry: () -> Unit, onSettings: () -> Unit) {
    Column(Modifier.fillMaxSize().background(Pale)) {
        Header("Could not complete", "Analysis error", message)
        Column(Modifier.padding(24.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Button(onRetry, Modifier.fillMaxWidth()) { Text("Retry") }
            OutlinedButton(onSettings, Modifier.fillMaxWidth()) { Text("Check backend settings") }
        }
    }
}

package in.drishti.client

import android.app.Application
import in.drishti.client.model.AnalysisReport
import in.drishti.client.model.Confidence
import in.drishti.client.model.CitedStatement
import in.drishti.client.model.JobStatus
import in.drishti.client.model.Provenance
import in.drishti.client.net.AnalysisRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File

@OptIn(ExperimentalCoroutinesApi::class)
class DrishtiViewModelTest {
    private val dispatcher = StandardTestDispatcher()

    @Before fun setup() { Dispatchers.setMain(dispatcher) }
    @After fun tearDown() { Dispatchers.resetMain() }

    @Test fun `upload transitions to completed report`() = runTest(dispatcher) {
        val report = sampleReport()
        val repo = object : AnalysisRepository {
            override suspend fun upload(file: File, onProgress: (Int) -> Unit): String {
                onProgress(100); return "job-1"
            }
            override suspend fun status(id: String) = JobStatus(id, "completed", "a".repeat(64))
            override suspend fun report(id: String) = report
        }
        val vm = DrishtiViewModel(Application())
        vm.setRepositoryForTest(repo)
        val file = File.createTempFile("fixture", ".apk")
        vm.startAnalysis(file, "a".repeat(64))
        advanceUntilIdle()
        assertTrue(vm.state.value is UiState.Complete)
        assertEquals(17, (vm.state.value as UiState.Complete).report.threat_score)
        file.delete()
    }

    @Test fun `failed backend transitions to retryable error`() = runTest(dispatcher) {
        val repo = object : AnalysisRepository {
            override suspend fun upload(file: File, onProgress: (Int) -> Unit) = "job-2"
            override suspend fun status(id: String) = JobStatus(id, "failed", error = "parser")
            override suspend fun report(id: String): AnalysisReport = error("not called")
        }
        val vm = DrishtiViewModel(Application())
        vm.setRepositoryForTest(repo)
        val file = File.createTempFile("fixture", ".apk")
        vm.startAnalysis(file, "b".repeat(64))
        advanceUntilIdle()
        assertTrue(vm.state.value is UiState.Error)
        file.delete()
    }

    private fun sampleReport() = AnalysisReport(
        analysis_id = "job-1", sha256 = "a".repeat(64), threat_score = 17,
        severity = "Low", confidence = Confidence(.8, "High"),
        provenance = Provenance("completed", "test-v1", "mock", "absent", "No dynamics"),
        genai_summary = CitedStatement("No verified high-risk behavior", listOf("n1")),
        safety_notice = "Decision support",
    )
}

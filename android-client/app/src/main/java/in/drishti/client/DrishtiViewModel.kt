package in.drishti.client

import android.app.Application
import android.content.ContentResolver
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import in.drishti.client.model.AnalysisReport
import in.drishti.client.net.AnalysisRepository
import in.drishti.client.net.RetrofitAnalysisRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest
import java.util.UUID

sealed interface UiState {
    data object Configure : UiState
    data object Select : UiState
    data class Preparing(val name: String) : UiState
    data class Uploading(val sha256: String, val progress: Int) : UiState
    data class Analyzing(val sha256: String, val serverState: String) : UiState
    data class Complete(val report: AnalysisReport, val localFile: File) : UiState
    data class Error(val message: String, val retryable: Boolean = true) : UiState
}

class DrishtiViewModel(application: Application) : AndroidViewModel(application) {
    private val prefs = runCatching { application.getSharedPreferences("drishti", 0) }.getOrNull()
    private val _state = MutableStateFlow<UiState>(
        if (prefs?.contains("base_url") == true) UiState.Select else UiState.Configure
    )
    val state: StateFlow<UiState> = _state.asStateFlow()
    private var repository: AnalysisRepository? = configuredRepository()
    private var retryFile: File? = null
    private var retrySha: String? = null

    private fun configuredRepository(): AnalysisRepository? {
        val preferences = prefs ?: return null
        val url = preferences.getString("base_url", null) ?: return null
        val token = preferences.getString("token", null) ?: return null
        return RetrofitAnalysisRepository(url, token)
    }

    fun configure(baseUrl: String, token: String) {
        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
            _state.value = UiState.Error("Enter a complete http:// or https:// backend URL.")
            return
        }
        prefs?.edit()?.putString("base_url", baseUrl.trim())?.putString("token", token.trim())?.apply()
        repository = configuredRepository()
        _state.value = UiState.Select
    }

    fun acceptUri(uri: Uri, resolver: ContentResolver) {
        _state.value = UiState.Preparing(uri.lastPathSegment ?: "shared APK")
        viewModelScope.launch {
            try {
                val prepared = withContext(Dispatchers.IO) { copyAndHash(uri, resolver) }
                startAnalysis(prepared.first, prepared.second)
            } catch (_: Exception) {
                _state.value = UiState.Error("The selected APK could not be read from Android storage.")
            }
        }
    }

    internal fun startAnalysis(file: File, sha256: String) {
        retryFile = file
        retrySha = sha256
        val repo = repository ?: run {
            _state.value = UiState.Configure
            return
        }
        viewModelScope.launch {
            try {
                _state.value = UiState.Uploading(sha256, 0)
                val id = repo.upload(file) { value -> _state.value = UiState.Uploading(sha256, value) }
                while (true) {
                    val job = repo.status(id)
                    _state.value = UiState.Analyzing(sha256, job.state)
                    when (job.state) {
                        "completed" -> {
                            _state.value = UiState.Complete(repo.report(id), file)
                            return@launch
                        }
                        "failed" -> throw IllegalStateException(job.error ?: "Analysis failed")
                    }
                    delay(1_000)
                }
            } catch (_: Exception) {
                _state.value = UiState.Error("Analysis failed. Check the backend URL, token, and connection.")
            }
        }
    }

    fun retry() {
        val file = retryFile
        val sha = retrySha
        if (file != null && sha != null && file.exists()) startAnalysis(file, sha) else _state.value = UiState.Select
    }

    fun deleteAndReset() {
        retryFile?.delete()
        retryFile = null
        retrySha = null
        _state.value = UiState.Select
    }

    fun showConfiguration() { _state.value = UiState.Configure }

    private fun copyAndHash(uri: Uri, resolver: ContentResolver): Pair<File, String> {
        val directory = File(getApplication<Application>().cacheDir, "selected-apks").apply { mkdirs() }
        val target = File(directory, "${UUID.randomUUID()}.apk")
        val digest = MessageDigest.getInstance("SHA-256")
        resolver.openInputStream(uri).use { input ->
            requireNotNull(input)
            target.outputStream().use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                var count: Int
                while (input.read(buffer).also { count = it } != -1) {
                    output.write(buffer, 0, count)
                    digest.update(buffer, 0, count)
                }
            }
        }
        return target to digest.digest().joinToString("") { "%02x".format(it) }
    }

    internal fun setRepositoryForTest(value: AnalysisRepository) { repository = value }
}

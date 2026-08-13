package in.drishti.client.net

import in.drishti.client.model.AnalysisReport
import in.drishti.client.model.JobStatus
import kotlinx.coroutines.delay
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MultipartBody
import okhttp3.OkHttpClient
import okhttp3.RequestBody
import okio.BufferedSink
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.File

interface AnalysisRepository {
    suspend fun upload(file: File, onProgress: (Int) -> Unit): String
    suspend fun status(id: String): JobStatus
    suspend fun report(id: String): AnalysisReport
}

class RetrofitAnalysisRepository(baseUrl: String, token: String) : AnalysisRepository {
    private val api: DrishtiApi
    init {
        val normalized = if (baseUrl.endsWith('/')) baseUrl else "$baseUrl/"
        val client = OkHttpClient.Builder().addInterceptor { chain ->
            chain.proceed(chain.request().newBuilder().header("Authorization", "Bearer $token").build())
        }.build()
        api = Retrofit.Builder().baseUrl(normalized).client(client)
            .addConverterFactory(GsonConverterFactory.create()).build().create(DrishtiApi::class.java)
    }

    override suspend fun upload(file: File, onProgress: (Int) -> Unit): String {
        val body = ProgressRequestBody(file, onProgress)
        return api.upload(MultipartBody.Part.createFormData("file", "selected.apk", body)).analysis_id
    }
    override suspend fun status(id: String) = api.status(id)
    override suspend fun report(id: String) = api.report(id)
}

private class ProgressRequestBody(
    private val file: File,
    private val progress: (Int) -> Unit,
) : RequestBody() {
    override fun contentType() = "application/vnd.android.package-archive".toMediaType()
    override fun contentLength() = file.length()
    override fun writeTo(sink: BufferedSink) {
        file.inputStream().use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            var sent = 0L
            var count: Int
            while (input.read(buffer).also { count = it } != -1) {
                sink.write(buffer, 0, count)
                sent += count
                progress(((sent * 100) / contentLength().coerceAtLeast(1)).toInt())
            }
        }
    }
}

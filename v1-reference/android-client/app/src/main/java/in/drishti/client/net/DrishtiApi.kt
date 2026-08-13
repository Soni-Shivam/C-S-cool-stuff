package in.drishti.client.net

import in.drishti.client.model.Accepted
import in.drishti.client.model.AnalysisReport
import in.drishti.client.model.JobStatus
import okhttp3.MultipartBody
import retrofit2.http.GET
import retrofit2.http.Multipart
import retrofit2.http.POST
import retrofit2.http.Part
import retrofit2.http.Path

interface DrishtiApi {
    @Multipart @POST("v1/analyses")
    suspend fun upload(@Part file: MultipartBody.Part): Accepted

    @GET("v1/analyses/{id}")
    suspend fun status(@Path("id") id: String): JobStatus

    @GET("v1/analyses/{id}/report")
    suspend fun report(@Path("id") id: String): AnalysisReport
}

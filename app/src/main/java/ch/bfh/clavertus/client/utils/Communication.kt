package ch.bfh.clavertus.client.utils

import ch.bfh.clavertus.authenticator.modules.IODispatcher
import ch.bfh.clavertus.client.models.NetworkResult
import ch.bfh.clavertus.client.modules.ClientHttpClient
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class Communication @Inject constructor(
    @ClientHttpClient private val okHttpClient: OkHttpClient,
    @IODispatcher private val ioDispatcher: CoroutineDispatcher
) {
    suspend fun makeNetworkRequest(
        request: Request,
        action: String,
    ): Result<NetworkResult> = withContext(ioDispatcher) {
        try {
            val response = okHttpClient.newCall(request).execute()
            if (response.isSuccessful) {
                val bodyString = response.body?.string().orEmpty()
                Result.success(NetworkResult(bodyString, action))
            } else {
                val bodyString = response.body?.string().orEmpty()
                val errorBody = bodyString.substring(
                    0,
                    bodyString.length.coerceAtMost(
                        ERROR_MESSAGE_BODY_MAX_LENGTH
                    )
                )
                val errorMessage = """
                    Http status code ${response.code}             
                    $errorBody
                """.trimIndent()
                Result.failure(IOException(errorMessage))
            }
        } catch (e: IOException) {
            Result.failure(e)
        }
    }

    companion object {
        private const val ERROR_MESSAGE_BODY_MAX_LENGTH = 100
    }
}

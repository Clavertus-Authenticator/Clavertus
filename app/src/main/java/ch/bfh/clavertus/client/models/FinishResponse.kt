package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable

@Serializable
data class FinishResponse(
    val success: Boolean,
    @Serializable(with = Base64ByteArraySerializer::class)
    val sessionToken: ByteArray,
    val response: Response,
) {
    companion object {
        fun fromJSON(json: String): FinishResponse {
            return JsonUtils.json.decodeFromString(json)
        }
    }

    @Serializable
    data class Response(
        val credential: Credential
    )

    @Serializable
    data class Credential(
        @Serializable(with = Base64ByteArraySerializer::class)
        val id: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Credential

            return id.contentEquals(other.id)
        }

        override fun hashCode(): Int {
            return id.contentHashCode()
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as FinishResponse

        if (success != other.success) return false
        if (!sessionToken.contentEquals(other.sessionToken)) return false
        return response == other.response
    }

    override fun hashCode(): Int {
        var result = success.hashCode()
        result = 31 * result + sessionToken.contentHashCode()
        result = 31 * result + response.hashCode()
        return result
    }
}

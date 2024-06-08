package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable

/**
 * Kotlin object for the "registration-begin"-message
 */
@Serializable
data class RegBeginResponse(
    val success: Boolean,
    val request: CredentialOptions,
) {
    companion object {
        fun fromJSON(json: String): RegBeginResponse {
            return JsonUtils.json.decodeFromString(json)
        }
    }
}

@Serializable
data class CredentialOptions(
    val publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions,
    // Java-server attributes
    @Serializable(with = Base64ByteArraySerializer::class)
    val requestId: ByteArray,
    @Serializable(with = Base64ByteArraySerializer::class)
    val sessionToken: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as CredentialOptions

        if (publicKeyCredentialCreationOptions != other.publicKeyCredentialCreationOptions) return false
        if (!requestId.contentEquals(other.requestId)) return false
        return sessionToken.contentEquals(other.sessionToken)
    }

    override fun hashCode(): Int {
        var result = publicKeyCredentialCreationOptions.hashCode()
        result = 31 * result + requestId.contentHashCode()
        result = 31 * result + sessionToken.contentHashCode()
        return result
    }
}

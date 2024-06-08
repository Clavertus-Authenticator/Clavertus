package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable

/**
 * Kotlin object for the "authentication-begin"-message
 * This class represents the authentication challenge sent from the RP to the client.
 * It contains the options for the authentication request.
 * The client will use these options to create the authentication response.
 */
@Serializable
data class AuthBeginResponse(
    val success: Boolean,
    val request: AuthenticationOptions,
) {
    companion object {
        fun fromJSON(json: String): AuthBeginResponse {
            return JsonUtils.json.decodeFromString(json)
        }
    }
}

@Serializable
data class AuthenticationOptions(
    val publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions,
    // Java-server attributes
    @Serializable(with = Base64ByteArraySerializer::class)
    val requestId: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticationOptions

        if (publicKeyCredentialRequestOptions != other.publicKeyCredentialRequestOptions) return false
        return requestId.contentEquals(other.requestId)
    }

    override fun hashCode(): Int {
        var result = publicKeyCredentialRequestOptions.hashCode()
        result = 31 * result + requestId.contentHashCode()
        return result
    }
}

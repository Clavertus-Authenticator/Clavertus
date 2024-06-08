package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

@Serializable
data class PublickeyCredentialAuth(
    val response: AuthenticatorGetAssertionResult,
    val type: String,
    @Serializable(with = Base64ByteArraySerializer::class)
    val id: ByteArray,
    @Serializable(with = Base64ByteArraySerializer::class)
    val rawId: ByteArray,
    val clientExtensionResults: HashMap<String, String> = hashMapOf(),
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublickeyCredentialAuth

        if (response != other.response) return false
        if (type != other.type) return false
        if (!id.contentEquals(other.id)) return false
        if (!rawId.contentEquals(other.rawId)) return false
        return clientExtensionResults == other.clientExtensionResults
    }

    override fun hashCode(): Int {
        var result = response.hashCode()
        result = 31 * result + type.hashCode()
        result = 31 * result + id.contentHashCode()
        result = 31 * result + rawId.contentHashCode()
        result = 31 * result + clientExtensionResults.hashCode()
        return result
    }

    fun toJson(): String {
        return JsonUtils.json.encodeToString(this)
    }

    companion object {
        fun fromJson(json: String): PublickeyCredentialAuth {
            return JsonUtils.json.decodeFromString(json)
        }
    }

    @Serializable
    data class AuthenticatorGetAssertionResult(
        val clientDataJSON: String,
        @Serializable(with = Base64ByteArraySerializer::class)
        val authenticatorData: ByteArray,
        @Serializable(with = Base64ByteArraySerializer::class)
        val signature: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as AuthenticatorGetAssertionResult

            if (clientDataJSON != other.clientDataJSON) return false
            if (!authenticatorData.contentEquals(other.authenticatorData)) return false
            return signature.contentEquals(other.signature)
        }

        override fun hashCode(): Int {
            var result = clientDataJSON.hashCode()
            result = 31 * result + authenticatorData.contentHashCode()
            result = 31 * result + signature.contentHashCode()
            return result
        }
    }
}

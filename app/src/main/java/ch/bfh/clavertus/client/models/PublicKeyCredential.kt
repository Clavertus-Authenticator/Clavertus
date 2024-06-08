package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

@Serializable
data class PublicKeyCredential(
    val type: String,
    @Serializable(with = Base64ByteArraySerializer::class)
    val id: ByteArray,
    @Serializable(with = Base64ByteArraySerializer::class)
    val rawId: ByteArray,
    val response: AuthenticatorRegisterResult,
    val clientExtensionResults: HashMap<String, String> = hashMapOf(),
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKeyCredential

        if (type != other.type) return false
        if (!id.contentEquals(other.id)) return false
        if (!rawId.contentEquals(other.rawId)) return false
        if (response != other.response) return false
        return clientExtensionResults == other.clientExtensionResults
    }

    override fun hashCode(): Int {
        var result = type.hashCode()
        result = 31 * result + id.contentHashCode()
        result = 31 * result + rawId.contentHashCode()
        result = 31 * result + response.hashCode()
        result = 31 * result + clientExtensionResults.hashCode()
        return result
    }

    fun toJson(): String {
        return JsonUtils.json.encodeToString(this)
    }

    companion object {
        fun fromJson(json: String): PublicKeyCredential {
            return JsonUtils.json.decodeFromString(json)
        }
    }

    @Serializable
    data class AuthenticatorRegisterResult(
        val clientDataJSON: String,
        @Serializable(with = Base64ByteArraySerializer::class)
        val attestationObject: ByteArray,
        val transports: MutableList<String> = mutableListOf(),
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as AuthenticatorRegisterResult

            if (clientDataJSON != other.clientDataJSON) return false
            if (!attestationObject.contentEquals(other.attestationObject)) return false
            return transports == other.transports
        }

        override fun hashCode(): Int {
            var result = clientDataJSON.hashCode()
            result = 31 * result + attestationObject.contentHashCode()
            result = 31 * result + transports.hashCode()
            return result
        }
    }
}

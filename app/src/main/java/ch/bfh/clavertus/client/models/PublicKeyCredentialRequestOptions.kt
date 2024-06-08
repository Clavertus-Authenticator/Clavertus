package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonElement

@Serializable
data class PublicKeyCredentialRequestOptions(
    val allowCredentials: List<AllowCredential>,
    @Serializable(with = Base64ByteArraySerializer::class)
    val challenge: ByteArray,
    val rpId: String,
    val extensions: Map<String, JsonElement> // ToDo replace with class
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKeyCredentialRequestOptions

        if (allowCredentials != other.allowCredentials) return false
        if (!challenge.contentEquals(other.challenge)) return false
        if (rpId != other.rpId) return false
        return extensions == other.extensions
    }

    override fun hashCode(): Int {
        var result = allowCredentials.hashCode()
        result = 31 * result + challenge.contentHashCode()
        result = 31 * result + rpId.hashCode()
        result = 31 * result + extensions.hashCode()
        return result
    }

    fun toJson(): String {
        return JsonUtils.json.encodeToString(this)
    }

    companion object {
        fun fromJson(json: String): PublicKeyCredentialRequestOptions {
            return JsonUtils.json.decodeFromString(json)
        }
    }

    @Serializable
    data class AllowCredential(
        @Serializable(with = Base64ByteArraySerializer::class)
        val id: ByteArray,
        val type: String,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as AllowCredential

            if (!id.contentEquals(other.id)) return false
            return type == other.type
        }

        override fun hashCode(): Int {
            var result = id.contentHashCode()
            result = 31 * result + type.hashCode()
            return result
        }
    }
}

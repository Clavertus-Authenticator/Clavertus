package ch.bfh.clavertus.client.models

import android.util.Base64
import ch.bfh.clavertus.authenticator.utils.crypto.Cryptography
import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Kotlin object for the ClientDataJson-structure
 */
@Serializable
data class ClientData(
    @Serializable(with = Base64ByteArraySerializer::class)
    val challenge: ByteArray,
    val origin: String,
    val type: String
) {
    fun getHash(): ByteArray {
        return Cryptography.sha256(this.toJson().toByteArray())
    }

    fun getBase64UrlEncodedJson(): String {
        return Base64.encodeToString(
            toJson().toByteArray(),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )
    }

    private fun toJson(): String {
        return JsonUtils.json.encodeToString(this)
    }

    companion object {
        fun fromJson(json: String): ClientData {
            return JsonUtils.json.decodeFromString(serializer(), json)
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ClientData

        if (!challenge.contentEquals(other.challenge)) return false
        if (origin != other.origin) return false
        return type == other.type
    }

    override fun hashCode(): Int {
        var result = challenge.contentHashCode()
        result = 31 * result + origin.hashCode()
        result = 31 * result + type.hashCode()
        return result
    }
}

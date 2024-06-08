package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Kotlin object for the "registration-complete"-message
 */
@Serializable
data class RegCompletePostData(
    val credential: PublicKeyCredential,

    // Java-server attributes
    @Serializable(with = Base64ByteArraySerializer::class)
    val requestId: ByteArray,
    @Serializable(with = Base64ByteArraySerializer::class)
    val sessionToken: ByteArray,
) {
    fun toJson(): String {
        return JsonUtils.json.encodeToString(this)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as RegCompletePostData

        if (credential != other.credential) return false
        if (!requestId.contentEquals(other.requestId)) return false
        return sessionToken.contentEquals(other.sessionToken)
    }

    override fun hashCode(): Int {
        var result = credential.hashCode()
        result = 31 * result + requestId.contentHashCode()
        result = 31 * result + sessionToken.contentHashCode()
        return result
    }
}

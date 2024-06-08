package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

/**
 * Kotlin object for the "authentication-complete"-message
 */
@Serializable
data class AuthCompletePostData(
    val credential: PublickeyCredentialAuth,
    // Java-server attributes
    @Serializable(with = Base64ByteArraySerializer::class)
    val requestId: ByteArray,
) {
    fun toJson(): String {
        return JsonUtils.json.encodeToString(this)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthCompletePostData

        if (credential != other.credential) return false
        return requestId.contentEquals(other.requestId)
    }

    override fun hashCode(): Int {
        var result = credential.hashCode()
        result = 31 * result + requestId.contentHashCode()
        return result
    }
}

package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable

@Serializable
data class DeregisterResponse(
    val success: Boolean,
    val accountDeleted: Boolean,
    val droppedRegistration: DroppedRegistration,
) {
    companion object {
        fun fromJSON(json: String): DeregisterResponse {
            return JsonUtils.json.decodeFromString(json)
        }
    }

    @Serializable
    data class DroppedRegistration(
        val credential: Credential
    )

    @Serializable
    data class Credential(
        @Serializable(with = Base64ByteArraySerializer::class)
        val credentialId: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as Credential

            return credentialId.contentEquals(other.credentialId)
        }

        override fun hashCode(): Int {
            return credentialId.contentHashCode()
        }
    }
}

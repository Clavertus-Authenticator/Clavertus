package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import kotlinx.serialization.Serializable

@Serializable
data class ExcludeCredential(
    @Serializable(with = Base64ByteArraySerializer::class)
    val id: ByteArray,
    val type: String,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ExcludeCredential

        if (!id.contentEquals(other.id)) return false
        return type == other.type
    }

    override fun hashCode(): Int {
        var result = id.contentHashCode()
        result = 31 * result + type.hashCode()
        return result
    }
}

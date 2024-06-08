package ch.bfh.clavertus.authenticator.models

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

@Serializable
data class PublicKeyCredentialDescriptor(
    @ByteString
    val id: ByteArray,
    val type: String
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKeyCredentialDescriptor

        if (!id.contentEquals(other.id)) return false
        return type == other.type
    }

    override fun hashCode(): Int {
        var result = id.contentHashCode()
        result = 31 * result + type.hashCode()
        return result
    }
}

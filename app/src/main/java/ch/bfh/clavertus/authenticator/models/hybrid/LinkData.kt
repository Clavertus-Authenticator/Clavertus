package ch.bfh.clavertus.authenticator.models.hybrid

import ch.bfh.clavertus.authenticator.utils.serialization.CBORUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor

@Serializable
data class LinkData(
    @SerialName("1") @ByteString val contactId: ByteArray,
    @SerialName("2") @ByteString val linkId: ByteArray,
    @SerialName("3") @ByteString val linkSecret: ByteArray,
    @SerialName("4") @ByteString val authenticatorPublicKey: ByteArray,
    @SerialName("5") val authenticatorName: String,
    @SerialName("6") @ByteString val signature: ByteArray,
) {
    fun toCbor(): ByteArray {
        return CBORUtils.transformCborData(
            Cbor.encodeToByteArray(serializer(), this),
            CBORUtils.KeyTransformation.STRING_TO_INT
        )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LinkData

        if (!contactId.contentEquals(other.contactId)) return false
        if (!linkId.contentEquals(other.linkId)) return false
        if (!linkSecret.contentEquals(other.linkSecret)) return false
        if (!authenticatorPublicKey.contentEquals(other.authenticatorPublicKey)) return false
        if (authenticatorName != other.authenticatorName) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = contactId.contentHashCode()
        result = 31 * result + linkId.contentHashCode()
        result = 31 * result + linkSecret.contentHashCode()
        result = 31 * result + authenticatorPublicKey.contentHashCode()
        result = 31 * result + authenticatorName.hashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }
}

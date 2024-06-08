package ch.bfh.clavertus.authenticator.models.hybrid

import ch.bfh.clavertus.authenticator.utils.serialization.CBORUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor

@Serializable
data class ClientPayload(
    @SerialName("1") @ByteString val linkId: ByteArray,
    @SerialName("2") @ByteString val clientNonce: ByteArray,
    @SerialName("3") val operationHint: String,
) {
    companion object {
        fun fromCbor(cbor: ByteArray): ClientPayload {
            return Cbor { ignoreUnknownKeys = true }.decodeFromByteArray(
                serializer(),
                CBORUtils.transformCborData(cbor, CBORUtils.KeyTransformation.INT_TO_STRING)
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as ClientPayload

        if (!linkId.contentEquals(other.linkId)) return false
        if (!clientNonce.contentEquals(other.clientNonce)) return false
        if (operationHint != other.operationHint) return false

        return true
    }

    override fun hashCode(): Int {
        var result = linkId.contentHashCode()
        result = 31 * result + clientNonce.contentHashCode()
        result = 31 * result + operationHint.hashCode()
        return result
    }
}

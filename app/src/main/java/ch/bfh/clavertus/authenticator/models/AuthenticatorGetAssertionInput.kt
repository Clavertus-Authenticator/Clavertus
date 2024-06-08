package ch.bfh.clavertus.authenticator.models

import ch.bfh.clavertus.authenticator.utils.serialization.CBORUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.json.JsonElement

@Serializable
data class AuthenticatorGetAssertionInput(
    @SerialName("1") val rpId: String,
    @ByteString
    @SerialName("2") val clientDataHash: ByteArray,
    @SerialName("3") val allowList: List<PublicKeyCredentialDescriptor>? = null,
    @SerialName("4") val extensions: Map<String, JsonElement>? = null // ToDo replace with class
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

        other as AuthenticatorGetAssertionInput

        if (allowList != other.allowList) return false
        if (!clientDataHash.contentEquals(other.clientDataHash)) return false
        if (rpId != other.rpId) return false
        return extensions == other.extensions
    }

    override fun hashCode(): Int {
        var result = allowList.hashCode()
        result = 31 * result + clientDataHash.contentHashCode()
        result = 31 * result + rpId.hashCode()
        result = 31 * result + extensions.hashCode()
        return result
    }

    companion object {
        fun fromCbor(cbor: ByteArray): AuthenticatorGetAssertionInput {
            return Cbor { ignoreUnknownKeys = true }.decodeFromByteArray(
                serializer(),
                CBORUtils.transformCborData(cbor, CBORUtils.KeyTransformation.INT_TO_STRING)
            )
        }
    }
}

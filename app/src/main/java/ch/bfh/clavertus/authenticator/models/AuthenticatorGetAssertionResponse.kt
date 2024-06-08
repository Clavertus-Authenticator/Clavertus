package ch.bfh.clavertus.authenticator.models

import ch.bfh.clavertus.authenticator.utils.serialization.CBORUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor

@Serializable
data class AuthenticatorGetAssertionResponse(
    @SerialName("1") val credential: PublicKeyCredentialDescriptor,
    @ByteString
    @SerialName("2") val authData: ByteArray,
    @ByteString
    @SerialName("3") val signature: ByteArray,
    @SerialName("4") val user: PublicKeyCredentialUserEntity? = null
) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorGetAssertionResponse

        if (credential != other.credential) return false
        if (!authData.contentEquals(other.authData)) return false
        if (!signature.contentEquals(other.signature)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = credential.hashCode()
        result = 31 * result + authData.contentHashCode()
        result = 31 * result + signature.contentHashCode()
        return result
    }

    fun toCbor(): ByteArray {
        return CBORUtils.transformCborData(
            Cbor.encodeToByteArray(serializer(), this),
            CBORUtils.KeyTransformation.STRING_TO_INT
        )
    }

    companion object {
        fun fromCbor(cbor: ByteArray): AuthenticatorGetAssertionResponse {
            return Cbor { ignoreUnknownKeys = true }.decodeFromByteArray(
                serializer(),
                CBORUtils.transformCborData(cbor, CBORUtils.KeyTransformation.INT_TO_STRING)
            )
        }
    }
}

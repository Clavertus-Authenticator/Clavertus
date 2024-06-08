package ch.bfh.clavertus.authenticator.models

import ch.bfh.clavertus.authenticator.utils.serialization.CBORUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor

@Serializable
data class AuthenticatorMakeCredentialResponse(
    @ByteString
    @SerialName("1") val fmt: String,
    @SerialName("2") @ByteString val authData: ByteArray,
    @SerialName("3") val attStmt: AttestationStatement,
) {
    fun toCbor(): ByteArray {
        return CBORUtils.transformCborData(
            Cbor.encodeToByteArray(serializer(), this),
            CBORUtils.KeyTransformation.STRING_TO_INT
        )
    }

    companion object {
        fun fromCbor(cbor: ByteArray): AuthenticatorMakeCredentialResponse {
            return Cbor { ignoreUnknownKeys = true }.decodeFromByteArray(
                serializer(),
                CBORUtils.transformCborData(cbor, CBORUtils.KeyTransformation.INT_TO_STRING)
            )
        }
    }
}

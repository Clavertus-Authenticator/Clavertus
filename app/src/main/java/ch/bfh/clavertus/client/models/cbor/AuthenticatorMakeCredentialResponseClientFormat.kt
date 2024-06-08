package ch.bfh.clavertus.client.models.cbor

import ch.bfh.clavertus.authenticator.models.AttestationStatement
import ch.bfh.clavertus.authenticator.utils.serialization.CBORUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor

@Serializable
data class AuthenticatorMakeCredentialResponseClientFormat(
    @ByteString val fmt: String,
    @ByteString val authData: ByteArray,
    val attStmt: AttestationStatement,
) {
    fun toCbor(): ByteArray {
        return CBORUtils.transformCborData(
            Cbor.encodeToByteArray(serializer(), this),
            CBORUtils.KeyTransformation.STRING_TO_INT
        )
    }
}

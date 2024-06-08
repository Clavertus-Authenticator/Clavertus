package ch.bfh.clavertus.client.models.cbor

import ch.bfh.clavertus.authenticator.models.PublicKeyCredentialDescriptor
import ch.bfh.clavertus.authenticator.utils.serialization.CBORUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor

@Serializable
data class AuthenticatorGetAssertionResponseClientFormat(
    val credential: PublicKeyCredentialDescriptor,
    @ByteString val authData: ByteArray,
    @ByteString val signature: ByteArray,
) {
    fun toCbor(): ByteArray {
        return CBORUtils.transformCborData(
            Cbor.encodeToByteArray(serializer(), this),
            CBORUtils.KeyTransformation.STRING_TO_INT
        )
    }
}

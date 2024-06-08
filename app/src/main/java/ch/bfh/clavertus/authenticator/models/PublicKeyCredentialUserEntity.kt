package ch.bfh.clavertus.authenticator.models

import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

@Serializable
data class PublicKeyCredentialUserEntity(
    @ByteString val id: ByteArray,
    val name: String?,
    val displayName: String?
)

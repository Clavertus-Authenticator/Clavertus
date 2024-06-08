package ch.bfh.clavertus.authenticator.events.models

import ch.bfh.clavertus.authenticator.db.PublicKeyCredentialSource

data class AuthenticationPromptParameters(
    val authenticatorData: ByteArray,
    val clientDataHash: ByteArray,
    val selectedCredential: PublicKeyCredentialSource,
    val pkcs7Signature: String? = null
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticationPromptParameters

        if (!authenticatorData.contentEquals(other.authenticatorData)) return false
        if (!clientDataHash.contentEquals(other.clientDataHash)) return false
        if (selectedCredential != other.selectedCredential) return false
        if (pkcs7Signature != other.pkcs7Signature) return false

        return true
    }

    override fun hashCode(): Int {
        var result = authenticatorData.contentHashCode()
        result = 31 * result + clientDataHash.contentHashCode()
        result = 31 * result + selectedCredential.hashCode()
        result = 31 * result + (pkcs7Signature?.hashCode() ?: 0)
        return result
    }
}

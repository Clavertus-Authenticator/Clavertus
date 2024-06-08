package ch.bfh.clavertus.authenticator.models

/**
 * Values from https://w3c.github.io/webauthn/#enum-credentialType
 */
enum class PublicKeyCredentialType(val type: String) {
    PUBLIC_KEY("public-key");

    companion object {
        fun fromType(type: String) = entries.firstOrNull { it.type == type }
    }
}

package ch.bfh.clavertus.client.models

import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.client.serialization.Base64ByteArraySerializer
import ch.bfh.clavertus.client.serialization.JsonUtils
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.JsonElement

@Serializable
@Suppress("LongParameterList")
data class PublicKeyCredentialCreationOptions(
    val rp: RelyingPartyIdentity,
    val user: UserIdentity,
    @Serializable(with = Base64ByteArraySerializer::class)
    val challenge: ByteArray,
    val pubKeyCredParams: List<PublicKeyCredentialParameters>,
    val excludeCredentials: List<ExcludeCredential>,
    val authenticatorSelection: AuthenticatorSelection,
    val extensions: Map<String, JsonElement> // ToDo replace with class
) {
    fun areWellFormed(): Boolean {
        val isWellFormed = rp.id.isNotEmpty() &&
            user.id.isNotEmpty() && user.id.size <= Constants.BYTE_64 &&
            challenge.size == Constants.BYTE_32 &&
            pubKeyCredParams.isNotEmpty() &&
            pubKeyCredParams.all { param ->
                param.type.isNotEmpty() && param.alg < 0
            }

        return isWellFormed
    }

    fun keyCredParamsContain(type: String, alg: Int): Boolean {
        for (param in pubKeyCredParams) {
            if (param.type == type && param.alg == alg) {
                return true
            }
        }
        return false
    }

    fun toJson(): String {
        return JsonUtils.json.encodeToString(this)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKeyCredentialCreationOptions

        if (rp != other.rp) return false
        if (user != other.user) return false
        if (!challenge.contentEquals(other.challenge)) return false
        if (pubKeyCredParams != other.pubKeyCredParams) return false
        if (excludeCredentials != other.excludeCredentials) return false
        if (authenticatorSelection != other.authenticatorSelection) return false
        if (extensions != other.extensions) return false

        return true
    }

    override fun hashCode(): Int {
        var result = rp.hashCode()
        result = 31 * result + user.hashCode()
        result = 31 * result + challenge.contentHashCode()
        result = 31 * result + pubKeyCredParams.hashCode()
        result = 31 * result + excludeCredentials.hashCode()
        result = 31 * result + authenticatorSelection.hashCode()
        result = 31 * result + extensions.hashCode()
        return result
    }

    companion object {
        fun fromJson(json: String): PublicKeyCredentialCreationOptions {
            return JsonUtils.json.decodeFromString(json)
        }
    }

    @Serializable
    data class PublicKeyCredentialParameters(
        val alg: Int,
        val type: String,
    )

    @Serializable
    data class AuthenticatorSelection(
        val requireResidentKey: Boolean,
        val residentKey: String,
        val userVerification: String? = null
    )

    @Serializable
    data class RelyingPartyIdentity(
        val name: String,
        val id: String
    )

    @Serializable
    data class UserIdentity(
        val name: String,
        val displayName: String,
        @Serializable(with = Base64ByteArraySerializer::class)
        val id: ByteArray,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false

            other as UserIdentity

            if (name != other.name) return false
            if (displayName != other.displayName) return false
            return id.contentEquals(other.id)
        }

        override fun hashCode(): Int {
            var result = name.hashCode()
            result = 31 * result + displayName.hashCode()
            result = 31 * result + id.contentHashCode()
            return result
        }
    }
}

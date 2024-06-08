package ch.bfh.clavertus.authenticator.models

import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.serialization.CBORUtils
import ch.bfh.clavertus.authenticator.utils.serialization.CBORUtils.transformCborData
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor
import kotlinx.serialization.json.JsonElement

@Serializable
@Suppress("LongParameterList")
data class AuthenticatorMakeCredentialInput(
    @ByteString
    @SerialName("1") val clientDataHash: ByteArray,
    @SerialName("2") val rp: PublicKeyCredentialRpEntity,
    @SerialName("3") val user: PublicKeyCredentialUserEntity,
    @SerialName("4") private val pubKeyCredParams: List<PublicKeyCredentialParameters>,
    @SerialName("5") val excludeList: List<PublicKeyCredentialDescriptor>? = null,
    @SerialName("6") val extensions: Map<String, JsonElement>? = null, // ToDo replace with class
    @SerialName("7") val options: MakeCredentialOptions? = null
) {
    fun toCbor(): ByteArray {
        return transformCborData(
            Cbor.encodeToByteArray(serializer(), this),
            CBORUtils.KeyTransformation.STRING_TO_INT
        )
    }

    fun areWellFormed(): Boolean {
        val isWellFormed = rp.id.isNotEmpty() &&
            user.id.isNotEmpty() && user.id.size <= Constants.BYTE_64 &&
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

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AuthenticatorMakeCredentialInput

        if (!clientDataHash.contentEquals(other.clientDataHash)) return false
        if (rp != other.rp) return false
        if (user != other.user) return false
        if (pubKeyCredParams != other.pubKeyCredParams) return false

        return true
    }

    override fun hashCode(): Int {
        var result = clientDataHash.contentHashCode()
        result = 31 * result + rp.hashCode()
        result = 31 * result + user.hashCode()
        result = 31 * result + pubKeyCredParams.hashCode()

        return result
    }

    companion object {
        fun fromCbor(cbor: ByteArray): AuthenticatorMakeCredentialInput {
            return Cbor.decodeFromByteArray(
                serializer(),
                transformCborData(cbor, CBORUtils.KeyTransformation.INT_TO_STRING)
            )
        }
    }

    @Serializable
    data class PublicKeyCredentialParameters(
        val alg: Int,
        val type: String,
    )

    @Serializable
    data class PublicKeyCredentialRpEntity(
        val id: String,
        val name: String
    )
}

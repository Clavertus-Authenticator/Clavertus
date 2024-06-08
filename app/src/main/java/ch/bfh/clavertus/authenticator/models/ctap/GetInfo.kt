package ch.bfh.clavertus.authenticator.models.ctap

import ch.bfh.clavertus.authenticator.utils.serialization.CBORUtils
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.cbor.Cbor

@Serializable
data class Options(
    @SerialName("rk") val passkeyPossible: Boolean,
    @SerialName("up") val userPresencePossible: Boolean,
    @SerialName("uv") val userVerifiedPossible: Boolean,
    @SerialName("plat") val isPlatformAuthenticator: Boolean,
)

@Serializable
data class GetInfo(
    @SerialName("1") val versions: List<String>,
    @SerialName("2") val extensions: List<String>? = null,
    @SerialName("3") @ByteString val aaguid: ByteArray,
    @SerialName("4") val options: Options? = null,
    @SerialName("9") val transports: List<String>? = null,
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

        other as GetInfo

        if (versions != other.versions) return false
        if (extensions != other.extensions) return false
        if (!aaguid.contentEquals(other.aaguid)) return false
        if (options != other.options) return false
        if (transports != other.transports) return false

        return true
    }

    override fun hashCode(): Int {
        var result = versions.hashCode()
        result = 31 * result + (extensions?.hashCode() ?: 0)
        result = 31 * result + aaguid.contentHashCode()
        result = 31 * result + (options?.hashCode() ?: 0)
        result = 31 * result + (transports?.hashCode() ?: 0)
        return result
    }
}

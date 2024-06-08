package ch.bfh.clavertus.authenticator.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.cbor.ByteString

@Serializable
data class AttestationStatement(
    @SerialName("alg") val alg: Long,
    @SerialName("sig") @ByteString val sig: ByteArray,
    @SerialName("x5c") val x5c: List<ByteArray>,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as AttestationStatement

        if (alg != other.alg) return false
        if (!sig.contentEquals(other.sig)) return false
        if (x5c != other.x5c) return false

        return true
    }

    override fun hashCode(): Int {
        var result = alg.hashCode()
        result = 31 * result + sig.contentHashCode()
        result = 31 * result + x5c.hashCode()
        return result
    }
}

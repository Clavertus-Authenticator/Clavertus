package ch.bfh.clavertus.authenticator.utils.ctap

import ch.bfh.clavertus.authenticator.models.ctap.GetInfo
import ch.bfh.clavertus.authenticator.models.ctap.Options
import ch.bfh.clavertus.authenticator.utils.Constants
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import java.io.ByteArrayOutputStream

object CtapUtils {
    fun prepareGetInfoResponse(): ByteArray {
        val getInfo = GetInfo(
            versions = listOf("FIDO_2_0", "FIDO_2_1"),
            extensions = listOf("uvm"),
            aaguid = ByteArray(Constants.AAGUID_LENGTH) { 0x00 },
            options = Options(
                passkeyPossible = true,
                userPresencePossible = true,
                userVerifiedPossible = true,
                isPlatformAuthenticator = false
            ),
            transports = listOf("hybrid", "internal")
        )

        val output = ByteArrayOutputStream()
        CborEncoder(output).encode(
            CborBuilder()
                .addMap()
                .put(0x01, getInfo.toCbor())
                .end()
                .build()
        )
        return output.toByteArray()
    }
}

package ch.bfh.clavertus.authenticator.utils.builder

import android.util.Log
import ch.bfh.clavertus.authenticator.db.PublicKeyCredentialSource
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.crypto.Cryptography
import ch.bfh.clavertus.authenticator.utils.crypto.HpcUtility
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.CborException
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Authenticator-data according to the Webauthn-2 standard.
 */
@Singleton
class AuthenticatorDataBuilder @Inject constructor(private val hpcUtility: HpcUtility) {
    companion object {
        private val TAG = AuthenticatorDataBuilder::class.java.simpleName
    }

    suspend fun calculateAuthenticatorData(
        selectedCredential: PublicKeyCredentialSource,
        txAuthSimplePKCS7Signature: String? = null,
        register: Boolean
    ): ByteArray {
        return if (txAuthSimplePKCS7Signature != null) {
            createAuthenticatorData(selectedCredential, txAuthSimplePKCS7Signature, register)
        } else {
            createAuthenticatorData(selectedCredential, null, register)
        }
    }

    /**
     * Create the authenticator data with or without extension.
     *
     * @param selectedCredential the selected credential
     * @param extensionsIncluded txAuthSimple-Extension available?
     * @return finished authenticator-data
     */
    private suspend fun createAuthenticatorData(
        selectedCredential: PublicKeyCredentialSource,
        txAuthSimplePKCS7Signature: String?,
        register: Boolean
    ): ByteArray {
        val rpIDHash = Cryptography.sha256(selectedCredential.rpId.toByteArray())
        var flags: Byte = 0x01 // user present already set
        var attestedCredentialData = ByteArray(0)
        if (register) {
            flags =
                (flags.toInt() or (0x01 shl Constants.SHIFT_ATTESTED_CREDENTIAL_DATA_INCLUDED)).toByte()
            attestedCredentialData = createAttestedCredentialData(selectedCredential)
        }
        flags = (flags.toInt() or (0x01 shl Constants.SHIFT_USER_VERIFIED)).toByte()
        if (txAuthSimplePKCS7Signature != null) {
            flags = (flags.toInt() or (0x01 shl Constants.SHIFT_EXTENSION_DATA_INCLUDED)).toByte()
        }
        var extensions = ByteArray(0)

        if (txAuthSimplePKCS7Signature != null) {
            // this only works with txAuthSimple-extension (own version with pkcs7 for the RP)
            // Extension-defined authenticator data. This is a CBOR [RFC8949] map with extension
            // identifiers as keys, and authenticator extension outputs as values.
            val output = ByteArrayOutputStream()
            try {
                CborEncoder(output).encode(
                    CborBuilder()
                        .addMap()
                        // standard v1: prompt as displayed.
                        // Instead pkcs7 which provides a prove that the client-implementation is correct.
                        .put("txAuthSimple", txAuthSimplePKCS7Signature)
                        .end() // // add more extensions as soon as they are implemented
                        .build()
                )
                extensions = output.toByteArray()
            } catch (e: CborException) {
                Log.e(TAG, "Returning attestation-object as cbor failed: $e")
            }
        }

        // 32-byte RP-ID-hash + 1-byte flags + 4 bytes counter = 37 bytes + attestedCredData and extensions
        val authData = ByteBuffer.allocate(
            Constants.RP_ID_HASH_LENGTH +
                Constants.FLAGS_LENGTH +
                Constants.SIGN_COUNT_LENGTH +
                attestedCredentialData.size +
                extensions.size
        )
        authData.put(rpIDHash)
        authData.put(flags)
        authData.putInt(selectedCredential.keyUseCounter) // signCount
        authData.put(attestedCredentialData)
        authData.put(extensions)
        return authData.array()
    }

    private suspend fun createAttestedCredentialData(credentialSource: PublicKeyCredentialSource): ByteArray {
        // | AAGUID | L | credentialId | credentialPublicKey |
        // |   16   | 2 |      32      |          n          |
        val encodedPublicKey = hpcUtility.coseEncodePublicKey(credentialSource.keyPairAlias)
        val credentialData = ByteBuffer.allocate(
            Constants.AAGUID_LENGTH +
                Constants.CREDENTIAL_ID_LENGTH +
                credentialSource.id.size +
                encodedPublicKey.size
        )
        // AAGUID will be 16 bytes of zeroes
        credentialData.position(Constants.AAGUID_LENGTH)
        credentialData.putShort(credentialSource.id.size.toShort()) // L
        credentialData.put(credentialSource.id) // credentialId
        // should only be sent when registering. However, the Python server gives an error if it is
        // missing during authentication. Therefore it is always sent.
        credentialData.put(encodedPublicKey)
        return credentialData.array()
    }
}

package ch.bfh.clavertus.authenticator.utils.builder

import androidx.fragment.app.FragmentActivity
import ch.bfh.clavertus.authenticator.db.PublicKeyCredentialSource
import ch.bfh.clavertus.authenticator.models.AttestationStatement
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.crypto.HpcUtility
import ch.bfh.clavertus.authenticator.utils.signer.Signer
import java.security.cert.X509Certificate
import javax.inject.Inject
import javax.inject.Singleton

/**
 * With help from the android-webauthn-authenticator app.
 * Attestation-object according to the Webauthn-2 standard.
 *
 *     private val clientDataHash: ByteArray,
 *     private val context: Context,
 *     publicKeyCredentialSource: PublicKeyCredentialSource
 */
@Singleton
class AttestationObjectBuilder @Inject constructor(
    private val hpcUtility: HpcUtility,
    private val signer: Signer,
    private val authenticatorDataBuilder: AuthenticatorDataBuilder
) {

    companion object {
        private var ALG: Long = Constants.Crypto.ES256_SIG_ALGORITHM
    }

    private var authData: ByteArray = "init".toByteArray()

    // ToDo Refactor this class later
    suspend fun getAttestationStatement(
        clientDataHash: ByteArray,
        fragmentActivity: FragmentActivity,
        publicKeyCredentialSource: PublicKeyCredentialSource
    ): AttestationStatement {
        authData =
            authenticatorDataBuilder.calculateAuthenticatorData(publicKeyCredentialSource, null, true)
        val signature = signer.sign(
            Constants.FidoActions.REGISTER_FIDO,
            authData,
            clientDataHash,
            fragmentActivity,
            publicKeyCredentialSource.keyPairAlias,
            publicKeyCredentialSource.requiresAuthentication,
            publicKeyCredentialSource.rpId,
            publicKeyCredentialSource.userDisplayName.ifEmpty { publicKeyCredentialSource.userName }
        )
        val x5c = finishAttestationStatement(publicKeyCredentialSource.keyPairAlias)
        return AttestationStatement(ALG, signature, x5c)
    }

    /**
     * Finish the attestation-statement add the signature and the certificate-chain
     *
     * @throws Exception cannot encode a certificate
     */
    private suspend fun finishAttestationStatement(keyAlias: String): List<ByteArray> {
        val x5c = mutableListOf<ByteArray>()

        val cert = hpcUtility.getCert(keyAlias)
        ALG = if (cert.publicKey?.algorithm?.contains("RSA") == true) {
            Constants.Crypto.RS256
        } else {
            Constants.Crypto.ES256_SIG_ALGORITHM
        }
        val certificates = hpcUtility.getCertChain(keyAlias)
        // Convert each certificate to its X.509 encoded form
        certificates?.forEach { certificate ->
            if (certificate is X509Certificate) { // only X509 certificates are supported
                x5c.add(certificate.encoded)
            }
        }
        return x5c
    }

    fun getAuthData(): ByteArray {
        return authData
    }
}

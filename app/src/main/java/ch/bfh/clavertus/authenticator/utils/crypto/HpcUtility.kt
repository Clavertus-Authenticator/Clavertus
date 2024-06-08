package ch.bfh.clavertus.authenticator.utils.crypto

import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import androidx.lifecycle.LiveData
import ch.bfh.clavertus.authenticator.db.CredentialDatabase
import ch.bfh.clavertus.authenticator.db.LinkCredentialSource
import ch.bfh.clavertus.authenticator.db.PublicKeyCredentialSource
import ch.bfh.clavertus.authenticator.db.PublicKeyCredentialSource.Companion.createNew
import ch.bfh.clavertus.authenticator.modules.DefaultDispatcher
import ch.bfh.clavertus.authenticator.modules.IODispatcher
import ch.bfh.clavertus.authenticator.modules.RegularPreferences
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.getEcCurve
import ch.bfh.clavertus.authenticator.utils.getKeyType
import ch.bfh.clavertus.authenticator.utils.getRSAKeyLength
import ch.bfh.clavertus.authenticator.utils.getStrongBoxRequired
import ch.bfh.clavertus.authenticator.utils.getUserAuthenticationRequired
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.CborException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.InvalidKeyException
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.RSAKeyGenParameterSpec
import javax.inject.Inject
import javax.inject.Singleton
import javax.security.auth.x500.X500Principal

/**
 * Inspired by APC demo app. The class manages the handling of the keys. Like registering, encoding,
 * checking etc.
 */
@Singleton
class HpcUtility @Inject constructor(
    private val db: CredentialDatabase,
    @RegularPreferences private val prefs: SharedPreferences,
    @DefaultDispatcher private val defaultDispatcher: CoroutineDispatcher,
    @IODispatcher private val ioDispatcher: CoroutineDispatcher,
    private val keyStore: KeyStore
) {
    /**
     * Creates an new key pair and register it.
     *
     * @param challenge                This challenge will be included in the attestation certificate
     * @param rpEntityId               Id from the relaying party
     * @param userIDFromRP             Id from the user
     * @param userDisplayName          Name of the user
     * @param userConfirmationRequired If user confirmation is required
     * @return created and registered credential-source
     */
    @Suppress("LongParameterList")
    suspend fun register(
        challenge: ByteArray,
        rpEntityId: String,
        userIDFromRP: ByteArray,
        userName: String?,
        userDisplayName: String?,
        userConfirmationRequired: Boolean,
        isPasskey: Boolean,
    ): PublicKeyCredentialSource {
        val credentialSource = createNew(
            rpEntityId,
            userIDFromRP,
            userName,
            userDisplayName,
            prefs.getUserAuthenticationRequired(),
            isPasskey,
            null
        )
        if (generateKeyPair(challenge, credentialSource.keyPairAlias, userConfirmationRequired)) {
            db.credentialDao().insert(credentialSource)
        }
        return credentialSource
    }

    /**
     * Generate a key pair for signing and verification. The key parameter are static.
     *
     * @param challenge                This challenge will be included in the attestation certificate
     * @param keyAliasName             the name for the Key-Alias
     * @param userConfirmationRequired If user confirmation is required
     */

    @Suppress("LongMethod")
    private suspend fun generateKeyPair(
        challenge: ByteArray,
        keyAliasName: String,
        userConfirmationRequired: Boolean
    ): Boolean = withContext(defaultDispatcher) {
        // Read preferred key settings
        val strongBoxRequired = prefs.getStrongBoxRequired()
        val keyType =
            prefs.getKeyType()
        // only 256 bit key-size is supported by strongbox
        val ecCurve: String = if (strongBoxRequired) {
            "secp256r1"
        } else {
            prefs.getEcCurve()
        }
        val cname =
            X500Principal("CN=$keyAliasName, OU=Authenticator, OU=Clavertus, C=CH")
        val builder = KeyGenParameterSpec.Builder(keyAliasName, KeyProperties.PURPOSE_SIGN)
            .setCertificateSubject(cname)
            .setIsStrongBoxBacked(strongBoxRequired) // generate on HSM
            .setDigests(
                KeyProperties.DIGEST_SHA256,
                KeyProperties.DIGEST_SHA384,
                KeyProperties.DIGEST_SHA512
            )
            // From https://github.com/authgear/authgear-server/issues/2009:
            // If setUnlockedDeviceRequired is true, then the device must be unlocked
            // with the same level of security requirement.
            // Otherwise, UserNotAuthenticatedException will be thrown when a cryptographic operation is initialized.
            // Biometric prompt needs an unlocked device anyway, therefore setting to false.
            .setUnlockedDeviceRequired(false)
            .setUserConfirmationRequired(userConfirmationRequired)
            .setUserAuthenticationRequired(prefs.getUserAuthenticationRequired())
            .setAttestationChallenge(challenge)
        try {
            val keyPairGenerator: KeyPairGenerator?
            if (keyType.contains("EC")) {
                keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    "AndroidKeyStore"
                )
                builder.setAlgorithmParameterSpec(ECGenParameterSpec(ecCurve))
            } else {
                keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA,
                    "AndroidKeyStore"
                )
                builder.setAlgorithmParameterSpec(
                    RSAKeyGenParameterSpec(
                        prefs.getRSAKeyLength(),
                        RSAKeyGenParameterSpec.F4
                    )
                )
                    .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
            }
            keyPairGenerator.initialize(builder.build())
            keyPairGenerator.generateKeyPair()
            return@withContext true
        } catch (ex: GeneralSecurityException) {
            Log.e(TAG, "Failed to generate key pair: ${ex.message}")
            return@withContext false
        }
    }

    /**
     * Get keys belonging to this RP ID.
     *
     * @param rpEntityId rpEntity.id from WebAuthn spec.
     * @return The set of associated PublicKeyCredentialSources.
     */
    suspend fun getKeysForEntity(rpEntityId: String): List<PublicKeyCredentialSource> {
        return db.credentialDao().getAllByRpId(rpEntityId)
    }

    /**
     * Get key belonging to this id.
     *
     * @param id id from key
     * @return The set of associated PublicKeyCredentialSources.
     */
    suspend fun getKeyForId(id: ByteArray): PublicKeyCredentialSource? {
        return db.credentialDao().getById(id)
    }

    /**
     * Increment the credential use counter for this credential.
     *
     * @param credential The credential whose counter we want to increase.
     */
    suspend fun incrementCredentialUseCounter(credential: PublicKeyCredentialSource) {
        db.credentialDao().incrementUseCounter(credential)
    }

    /**
     * Delete a key in keystore and db
     */
    suspend fun deleteKey(credential: PublicKeyCredentialSource?): Boolean =
        withContext(ioDispatcher) {
            return@withContext try {
                if (credential != null) {
                    keyStore.deleteEntry(credential.keyPairAlias)
                    db.credentialDao().delete(credential)
                }
                true
            } catch (e: KeyStoreException) {
                Log.e(TAG, "Failed to delete key: $e")
                false
            }
        }

    /**
     * Gets the key pair for a key alias
     *
     * @param keyName alias for this key
     * @return the key pair for the key alias
     */
    private suspend fun getKeyPair(keyName: String): KeyPair =
        withContext(ioDispatcher) {
            return@withContext try {
                val privateKey = keyStore.getKey(keyName, null) as PrivateKey
                val publicKey = keyStore.getCertificate(keyName).publicKey
                KeyPair(publicKey, privateKey)
            } catch (e: GeneralSecurityException) {
                Log.e(TAG, "Failed to get key pair for $keyName: ${e.message}")
                throw e
            } catch (e: IOException) {
                Log.e(TAG, "Failed to get key pair for $keyName: ${e.message}")
                throw e
            }
        }

    /**
     * Get a certificate for a key
     *
     * @param keyName alias for this key
     * @return the certificate for this key
     */
    suspend fun getCert(keyName: String): Certificate =
        withContext(ioDispatcher) {
            return@withContext try {
                keyStore.getCertificate(keyName)
            } catch (e: KeyStoreException) {
                Log.e(TAG, "Failed to get cert for $keyName: $e")
                throw e
            }
        }

    /**
     * Get algorithm for the signature.
     *
     * @param alias for the key
     * @return the algorithm for the signature.
     */
    suspend fun getSignatureAlgorithm(alias: String): String {
        val cert = getCert(alias)
        return if (cert.publicKey.algorithm.contains("RSA")) {
            "SHA256withRSA"
        } else {
            "SHA256withECDSA"
        }
    }

    /**
     * Get the certificate-chain for this key. Needed for the PKCS7-Signature.
     *
     * @param keyName Alias for this key
     * @return Certificate chain
     */
    suspend fun getCertChain(keyName: String?): Array<Certificate>? =
        withContext(ioDispatcher) {
            return@withContext try {
                keyStore.getCertificateChain(keyName)
            } catch (e: KeyStoreException) {
                Log.e(TAG, "Failed to get cert chain for $keyName: $e")
                throw e
            }
        }

    /**
     * Encode an EC public key in the COSE/CBOR format.
     * Function from the [
         * android-webauthn-authenticator ](https://github.com/duo-labs/android-webauthn-authenticator.git)
     * and adapted to my needs
     *
     * ECPoint coordinates are *unsigned* values that span the range [0, 2**32). The getAffine
     * methods return BigInteger objects, which are signed. toByteArray will output a byte array
     * containing the two's complement representation of the value, outputting only as many
     * bytes as necessary to do so. We want an unsigned byte array of length 32, but when we
     * call toByteArray, we could get:
     * 1) A 33-byte array, if the point's unsigned representation has a high 1 bit.
     * toByteArray will prepend a zero byte to keep the value positive.
     * 2) A <32-byte array, if the point's unsigned representation has 9 or more high zero
     * bits.
     * Due to this, we need to either chop off the high zero byte or prepend zero bytes
     * until we have a 32-length byte array.
     *
     * @param keyName name of needed key.
     * @return A COSE_Key-encoded public key as byte array.
     */
    suspend fun coseEncodePublicKey(keyName: String): ByteArray {
        val publicKey =
            getKeyPair(keyName).public as PublicKey
        if (publicKey is ECPublicKey) {
            val point = publicKey.w
            val xVariableLength = point.affineX.toByteArray()
            val yVariableLength = point.affineY.toByteArray()
            val x = toUnsignedFixedLength(xVariableLength, Constants.BYTE_32)
            assert(x.size == Constants.BYTE_32)
            val y = toUnsignedFixedLength(yVariableLength, Constants.BYTE_32)
            assert(y.size == Constants.BYTE_32)
            val output = ByteArrayOutputStream()
            try {
                CborEncoder(output).encode(
                    CborBuilder()
                        .addMap()
                        .put(Constants.Crypto.KEY_TYPE, Constants.Crypto.EC2_KEY_TYPE)
                        .put(
                            Constants.Crypto.SIGNATURE_ALGORITHM,
                            Constants.Crypto.ES256_SIG_ALGORITHM
                        )
                        .put(Constants.Crypto.CURVE, Constants.Crypto.P_256_CURVE)
                        .put(Constants.Crypto.X_COORDINATE, x)
                        .put(Constants.Crypto.Y_COORDINATE, y)
                        .end()
                        .build()
                )
            } catch (e: CborException) {
                Log.e(TAG, "Failed the public key for $keyName: $e")
            }
            return output.toByteArray()
        } else { // RSA-key
            val output = ByteArrayOutputStream()
            try {
                val rPublicKey = publicKey as RSAPublicKey
                val n = toUnsignedFixedLength(rPublicKey.modulus.toByteArray(), Constants.BYTE_256)
                assert(n.size == Constants.BYTE_256)
                val e = toUnsignedFixedLength(
                    rPublicKey.publicExponent.toByteArray(),
                    Constants.Crypto.RSA_EXPONENT_LENGTH
                )
                assert(e.size == Constants.Crypto.RSA_EXPONENT_LENGTH)
                CborEncoder(output).encode(
                    CborBuilder()
                        .addMap()
                        .put(Constants.Crypto.KEY_TYPE, Constants.Crypto.RSA_KEY_TYPE)
                        .put(Constants.Crypto.SIGNATURE_ALGORITHM, Constants.Crypto.RS256)
                        .put(Constants.Crypto.RSA_MODULUS, n) // n byte string 256 bytes in length
                        .put(Constants.Crypto.RSA_EXPONENT, e) // e byte string 3 bytes in length
                        .end()
                        .build()
                )
            } catch (e: CborException) {
                Log.e(TAG, "Failed the public key for $keyName: $e")
            }
            return output.toByteArray()
        }
    }

    /**
     * Fix the length of a byte array such that:
     * 1) If the desired length is less than the length of `arr`, the left-most source bytes are
     * truncated.
     * 2) If the desired length is more than the length of `arr`, the left-most destination bytes
     * are set to 0x00.
     * Function from the android-webauthn-authenticator [...](https://github.com/duo-labs/android-webauthn-authenticator.git)
     *
     * @param arr The source byte array.
     * @return A new array of length fixedLength.
     */
    private fun toUnsignedFixedLength(arr: ByteArray, length: Int): ByteArray {
        val fixed = ByteArray(length)
        val offset = length - arr.size
        val srcPos = (-offset).coerceAtLeast(0)
        val dstPos = offset.coerceAtLeast(0)
        val copyLength = arr.size.coerceAtMost(length)
        System.arraycopy(arr, srcPos, fixed, dstPos, copyLength)
        return fixed
    }

    /**
     * check whether a key already exists on this device
     *
     * @param keyName Alias of the key
     * @return if true, the key is available
     */
    suspend fun checkKeyPresence(keyName: String) = withContext(ioDispatcher) {
        return@withContext try {
            keyStore.containsAlias(keyName)
        } catch (e: KeyStoreException) {
            Log.e(TAG, "Failed to check presence of the key $keyName: $e")
            throw e
        }
    }

    /**
     * Initializes a signature for the key with the alias
     *
     * @param alias of the key
     * @return Signature for the key
     */
    suspend fun initSignature(alias: String): Signature {
        val keyPair = getKeyPair(alias)
        val signature: Signature
        return try {
            signature = Signature.getInstance(getSignatureAlgorithm(alias))
            signature.initSign(keyPair.private)
            signature
        } catch (e: NoSuchAlgorithmException) {
            Log.e(TAG, "Failed to init signature: $e")
            throw e
        } catch (e: InvalidKeyException) {
            Log.e(TAG, "Failed to init signature: $e")
            throw e
        }
    }

    fun getAll(): LiveData<List<PublicKeyCredentialSource>> = db.credentialDao().getAllKeys()
    suspend fun getLinkSecret(linkId: ByteArray): ByteArray {
        return db.credentialDao().getLinkSecret(linkId)
    }

    suspend fun insertLinkCredentialSource(linkCredentialSource: LinkCredentialSource) {
        db.credentialDao().insert(linkCredentialSource)
    }

    companion object {
        private val TAG = HpcUtility::class.java.simpleName
    }
}

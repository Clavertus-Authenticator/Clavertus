package ch.bfh.clavertus.authenticator.utils.crypto

import ch.bfh.clavertus.authenticator.models.hybrid.KeyPurpose
import ch.bfh.clavertus.authenticator.utils.Constants
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.Provider
import java.security.SecureRandom
import java.security.Security
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Utility class which offers static cryptographic methods.
 */
object Cryptography {
    init {
        this.removeSecurityProvider(BouncyCastleProvider.PROVIDER_NAME)
        this.addSecurityProvider(BouncyCastleProvider())
    }

    private fun addSecurityProvider(provider: Provider) {
        Security.addProvider(provider)
    }

    private fun removeSecurityProvider(str: String) {
        Security.removeProvider(str)
    }

    /**
     * Hashes the given data with the SHA-256 algorithm.
     *
     * @param data to be hashed
     * @return SHA-256 hash
     */
    fun sha256(data: ByteArray): ByteArray {
        val md: MessageDigest = MessageDigest.getInstance("SHA-256")
        md.update(data)
        return md.digest()
    }

    fun generateRandomByteArray(length: Int): ByteArray {
        val random = SecureRandom()
        return ByteArray(length).also { random.nextBytes(it) }
    }

    /**
     * From CTAP2.2 spec: In order to derive the key needed to trial decrypt BLE adverts, the following
     * key derivation is used. Whenever a key is needed for a specific purpose it is always derived from
     * a parent key in order to ensure domain separation. The derivation uses RFC5869 with SHA-256,
     * where the input keying material is the parent key, the salt is an optional input, and the info
     * value is a 32-bit, little-endian, purpose identifier.
     */

    fun deriveKey(
        secret: ByteArray,
        salt: ByteArray?,
        purpose: KeyPurpose,
        keyLength: Int
    ): ByteArray {
        require(purpose.type < Constants.PURPOSE_MAX) { "unsupported purpose" }
        // Convert purpose to a 4-byte array
        val purposeBytes =
            ByteBuffer.allocate(Constants.PURPOSE_BYTES_LENGTH).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(purpose.type).array()
        val hkdfParameters = HKDFParameters(secret, salt, purposeBytes)
        val hkdfGenerator = HKDFBytesGenerator(SHA256Digest()).apply {
            init(hkdfParameters)
        }

        val derivedKey = ByteArray(keyLength)
        hkdfGenerator.generateBytes(derivedKey, 0, keyLength)
        return derivedKey
    }

    /** Encrypt BLEAdvertData with key and create/add HMAC
     * From CTAP2 documentation: When decrypting adverts, these 64 bytes of EID key are considered as
     * a pair of 256-bit keys where the first 32 bytes are an AES key and the second 32 bytes are an
     * HMAC-SHA256 key. A candidate BLE advert is valid if the final four bytes are a correct HMAC tag of
     * the other 16 bytes. For each valid BLE advert, those initial 16 bytes are then taken to be
     * an AES block and decrypted with the AES key.
     *
     * **/
    fun encryptAndAddHMAC(bleAdvertData: ByteArray, key: ByteArray): ByteArray {
        require(bleAdvertData.size == Constants.BLE_ADVERT_LENGTH) { "bleAdvertData must be 16 bytes" }
        require(key.size == Constants.EID_KEY_LENGTH) { "EID key must be 64 bytes (256 bits * 2 keys)" }

        // Encrypt using AES. Exactly one full block. So no padding needed and ECB is fine.
        val cipher = Cipher.getInstance("AES")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key.copyOfRange(Constants.START_ZERO, Constants.KEY_LENGTH), "AES")
        )
        val encryptedBLEAdvertData = cipher.doFinal(bleAdvertData)

        // Compute HMAC using SHA-256
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(
            SecretKeySpec(
                key.copyOfRange(Constants.KEY_LENGTH, Constants.EID_KEY_LENGTH),
                "HmacSHA256"
            )
        )
        val hmac =
            mac.doFinal(
                encryptedBLEAdvertData.copyOfRange(
                    Constants.START_ZERO,
                    Constants.BLE_ADVERT_LENGTH
                )
            )

        // Append the first 4 bytes of the HMAC to the encrypted data
        val encryptedBLEAdvertDataHMAC =
            encryptedBLEAdvertData.copyOf(Constants.BLE_ADVERT_ENCRYPTED_LENGTH)
        System.arraycopy(
            hmac,
            Constants.START_ZERO,
            encryptedBLEAdvertDataHMAC,
            Constants.BLE_ADVERT_LENGTH,
            Constants.HMAC_LENGTH
        )

        return encryptedBLEAdvertDataHMAC
    }
}

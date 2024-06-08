package ch.bfh.clavertus.authenticator.noise

import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.util.Arrays
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.SecretKey
import javax.crypto.ShortBufferException
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Inspired by: https://github.com/rweather/noise-java/blob/master/src/main/java/com/southernstorm/noise/protocol/AESGCMOnCtrCipherState.java
 * */
@Suppress("detekt:all")
class AESGCMOnCtrCipherState : CipherState {
    private var cipher: Cipher = Cipher.getInstance("AES/CTR/NoPadding")
    private var keySpec: SecretKeySpec? = null
    private var n: Long = 0
    private var iv: ByteArray = ByteArray(16)
    private var hashKey: ByteArray = ByteArray(16)
    private var ghash: GHASH = GHASH()

    init {
        // Try to set a 256-bit key on the cipher.  Some JCE's are
        // configured to disallow 256-bit AES if an extra policy
        // file has not been installed.
        try {
            val spec = SecretKeySpec(ByteArray(32), "AES")
            val params = IvParameterSpec(iv)
            cipher.init(Cipher.ENCRYPT_MODE, spec, params)
        } catch (e: InvalidKeyException) {
            throw NoSuchAlgorithmException("AES/CTR/NoPadding does not support 256-bit keys", e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw NoSuchAlgorithmException("AES/CTR/NoPadding does not support 256-bit keys", e)
        }
    }

    override fun initializeKey(key: ByteArray, offset: Int) {
        // Set the encryption key.
        keySpec = SecretKeySpec(key, offset, 32, "AES")

        // Generate the hashing key by encrypting a block of zeroes.
        Arrays.fill(iv, 0.toByte())
        Arrays.fill(hashKey, 0.toByte())
        try {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, IvParameterSpec(iv))
            try {
                val result = cipher.update(hashKey, 0, 16, hashKey, 0)
                cipher.doFinal(hashKey, result)
                ghash.reset(hashKey, 0)
                // Reset the nonce.
                n = 0
            } catch (e: ShortBufferException) {
                throw IllegalStateException(e)
            } catch (e: IllegalBlockSizeException) {
                throw IllegalStateException(e)
            } catch (e: BadPaddingException) {
                throw IllegalStateException(e)
            }
        } catch (e: InvalidKeyException) {
            throw IllegalStateException(e)
        } catch (e: InvalidAlgorithmParameterException) {
            throw IllegalStateException(e)
        }
    }

    override fun getKeyLength(): Int {
        return 32
    }

    override fun getKeySpec(): SecretKey {
        return keySpec!!
    }
}

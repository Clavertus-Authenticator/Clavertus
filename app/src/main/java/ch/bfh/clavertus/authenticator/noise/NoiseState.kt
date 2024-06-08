package ch.bfh.clavertus.authenticator.noise

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.util.Arrays
import java.security.DigestException
import java.security.MessageDigest
import javax.crypto.SecretKey

/**
 * Inspired by https://github.com/rweather/noise-java/blob/master/src/main/java/com/southernstorm/noise/protocol/SymmetricState.java
 */
@Suppress("detekt:all")
class NoiseState(
    protocolName: String,
) {
    private val cipher = AESGCMOnCtrCipherState()
    private val hash = MessageDigest.getInstance("SHA256")
    private val hashLength = hash.digestLength
    private var ck = ByteArray(hashLength)
    private var h = ByteArray(hashLength)

    init {
        val protocolNameBytes = protocolName.toByteArray(Charsets.UTF_8)

        if (protocolNameBytes.size <= hashLength) {
            System.arraycopy(protocolNameBytes, 0, h, 0, protocolNameBytes.size)
            h.fill(0, fromIndex = protocolNameBytes.size, toIndex = h.size)
        } else {
            hashOne(protocolNameBytes, 0, protocolNameBytes.size, h, 0, h.size)
        }

        System.arraycopy(h, 0, ck, 0, hashLength)
    }

    /**
     * Gets the current value of the handshake hash.
     *
     * @return The handshake hash.  This must not be modified by the caller.
     *
     * The handshake hash value is only of use to the application after
     * split() has been called.
     */
    fun getHandshakeHash(): ByteArray {
        return h
    }

    /**
     * Hashes a single data buffer.
     *
     * @param data The buffer containing the data to hash.
     * @param offset Offset into the data buffer of the first byte to hash.
     * @param length Length of the data to be hashed.
     * @param output The buffer to receive the output hash value.
     * @param outputOffset Offset into the output buffer to place the hash value.
     * @param outputLength The length of the hash output.
     *
     * The output buffer can be the same as the input data buffer.
     */
    private fun hashOne(
        data: ByteArray,
        offset: Int,
        length: Int,
        output: ByteArray,
        outputOffset: Int,
        outputLength: Int
    ) {
        hash.reset()
        hash.update(data, offset, length)
        try {
            hash.digest(output, outputOffset, outputLength)
        } catch (e: DigestException) {
            Arrays.fill(output, outputOffset, outputLength, 0.toByte())
        }
    }

    /**
     * Hashes two data buffers.
     *
     * @param data1 The buffer containing the first data to hash.
     * @param offset1 Offset into the first data buffer of the first byte to hash.
     * @param length1 Length of the first data to be hashed.
     * @param data2 The buffer containing the second data to hash.
     * @param offset2 Offset into the second data buffer of the first byte to hash.
     * @param length2 Length of the second data to be hashed.
     * @param output The buffer to receive the output hash value.
     * @param outputOffset Offset into the output buffer to place the hash value.
     * @param outputLength The length of the hash output.
     *
     * The output buffer can be same as either of the input buffers.
     */
    private fun hashTwo(
        data1: ByteArray,
        offset1: Int,
        length1: Int,
        data2: ByteArray,
        offset2: Int,
        length2: Int,
        output: ByteArray,
        outputOffset: Int,
        outputLength: Int
    ) {
        hash.reset()
        hash.update(data1, offset1, length1)
        hash.update(data2, offset2, length2)
        try {
            hash.digest(output, outputOffset, outputLength)
        } catch (e: DigestException) {
            Arrays.fill(output, outputOffset, outputLength, 0.toByte())
        }
    }

    /**
     * Computes a HMAC value using key and data values.
     *
     * @param key The buffer that contains the key.
     * @param keyOffset The offset of the key in the key buffer.
     * @param keyLength The length of the key in bytes.
     * @param data The buffer that contains the data.
     * @param dataOffset The offset of the data in the data buffer.
     * @param dataLength The length of the data in bytes.
     * @param output The output buffer to place the HMAC value in.
     * @param outputOffset Offset into the output buffer for the HMAC value.
     * @param outputLength The length of the HMAC output.
     */
    private fun hmac(
        key: ByteArray,
        keyOffset: Int,
        keyLength: Int,
        data: ByteArray,
        dataOffset: Int,
        dataLength: Int,
        output: ByteArray,
        outputOffset: Int,
        outputLength: Int
    ) {
        // In all of the algorithms of interest to us, the block length
        // is twice the size of the hash length.
        val hashLength = hash.getDigestLength()
        val blockLength = hashLength * 2
        val block = ByteArray(blockLength)
        var index: Int
        try {
            if (keyLength <= blockLength) {
                System.arraycopy(key, keyOffset, block, 0, keyLength)
                Arrays.fill(block, keyLength, blockLength, 0.toByte())
            } else {
                hash.reset()
                hash.update(key, keyOffset, keyLength)
                hash.digest(block, 0, hashLength)
                Arrays.fill(block, hashLength, blockLength, 0.toByte())
            }
            index = 0
            while (index < blockLength) {
                block[index] = (block[index].toInt() xor 0x36.toByte().toInt()).toByte()
                ++index
            }
            hash.reset()
            hash.update(block, 0, blockLength)
            hash.update(data, dataOffset, dataLength)
            hash.digest(output, outputOffset, hashLength)
            index = 0
            while (index < blockLength) {
                block[index] = (block[index].toInt() xor (0x36 xor 0x5C).toByte().toInt()).toByte()
                ++index
            }
            hash.reset()
            hash.update(block, 0, blockLength)
            hash.update(output, outputOffset, hashLength)
            hash.digest(output, outputOffset, outputLength)
        } catch (e: DigestException) {
            Arrays.fill(output, outputOffset, outputLength, 0.toByte())
        } finally {
            destroy(block)
        }
    }

    /**
     * Computes a HKDF value.
     *
     * @param key The buffer that contains the key.
     * @param keyOffset The offset of the key in the key buffer.
     * @param keyLength The length of the key in bytes.
     * @param data The buffer that contains the data.
     * @param dataOffset The offset of the data in the data buffer.
     * @param dataLength The length of the data in bytes.
     * @param output1 The first output buffer.
     * @param output1Offset Offset into the first output buffer.
     * @param output1Length Length of the first output which can be
     * less than the hash length.
     * @param output2 The second output buffer.
     * @param output2Offset Offset into the second output buffer.
     * @param output2Length Length of the second output which can be
     * less than the hash length.
     */
    private fun hkdf(
        key: ByteArray,
        keyOffset: Int,
        keyLength: Int,
        data: ByteArray,
        dataOffset: Int,
        dataLength: Int,
        output1: ByteArray,
        output1Offset: Int,
        output1Length: Int,
        output2: ByteArray,
        output2Offset: Int,
        output2Length: Int
    ) {
        val hashLength = hash.getDigestLength()
        val tempKey = ByteArray(hashLength)
        val tempHash = ByteArray(hashLength + 1)
        try {
            hmac(key, keyOffset, keyLength, data, dataOffset, dataLength, tempKey, 0, hashLength)
            tempHash[0] = 0x01.toByte()
            hmac(tempKey, 0, hashLength, tempHash, 0, 1, tempHash, 0, hashLength)
            System.arraycopy(tempHash, 0, output1, output1Offset, output1Length)
            tempHash[hashLength] = 0x02.toByte()
            hmac(tempKey, 0, hashLength, tempHash, 0, hashLength + 1, tempHash, 0, hashLength)
            System.arraycopy(tempHash, 0, output2, output2Offset, output2Length)
        } finally {
            destroy(tempKey)
            destroy(tempHash)
        }
    }

    fun getSymmetricKey(): SecretKey {
        return cipher.getKeySpec()
    }

    fun split(): TrafficKeys {
        val keyLength = cipher.getKeyLength()
        val k1 = ByteArray(keyLength)
        val k2 = ByteArray(keyLength)
        try {
            hkdf(ck, 0, ck.size, byteArrayOf(0), 0, 0, k1, 0, k1.size, k2, 0, k2.size)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return TrafficKeys(k1, k2)
    }

    /**
     * Mixes data into the handshake hash.
     *
     * @param data The buffer containing the data to mix in.
     * @param offset The offset of the first data byte to mix in.
     * @param length The number of bytes to mix in.
     */
    fun mixHash(data: ByteArray, offset: Int, length: Int) {
        hashTwo(h, 0, h.size, data, offset, length, h, 0, h.size)
    }

    /**
     * Mixes data into the chaining key.
     *
     * @param data The buffer containing the data to mix in.
     * @param offset The offset of the first data byte to mix in.
     * @param length The number of bytes to mix in.
     */
    fun mixKey(data: ByteArray, offset: Int, length: Int) {
        val keyLength = cipher.getKeyLength()
        val tempKey = ByteArray(keyLength)
        try {
            hkdf(ck, 0, ck.size, data, offset, length, ck, 0, ck.size, tempKey, 0, keyLength)
            cipher.initializeKey(tempKey, 0)
        } finally {
            destroy(tempKey)
        }
    }

    fun mixKeyAndHash(data: ByteArray) {
        val key: ByteArray =
            deriveKey(data, this.ck, 96)
        System.arraycopy(key, 0, this.ck, 0, 32)
        val temp_h = ByteArray(32)
        System.arraycopy(key, 32, temp_h, 0, 32)
        val temp_k = ByteArray(32)
        System.arraycopy(key, 64, temp_k, 0, 32)
        mixHash(temp_h, 0, 32)
        this.cipher.initializeKey(temp_k, 0)
    }

    companion object {
        /**
         * Destroys the contents of a byte array.
         *
         * @param array The array whose contents should be destroyed.
         */
        fun destroy(array: ByteArray?) {
            Arrays.fill(array, 0.toByte())
        }

        /**
         * Derives a key of a specified length from input key material and optional salt.
         *
         * @param inputKeyMaterial The input key material from which the key will be derived.
         * @param salt Optional salt to use in the key derivation process. Can enhance security.
         * @param keyLength The length of the derived key to generate, in bytes.
         * @return A byte array containing the derived key.
         */
        fun deriveKey(inputKeyMaterial: ByteArray, salt: ByteArray, keyLength: Int): ByteArray {
            // Create an array to hold the derived key, of the desired length.
            val derivedKey = ByteArray(keyLength)
            val kdf = HKDFBytesGenerator(SHA256Digest())
            kdf.init(HKDFParameters(inputKeyMaterial, salt, null))
            // Use the KDF to fill the derivedKey array with the generated key material.
            kdf.generateBytes(derivedKey, 0, keyLength)
            return derivedKey
        }
    }
}

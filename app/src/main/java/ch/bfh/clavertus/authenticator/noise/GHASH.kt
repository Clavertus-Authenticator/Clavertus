package ch.bfh.clavertus.authenticator.noise

import java.util.Arrays

/**
 * Inspired by https://github.com/rweather/noise-java/blob/master/src/main/java/com/southernstorm/noise/crypto/GHASH.java
 * */
@Suppress("detekt:all")
class GHASH {
    private var H: LongArray = LongArray(2)
    private var Y: ByteArray = ByteArray(16)
    var posn = 0

    /**
     * Resets this GHASH object with a new key.
     *
     * @param key The key, which must contain at least 16 bytes.
     * @param offset The offset of the first key byte.
     */
    fun reset(key: ByteArray, offset: Int) {
        H[0] = readBigEndian(key, offset)
        H[1] = readBigEndian(key, offset + 8)
        Arrays.fill(Y, 0.toByte())
        posn = 0
    }

    /**
     * Resets the GHASH object but retains the previous key.
     */
    fun reset() {
        Arrays.fill(Y, 0.toByte())
        posn = 0
    }

    /**
     * Updates this GHASH object with more data.
     *
     * @param data Buffer containing the data.
     * @param offset Offset of the first data byte in the buffer.
     * @param length The number of bytes from the buffer to hash.
     */
    fun update(data: ByteArray, offset: Int, length: Int) {
        var offsetTmp = offset
        var lengthTmp = length
        while (lengthTmp > 0) {
            var size = 16 - posn
            if (size > lengthTmp) size = lengthTmp
            for (index in 0 until size) Y[posn + index] =
                (Y[posn + index].toInt() xor data[offsetTmp + index].toInt()).toByte()
            posn += size
            lengthTmp -= size
            offsetTmp += size
            if (posn == 16) {
                GF128_mul(Y, H)
                posn = 0
            }
        }
    }

    /**
     * Finishes the GHASH process and returns the tag.
     *
     * @param tag Buffer to receive the tag.
     * @param offset Offset of the first byte of the tag.
     * @param length The length of the tag, which must be less
     * than or equal to 16.
     */
    fun finish(tag: ByteArray, offset: Int, length: Int) {
        pad()
        System.arraycopy(Y, 0, tag, offset, length)
    }

    /**
     * Pads the input to a 16-byte boundary.
     */
    fun pad() {
        if (posn != 0) {
            // Padding involves XOR'ing the rest of state->Y with zeroes,
            // which does nothing.  Immediately process the next chunk.
            GF128_mul(Y, H)
            posn = 0
        }
    }

    /**
     * Pads the input to a 16-byte boundary and then adds a block
     * containing the AD and data lengths.
     *
     * @param adLen Length of the associated data in bytes.
     * @param dataLen Length of the data in bytes.
     */
    fun pad(adLen: Long, dataLen: Long) {
        val temp = ByteArray(16)
        try {
            pad()
            writeBigEndian(temp, 0, adLen * 8)
            writeBigEndian(temp, 8, dataLen * 8)
            update(temp, 0, 16)
        } finally {
            Arrays.fill(temp, 0.toByte())
        }
    }

    private fun readBigEndian(buf: ByteArray, offset: Int): Long {
        return buf[offset].toLong() and 0xFFL shl 56 or
            (buf[offset + 1].toLong() and 0xFFL shl 48) or
            (buf[offset + 2].toLong() and 0xFFL shl 40) or
            (buf[offset + 3].toLong() and 0xFFL shl 32) or
            (buf[offset + 4].toLong() and 0xFFL shl 24) or
            (buf[offset + 5].toLong() and 0xFFL shl 16) or
            (buf[offset + 6].toLong() and 0xFFL shl 8) or
            (buf[offset + 7].toLong() and 0xFFL)
    }

    private fun writeBigEndian(buf: ByteArray, offset: Int, value: Long) {
        buf[offset] = (value shr 56).toByte()
        buf[offset + 1] = (value shr 48).toByte()
        buf[offset + 2] = (value shr 40).toByte()
        buf[offset + 3] = (value shr 32).toByte()
        buf[offset + 4] = (value shr 24).toByte()
        buf[offset + 5] = (value shr 16).toByte()
        buf[offset + 6] = (value shr 8).toByte()
        buf[offset + 7] = value.toByte()
    }

    private fun GF128_mul(Y: ByteArray, H: LongArray) {
        var Z0: Long = 0 // Z = 0
        var Z1: Long = 0
        var V0 = H[0] // V = H
        var V1 = H[1]

        // Multiply Z by V for the set bits in Y, starting at the top.
        // This is a very simple bit by bit version that may not be very
        // fast but it should be resistant to cache timing attacks.
        for (posn in 0..15) {
            val value = Y[posn].toInt() and 0xFF
            for (bit in 7 downTo 0) {
                // Extract the high bit of "value" and turn it into a mask.
                var mask = -(value shr bit and 0x01).toLong()

                // XOR V with Z if the bit is 1.
                Z0 = Z0 xor (V0 and mask)
                Z1 = Z1 xor (V1 and mask)

                // Rotate V right by 1 bit.
                mask = (V1 and 0x01L).inv() + 1 and -0x1f00000000000000L
                V1 = V1 ushr 1 or (V0 shl 63)
                V0 = V0 ushr 1 xor mask
            }
        }

        // We have finished the block so copy Z into Y and byte-swap.
        writeBigEndian(Y, 0, Z0)
        writeBigEndian(Y, 8, Z1)
    }
}

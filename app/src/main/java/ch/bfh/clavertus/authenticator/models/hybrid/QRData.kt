package ch.bfh.clavertus.authenticator.models.hybrid

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder

data class QRData(
    val publicKey: ByteArray,
    val qrSecret: ByteArray,
    val tunnelServerDomains: Int,
    val currentTime: Long?,
    val canPerformTransactions: Boolean?,
    val operationHint: String,
) {
    companion object {
        private const val PUBLIC_KEY_INDEX = 0
        private const val QR_SECRET_INDEX = 1
        private const val TUNNEL_SERVER_DOMAINS_INDEX = 2
        private const val CURRENT_TIME_INDEX = 3
        private const val CAN_PERFORM_TRANSACTIONS_INDEX = 4
        private const val OPERATION_HINT_INDEX = 5
        private const val CHUNK_SIZE = 7
        private const val CHUNK_DIGITS = 17
        private const val BYTES_8 = 8
        private val PARTIAL_CHUNK_DIGITS = listOf(0, 3, 5, 8, 10, 13, 15)

        fun decodeQRContents(encoded: String): QRData {
            val cborData = digitDecode(encoded)
            return cborDecode(cborData)
        }

        /**
         * Decodes digit-encoded data into a byte array.
         * @see <a href="https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#hybrid-qr-initiated">CTAP2.2 Standard</a>
         * @param encodedString The digit-encoded string to decode
         * @return The decoded byte array
         */
        private fun digitDecode(encodedString: String): ByteArray {
            val result = ByteBuffer.allocate(encodedString.length) // Allocate more than needed
            var index = 0

            // Process full chunks
            while (index + CHUNK_DIGITS <= encodedString.length) {
                // Using Long instead of ULong here is due to JVMs lack of native unsigned support. Since we're focused on the binary
                // representation for decoding, and not the numerical value, the usage of Long does not impact the underlying binary data.
                val chunk = encodedString.substring(index, index + CHUNK_DIGITS).toLong()
                val bytes = ByteBuffer.allocate(BYTES_8).order(ByteOrder.LITTLE_ENDIAN).putLong(chunk).array()
                result.put(bytes, 0, CHUNK_SIZE) // Put 7 bytes into result
                index += CHUNK_DIGITS
            }

            // Process partial chunk, if any
            if (index < encodedString.length) {
                val remainingDigits = encodedString.length - index
                val expectedDigits = PARTIAL_CHUNK_DIGITS.firstOrNull { remainingDigits <= it }
                    ?: throw IllegalArgumentException("Invalid encoded string length")

                val chunk = encodedString.substring(index).toLong()
                val bytes = ByteBuffer.allocate(BYTES_8).order(ByteOrder.LITTLE_ENDIAN).putLong(chunk).array()
                val partialChunkSize = PARTIAL_CHUNK_DIGITS.indexOf(expectedDigits)
                result.put(bytes, 0, partialChunkSize) // Put partial chunk bytes into result
            }

            // Trim the buffer to the actual size of the decoded data
            val decodedSize = result.position()
            return result.array().sliceArray(0 until decodedSize)
        }

        /**
         * Decodes a CBOR-encoded byte array into a QRData object.
         * @see <a href="https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#hybrid-qr-initiated">CTAP2.2 Standard</a>
         * @param cborData The CBOR-encoded byte array to decode
         * @return The decoded QRData object
         */
        @Suppress("NestedBlockDepth")
        private fun cborDecode(cborData: ByteArray): QRData {
            // Too hard with kotlin serialization as integer keys are not supported out of the box

            val inputStream = ByteArrayInputStream(cborData)
            val dataItems = CborDecoder(inputStream).decode()

            var publicKey = ByteArray(0)
            var qrSecret = ByteArray(0)
            var tunnelServerDomains = 0
            var currentTime: Long? = null
            var canPerformTransactions: Boolean? = null
            var operationHint = "ga"

            if (dataItems.isNotEmpty() && dataItems[0] is co.nstant.`in`.cbor.model.Map) {
                val dataMap = dataItems[0] as co.nstant.`in`.cbor.model.Map
                dataMap.keys.forEach { key ->
                    when ((key as UnsignedInteger).value.toInt()) {
                        PUBLIC_KEY_INDEX ->
                            publicKey = (dataMap[key] as ByteString).bytes
                        QR_SECRET_INDEX ->
                            qrSecret = (dataMap[key] as ByteString).bytes
                        TUNNEL_SERVER_DOMAINS_INDEX ->
                            tunnelServerDomains = (dataMap[key] as UnsignedInteger).value.toInt()
                        CURRENT_TIME_INDEX ->
                            currentTime = (dataMap[key] as? UnsignedInteger)?.value?.toLong()
                        CAN_PERFORM_TRANSACTIONS_INDEX ->
                            canPerformTransactions = (dataMap[key] as? SimpleValue)?.let { it == SimpleValue.TRUE }
                        OPERATION_HINT_INDEX ->
                            operationHint = (dataMap[key] as? UnicodeString)?.string?.takeIf { it == "mc" } ?: "ga"
                    }
                }
            }

            return QRData(
                publicKey,
                qrSecret,
                tunnelServerDomains,
                currentTime,
                canPerformTransactions,
                operationHint
            )
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as QRData

        if (!publicKey.contentEquals(other.publicKey)) return false
        if (!qrSecret.contentEquals(other.qrSecret)) return false
        if (tunnelServerDomains != other.tunnelServerDomains) return false
        if (currentTime != other.currentTime) return false
        if (canPerformTransactions != other.canPerformTransactions) return false
        if (operationHint != other.operationHint) return false

        return true
    }

    override fun hashCode(): Int {
        var result = publicKey.contentHashCode()
        result = 31 * result + qrSecret.contentHashCode()
        result = 31 * result + tunnelServerDomains
        result = 31 * result + (currentTime?.hashCode() ?: 0)
        result = 31 * result + (canPerformTransactions?.hashCode() ?: 0)
        result = 31 * result + operationHint.hashCode()
        return result
    }
}

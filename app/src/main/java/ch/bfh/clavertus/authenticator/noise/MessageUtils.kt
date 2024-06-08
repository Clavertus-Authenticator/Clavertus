package ch.bfh.clavertus.authenticator.noise

import android.util.Log
import ch.bfh.clavertus.authenticator.utils.SessionHandler
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class MessageUtils @Inject constructor(
    private val sessionHandler: SessionHandler
) {
    private var gcmCounterDecrypt = 0
    private var gcmCounterEncrypt = 0

    fun decryptMessage(data: ByteArray): ByteArray {
        val decryptMessage: ByteArray = NoiseCryptoUtilities.decryptMessage(
            data,
            SecretKeySpec(sessionHandler.getTrafficReadKey(), "AES"),
            gcmCounterDecrypt
        )
        gcmCounterDecrypt++
        return decryptMessage
    }

    fun encryptMessage(data: ByteArray): ByteArray {
        try {
            val encryptedMessage: ByteArray = NoiseCryptoUtilities.encryptMessage(
                data,
                SecretKeySpec(sessionHandler.getTrafficWriteKey(), "AES"),
                gcmCounterEncrypt
            )
            gcmCounterEncrypt++
            return encryptedMessage
        } catch (ex: IllegalArgumentException) {
            Log.e(TAG, "Message could not be encrypted", ex)
            return byteArrayOf()
        }
    }

    fun resetCounters() {
        gcmCounterDecrypt = 0
        gcmCounterEncrypt = 0
    }

    companion object {
        private val TAG = MessageUtils::class.java.simpleName
    }
}

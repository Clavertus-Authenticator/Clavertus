package ch.bfh.clavertus.authenticator.socket

import okhttp3.Response
import okio.ByteString

interface WebSocketMessageListener {
    fun onMessage(byteString: ByteString)

    fun onOpen() {
        // Default implementation does nothing
    }

    fun onClosed(code: Int, reason: String) {
        // Default implementation does nothing
    }

    fun onFailure(t: Throwable, response: Response?) {
        // Default implementation does nothing
    }
}

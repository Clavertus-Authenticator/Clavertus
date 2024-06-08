package ch.bfh.clavertus.authenticator.socket

import android.util.Log
import ch.bfh.clavertus.authenticator.modules.AuthenticatorHttpClient
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.SessionHandler
import ch.bfh.clavertus.authenticator.utils.toHexString
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.util.Base64
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class WebSocketManager @Inject constructor(
    private val sessionHandler: SessionHandler,
    @AuthenticatorHttpClient private val httpClient: OkHttpClient
) {
    private var socket: WebSocket? = null
    private val listeners = mutableListOf<WebSocketMessageListener>()
    private var isConnected = false

    fun addListener(listener: WebSocketMessageListener) {
        Log.i(TAG, "Adding listener")
        listeners.add(listener)
    }

    fun removeListener(listener: WebSocketMessageListener) {
        Log.i(TAG, "Removing listener")
        listeners.remove(listener)
    }

    fun isConnected(): Boolean {
        return isConnected
    }

    fun connect(qrInitiated: Boolean) {
        val subProtocol = "fido.cable"
        val connectURL = buildConnectUrl(sessionHandler, qrInitiated)
        val request = Request.Builder()
            .url(connectURL)
            .header("Sec-WebSocket-Protocol", subProtocol)
            .build()
        socket = httpClient.newWebSocket(
            request,
            object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: okhttp3.Response) {
                    super.onOpen(webSocket, response)
                    Log.i(TAG, "WebSocket opened: $response")
                    isConnected = true
                    listeners.forEach { it.onOpen() }
                }

                override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                    super.onMessage(webSocket, bytes)
                    Log.i(TAG, "WebSocket message received")
                    listeners.forEach { it.onMessage(bytes) }
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    super.onClosed(webSocket, code, reason)
                    Log.i(TAG, "WebSocket closed: $code $reason")
                    isConnected = false
                    listeners.forEach { it.onClosed(code, reason) }
                }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    super.onFailure(webSocket, t, response)
                    Log.e(TAG, "WebSocket failure: ${t.message}")
                    isConnected = false
                    listeners.forEach { it.onFailure(t, response) }
                }
            }
        )
    }

    private fun buildConnectUrl(sessionHandler: SessionHandler, qrInitiated: Boolean): String {
        return if (qrInitiated) {
            Constants.SOCKET_URL + Constants.SOCKET_PATH_CONNECT +
                sessionHandler.getRoutingID().toHexString() + "/" +
                sessionHandler.getTunnelID().toHexString()
        } else {
            Constants.SOCKET_URL + Constants.SOCKET_PATH_CONTACT +
                Base64.getUrlEncoder().withoutPadding().encodeToString(
                    sessionHandler.getContactId()
                )
        }
    }

    fun send(data: ByteArray) {
        if (socket == null) {
            Log.e(TAG, "Websocket is null. Did you forget to connect to the WebSocket?")
            return
        }

        socket?.send(data.toByteString())
    }

    fun close() {
        socket?.close(NORMAL_CLOSE, "Normal close")
    }

    companion object {
        private const val NORMAL_CLOSE = 1000
        private val TAG = WebSocketManager::class.java.simpleName
    }
}

@file:Suppress("TooManyFunctions")

package ch.bfh.clavertus.authenticator.utils

import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import ch.bfh.clavertus.authenticator.models.Transportation
import ch.bfh.clavertus.authenticator.modules.EncryptedPreferences
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.math.ec.ECPoint
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class SessionHandler @Inject constructor(
    @EncryptedPreferences private val prefs: SharedPreferences
) {
    fun setRequestId(requestId: ByteArray) {
        prefs.edit().putString(
            "requestId",
            Base64.encodeToString(
                requestId,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
            )
        ).apply()
    }

    fun getRequestId(): ByteArray {
        return Base64.decode(
            prefs.getRequestId(),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )
    }

    fun setSessionToken(sessionToken: ByteArray) {
        prefs.edit().putString(
            "sessionToken",
            Base64.encodeToString(
                sessionToken,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
            )
        ).apply()
    }

    fun getSessionToken(): ByteArray {
        return Base64.decode(
            prefs.getSessionToken(),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )
    }

    fun setCredentialID(credentialID: ByteArray) {
        prefs.edit().putString(
            "credentialID",
            Base64.encodeToString(
                credentialID,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
            )
        ).apply()
    }

    fun getCredentialID(): ByteArray {
        return Base64.decode(
            prefs.getCredentialID(),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )
    }

    fun setClientData(clientData: String) {
        prefs.edit().putString("clientData", clientData).apply()
    }

    fun getClientData(): String {
        return prefs.getClientData()
    }

    // Routing-id for wss communication transfer in BLE advert
    fun setRoutingID(routingId: ByteArray) {
        prefs.edit().putString(
            "routingID",
            Base64.encodeToString(
                routingId,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
            )
        ).apply()
    }

    fun getRoutingID(): ByteArray {
        return Base64.decode(
            prefs.getRoutingID(),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )
    }

    // Tunnel-id for wss communication after BLE advert
    fun setTunnelID(tunnelId: ByteArray) {
        prefs.edit().putString(
            "tunnelID",
            Base64.encodeToString(
                tunnelId,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
            )
        ).apply()
    }

    fun getTunnelID(): ByteArray {
        return Base64.decode(
            prefs.getTunnelID(),
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )
    }

    fun setPSK(psk: ByteArray) {
        prefs.edit().putString(
            "psk",
            Base64.encodeToString(psk, Base64.DEFAULT)
        ).apply()
    }

    fun getPSK(): ByteArray {
        return Base64.decode(prefs.getPSK(), Base64.DEFAULT)
    }

    // QR Public key for WSS
    fun setQRPublicKey(publicKey: ByteArray) {
        prefs.edit().putString(
            "QRPublicKey",
            Base64.encodeToString(publicKey, Base64.DEFAULT)
        ).apply()
    }

    fun getQRPublicKey(): ByteArray {
        return Base64.decode(prefs.getQRPublicKey(), Base64.DEFAULT)
    }

    fun getQRPublicKeyUncompressed(): ECPoint {
        val compressedKey = Base64.decode(prefs.getQRPublicKey(), Base64.DEFAULT)
        val parameterSpec = ECNamedCurveTable.getParameterSpec("P-256")
        return parameterSpec.curve.decodePoint(compressedKey)
    }

    // Traffic writeKey after noise handshake
    fun setTrafficWriteKey(writeKey: ByteArray) {
        prefs.edit().putString(
            "TrafficWriteKey",
            Base64.encodeToString(writeKey, Base64.DEFAULT)
        ).apply()
    }

    fun getTrafficWriteKey(): ByteArray {
        prefs.getTrafficWriteKey()?.let { return Base64.decode(it, Base64.DEFAULT) }
            ?: return ByteArray(0)
    }

    // Traffic readKey after noise handshake
    fun setTrafficReadKey(readKey: ByteArray) {
        prefs.edit().putString(
            "TrafficReadKey",
            Base64.encodeToString(readKey, Base64.DEFAULT)
        ).apply()
    }

    fun getTrafficReadKey(): ByteArray {
        prefs.getTrafficReadKey()?.let { return Base64.decode(it, Base64.DEFAULT) }
            ?: return ByteArray(0)
    }

    fun setQRSecret(readKey: ByteArray) {
        prefs.edit().putString(
            "QRSecret",
            Base64.encodeToString(readKey, Base64.DEFAULT)
        ).apply()
    }

    fun getQRSecret(): ByteArray {
        return Base64.decode(prefs.getQRSecret(), Base64.DEFAULT)
    }

    fun setAuthenticatorPublicKey(linkPublicKey: ByteArray) {
        prefs.edit().putString(
            "authenticatorPublicKey",
            Base64.encodeToString(linkPublicKey, Base64.DEFAULT)
        ).apply()
    }

    fun getAuthenticatorPublicKey(): ByteArray {
        prefs.getAuthenticatorPublicKey()?.let { return Base64.decode(it, Base64.DEFAULT) }
            ?: return ByteArray(0)
    }

    fun setAuthenticatorPrivateKey(authenticatorPrivateKey: ByteArray) {
        prefs.edit().putString(
            "authenticatorPrivateKey",
            Base64.encodeToString(authenticatorPrivateKey, Base64.DEFAULT)
        ).apply()
    }

    fun getAuthenticatorPrivateKey(): ByteArray {
        prefs.getAuthenticatorPrivateKey()?.let { return Base64.decode(it, Base64.DEFAULT) }
            ?: return ByteArray(0)
    }

    fun setLinkSecret(linkSecret: ByteArray) {
        prefs.edit().putString(
            "linkSecret",
            Base64.encodeToString(linkSecret, Base64.DEFAULT)
        ).apply()
    }

    fun getLinkSecret(): ByteArray {
        return Base64.decode(prefs.getLinkSecret(), Base64.DEFAULT)
    }

    fun setContactId(contactId: ByteArray) {
        prefs.edit().putString(
            "contactId",
            Base64.encodeToString(contactId, Base64.DEFAULT)
        ).apply()
    }

    fun getContactId(): ByteArray {
        return Base64.decode(prefs.getContactId(), Base64.DEFAULT)
    }

    fun setTransport(transport: Transportation) {
        Log.i("SessionHandler", "Set transport: " + transport.name)
        prefs.edit().putString(
            "transport",
            transport.name
        ).apply()
    }

    fun getTransport(): Transportation {
        Log.i("SessionHandler", "Read transport: " + prefs.getTransport())
        return Transportation.valueOf(prefs.getTransport())
    }

    fun isTransportQR(): Boolean {
        return this.getTransport() == Transportation.HYBRID_QR
    }
}

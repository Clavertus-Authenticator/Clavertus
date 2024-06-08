@file:Suppress("TooManyFunctions")

package ch.bfh.clavertus.authenticator.utils

import android.content.SharedPreferences

inline fun <reified T> SharedPreferences.get(key: String, defaultValue: T): T {
    return when (T::class) {
        String::class -> getString(key, defaultValue as? String).orEmpty() as T
        Boolean::class -> getBoolean(key, defaultValue as? Boolean ?: false) as T
        Int::class -> getInt(key, defaultValue as? Int ?: 0) as T
        Float::class -> getFloat(key, defaultValue as? Float ?: 0f) as T
        Long::class -> getLong(key, defaultValue as? Long ?: 0L) as T
        else -> throw IllegalArgumentException("Unsupported preference type.")
    }
}

fun ByteArray.toHexString(): String {
    return this.joinToString("") { "%02x".format(it) }
}

fun SharedPreferences.getSessionToken(): String {
    return this.get("sessionToken", "null")
}

fun SharedPreferences.getClientData(): String {
    return this.get("clientData", "null")
}

fun SharedPreferences.getRoutingID(): String {
    return this.get("routingID", "null")
}

fun SharedPreferences.getTunnelID(): String {
    return this.get("tunnelID", "null")
}

fun SharedPreferences.getPSK(): String {
    return this.get("psk", "null")
}

fun SharedPreferences.getQRPublicKey(): String {
    return this.get("QRPublicKey", "null")
}

fun SharedPreferences.getTrafficReadKey(): String? {
    return this.get("TrafficReadKey", null)
}

fun SharedPreferences.getQRSecret(): String {
    return this.get("QRSecret", "null")
}

fun SharedPreferences.getAuthenticatorPublicKey(): String? {
    return this.get("authenticatorPublicKey", null)
}

fun SharedPreferences.getAuthenticatorPrivateKey(): String? {
    return this.get("authenticatorPrivateKey", null)
}

fun SharedPreferences.getTrafficWriteKey(): String? {
    return this.get("TrafficWriteKey", null)
}

fun SharedPreferences.getRequestId(): String {
    return this.get("requestId", "null")
}

fun SharedPreferences.getCredentialID(): String {
    return this.get("credentialID", "null")
}

fun SharedPreferences.getLinkSecret(): String {
    return this.get("linkSecret", "null")
}

fun SharedPreferences.getEcCurve(): String {
    return this.get("ec_curve", "secp256r1")
}

fun SharedPreferences.getKeyType(): String {
    return this.get("key_type", "EC")
}

fun SharedPreferences.getContactId(): String {
    return this.get("contactId", "null")
}

fun SharedPreferences.getTransport(): String {
    return this.get("transport", "IDLE")
}

fun SharedPreferences.getDemoBackendUrl(): String {
    return this.get("demo_backend_url", "https://trusty-bfh.com:8443")
}

fun SharedPreferences.getUserAuthenticationRequired(): Boolean {
    return this.get("user_authentication_required", true)
}

fun SharedPreferences.getStrongBoxRequired(): Boolean {
    return this.get("strong_box_required", true)
}

fun SharedPreferences.getRSAKeyLength(): Int {
    return this.get(
        "rsa_key_length",
        "${Constants.Crypto.RSA_KEY_LENGTH_2048}"
    ).toIntOrNull() ?: Constants.Crypto.RSA_KEY_LENGTH_2048
}

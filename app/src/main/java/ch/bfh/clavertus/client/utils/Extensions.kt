@file:Suppress("TooManyFunctions")

package ch.bfh.clavertus.client.utils

import android.annotation.SuppressLint
import android.util.Base64
import okhttp3.OkHttpClient
import java.security.SecureRandom
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

// ! This is only for testing purposes and should not be used in production code!
fun OkHttpClient.Builder.ignoreAllTLSErrors(): OkHttpClient.Builder {
    val naiveTrustManager =
        @SuppressLint("CustomX509TrustManager")
        object : X509TrustManager {
            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
            override fun checkClientTrusted(certs: Array<X509Certificate>, authType: String) = Unit
            override fun checkServerTrusted(certs: Array<X509Certificate>, authType: String) = Unit
        }

    val insecureSocketFactory = SSLContext.getInstance("TLSv1.3").apply {
        val trustAllCerts = arrayOf<TrustManager>(naiveTrustManager)
        init(null, trustAllCerts, SecureRandom())
    }.socketFactory

    sslSocketFactory(insecureSocketFactory, naiveTrustManager)
    hostnameVerifier { hostname, _ -> hostname == "trusty-bfh.com" || hostname == "localhost" }
    return this
}

/**
 * Encodes this byte array to a Base64 string.
 * @return The Base64-encoded string representation of this byte array.
 */

fun ByteArray.toBase64String(): String =
    Base64.encodeToString(this, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

/**
 * Decodes this Base64 string to a byte array.
 * @return The byte array decoded from this Base64 string.
 */
fun String.fromBase64ToByteArray(): ByteArray =
    Base64.decode(this, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

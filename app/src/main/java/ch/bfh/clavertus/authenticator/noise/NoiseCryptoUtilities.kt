package ch.bfh.clavertus.authenticator.noise

import ch.bfh.clavertus.authenticator.utils.Constants
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.interfaces.ECPublicKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Provider
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.spec.ECGenParameterSpec
import java.util.Arrays
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

@Suppress("detekt:all")
object NoiseCryptoUtilities {
    init {
        this.removeSecurityProvider(BouncyCastleProvider.PROVIDER_NAME)
        this.addSecurityProvider(BouncyCastleProvider())
    }

    fun calculateHandshake(message: ByteArray, handshake: Handshake, qrInitiated: Boolean): ByteArray {
        val ephemeralPublicKeyBytes = message.sliceArray(0 until Constants.Crypto.P256_X9_62_LENGTH)
        val encryptedHashedPayload = message.sliceArray(Constants.Crypto.P256_X9_62_LENGTH until message.size)

        return if (qrInitiated) {
            handshake.makeQRInitiatedHandshake(ephemeralPublicKeyBytes, encryptedHashedPayload)
        } else {
            handshake.makeStateAssistedHandshake(ephemeralPublicKeyBytes, encryptedHashedPayload)
        }
    }

    private fun addSecurityProvider(provider: Provider) {
        Security.addProvider(provider)
    }

    private fun removeSecurityProvider(str: String) {
        Security.removeProvider(str)
    }

    fun generateKeyPair(curve: String?): KeyPair {
        val keyPairGenerator =
            KeyPairGenerator.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME)
        keyPairGenerator.initialize(ECGenParameterSpec(curve), SecureRandom())
        return keyPairGenerator.generateKeyPair()
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun getPublicKeyFromXandYPoints(x: ByteArray, y: ByteArray): PublicKey {
        val ecNamedCurveParameterSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(
            Constants.Crypto.NOISE_CURVE_P256
        )

        return KeyFactory.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME).generatePublic(
            org.bouncycastle.jce.spec.ECPublicKeySpec(
                ECDomainParameters(
                    ecNamedCurveParameterSpec.curve,
                    ecNamedCurveParameterSpec.g,
                    ecNamedCurveParameterSpec.n,
                    ecNamedCurveParameterSpec.h
                ).curve.createPoint(
                    BigInteger(x.toHexString(), 16),
                    BigInteger(y.toHexString(), 16)
                ),
                ecNamedCurveParameterSpec
            )
        )
    }

    fun generateDHSecretUtil(
        privateKeyBytes: ByteArray,
        publicKeyBytes: ByteArray
    ): ByteArray {
        val keyAgreement = KeyAgreement.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME)
        keyAgreement.init(generatePrivateKey(privateKeyBytes))
        keyAgreement.doPhase(generatePublicKey(publicKeyBytes), true)
        return keyAgreement.generateSecret()
    }

    fun getPublicXCoordinateAsByte(keyPair: KeyPair): ByteArray {
        return (keyPair.public as ECPublicKey).q.affineXCoord.encoded
    }

    fun getPublicYCoordinateAsByte(keyPair: KeyPair): ByteArray {
        return (keyPair.public as ECPublicKey).q.affineYCoord.encoded
    }

    @OptIn(ExperimentalStdlibApi::class)
    fun generatePrivateKey(privateKeyBytes: ByteArray): PrivateKey {
        val curveSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(Constants.Crypto.NOISE_CURVE_P256)
        return KeyFactory.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME).generatePrivate(
            org.bouncycastle.jce.spec.ECPrivateKeySpec(
                BigInteger(privateKeyBytes.toHexString(), 16),
                curveSpec
            )
        )
    }

    fun generatePublicKey(publicKeyBytes: ByteArray): PublicKey {
        val curveSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(Constants.Crypto.NOISE_CURVE_P256)
        return KeyFactory.getInstance("ECDH", BouncyCastleProvider.PROVIDER_NAME)
            .generatePublic(
                org.bouncycastle.jce.spec.ECPublicKeySpec(
                    curveSpec.curve.decodePoint(
                        publicKeyBytes
                    ),
                    curveSpec
                )
            )
    }

    fun getEncodedPrivateKey(privateKey: PrivateKey): ByteArray {
        return (privateKey as ECPrivateKey).d.toByteArray()
    }

    fun getEncodedPublicKey(publicKey: PublicKey, compressed: Boolean): ByteArray {
        return (publicKey as ECPublicKey).q.getEncoded(compressed)
    }

    fun generateDHSecret(privateKey: PrivateKey, publicKeyX: ByteArray, publicKeyY: ByteArray): ByteArray {
        return generateDHSecretUtil(
            getEncodedPrivateKey(privateKey),
            getEncodedPublicKey(
                getPublicKeyFromXandYPoints(
                    publicKeyX,
                    publicKeyY,
                ),
                false
            ),
        )
    }

    fun generateDHSecret(privateKey: ByteArray, publicKeyX: ByteArray, publicKeyY: ByteArray): ByteArray {
        return generateDHSecretUtil(
            privateKey,
            getEncodedPublicKey(
                getPublicKeyFromXandYPoints(
                    publicKeyX,
                    publicKeyY,
                ),
                false
            ),
        )
    }

    fun encryptHandshake(ad: ByteArray, data: ByteArray, key: Key, i: Int): ByteArray {
        val prepareHandshakeResponse: ByteArray = prepareHandshakeResponse(
            byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0),
            prepareByteArray(i, 4)
        )
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, prepareHandshakeResponse))
        cipher.updateAAD(ad)
        return cipher.doFinal(data)
    }

    fun encryptMessage(data: ByteArray, key: Key, i: Int): ByteArray {
        val prepareHandshakeResponse: ByteArray = prepareHandshakeResponse(
            byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0),
            prepareByteArray(i, 4)
        )
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, prepareHandshakeResponse))
        cipher.updateAAD(ByteArray(0))
        return cipher.doFinal(padding(data))
    }

    private fun padding(message: ByteArray): ByteArray {
        val paddingLength: Int
        val messageLength = message.size % 32
        val paddedLength = message.size + (32 - messageLength)
        val paddedBytes = ByteArray(paddedLength)
        System.arraycopy(message, 0, paddedBytes, 0, message.size)
        Arrays.fill(paddedBytes, message.size, paddedLength, 0.toByte())
        paddingLength = paddedBytes.size - 1
        paddedBytes[paddingLength] = (31 - messageLength).toByte()
        return paddedBytes
    }

    fun decryptMessage(data: ByteArray, key: Key, i: Int): ByteArray {
        val prepareHandshakeResponse: ByteArray = prepareHandshakeResponse(
            byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0),
            prepareByteArray(i, 4)
        )
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, prepareHandshakeResponse))
        cipher.updateAAD(ByteArray(0))
        return cipher.doFinal(data)
    }

    private fun prepareHandshakeResponse(bArr: ByteArray, bArr2: ByteArray): ByteArray {
        val bArr3 = ByteArray(bArr.size + bArr2.size)
        System.arraycopy(bArr, 0, bArr3, 0, bArr.size)
        System.arraycopy(bArr2, 0, bArr3, bArr.size, bArr2.size)
        return bArr3
    }

    private fun prepareByteArray(byteArrayInteger: Int, byteArrayLength: Int): ByteArray {
        var i = byteArrayInteger
        val bArr = ByteArray(byteArrayLength)
        var i12 = byteArrayLength - 1
        while (i > 0) {
            bArr[i12] = (i and 255).toByte()
            i = i ushr 8
            i12--
        }
        return bArr
    }

    fun generateHMAC(data: ByteArray, key: ByteArray): ByteArray {
        val mac: Mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }
}

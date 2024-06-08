package ch.bfh.clavertus.authenticator.noise

import ch.bfh.clavertus.authenticator.utils.SessionHandler
import java.security.KeyPair
import javax.crypto.SecretKey
import javax.inject.Inject

@Suppress("detekt:all")
class Handshake @Inject constructor(
    private val sessionHandler: SessionHandler,
) {
    private var noiseState: NoiseState = NoiseState("Noise_KNpsk0_P256_AESGCM_SHA256")

    fun makeQRInitiatedHandshake(
        ephemeralPubKeyBytes: ByteArray,
        encryptedHashedPayload: ByteArray
    ): ByteArray {
        noiseState = NoiseState("Noise_KNpsk0_P256_AESGCM_SHA256")
        val encodedPublicKey: ByteArray = NoiseCryptoUtilities.getEncodedPublicKey(
            NoiseCryptoUtilities.generatePublicKey(
                sessionHandler.getQRPublicKey(),
            ),
            false
        )
        val typeBit = byteArrayOf(1)

        noiseState.mixHash(typeBit, 0, 1)

        noiseState.mixHash(encodedPublicKey, 0, 65)

        noiseState.mixKeyAndHash(sessionHandler.getPSK())

        noiseState.mixHash(ephemeralPubKeyBytes.clone(), 0, 65)

        noiseState.mixKey(ephemeralPubKeyBytes.clone(), 0, 65)

        noiseState.mixHash(
            encryptedHashedPayload.clone(),
            0,
            encryptedHashedPayload.clone().size
        )
        val keyPair: KeyPair = NoiseCryptoUtilities.generateKeyPair("prime256v1")
        val peerPointBytes: ByteArray = concatenateArrays(
            concatenateArrays(
                byteArrayOf(4),
                NoiseCryptoUtilities.getPublicXCoordinateAsByte(keyPair)
            ),
            NoiseCryptoUtilities.getPublicYCoordinateAsByte(keyPair)
        )

        noiseState.mixHash(peerPointBytes, 0, 65)

        noiseState.mixKey(peerPointBytes, 0, 65)
        val privateKey = keyPair.private
        val generateDHSecret: ByteArray = NoiseCryptoUtilities.generateDHSecret(
            privateKey,
            ephemeralPubKeyBytes.copyOfRange(1, 33),
            ephemeralPubKeyBytes.copyOfRange(33, 65)
        )
        noiseState.mixKey(generateDHSecret, 0, generateDHSecret.size)
        val privateKey2 = keyPair.private
        val generateDHSecret2: ByteArray = NoiseCryptoUtilities.generateDHSecret(
            privateKey2,
            encodedPublicKey.copyOfRange(1, 33),
            encodedPublicKey.copyOfRange(33, 65)
        )

        noiseState.mixKey(generateDHSecret2, 0, generateDHSecret2.size)

        val handshakeHash: ByteArray = noiseState.getHandshakeHash()
        val bArr = ByteArray(0)
        val symmetricKey: SecretKey = noiseState.getSymmetricKey()
        val ciphertext: ByteArray =
            NoiseCryptoUtilities.encryptHandshake(handshakeHash, bArr, symmetricKey, 0)

        noiseState.mixHash(ciphertext, 0, ciphertext.size)

        val split: TrafficKeys = noiseState.split()
        sessionHandler.setTrafficReadKey(split.readKey)
        sessionHandler.setTrafficWriteKey(split.writeKey)
        return concatenateArrays(peerPointBytes, ciphertext)
    }

    fun makeStateAssistedHandshake(
        ephemeralPubKeyBytes: ByteArray,
        encryptedHashedPayload: ByteArray
    ): ByteArray {
        this.noiseState = NoiseState("Noise_NKpsk0_P256_AESGCM_SHA256")
        val encodedPublicKey: ByteArray = NoiseCryptoUtilities.getEncodedPublicKey(
            NoiseCryptoUtilities.generatePublicKey(
                sessionHandler.getAuthenticatorPublicKey(),
            ),
            false
        )
        val typeBit = byteArrayOf(0)

        noiseState.mixHash(typeBit, 0, 1)

        noiseState.mixHash(encodedPublicKey, 0, 65)

        noiseState.mixKeyAndHash(sessionHandler.getPSK())

        noiseState.mixHash(ephemeralPubKeyBytes.clone(), 0, 65)

        noiseState.mixKey(ephemeralPubKeyBytes.clone(), 0, 65)

        val generateDHSecret: ByteArray = NoiseCryptoUtilities.generateDHSecret(
            NoiseCryptoUtilities.generatePrivateKey(
                this.sessionHandler.getAuthenticatorPrivateKey(),
            ),
            ephemeralPubKeyBytes.copyOfRange(1, 33),
            ephemeralPubKeyBytes.copyOfRange(33, 65)
        )

        noiseState.mixKey(generateDHSecret, 0, generateDHSecret.size)

        noiseState.mixHash(
            encryptedHashedPayload.clone(),
            0,
            encryptedHashedPayload.clone().size
        )

        val keyPair: KeyPair = NoiseCryptoUtilities.generateKeyPair("prime256v1")
        val peerPointBytes: ByteArray = concatenateArrays(
            concatenateArrays(
                byteArrayOf(4),
                NoiseCryptoUtilities.getPublicXCoordinateAsByte(keyPair)
            ),
            NoiseCryptoUtilities.getPublicYCoordinateAsByte(keyPair)
        )

        noiseState.mixHash(peerPointBytes, 0, 65)

        noiseState.mixKey(peerPointBytes, 0, 65)

        val privateKey2 = keyPair.private
        val generateDHSecret2: ByteArray = NoiseCryptoUtilities.generateDHSecret(
            privateKey2,
            ephemeralPubKeyBytes.copyOfRange(1, 33),
            ephemeralPubKeyBytes.copyOfRange(33, 65)
        )

        noiseState.mixKey(generateDHSecret2, 0, generateDHSecret2.size)

        val handshakeHash: ByteArray = noiseState.getHandshakeHash()
        val bArr = ByteArray(0)
        val symmetricKey: SecretKey = noiseState.getSymmetricKey()
        val ciphertext: ByteArray =
            NoiseCryptoUtilities.encryptHandshake(handshakeHash, bArr, symmetricKey, 0)

        noiseState.mixHash(ciphertext, 0, ciphertext.size)

        val split: TrafficKeys = noiseState.split()
        sessionHandler.setTrafficReadKey(split.readKey)
        sessionHandler.setTrafficWriteKey(split.writeKey)
        return concatenateArrays(peerPointBytes, ciphertext)
    }

    private fun concatenateArrays(first: ByteArray, second: ByteArray): ByteArray {
        return first + second
    }

    fun getHash(): ByteArray {
        val noiseState = this.noiseState
        return noiseState.getHandshakeHash()
    }
}

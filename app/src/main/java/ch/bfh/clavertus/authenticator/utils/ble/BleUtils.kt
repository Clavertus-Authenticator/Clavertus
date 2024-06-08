package ch.bfh.clavertus.authenticator.utils.ble

import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.os.ParcelUuid
import android.util.Log
import ch.bfh.clavertus.authenticator.events.models.BleAdvertParameters
import ch.bfh.clavertus.authenticator.models.hybrid.KeyPurpose
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.SessionHandler
import ch.bfh.clavertus.authenticator.utils.crypto.Cryptography
import java.nio.ByteBuffer
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class BleUtils @Inject constructor(private val sessionHandler: SessionHandler) {
    private var clientNonce: ByteArray = "".toByteArray()
    fun getBleAdvertParameters(qrInitiated: Boolean): BleAdvertParameters {
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
            .setConnectable(true)
            .setTimeout(Constants.TIMEOUT)
            .build()
        val advertData: ByteArray = if (qrInitiated) {
            getQRBLEAdvertData()
        } else {
            getStateBLEAdvertData()
        }

        val data = AdvertiseData.Builder()
            .setIncludeDeviceName(false)
            .setIncludeTxPowerLevel(false)
            .addServiceUuid(ParcelUuid.fromString(Constants.BLE_UUID))
            .addServiceData(
                ParcelUuid.fromString(Constants.BLE_UUID),
                advertData
            )
            .build()

        val advertisingCallback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                Log.i(TAG, "Advertising started: $settingsInEffect")
            }

            override fun onStartFailure(errorCode: Int) {
                Log.e(TAG, "Advertising failed to start: $errorCode")
            }
        }

        return BleAdvertParameters(settings, data, advertisingCallback)
    }

    /**
     * From https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html:
     * Once successfully authenticated and decrypted, a BLE advert yields 16 bytes of plaintext. These 16 bytes consist of (in order):
     * - A flags byte, which is currently zero. This could be used for versioning in the future.
     * - 80 bits of connection nonce.
     * - A 24-bit routing ID.
     * - A 16-bit tunnel service identifier.
     * A candidate BLE advert is valid if the final four bytes are a correct HMAC tag of the other 16 bytes. For each valid BLE advert,
     * those initial 16 bytes are then taken to be an AES block and decrypted with the AES key.
     * **/
    private fun getQRBLEAdvertData(): ByteArray {
        val bleAdvertData = ByteBuffer.allocate(Constants.BLE_ADVERT_LENGTH)
        // first prepare the BLE advert data
        bleAdvertData.position(Constants.FLAG_BYTE_LENGTH) // zero flag-byte
        // create a random connection nonce (size 80 bites)
        val random = SecureRandom()
        val nonce = ByteArray(Constants.CONNECTION_NONCE_LENGTH)
        random.nextBytes(nonce)
        bleAdvertData.put(nonce) // Connection nonce
        bleAdvertData.put(sessionHandler.getRoutingID())
        // The encoded tunnel service identifier is a uint16. Values zero through 255 are assigned,
        // and values >= 256 are translated into a domain name by hashing
        val tunnelServiceIdentifier: Short = Constants.TUNNEL_IDENTIFIER_SHORT // our domain
        bleAdvertData.putShort(tunnelServiceIdentifier)
        /** CTAP 2.2 spec: pre-shared symmetric key is derived from the QR secret and decrypted BLE advert.
         * The full BLE advert is included in the PSK derivation to ensure that any future additions to
         * the advert format are automatically authenticated.
         // derive PSK for QRHandshake*/
        sessionHandler.setPSK(
            Cryptography.deriveKey(
                sessionHandler.getQRSecret(),
                bleAdvertData.array(),
                KeyPurpose.PSK,
                Constants.PSK_LENGTH
            )
        )
        // encrypt and hash it
        // The key used to decrypt adverts is then a 64-byte value derived from the QR secret with keyPurposeEIDKey.
        return Cryptography.encryptAndAddHMAC(
            bleAdvertData.array(),
            Cryptography.deriveKey(
                sessionHandler.getQRSecret(),
                null,
                KeyPurpose.EID_KEY,
                Constants.EID_KEY_LENGTH
            )
        )
    }

    /***
     * From CTAP 2.2 chapter 11.5.2:
     * The authenticator needs two values to start communicating on the tunnel: the link ID so that
     * it knows which client platform is contacting it (and thus which keys to use), and a nonce from
     * the client platform. The latter diversifies the key that encrypts the BLE advert and prevents
     * anyone passively listening from being able the link the advert to any set of link keys retrospectively.
     * The two values are called the “client payload” and are hex-encoded in a X-caBLE-Client-Payload
     * HTTP header.
     *
     */

    private fun getStateBLEAdvertData(): ByteArray {
        val bleAdvertData = ByteBuffer.allocate(Constants.BLE_ADVERT_LENGTH)
        // first prepare the BLE advert data
        bleAdvertData.position(Constants.FLAG_BYTE_LENGTH) // zero flag-byte
        // derive PSK for QRHandshake
        // From CTAP: derive(psk[:], linkData.LinkSecret[:], advertPlaintext[:], keyPurposePSK)
        sessionHandler.setPSK(
            Cryptography.deriveKey(
                sessionHandler.getLinkSecret(),
                bleAdvertData.array(),
                KeyPurpose.PSK,
                Constants.PSK_LENGTH
            )
        )
        // From CTAP: derive(eidKey[:], linkData.LinkSecret[:], clientNonce[:], keyPurposeEIDKey)
        return Cryptography.encryptAndAddHMAC(
            bleAdvertData.array(),
            Cryptography.deriveKey(
                sessionHandler.getLinkSecret(),
                this.clientNonce,
                KeyPurpose.EID_KEY,
                Constants.EID_KEY_LENGTH
            )
        )
    }

    fun setClientNonce(clientNonce: ByteArray) {
        this.clientNonce = clientNonce
    }

    companion object {
        private val TAG = BleUtils::class.java.simpleName
    }
}

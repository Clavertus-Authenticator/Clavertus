package ch.bfh.clavertus.authenticator.viewmodels

import android.Manifest
import android.app.KeyguardManager
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import android.util.Log
import androidx.activity.result.ActivityResult
import androidx.core.app.ActivityCompat
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ch.bfh.clavertus.authenticator.db.LinkCredentialSource
import ch.bfh.clavertus.authenticator.events.Event
import ch.bfh.clavertus.authenticator.events.UIEvent
import ch.bfh.clavertus.authenticator.exceptions.CtapException
import ch.bfh.clavertus.authenticator.models.AuthenticatorGetAssertionInput
import ch.bfh.clavertus.authenticator.models.AuthenticatorMakeCredentialInput
import ch.bfh.clavertus.authenticator.models.Transportation
import ch.bfh.clavertus.authenticator.models.ctap.CtapCommand
import ch.bfh.clavertus.authenticator.models.ctap.CtapStatusCode
import ch.bfh.clavertus.authenticator.models.hybrid.ClientPayload
import ch.bfh.clavertus.authenticator.models.hybrid.KeyPurpose
import ch.bfh.clavertus.authenticator.models.hybrid.LinkData
import ch.bfh.clavertus.authenticator.models.hybrid.MessageType
import ch.bfh.clavertus.authenticator.models.hybrid.QRData
import ch.bfh.clavertus.authenticator.noise.Handshake
import ch.bfh.clavertus.authenticator.noise.MessageUtils
import ch.bfh.clavertus.authenticator.noise.NoiseCryptoUtilities
import ch.bfh.clavertus.authenticator.socket.WebSocketManager
import ch.bfh.clavertus.authenticator.socket.WebSocketMessageListener
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.Constants.FIRST_KEY_LENGTH
import ch.bfh.clavertus.authenticator.utils.Constants.SECOND_KEY_END
import ch.bfh.clavertus.authenticator.utils.SessionHandler
import ch.bfh.clavertus.authenticator.utils.ble.BleUtils
import ch.bfh.clavertus.authenticator.utils.crypto.Cryptography
import ch.bfh.clavertus.authenticator.utils.crypto.HpcUtility
import ch.bfh.clavertus.authenticator.utils.ctap.CtapUtils
import co.nstant.`in`.cbor.CborBuilder
import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.CborEncoder
import co.nstant.`in`.cbor.model.UnsignedInteger
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.launch
import okhttp3.Response
import okio.ByteString
import org.bouncycastle.util.encoders.Hex
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import javax.inject.Inject

@Suppress("LongParameterList")
@HiltViewModel
class HybridViewModel @Inject constructor(
    private val hpcUtility: HpcUtility,
    private val sessionHandler: SessionHandler,
    private val webSocketManager: WebSocketManager,
    private val bleUtils: BleUtils,
    private val messageUtils: MessageUtils,
    private val handshake: Handshake,
    private val bluetoothManager: BluetoothManager,
    @ApplicationContext private val applicationContext: Context
) : ViewModel(), WebSocketMessageListener {

    private val _uiEvent = MutableLiveData<Event<UIEvent>>()
    val uiEvent: LiveData<Event<UIEvent>> = _uiEvent

    private val _connectionStatus = MutableLiveData<Boolean>()
    val connectionStatus: LiveData<Boolean> = _connectionStatus

    init {
        _connectionStatus.value = webSocketManager.isConnected()
    }

    fun registerWebSocketListener() {
        webSocketManager.addListener(this)
    }

    fun deregisterWebSocketListener() {
        webSocketManager.removeListener(this)
    }

    fun processQrCodeAndStoreSessionData(activityResult: ActivityResult) {
        sessionHandler.setTransport(Transportation.HYBRID_QR)
        // process qr code attributes as described in
        // https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hybrid
        val qrFidoString = activityResult.data?.getStringExtra("fido_qr_string")

        if (qrFidoString != null) {
            _uiEvent.postValue(Event(UIEvent.ShowSnackbar("Successfully scanned FIDO QR code!")))
            val qrData = QRData.decodeQRContents(qrFidoString)
            Log.i(TAG, "QR code decoded.")
            // derive tunnel id and save it in session for wss connection -> connectURL
            val tunnelId = Cryptography.deriveKey(
                qrData.qrSecret,
                null,
                KeyPurpose.TUNNEL_ID,
                Constants.TUNNEL_ID_LENGTH
            )
            val routingId = Cryptography.generateRandomByteArray(Constants.ROUTING_ID_LENGTH)

            sessionHandler.setTunnelID(tunnelId)
            sessionHandler.setRoutingID(routingId)
            sessionHandler.setQRSecret(qrData.qrSecret)
            sessionHandler.setQRPublicKey(qrData.publicKey)
        }
    }

    fun setupWSS() {
        // Reset / close old connection first
        sessionHandler.setTrafficReadKey(byteArrayOf())
        sessionHandler.setTrafficWriteKey(byteArrayOf())
        messageUtils.resetCounters()
        webSocketManager.close()
        webSocketManager.connect(sessionHandler.isTransportQR())
    }

    fun sendCTAPMessage(type: MessageType, statusCode: CtapStatusCode, message: ByteArray? = null) {
        val response = byteArrayOf(type.type, statusCode.id) + (message ?: byteArrayOf())
        Log.i(TAG, "Sending ${type.name} ${statusCode.name} message.")
        webSocketManager.send(messageUtils.encryptMessage(response))
    }

    private fun sendUpdateMessage(message: ByteArray) {
        val response = byteArrayOf(MessageType.UPDATE.type) + message
        Log.i(TAG, "Sending ${MessageType.UPDATE.name} message.")
        webSocketManager.send(messageUtils.encryptMessage(response))
    }

    override fun onOpen() {
        _connectionStatus.postValue(true)
        if (sessionHandler.isTransportQR()) {
            startBleAdvertisement(null)
        }
    }

    @Suppress("NestedBlockDepth", "LongMethod", "TooGenericExceptionCaught", "CyclomaticComplexMethod")
    override fun onMessage(byteString: ByteString) {
        val message = byteString.toByteArray()

        try {
            // If we have no traffic keys, we are in the handshake phase
            if (
                sessionHandler.getTrafficReadKey().isEmpty() &&
                sessionHandler.getTrafficWriteKey().isEmpty()
            ) {
                if (sessionHandler.getTransport() == Transportation.IDLE) {
                    sessionHandler.setTransport(Transportation.HYBRID_STATE)
                    startBleAdvertisement(ClientPayload.fromCbor(Hex.decode(message)))
                    return
                }
                Log.i(TAG, "Received handshake message.")
                val handshake = NoiseCryptoUtilities.calculateHandshake(
                    message,
                    this.handshake,
                    sessionHandler.isTransportQR()
                )
                Log.i(TAG, "Sending handshake message.")
                webSocketManager.send(handshake)

                val getInfoResponse = CtapUtils.prepareGetInfoResponse()
                webSocketManager.send(messageUtils.encryptMessage(getInfoResponse))
                if (sessionHandler.isTransportQR()) {
                    val linkData = prepareGetLinkData()
                    sendUpdateMessage(linkData)
                }
                return
            }

            // Now we have an open and encrypted connection and process messages
            val decryptedMessageWithPadding = messageUtils.decryptMessage(message)
            val paddingByte = decryptedMessageWithPadding.last()
            val decryptedMessageLength = decryptedMessageWithPadding.size
            val decryptedMessage =
                decryptedMessageWithPadding.copyOfRange(0, decryptedMessageLength - paddingByte - 1)

            if (decryptedMessage.size == 1 && decryptedMessage.first() == MessageType.SHUTDOWN.type) {
                Log.i(TAG, "Received shutdown message.")
                // shutdown websocket and prepare new connection for state initiated connections
                setupWSS()
            } else if (decryptedMessage.size >= 2 && decryptedMessage.first() == MessageType.CTAP.type) {
                Log.i(TAG, "Received CTAP message.")

                when (decryptedMessage[1]) {
                    CtapCommand.MAKE_CREDENTIAL.id -> {
                        val startRegistration = UIEvent.StartRegistration(
                            AuthenticatorMakeCredentialInput.fromCbor(
                                decryptedMessage.drop(2).toByteArray()
                            )
                        )
                        _uiEvent.postValue(Event(startRegistration))
                    }

                    CtapCommand.GET_ASSERTION.id -> {
                        val startAuthentication = UIEvent.StartAuthentication(
                            AuthenticatorGetAssertionInput.fromCbor(
                                decryptedMessage.drop(2).toByteArray()
                            )
                        )
                        _uiEvent.postValue(
                            Event(startAuthentication)
                        )
                    }

                    CtapCommand.SELECTION.id -> {
                        if (isDeviceUnlocked()) {
                            _uiEvent.postValue(Event(UIEvent.SelectionResult(true)))
                        } else {
                            throw CtapException(CtapStatusCode.CTAP2_ERR_UP_REQUIRED)
                        }
                    }

                    else -> {
                        throw CtapException(CtapStatusCode.CTAP1_ERR_INVALID_COMMAND)
                    }
                }
            } else {
                throw CtapException(CtapStatusCode.CTAP1_ERR_INVALID_COMMAND)
            }
        } catch (e: CtapException) {
            _uiEvent.postValue(Event(UIEvent.CtapException(e.code)))
        }
    }

    override fun onClosed(code: Int, reason: String) {
        _connectionStatus.postValue(false)
    }

    override fun onFailure(t: Throwable, response: Response?) {
        _connectionStatus.postValue(false)
    }

    private fun isDeviceUnlocked(): Boolean {
        val keyguardManager =
            applicationContext.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        // This method returns true if the device is not secure or the lock screen is disabled.
        return keyguardManager.isDeviceSecure.not() || keyguardManager.isKeyguardLocked.not()
    }

    private fun startBleAdvertisement(clientPayload: ClientPayload?) = viewModelScope.launch {
        if (clientPayload != null) {
            bleUtils.setClientNonce(clientPayload.clientNonce)
            sessionHandler.setLinkSecret(hpcUtility.getLinkSecret(clientPayload.linkId))
        }
        val parameters = bleUtils.getBleAdvertParameters(sessionHandler.isTransportQR())
        if (ActivityCompat.checkSelfPermission(
                applicationContext,
                Manifest.permission.BLUETOOTH_ADVERTISE
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            bluetoothManager.adapter?.bluetoothLeAdvertiser?.let { advertiser ->
                Log.i(TAG, "Starting BLE advertising")
                advertiser.startAdvertising(
                    parameters.settings,
                    parameters.data,
                    parameters.callback
                )
            }
                ?: _uiEvent.postValue(Event(UIEvent.ShowSnackbar("Please enable Bluetooth and try again.")))
        } else {
            // This should never happen as we are only allowing QR code scanning if BLE advertising is also allowed
            error("No permission for BLE advertising")
        }
    }

    private fun prepareGetLinkData(): ByteArray {
        val linkCredentialSource = LinkCredentialSource.createNewLink()
        viewModelScope.launch {
            hpcUtility.insertLinkCredentialSource(linkCredentialSource)
        }
        val linkData = LinkData(
            contactId = sessionHandler.getContactId(), // opaque value
            // that can be presented to the
            // tunnel service to identify this authenticator. (For Android this an an FCM registration token.)
            linkId = linkCredentialSource.linkId, // opaque value that identifies this link to the
            // authenticator. This must be sent back to the authenticator when contacting it so that
            // it knows what set of keys to use for this client platform.
            linkSecret = linkCredentialSource.linkSecret, // the “link secret”, a shared secret key.
            authenticatorPublicKey = sessionHandler.getAuthenticatorPublicKey(), // the authenticator's public key,
            // X9.62 uncompressed. This value is global to the authenticator and identifies it.
            // If the same authenticator is used multiple times with a a QR-initiated transaction
            // then this lets the client platform deduplicate the linking information. Desktops may sync
            // linking information using systems like Chrome Sync and this public key prevents a client platform
            // with linking information from impersonating the authenticator to another client platform.
            authenticatorName = "Clavertus installed on " + android.os.Build.MODEL,
            signature = createSignature(),
        )
        val linkDataCbor = linkData.toCbor()

        val input = ByteArrayInputStream(linkDataCbor)
        val dataItems = CborDecoder(input).decode()
        val innerMap = dataItems[0]

        val output = ByteArrayOutputStream()
        CborEncoder(output).encode(
            CborBuilder()
                .addMap()
                .put(UnsignedInteger(1), innerMap)
                .end()
                .build()
        )
        return output.toByteArray()
    }

    private fun createSignature(): ByteArray {
        val encodedQRPublicKey: ByteArray = NoiseCryptoUtilities.getEncodedPublicKey(
            NoiseCryptoUtilities.generatePublicKey(
                sessionHandler.getQRPublicKey(),
            ),
            false
        )
        val dhSecret: ByteArray = NoiseCryptoUtilities.generateDHSecret(
            sessionHandler.getAuthenticatorPrivateKey(),
            encodedQRPublicKey.copyOfRange(1, FIRST_KEY_LENGTH),
            encodedQRPublicKey.copyOfRange(FIRST_KEY_LENGTH, SECOND_KEY_END)
        )
        return NoiseCryptoUtilities.generateHMAC(this.handshake.getHash(), dhSecret)
    }

    companion object {
        private val TAG = HybridViewModel::class.java.simpleName
    }
}

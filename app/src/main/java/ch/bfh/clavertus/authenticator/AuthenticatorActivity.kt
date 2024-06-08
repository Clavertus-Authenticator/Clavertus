package ch.bfh.clavertus.authenticator

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.Menu
import android.view.MenuItem
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.constraintlayout.widget.ConstraintLayout
import ch.bfh.clavertus.R
import ch.bfh.clavertus.authenticator.events.UIEvent
import ch.bfh.clavertus.authenticator.models.AuthenticatorGetAssertionInput
import ch.bfh.clavertus.authenticator.models.AuthenticatorMakeCredentialInput
import ch.bfh.clavertus.authenticator.models.Transportation
import ch.bfh.clavertus.authenticator.models.ctap.CtapStatusCode
import ch.bfh.clavertus.authenticator.models.hybrid.MessageType
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.SessionHandler
import ch.bfh.clavertus.authenticator.viewmodels.AuthenticatorViewModel
import ch.bfh.clavertus.authenticator.viewmodels.HybridViewModel
import ch.bfh.clavertus.client.ClientActivity
import com.google.android.material.snackbar.Snackbar
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class AuthenticatorActivity : AppCompatActivity() {
    @Inject
    lateinit var sessionHandler: SessionHandler

    private val viewModel: AuthenticatorViewModel by viewModels()
    private val hybridViewModel: HybridViewModel by viewModels()

    private lateinit var webSocketLabel: TextView
    private lateinit var scanQRCode: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_authenticator)
        setSupportActionBar(findViewById(R.id.toolbar))
        webSocketLabel = findViewById<TextView>(R.id.wss_connected)
        initializeUi()
        initializeActivityResultContracts()
        prepareLiveDataListener()
        viewModel.ensureAuthenticatorKeyPresence()
        hybridViewModel.registerWebSocketListener()
        sessionHandler.setTransport(Transportation.IDLE)
        hybridViewModel.setupWSS()
        processIntents()
    }

    override fun onDestroy() {
        super.onDestroy()
        hybridViewModel.deregisterWebSocketListener()
    }

    private fun initializeUi() {
        setupButton(R.id.btn_qr) {
            scanQRCode.launch(Intent(this, CameraActivity::class.java))
        }
        setupButton(R.id.btn_showKeys) {
            val intent = Intent(this, AuthenticatorShowKeysActivity::class.java)
            startActivity(intent)
        }
    }

    private fun initializeActivityResultContracts() {
        scanQRCode =
            registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res: ActivityResult ->
                if (res.resultCode == Activity.RESULT_OK) {
                    hybridViewModel.processQrCodeAndStoreSessionData(res)
                    hybridViewModel.setupWSS()
                }
            }
    }

    private fun prepareLiveDataListener() {
        viewModel.uiEvent.observe(this) { event ->
            event.getContentIfNotHandled()?.let { uiEvent ->
                handleUiEvent(uiEvent)
            }
        }
        hybridViewModel.uiEvent.observe(this) { event ->
            event.getContentIfNotHandled()?.let { uiEvent ->
                handleUiEvent(uiEvent)
            }
        }
        hybridViewModel.connectionStatus.observe(this) { isConnected ->
            webSocketLabel.text = if (isConnected) "WebSocket connected" else "WebSocket disconnected"
        }
    }

    private fun handleUiEvent(event: UIEvent) {
        when (event) {
            is UIEvent.StartRegistration -> {
                viewModel.register(event.data, this)
            }

            is UIEvent.RegistrationResult -> {
                if (sessionHandler.getTransport() == Transportation.INTERNAL) {
                    val data = Intent()
                    data.putExtra("attestationObject", event.data)
                    setResult(RESULT_OK, data)
                    finish()
                }
                if (sessionHandler.getTransport() == Transportation.HYBRID_QR ||
                    sessionHandler.getTransport() == Transportation.HYBRID_STATE
                ) {
                    hybridViewModel.sendCTAPMessage(
                        MessageType.CTAP,
                        CtapStatusCode.CTAP2_OK,
                        event.data
                    )
                }
                sessionHandler.setTransport(Transportation.IDLE)
            }

            is UIEvent.StartAuthentication -> {
                viewModel.authenticate(event.data, this)
            }

            is UIEvent.AuthenticationResult -> {
                if (sessionHandler.getTransport() == Transportation.INTERNAL) {
                    val data = Intent()
                    data.putExtra("authenticatorResponse", event.data)
                    setResult(RESULT_OK, data)
                    finish()
                }
                if (sessionHandler.getTransport() == Transportation.HYBRID_QR ||
                    sessionHandler.getTransport() == Transportation.HYBRID_STATE
                ) {
                    hybridViewModel.sendCTAPMessage(
                        MessageType.CTAP,
                        CtapStatusCode.CTAP2_OK,
                        event.data
                    )
                }
                sessionHandler.setTransport(Transportation.IDLE)
            }

            is UIEvent.SelectionResult -> {
                hybridViewModel.sendCTAPMessage(MessageType.CTAP, CtapStatusCode.CTAP2_OK)
            }

            is UIEvent.CtapException -> {
                hybridViewModel.sendCTAPMessage(MessageType.CTAP, event.code)
                sessionHandler.setTransport(Transportation.IDLE)
            }

            is UIEvent.ShowSnackbar -> {
                showSnackbar(event.message)
            }
        }
    }

    // Only used by the demo client at the moment. Needs refactoring
    private fun prepareAuthentication(intent: Intent) {
        Log.i(TAG, "--Start authentication--")
        val authenticatorGetAssertionInput =
            intent.getByteArrayExtra("publicKey")
                ?.let { AuthenticatorGetAssertionInput.fromCbor(it) }
        viewModel.authenticate(authenticatorGetAssertionInput, this)
    }

    private fun deregister() {
        Log.i(TAG, "--Start deregistration--")
        val keyId = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getSerializableExtra("publicKey2delete", ByteArray::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getSerializableExtra("publicKey2delete") as ByteArray
        }
        viewModel.deleteKey(keyId)
        setResult(RESULT_OK)
        finish()
    }

    private fun setupButton(buttonId: Int, action: () -> Unit) {
        findViewById<Button>(buttonId).setOnClickListener { action() }
    }

    private fun showSnackbar(message: String) {
        val layout = findViewById<ConstraintLayout>(R.id.authenticator)
        Snackbar.make(layout, message, Snackbar.LENGTH_LONG).show()
    }

    private fun processIntents() {
        when (intent.action) {
            Constants.FidoActions.REGISTER_FIDO -> {
                sessionHandler.setTransport(Transportation.INTERNAL)
                viewModel.register(
                    intent.getByteArrayExtra("publicKey")
                        ?.let {
                            AuthenticatorMakeCredentialInput.fromCbor(
                                it
                            )
                        },
                    this
                )
            }

            Constants.FidoActions.AUTHENTICATE_FIDO -> {
                sessionHandler.setTransport(Transportation.INTERNAL)
                prepareAuthentication(intent)
            }

            Constants.FidoActions.DEREGISTER_FIDO -> deregister()
        }
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_authenticator, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> {
                val intent = Intent(this, AuthenticatorSettingsActivity::class.java)
                startActivity(intent)
                true
            }

            R.id.action_client -> {
                val intent = Intent(this, ClientActivity::class.java)
                startActivity(intent)
                finish()
                return true
            }

            else -> super.onOptionsItemSelected(item)
        }
    }

    companion object {
        private val TAG = AuthenticatorActivity::class.java.simpleName
    }
}

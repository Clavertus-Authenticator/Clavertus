package ch.bfh.clavertus.client

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.Menu
import android.view.MenuItem
import android.widget.Button
import android.widget.EditText
import androidx.activity.result.ActivityResult
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.constraintlayout.widget.ConstraintLayout
import ch.bfh.clavertus.R
import ch.bfh.clavertus.authenticator.AuthenticatorActivity
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.SessionHandler
import ch.bfh.clavertus.client.viewmodels.ClientViewModel
import com.google.android.material.snackbar.Snackbar
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class ClientActivity : AppCompatActivity() {
    @Inject
    lateinit var sessionHandler: SessionHandler

    private val viewModel: ClientViewModel by viewModels()

    private lateinit var registerCredentialResult: ActivityResultLauncher<Intent>
    private lateinit var authenticateRequestResult: ActivityResultLauncher<Intent>
    private lateinit var deregisterCredentialResult: ActivityResultLauncher<Intent>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_client)
        setSupportActionBar(findViewById(R.id.toolbar))
        initializeUi()
        initializeActivityResultContracts()

        viewModel.snackbarQueue.observe(this) { event ->
            event.getContentIfNotHandled()?.let { message ->
                showSnackbar(message)
            }
        }
    }

    private fun initializeUi() {
        // default-values
        sessionHandler.setRequestId("".toByteArray())
        sessionHandler.setSessionToken("".toByteArray())
        val txtUsername = findViewById<EditText>(R.id.txt_username)
        txtUsername.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) =
                Unit

            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) =
                Unit

            override fun afterTextChanged(s: Editable?) {
                // change to default values for new username
                sessionHandler.setRequestId("".toByteArray())
                sessionHandler.setSessionToken("".toByteArray())
                sessionHandler.setCredentialID("".toByteArray())
            }
        })
        setupButton(R.id.btn_register) {
            viewModel.sendRegistrationBegin(txtUsername.text.toString())
        }
        setupButton(R.id.btn_authenticate) {
            viewModel.sendAuthenticationBegin(txtUsername.text.toString())
        }
        setupButton(R.id.btn_deregister) {
            viewModel.sendDeregistration()
        }
    }

    private fun initializeActivityResultContracts() {
        registerCredentialResult =
            registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res: ActivityResult ->
                if (res.resultCode == Activity.RESULT_OK) {
                    viewModel.sendRegistrationComplete(res)
                }
            }
        authenticateRequestResult =
            registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res: ActivityResult ->
                if (res.resultCode == Activity.RESULT_OK) {
                    viewModel.sendAuthenticationComplete(res)
                }
            }
        deregisterCredentialResult =
            registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res: ActivityResult ->
                if (res.resultCode == Activity.RESULT_OK) {
                    showSnackbar("Deregistration was successful!")
                    // default-values
                    sessionHandler.setCredentialID("".toByteArray())
                    sessionHandler.setSessionToken("".toByteArray())
                }
            }
        viewModel.launchRegisterActivity.observe(this) { event ->
            event.getContentIfNotHandled()?.let { publicKeyCredentialCreationOptions ->
                val intent = Intent(applicationContext, AuthenticatorActivity::class.java)
                intent.setAction(Constants.FidoActions.REGISTER_FIDO)
                intent.putExtra("publicKey", publicKeyCredentialCreationOptions)
                registerCredentialResult.launch(intent)
            }
        }

        viewModel.launchAuthenticateActivity.observe(this) { event ->
            event.getContentIfNotHandled()?.let { publicKeyCredentialRequestOptions ->
                val intent = Intent(applicationContext, AuthenticatorActivity::class.java)
                intent.setAction(Constants.FidoActions.AUTHENTICATE_FIDO)
                intent.putExtra("publicKey", publicKeyCredentialRequestOptions)
                authenticateRequestResult.launch(intent)
            }
        }

        viewModel.launchDeregisterActivity.observe(this) { event ->
            event.getContentIfNotHandled()?.let { credentialId ->
                val intent = Intent(applicationContext, AuthenticatorActivity::class.java)
                intent.setAction(Constants.FidoActions.DEREGISTER_FIDO)
                intent.putExtra("publicKey2delete", credentialId)
                deregisterCredentialResult.launch(intent)
            }
        }
    }

    private fun showSnackbar(message: String) {
        val layout = findViewById<ConstraintLayout>(R.id.layout)
        Snackbar.make(layout, message, Snackbar.LENGTH_LONG).show()
    }

    private fun setupButton(buttonId: Int, action: () -> Unit) {
        findViewById<Button>(buttonId).setOnClickListener { action() }
    }

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        // Inflate the menu; this adds items to the action bar if it is present.
        menuInflater.inflate(R.menu.menu_demo_client, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        return when (item.itemId) {
            R.id.action_settings -> {
                val intent = Intent(this, ClientSettingsActivity::class.java)
                startActivity(intent)
                true
            }
            R.id.action_authenticator -> {
                val intent = Intent(this, AuthenticatorActivity::class.java)
                startActivity(intent)
                finish()
                true
            }

            else -> super.onOptionsItemSelected(item)
        }
    }
}

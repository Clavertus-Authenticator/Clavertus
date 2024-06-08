package ch.bfh.clavertus.authenticator.viewmodels

import android.util.Log
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ch.bfh.clavertus.authenticator.db.LinkCredentialSource
import ch.bfh.clavertus.authenticator.db.PublicKeyCredentialSource
import ch.bfh.clavertus.authenticator.events.Event
import ch.bfh.clavertus.authenticator.events.UIEvent
import ch.bfh.clavertus.authenticator.exceptions.CtapException
import ch.bfh.clavertus.authenticator.models.AttestationStatement
import ch.bfh.clavertus.authenticator.models.AuthenticatorGetAssertionInput
import ch.bfh.clavertus.authenticator.models.AuthenticatorGetAssertionResponse
import ch.bfh.clavertus.authenticator.models.AuthenticatorMakeCredentialInput
import ch.bfh.clavertus.authenticator.models.AuthenticatorMakeCredentialResponse
import ch.bfh.clavertus.authenticator.models.PublicKeyCredentialDescriptor
import ch.bfh.clavertus.authenticator.models.PublicKeyCredentialType
import ch.bfh.clavertus.authenticator.models.PublicKeyCredentialUserEntity
import ch.bfh.clavertus.authenticator.models.ctap.CtapStatusCode
import ch.bfh.clavertus.authenticator.noise.NoiseCryptoUtilities
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.Constants.CONTACT_ID_LENGTH
import ch.bfh.clavertus.authenticator.utils.SessionHandler
import ch.bfh.clavertus.authenticator.utils.builder.AttestationObjectBuilder
import ch.bfh.clavertus.authenticator.utils.builder.AuthenticatorDataBuilder
import ch.bfh.clavertus.authenticator.utils.crypto.HpcUtility
import ch.bfh.clavertus.authenticator.utils.signer.Signer
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import java.nio.ByteBuffer
import java.security.SignatureException
import javax.inject.Inject

@HiltViewModel
class AuthenticatorViewModel @Inject constructor(
    private val hpcUtility: HpcUtility,
    private val authenticatorDataBuilder: AuthenticatorDataBuilder,
    private val attestationObjectBuilder: AttestationObjectBuilder,
    private val signer: Signer,
    private val sessionHandler: SessionHandler,
) : ViewModel() {

    private val _uiEvent = MutableLiveData<Event<UIEvent>>()
    val uiEvent: LiveData<Event<UIEvent>> = _uiEvent

    fun register(
        authenticatorMakeCredentialInput: AuthenticatorMakeCredentialInput?,
        fragmentActivity: FragmentActivity
    ) {
        viewModelScope.launch {
            initiateRegistration(authenticatorMakeCredentialInput, fragmentActivity)
        }
    }

    fun authenticate(
        authenticatorGetAssertionInput: AuthenticatorGetAssertionInput?,
        fragmentActivity:
        FragmentActivity
    ) {
        try {
            viewModelScope.launch {
                initializeAuthentication(authenticatorGetAssertionInput, fragmentActivity)
            }
        } catch (e: SignatureException) {
            _uiEvent.postValue(Event(UIEvent.ShowSnackbar(e.message ?: "Error signing data")))
        } catch (e: IllegalArgumentException) {
            _uiEvent.postValue(Event(UIEvent.ShowSnackbar(e.message ?: "Error signing data")))
        }
    }

    fun deleteKey(keyId: ByteArray?) {
        viewModelScope.launch {
            keyId?.let {
                hpcUtility.deleteKey(hpcUtility.getKeyForId(it))
            }
        }
    }

    fun ensureAuthenticatorKeyPresence() {
        viewModelScope.launch {
            if (sessionHandler.getAuthenticatorPublicKey().isEmpty()) {
                val keyPair = NoiseCryptoUtilities.generateKeyPair("prime256v1")
                sessionHandler.setAuthenticatorPublicKey(
                    NoiseCryptoUtilities.getEncodedPublicKey(
                        keyPair.public,
                        false
                    )
                )
                sessionHandler.setAuthenticatorPrivateKey(
                    NoiseCryptoUtilities.getEncodedPrivateKey(
                        keyPair.private
                    )
                )
                sessionHandler.setContactId(LinkCredentialSource.generateRandomBytes(CONTACT_ID_LENGTH))
            }
        }
    }

    private suspend fun initiateRegistration(
        authenticatorMakeCredentialInput: AuthenticatorMakeCredentialInput?,
        fragmentActivity: FragmentActivity
    ) {
        Log.i(TAG, "-- Start registration --")
        if (authenticatorMakeCredentialInput != null) {
            if (authenticatorMakeCredentialInput.keyCredParamsContain(
                    PublicKeyCredentialType.PUBLIC_KEY.type,
                    Constants.Crypto.ES256_SIG_ALGORITHM.toInt()
                ) || (
                    authenticatorMakeCredentialInput.keyCredParamsContain(
                        PublicKeyCredentialType.PUBLIC_KEY.type,
                        Constants.Crypto.RS256.toInt()
                    )
                    )
            ) {
                // create a new key-pair
                val publicKeyCredentialSource = hpcUtility.register(
                    authenticatorMakeCredentialInput.clientDataHash,
                    authenticatorMakeCredentialInput.rp.id,
                    authenticatorMakeCredentialInput.user.id,
                    authenticatorMakeCredentialInput.user.name,
                    authenticatorMakeCredentialInput.user.displayName,
                    userConfirmationRequired = false,
                    isPasskey = authenticatorMakeCredentialInput.options?.discoverableCredential
                        ?: false
                )

                try {
                    val attestationStatement = attestationObjectBuilder.getAttestationStatement(
                        authenticatorMakeCredentialInput.clientDataHash,
                        fragmentActivity,
                        publicKeyCredentialSource
                    )
                    val authData = attestationObjectBuilder.getAuthData()

                    finishRegistration(
                        attestationStatement,
                        authData
                    )
                } catch (e: SignatureException) {
                    _uiEvent.postValue(
                        Event(
                            UIEvent.ShowSnackbar(
                                e.message ?: "Error signing data"
                            )
                        )
                    )
                    _uiEvent.postValue(Event(UIEvent.CtapException(CtapStatusCode.CTAP2_ERR_UV_INVALID)))
                } catch (e: IllegalArgumentException) {
                    _uiEvent.postValue(
                        Event(
                            UIEvent.ShowSnackbar(
                                e.message ?: "Error signing data"
                            )
                        )
                    )
                    _uiEvent.postValue(Event(UIEvent.CtapException(CtapStatusCode.CTAP2_ERR_UV_INVALID)))
                }
            } else {
                throw CtapException(CtapStatusCode.CTAP2_ERR_UNSUPPORTED_ALGORITHM)
            }
        }
    }

    private fun finishRegistration(
        attestationStatement: AttestationStatement,
        authData: ByteArray
    ) {
        val authenticatorMakeCredentialResponse = AuthenticatorMakeCredentialResponse(
            Constants.ATTESTATION_FORMAT,
            authData,
            attestationStatement,
        ).toCbor()

        _uiEvent.postValue(Event(UIEvent.RegistrationResult(authenticatorMakeCredentialResponse)))
    }

    private suspend fun initializeAuthentication(
        authenticatorGetAssertionInput: AuthenticatorGetAssertionInput?,
        fragmentActivity: FragmentActivity,
        pkcs7Signature: String? = null
    ) {
        if (authenticatorGetAssertionInput == null) {
            // ToDo this should not be optional. Fail earlier.
            return
        }

        val selectedCredential = getKeyForAssertion(
            authenticatorGetAssertionInput.rpId,
            authenticatorGetAssertionInput.allowList.orEmpty() // Passkey has no allowList
        )

        if (selectedCredential != null) {
            hpcUtility.incrementCredentialUseCounter(selectedCredential)
        }

        val authenticatorData =
            selectedCredential?.let {
                authenticatorDataBuilder.calculateAuthenticatorData(
                    it,
                    pkcs7Signature,
                    false
                )
            }

        authenticatorData?.let {
            try {
                val signature = signer.sign(
                    Constants.FidoActions.AUTHENTICATE_FIDO,
                    it,
                    authenticatorGetAssertionInput.clientDataHash,
                    fragmentActivity,
                    selectedCredential.keyPairAlias,
                    selectedCredential.requiresAuthentication,
                    selectedCredential.rpId,
                    selectedCredential.userDisplayName.ifEmpty { selectedCredential.userName }
                )
                finishAuthentication(
                    it,
                    signature,
                    selectedCredential,
                )
            } catch (e: SignatureException) {
                _uiEvent.postValue(Event(UIEvent.ShowSnackbar(e.message ?: "Error signing data")))
                _uiEvent.postValue(Event(UIEvent.CtapException(CtapStatusCode.CTAP2_ERR_UV_INVALID)))
            } catch (e: IllegalArgumentException) {
                _uiEvent.postValue(Event(UIEvent.ShowSnackbar(e.message ?: "Error signing data")))
                _uiEvent.postValue(Event(UIEvent.CtapException(CtapStatusCode.CTAP2_ERR_UV_INVALID)))
            }
        }
    }

    private fun finishAuthentication(
        authenticatorData: ByteArray,
        signature: ByteArray,
        selectedCredential: PublicKeyCredentialSource
    ) {
        val authenticatorGetAssertionResult = AuthenticatorGetAssertionResponse(
            PublicKeyCredentialDescriptor(
                selectedCredential.id,
                PublicKeyCredentialType.PUBLIC_KEY.type
            ),
            authenticatorData,
            signature,
            PublicKeyCredentialUserEntity(
                selectedCredential.userIDFromRP,
                selectedCredential.userName,
                selectedCredential.userDisplayName
            ),
        ).toCbor()

        _uiEvent.postValue(Event(UIEvent.AuthenticationResult(authenticatorGetAssertionResult)))
    }

    private suspend fun getKeyForAssertion(
        rpId: String,
        publicKeyCredentialDescriptors: List<PublicKeyCredentialDescriptor>
    ): PublicKeyCredentialSource? {
        var credentials = hpcUtility.getKeysForEntity(rpId)
        credentials = if (publicKeyCredentialDescriptors.isNotEmpty()) {
            val filteredCredentials: MutableList<PublicKeyCredentialSource> = ArrayList()
            val allowedCredentialIds: MutableSet<ByteBuffer> = HashSet()
            for (allowCredential in publicKeyCredentialDescriptors) {
                allowedCredentialIds.add(ByteBuffer.wrap(allowCredential.id))
            }
            for (credential in credentials) {
                if (allowedCredentialIds.contains(ByteBuffer.wrap(credential.id))) {
                    filteredCredentials.add(credential)
                }
            }
            filteredCredentials
        } else {
            credentials.filter { it.isPasskey }
        }
        if (credentials.isEmpty()) {
            Log.e(TAG, "No credentials for this RpId exist")
            return null
            // ToDo handle
            // Show message. This authenticator has no credentials for this RP.
        }
        // There is only one credential per user/RP allowed
        if (credentials.size != 1) {
            Log.e(TAG, "Too many credentials are stored for the user! Will just use the first one.")
            // ToDo handle
            // for non-discoverable credentials, it should not be possible to have more than one credential per user
            // for passkeys we need to handle this case by providing a selection dialog (via the browser. see CTAP spec)
        }
        return credentials[0]
    }

    companion object {
        private val TAG = AuthenticatorViewModel::class.java.simpleName
    }
}

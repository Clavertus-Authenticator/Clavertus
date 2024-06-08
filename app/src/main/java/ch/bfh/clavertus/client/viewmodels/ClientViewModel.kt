package ch.bfh.clavertus.client.viewmodels

import android.content.SharedPreferences
import android.util.Log
import androidx.activity.result.ActivityResult
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import ch.bfh.clavertus.authenticator.events.Event
import ch.bfh.clavertus.authenticator.models.AuthenticatorGetAssertionInput
import ch.bfh.clavertus.authenticator.models.AuthenticatorGetAssertionResponse
import ch.bfh.clavertus.authenticator.models.AuthenticatorMakeCredentialInput
import ch.bfh.clavertus.authenticator.models.AuthenticatorMakeCredentialResponse
import ch.bfh.clavertus.authenticator.models.PublicKeyCredentialDescriptor
import ch.bfh.clavertus.authenticator.models.PublicKeyCredentialType
import ch.bfh.clavertus.authenticator.models.PublicKeyCredentialUserEntity
import ch.bfh.clavertus.authenticator.modules.RegularPreferences
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.SessionHandler
import ch.bfh.clavertus.authenticator.utils.getDemoBackendUrl
import ch.bfh.clavertus.client.models.AuthBeginResponse
import ch.bfh.clavertus.client.models.AuthCompletePostData
import ch.bfh.clavertus.client.models.ClientData
import ch.bfh.clavertus.client.models.DeregisterResponse
import ch.bfh.clavertus.client.models.FinishResponse
import ch.bfh.clavertus.client.models.PublicKeyCredential
import ch.bfh.clavertus.client.models.PublickeyCredentialAuth
import ch.bfh.clavertus.client.models.RegBeginResponse
import ch.bfh.clavertus.client.models.RegCompletePostData
import ch.bfh.clavertus.client.models.cbor.AuthenticatorGetAssertionResponseClientFormat
import ch.bfh.clavertus.client.models.cbor.AuthenticatorMakeCredentialResponseClientFormat
import ch.bfh.clavertus.client.utils.Communication
import ch.bfh.clavertus.client.utils.toBase64String
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import okhttp3.FormBody
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import javax.inject.Inject

@HiltViewModel
class ClientViewModel @Inject constructor(
    @RegularPreferences private val preferences: SharedPreferences,
    private val sessionHandler: SessionHandler,
    private val communication: Communication,
) : ViewModel() {

    private val _snackbarQueue = MutableLiveData<Event<String>>()
    val snackbarQueue: LiveData<Event<String>> = _snackbarQueue

    private val _launchRegisterActivity = MutableLiveData<Event<ByteArray>>()
    val launchRegisterActivity: LiveData<Event<ByteArray>> = _launchRegisterActivity

    private val _launchAuthenticateActivity = MutableLiveData<Event<ByteArray>>()
    val launchAuthenticateActivity: LiveData<Event<ByteArray>> = _launchAuthenticateActivity

    private val _launchDeregisterActivity = MutableLiveData<Event<ByteArray>>()
    val launchDeregisterActivity: LiveData<Event<ByteArray>> = _launchDeregisterActivity

    @Suppress("LongMethod")
    fun sendRegistrationBegin(username: String) = viewModelScope.launch {
        Log.i(TAG, "Send register-begin Post.")
        val requestBody = FormBody.Builder()
            .add("username", username)
            .add("displayName", username)
            .add("credentialNickname", username)
            .add("requireResidentKey", "false")
            .add("sessionToken", "null")
            .build()

        Log.i(TAG, requestBody.toString())
        val request = Request.Builder()
            .url("${preferences.getDemoBackendUrl()}/api/v1/register")
            .post(requestBody)
            .build()

        communication.makeNetworkRequest(
            request,
            Constants.FidoActions.REGISTER_FIDO
        ).onSuccess { networkResult ->
            Log.i(TAG, networkResult.responseBody)
            val regBeginResponse = RegBeginResponse.fromJSON(networkResult.responseBody)
            if (regBeginResponse.request.publicKeyCredentialCreationOptions.areWellFormed()) {
                sessionHandler.setRequestId(regBeginResponse.request.requestId)
                sessionHandler.setSessionToken(regBeginResponse.request.sessionToken)
                val clientData = ClientData(
                    regBeginResponse.request.publicKeyCredentialCreationOptions.challenge,
                    "https://${regBeginResponse.request.publicKeyCredentialCreationOptions.rp.id}:8443",
                    "webauthn.create"
                )
                sessionHandler.setClientData(clientData.getBase64UrlEncodedJson())
                val data = AuthenticatorMakeCredentialInput(
                    clientData.getHash(),
                    AuthenticatorMakeCredentialInput.PublicKeyCredentialRpEntity(
                        regBeginResponse.request.publicKeyCredentialCreationOptions.rp.id,
                        regBeginResponse.request.publicKeyCredentialCreationOptions.rp.name
                    ),
                    PublicKeyCredentialUserEntity(
                        regBeginResponse.request.publicKeyCredentialCreationOptions.user.id,
                        regBeginResponse.request.publicKeyCredentialCreationOptions.user.name,
                        regBeginResponse.request.publicKeyCredentialCreationOptions.user.displayName
                    ),
                    regBeginResponse.request.publicKeyCredentialCreationOptions
                        .pubKeyCredParams.map {
                            AuthenticatorMakeCredentialInput.PublicKeyCredentialParameters(
                                it.alg,
                                it.type
                            )
                        },
                    regBeginResponse.request.publicKeyCredentialCreationOptions
                        .excludeCredentials.map { PublicKeyCredentialDescriptor(it.id, it.type) },
                    null,
                    null
                )

                _launchRegisterActivity.postValue(
                    Event(data.toCbor())
                )
            } else {
                Log.e(TAG, "Response isn't well formed!")
                _snackbarQueue.postValue(Event("Response isn't well formed!"))
            }
        }.onFailure { exception ->
            Log.e(TAG, "Error on ${Constants.FidoActions.REGISTER_FIDO}: ${exception.message}")
            _snackbarQueue.postValue(Event("Error on ${Constants.FidoActions.REGISTER_FIDO}: ${exception.message}"))
        }
    }

    fun sendRegistrationComplete(activityResult: ActivityResult) = viewModelScope.launch {
        val attestationObjectCbor = activityResult.data?.getByteArrayExtra("attestationObject")
        requireNotNull(attestationObjectCbor) { "attestationObject is null" }

        // (╯°□°）╯︵ ┻━┻
        val attestationObject = AuthenticatorMakeCredentialResponse.fromCbor(attestationObjectCbor)
        val attestationObjectClientFormat = AuthenticatorMakeCredentialResponseClientFormat(
            attestationObject.fmt,
            attestationObject.authData,
            attestationObject.attStmt
        )

        val startIndex = Constants.RP_ID_HASH_LENGTH + Constants.FLAGS_LENGTH + Constants.SIGN_COUNT_LENGTH +
            Constants.AAGUID_LENGTH + Constants.CREDENTIAL_ID_LENGTH
        val credentialId = attestationObject.authData.copyOfRange(startIndex, startIndex + Constants.BYTE_32)

        val publicKeyCredential = PublicKeyCredential(
            PublicKeyCredentialType.PUBLIC_KEY.type,
            credentialId,
            credentialId,
            PublicKeyCredential.AuthenticatorRegisterResult(
                sessionHandler.getClientData(),
                attestationObjectClientFormat.toCbor(),
                mutableListOf("internal")
            )
        )

        val response = RegCompletePostData(
            publicKeyCredential,
            sessionHandler.getRequestId(),
            sessionHandler.getSessionToken()
        )

        val regCompletePostDataJson = response.toJson()
        Log.d(TAG, "Client Registration Response: $regCompletePostDataJson")

        val request = Request.Builder()
            .url("${preferences.getDemoBackendUrl()}/api/v1/register/finish")
            .post(regCompletePostDataJson.toRequestBody("application/json".toMediaTypeOrNull()))
            .build()

        communication.makeNetworkRequest(
            request,
            Constants.FidoActions.REGISTER_FIDO
        ).onSuccess { networkResult ->
            Log.i(TAG, networkResult.responseBody)
            val success = FinishResponse.fromJSON(networkResult.responseBody)
            sessionHandler.setCredentialID(success.response.credential.id)
            _snackbarQueue.postValue(Event("Registration is: $success"))
        }.onFailure { exception ->
            Log.e(TAG, "Error on ${Constants.FidoActions.REGISTER_FIDO}: ${exception.message}")
            _snackbarQueue.postValue(Event("Error on ${Constants.FidoActions.REGISTER_FIDO}: ${exception.message}"))
        }
    }

    fun sendAuthenticationBegin(username: String) = viewModelScope.launch {
        Log.i(TAG, "Send authenticate-begin-Post.")
        val requestBody = FormBody.Builder()
            .add("username", username)
            .build()
        val request = Request.Builder()
            .url("${preferences.getDemoBackendUrl()}/api/v1/authenticate")
            .post(requestBody)
            .build()

        communication.makeNetworkRequest(request, Constants.FidoActions.AUTHENTICATE_FIDO)
            .onSuccess { networkResult ->
                val authBeginResponse = AuthBeginResponse.fromJSON(networkResult.responseBody)
                sessionHandler.setRequestId(authBeginResponse.request.requestId)

                val clientData = ClientData(
                    authBeginResponse.request.publicKeyCredentialRequestOptions.challenge,
                    "https://${authBeginResponse.request.publicKeyCredentialRequestOptions.rpId}:8443",
                    "webauthn.get"
                )
                sessionHandler.setClientData(clientData.getBase64UrlEncodedJson())

                val data = AuthenticatorGetAssertionInput(
                    authBeginResponse.request.publicKeyCredentialRequestOptions.rpId,
                    clientData.getHash(),
                    authBeginResponse.request.publicKeyCredentialRequestOptions.allowCredentials.map {
                        PublicKeyCredentialDescriptor(it.id, it.type)
                    },
                    null
                )

                _launchAuthenticateActivity.postValue(
                    Event(data.toCbor())
                )
            }.onFailure { exception ->
                Log.e(TAG, "Error on ${Constants.FidoActions.AUTHENTICATE_FIDO}: ${exception.message}")
                _snackbarQueue.postValue(
                    Event("Error on ${Constants.FidoActions.AUTHENTICATE_FIDO}: ${exception.message}")
                )
            }
    }

    fun sendAuthenticationComplete(activityResult: ActivityResult) = viewModelScope.launch {
        val authenticatorResponseCbor = activityResult.data?.getByteArrayExtra("authenticatorResponse")
        requireNotNull(authenticatorResponseCbor) { "authenticatorResponse is null" }

        // (╯°□°）╯︵ ┻━┻
        val authenticatorResponse = AuthenticatorGetAssertionResponse.fromCbor(authenticatorResponseCbor)
        val authenticatorResponseClientFormat = AuthenticatorGetAssertionResponseClientFormat(
            authenticatorResponse.credential,
            authenticatorResponse.authData,
            authenticatorResponse.signature,
        )

        val response = AuthCompletePostData(
            PublickeyCredentialAuth(
                PublickeyCredentialAuth.AuthenticatorGetAssertionResult(
                    sessionHandler.getClientData(),
                    authenticatorResponseClientFormat.authData,
                    authenticatorResponseClientFormat.signature
                ),
                PublicKeyCredentialType.PUBLIC_KEY.type,
                authenticatorResponseClientFormat.credential.id,
                authenticatorResponseClientFormat.credential.id,
            ),
            sessionHandler.getRequestId(),
        )

        // convert to JSON and send it
        val authCompletePostDataJson = response.toJson()
        Log.i(TAG, authCompletePostDataJson)

        val request = Request.Builder()
            .url("${preferences.getDemoBackendUrl()}/api/v1/authenticate/finish")
            .post(authCompletePostDataJson.toRequestBody("application/json".toMediaTypeOrNull()))
            .build()

        communication.makeNetworkRequest(
            request,
            Constants.FidoActions.AUTHENTICATE_FIDO
        ).onSuccess { networkResult ->
            Log.i(TAG, networkResult.responseBody)
            val success = FinishResponse.fromJSON(networkResult.responseBody)
            _snackbarQueue.postValue(Event("Authentication is: $success"))
            // for deregister later
            sessionHandler.setCredentialID(success.response.credential.id)
            sessionHandler.setSessionToken(success.sessionToken)
        }.onFailure { exception ->
            Log.e(TAG, "Error on ${Constants.FidoActions.AUTHENTICATE_FIDO}: ${exception.message}")
            _snackbarQueue.postValue(
                Event("Error on ${Constants.FidoActions.AUTHENTICATE_FIDO}: ${exception.message}")
            )
        }
    }

    fun sendDeregistration() = viewModelScope.launch {
        val credentialId = sessionHandler.getCredentialID()
        val sessionToken = sessionHandler.getSessionToken()

        if (credentialId.isEmpty() || sessionToken.isEmpty()) {
            _snackbarQueue.postValue(Event("Register or authenticate first"))
            return@launch
        }

        val requestBody = FormBody.Builder()
            .add(
                "credentialId",
                credentialId.toBase64String()
            )
            .add("sessionToken", sessionToken.toBase64String())
            .build()
        Log.i(TAG, requestBody.toString())

        val request = Request.Builder()
            .url("${preferences.getDemoBackendUrl()}/api/v1/action/deregister")
            .post(requestBody)
            .build()

        communication.makeNetworkRequest(
            request,
            Constants.FidoActions.DEREGISTER_FIDO
        ).onSuccess { networkResult ->
            Log.i(TAG, networkResult.responseBody)
            val success = DeregisterResponse.fromJSON(networkResult.responseBody)
            _launchDeregisterActivity.postValue(Event(success.droppedRegistration.credential.credentialId))
        }.onFailure { exception ->
            Log.e(TAG, "Error on ${Constants.FidoActions.DEREGISTER_FIDO}: ${exception.message}")
            _snackbarQueue.postValue(Event("Error on ${Constants.FidoActions.DEREGISTER_FIDO}: ${exception.message}"))
        }
    }

    companion object {
        private val TAG = ClientViewModel::class.java.simpleName
    }
}

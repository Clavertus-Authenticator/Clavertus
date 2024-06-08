package ch.bfh.clavertus.authenticator.events

import ch.bfh.clavertus.authenticator.models.AuthenticatorGetAssertionInput
import ch.bfh.clavertus.authenticator.models.AuthenticatorMakeCredentialInput
import ch.bfh.clavertus.authenticator.models.ctap.CtapStatusCode

sealed class UIEvent {
    data class StartRegistration(val data: AuthenticatorMakeCredentialInput) : UIEvent()
    data class RegistrationResult(val data: ByteArray) : UIEvent()
    data class StartAuthentication(val data: AuthenticatorGetAssertionInput) : UIEvent()
    data class AuthenticationResult(val data: ByteArray) : UIEvent()
    data class SelectionResult(val unlocked: Boolean) : UIEvent()
    data class ShowSnackbar(val message: String) : UIEvent()
    data class CtapException(val code: CtapStatusCode) : UIEvent()
}

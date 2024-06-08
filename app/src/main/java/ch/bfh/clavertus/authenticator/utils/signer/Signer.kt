package ch.bfh.clavertus.authenticator.utils.signer

import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import ch.bfh.clavertus.authenticator.modules.IODispatcher
import ch.bfh.clavertus.authenticator.modules.MainDispatcher
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.crypto.HpcUtility
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.security.SignatureException
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class Signer @Inject constructor(
    private val hpcUtility: HpcUtility,
    @IODispatcher private val ioDispatcher: CoroutineDispatcher,
    @MainDispatcher private val mainDispatcher: CoroutineDispatcher,
) {

    @Suppress("LongParameterList")
    suspend fun sign(
        action: String,
        authData: ByteArray,
        clientDataHash: ByteArray,
        fragmentActivity: FragmentActivity,
        keyAlias: String,
        requiresAuthentication: Boolean,
        rpID: String,
        userDisplayName: String
    ): ByteArray = withContext(ioDispatcher) {
        val deferredSignature = CompletableDeferred<ByteArray>()
        val byteBuffer = ByteBuffer.allocate(clientDataHash.size + authData.size)
        byteBuffer.put(authData)
        byteBuffer.put(clientDataHash)
        val toSign = byteBuffer.array()
        val title: String = when (action) {
            Constants.FidoActions.REGISTER_FIDO -> "Register"
            Constants.FidoActions.AUTHENTICATE_FIDO -> "Authenticate"
            else -> {
                "Not known action!"
            }
        }

        try {
            val signature = hpcUtility.initSignature(keyAlias)

            if (!requiresAuthentication) {
                signature.update(toSign)
                val signedData = signature.sign()
                deferredSignature.complete(signedData)
            } else {
                // Maybe it would be better to have this in the activity and adapt the architecture a bit
                val biometricPrompt = BiometricPrompt(
                    fragmentActivity,
                    fragmentActivity.mainExecutor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence
                        ) {
                            super.onAuthenticationError(errorCode, errString)
                            Log.e(TAG, "Authentication Failed!")
                            deferredSignature.completeExceptionally(
                                SignatureException("Authentication error: $errString")
                            )
                        }

                        override fun onAuthenticationFailed() {
                            super.onAuthenticationFailed()
                            Log.e(TAG, "Authentication Failed!")
                        }

                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            super.onAuthenticationSucceeded(result)
                            result.cryptoObject?.signature?.apply {
                                try {
                                    update(toSign)
                                    deferredSignature.complete(sign())
                                } catch (e: SignatureException) {
                                    Log.e(TAG, "Signature exception: $e")
                                    deferredSignature.completeExceptionally(e)
                                }
                            } ?: deferredSignature.completeExceptionally(
                                SignatureException("Failed to get crypto object.")
                            )
                        }
                    }
                )

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .setSubtitle("on: $rpID, as: $userDisplayName")
                    .setNegativeButtonText("Cancel")
                    .build()

                withContext(mainDispatcher) {
                    biometricPrompt.authenticate(
                        promptInfo,
                        BiometricPrompt.CryptoObject(signature)
                    )
                }
            }

            deferredSignature.await()
        } catch (e: IllegalArgumentException) {
            Log.e(TAG, "Unexpected error: $e")
            throw e
        }
    }

    companion object {
        private val TAG = Signer::class.java.simpleName
    }
}

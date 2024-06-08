package ch.bfh.clavertus.authenticator.models

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
class MakeCredentialOptions(
    @SerialName("rk") val discoverableCredential: Boolean? = null,
    @SerialName("up") val userPresence: Boolean? = null,
    @SerialName("uv") val userVerification: Boolean? = null,
)

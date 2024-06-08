package ch.bfh.clavertus.authenticator.db

import android.util.Base64
import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import java.security.SecureRandom

/**
 * Inspired by the Fido2Client-App. This class represents the available credential that has been
 * registered with the authenticator. The handles to the key pairs are stored in a database.
 */
@Entity(tableName = "credentials", indices = [Index("rpId")])
data class PublicKeyCredentialSource(
    var rpId: String,
    var userIDFromRP: ByteArray,
    val userName: String,
    var userDisplayName: String,
    var requiresAuthentication: Boolean,
    var isPasskey: Boolean,

    @PrimaryKey(autoGenerate = true)
    var roomUid: Int = 0,
    var id: ByteArray = ByteArray(ID_LENGTH),
    var keyPairAlias: String = "",
    var keyUseCounter: Int = 1
) {
    companion object {
        private var random: SecureRandom? = null
        private const val KEYPAIR_PREFIX = "Clavertus-keypair-"
        private const val ID_LENGTH = 32

        private fun ensureRandomInitialized() {
            if (random == null) {
                random = SecureRandom()
            }
        }

        /**
         * Construct a new PublicKeyCredentialSource. This is the canonical object that represents a
         * WebAuthn credential.
         *
         * @param rpId            The relying party ID.
         * @param userIDFromRP    The unique ID used by the RP to identify the user.
         * @param userDisplayName A human-readable display name for the user.
         * @param keyPairAlias    A predefined key-pair-Alias for the key
         */
        @Suppress("LongParameterList")
        fun createNew(
            rpId: String,
            userIDFromRP: ByteArray,
            userName: String?,
            userDisplayName: String?,
            requiresAuthentication: Boolean,
            isPasskey: Boolean,
            keyPairAlias: String? = null,
        ): PublicKeyCredentialSource {
            val source = PublicKeyCredentialSource(
                rpId,
                userIDFromRP,
                userName.orEmpty(),
                userDisplayName.orEmpty(),
                requiresAuthentication,
                isPasskey
            )
            source.generateRandomID(keyPairAlias)
            return source
        }
    }

    private fun generateRandomID(alias: String?) {
        ensureRandomInitialized()
        random?.nextBytes(this.id)
        keyPairAlias = alias
            ?: (
                KEYPAIR_PREFIX + Base64.encodeToString(
                    this.id,
                    Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
                )
                )
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as PublicKeyCredentialSource

        if (rpId != other.rpId) return false
        if (!userIDFromRP.contentEquals(other.userIDFromRP)) return false
        if (userDisplayName != other.userDisplayName) return false
        if (roomUid != other.roomUid) return false
        if (!id.contentEquals(other.id)) return false
        if (keyPairAlias != other.keyPairAlias) return false
        return keyUseCounter == other.keyUseCounter
    }

    override fun hashCode(): Int {
        var result = rpId.hashCode()
        result = 31 * result + userIDFromRP.contentHashCode()
        result = 31 * result + userDisplayName.hashCode()
        result = 31 * result + roomUid
        result = 31 * result + id.contentHashCode()
        result = 31 * result + keyPairAlias.hashCode()
        result = 31 * result + keyUseCounter
        return result
    }
}

package ch.bfh.clavertus.authenticator.db

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey
import ch.bfh.clavertus.authenticator.utils.Constants
import java.security.SecureRandom

/**
 * This class is used to store the existing link credentials required for the link initiated transaction
 * in the hybrid transport. See CTAP 2.2 chapter 11.5.2
 */
@Entity(tableName = "links", indices = [Index("linkId")])
data class LinkCredentialSource(
    @PrimaryKey(autoGenerate = true)
    var roomUid: Int = 0,
    var linkId: ByteArray = ByteArray(Constants.LINK_ID_LENGTH),
    var linkSecret: ByteArray = ByteArray(Constants.LINK_SECRET_LENGTH)
) {
    companion object {
        private var random: SecureRandom? = null
        private fun ensureRandomInitialized() {
            if (random == null) {
                random = SecureRandom()
            }
        }

        fun createNewLink(): LinkCredentialSource {
            return LinkCredentialSource(
                linkId = generateRandomBytes(Constants.LINK_ID_LENGTH),
                linkSecret = generateRandomBytes(Constants.LINK_SECRET_LENGTH)
            )
        }

        fun generateRandomBytes(size: Int): ByteArray {
            ensureRandomInitialized()
            return ByteArray(size).also { random?.nextBytes(it) }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as LinkCredentialSource

        if (roomUid != other.roomUid) return false
        if (!linkId.contentEquals(other.linkId)) return false
        if (!linkSecret.contentEquals(other.linkSecret)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = roomUid
        result = 31 * result + linkId.contentHashCode()
        result = 31 * result + linkSecret.contentHashCode()
        return result
    }
}

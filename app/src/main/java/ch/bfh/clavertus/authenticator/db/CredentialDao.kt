package ch.bfh.clavertus.authenticator.db

import androidx.lifecycle.LiveData
import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.Query
import androidx.room.Transaction
import androidx.room.Update

/**
 * Inspired by the Fido2Client-App. All queries for the credential database.
 */
@Dao
abstract class CredentialDao {

    @Query("SELECT * FROM credentials")
    abstract fun getAllKeys(): LiveData<List<PublicKeyCredentialSource>>

    @Query("SELECT * FROM credentials WHERE rpId = :rpId")
    abstract suspend fun getAllByRpId(rpId: String?): List<PublicKeyCredentialSource>

    @Query("SELECT * FROM credentials WHERE id = :id LIMIT 1")
    abstract suspend fun getById(id: ByteArray): PublicKeyCredentialSource?

    @Insert
    abstract suspend fun insert(credential: PublicKeyCredentialSource)

    @Delete
    abstract suspend fun delete(credential: PublicKeyCredentialSource)

    @Update
    abstract suspend fun update(credential: PublicKeyCredentialSource)

    @Query("SELECT keyUseCounter FROM credentials WHERE roomUid = :uid LIMIT 1")
    abstract suspend fun getUseCounter(uid: Int): Int

    @Transaction
    open suspend fun incrementUseCounter(credential: PublicKeyCredentialSource): Int {
        val useCounter = getUseCounter(credential.roomUid)
        credential.keyUseCounter++
        update(credential)
        return useCounter
    }

    @Query("SELECT linkSecret FROM links WHERE linkId = :linkId LIMIT 1 ")
    abstract suspend fun getLinkSecret(linkId: ByteArray?): ByteArray

    @Insert
    abstract suspend fun insert(link: LinkCredentialSource)
}

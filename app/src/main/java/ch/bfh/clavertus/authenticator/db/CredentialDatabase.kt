package ch.bfh.clavertus.authenticator.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room.databaseBuilder
import androidx.room.RoomDatabase
import ch.bfh.clavertus.authenticator.utils.Constants

/**
 * Inspired by the Fido2Client-App.This class creates the credential-database.
 */
@Database(entities = [PublicKeyCredentialSource::class, LinkCredentialSource::class], version = 3)
abstract class CredentialDatabase : RoomDatabase() {
    abstract fun credentialDao(): CredentialDao

    companion object {
        private var INSTANCE: CredentialDatabase? = null
        private val LOCK = Any()
        fun getDatabase(context: Context): CredentialDatabase {
            return INSTANCE ?: synchronized(LOCK) {
                INSTANCE ?: buildDatabase(context).also { INSTANCE = it }
            }
        }

        private fun buildDatabase(context: Context) = databaseBuilder(
            context.applicationContext,
            CredentialDatabase::class.java,
            Constants.CREDENTIAL_DB_NAME,
        ).build()
    }
}

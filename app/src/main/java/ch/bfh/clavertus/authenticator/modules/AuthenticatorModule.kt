package ch.bfh.clavertus.authenticator.modules

import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import androidx.preference.PreferenceManager
import androidx.room.Room
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import ch.bfh.clavertus.authenticator.db.CredentialDatabase
import ch.bfh.clavertus.authenticator.utils.Constants
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import java.io.IOException
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.inject.Qualifier
import javax.inject.Singleton

@Qualifier
annotation class RegularPreferences

@Qualifier
annotation class EncryptedPreferences

@Qualifier
annotation class AuthenticatorHttpClient

@Module
@InstallIn(SingletonComponent::class)
object AuthenticatorModule {
    @Singleton
    @Provides
    fun provideCredentialDatabase(@ApplicationContext context: Context): CredentialDatabase {
        return Room.databaseBuilder(
            context,
            CredentialDatabase::class.java,
            Constants.CREDENTIAL_DB_NAME
        ).build()
    }

    @RegularPreferences
    @Singleton
    @Provides
    fun provideSharedPreferences(@ApplicationContext context: Context): SharedPreferences {
        return PreferenceManager.getDefaultSharedPreferences(context)
    }

    @EncryptedPreferences
    @Singleton
    @Provides
    fun provideEncryptedSharedPreferences(@ApplicationContext context: Context): SharedPreferences {
        val masterKeyAlias = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()

        return EncryptedSharedPreferences.create(
            context,
            "EncryptedSharedPreferences",
            masterKeyAlias,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    @Singleton
    @Provides
    fun provideKeyStore(): KeyStore {
        return try {
            val ks = KeyStore.getInstance(Constants.KEYSTORE_TYPE)
            ks.load(null)
            ks
        } catch (e: GeneralSecurityException) {
            Log.e("DI", "Failed to load keystore: ${e.message}")
            throw e
        } catch (e: IOException) {
            Log.e("DI", "Failed to load keystore: ${e.message}")
            throw e
        }
    }

    @Singleton
    @Provides
    fun provideBluetoothManager(@ApplicationContext context: Context): BluetoothManager {
        return context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    }

    @AuthenticatorHttpClient
    @Singleton
    @Provides
    fun okHttpClient(): OkHttpClient {
        return OkHttpClient()
    }
}

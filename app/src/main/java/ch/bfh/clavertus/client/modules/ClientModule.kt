package ch.bfh.clavertus.client.modules

import ch.bfh.clavertus.BuildConfig
import ch.bfh.clavertus.client.utils.ignoreAllTLSErrors
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import javax.inject.Qualifier
import javax.inject.Singleton

@Qualifier
annotation class ClientHttpClient

@Module
@InstallIn(SingletonComponent::class)
object ClientModule {
    @ClientHttpClient
    @Singleton
    @Provides
    fun okHttpClient(): OkHttpClient {
        return OkHttpClient.Builder().apply {
            if (BuildConfig.DEBUG) {
                ignoreAllTLSErrors()
            }
        }.build()
    }
}

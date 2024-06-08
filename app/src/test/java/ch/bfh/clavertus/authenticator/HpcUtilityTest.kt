package ch.bfh.clavertus.authenticator

import android.content.SharedPreferences
import android.util.Log
import ch.bfh.clavertus.authenticator.db.CredentialDao
import ch.bfh.clavertus.authenticator.db.CredentialDatabase
import ch.bfh.clavertus.authenticator.db.PublicKeyCredentialSource
import ch.bfh.clavertus.authenticator.utils.crypto.HpcUtility
import io.mockk.Runs
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.runTest
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.security.KeyStore
import java.security.KeyStoreException

@OptIn(ExperimentalCoroutinesApi::class)
class HpcUtilityTest {
    private lateinit var sharedPreferences: SharedPreferences
    private lateinit var credentialDatabase: CredentialDatabase
    private lateinit var credentialDao: CredentialDao
    private lateinit var mockKeyStore: KeyStore

    private lateinit var hpcUtility: HpcUtility

    @BeforeEach
    fun setUp() {
        val testDispatcher = UnconfinedTestDispatcher()

        mockkStatic(Log::class)
        every { Log.v(any(), any()) } returns 0
        every { Log.d(any(), any()) } returns 0
        every { Log.i(any(), any()) } returns 0
        every { Log.e(any(), any()) } returns 0

        mockKeyStore = mockk()
        sharedPreferences = mockk()
        credentialDatabase = mockk()
        credentialDao = mockk()

        every { credentialDatabase.credentialDao() } returns credentialDao
        coEvery { credentialDao.delete(any()) } just Runs

        hpcUtility = HpcUtility(credentialDatabase, sharedPreferences, testDispatcher, testDispatcher, mockKeyStore)
    }

    @AfterEach
    fun tearDown() {
        unmockkStatic(Log::class)
    }

    @Test
    fun deleteKey_success() = runTest(UnconfinedTestDispatcher()) {
        // given
        val credential = PublicKeyCredentialSource(
            "trusty-bfh.com",
            "Test".toByteArray(),
            "Test",
            "Test",
            requiresAuthentication = false,
            isPasskey = false
        )
        every { mockKeyStore.deleteEntry(credential.keyPairAlias) } just Runs

        // when
        val result = hpcUtility.deleteKey(credential)

        // then
        coVerify { credentialDao.delete(credential) }
        verify { mockKeyStore.deleteEntry(credential.keyPairAlias) }

        assertTrue(result)
    }

    @Test
    fun deleteKey_keyStoreThrowsException() = runTest(UnconfinedTestDispatcher()) {
        // Given
        val credential =
            PublicKeyCredentialSource(
                "alias",
                "Test".toByteArray(),
                "TestKeyPairAlias",
                "TestKeyPairAlias",
                requiresAuthentication = false,
                isPasskey = false
            )
        every { mockKeyStore.deleteEntry(credential.keyPairAlias) } throws KeyStoreException()

        // When
        val result = hpcUtility.deleteKey(credential)

        // Then
        assertFalse(result)
    }
}

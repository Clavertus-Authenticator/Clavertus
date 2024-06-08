package ch.bfh.clavertus.authenticator.noise

import javax.crypto.SecretKey

interface CipherState {
    fun initializeKey(key: ByteArray, offset: Int)
    fun getKeyLength(): Int
    fun getKeySpec(): SecretKey
}

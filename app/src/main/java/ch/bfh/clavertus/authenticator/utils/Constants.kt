package ch.bfh.clavertus.authenticator.utils

object Constants {
    const val KEYSTORE_TYPE = "AndroidKeyStore"
    const val ATTESTATION_FORMAT = "android-key"
    const val CREDENTIAL_DB_NAME = "credentialmetadata"
    const val BYTE_32 = 32
    const val BYTE_64 = 64
    const val BYTE_256 = 256
    const val AAGUID_LENGTH = 16
    const val CREDENTIAL_ID_LENGTH = 2
    const val RP_ID_HASH_LENGTH = 32
    const val FLAGS_LENGTH = 1
    const val SIGN_COUNT_LENGTH = 4
    const val SHIFT_USER_VERIFIED = 2
    const val SHIFT_ATTESTED_CREDENTIAL_DATA_INCLUDED = 6
    const val SHIFT_EXTENSION_DATA_INCLUDED = 7
    const val BLE_ADVERT_LENGTH = 16
    const val BLE_ADVERT_ENCRYPTED_LENGTH = 20
    const val FLAG_BYTE_LENGTH = 1
    const val CONNECTION_NONCE_LENGTH = 10
    const val ROUTING_ID_LENGTH = 3
    const val EID_KEY_LENGTH = 64
    const val HMAC_LENGTH = 4
    const val START_ZERO = 0
    const val TIMEOUT = 3000
    const val PURPOSE_MAX = 0x100
    const val KEY_LENGTH = 32
    const val TUNNEL_ID_LENGTH = 16
    const val PSK_LENGTH = 32
    const val TUNNEL_IDENTIFIER_SHORT: Short = -13223
    const val PURPOSE_BYTES_LENGTH = 4
    const val BLE_UUID = "0000fff9-0000-1000-8000-00805f9b34fb"
    const val SOCKET_URL = "wss://cable.i6khud6i7qci.com/"
    const val SOCKET_PATH_CONNECT = "cable/connect/"
    const val SOCKET_PATH_CONTACT = "cable/contact/"
    const val LINK_ID_LENGTH = 8
    const val LINK_SECRET_LENGTH = 32
    const val FIRST_KEY_LENGTH = 33
    const val SECOND_KEY_END = 65
    const val CONTACT_ID_LENGTH = 8

    object Crypto {
        const val RSA_KEY_LENGTH_2048 = 2048
        const val KEY_TYPE: Long = 1
        const val EC2_KEY_TYPE: Long = 2
        const val RSA_KEY_TYPE: Long = 3
        const val SIGNATURE_ALGORITHM: Long = 3
        const val ES256_SIG_ALGORITHM: Long = -7
        const val RS256: Long = -257
        const val CURVE: Long = -1
        const val P_256_CURVE: Long = 1
        const val X_COORDINATE: Long = -2
        const val Y_COORDINATE: Long = -3
        const val RSA_MODULUS: Long = -1
        const val RSA_EXPONENT: Long = -2
        const val RSA_EXPONENT_LENGTH = 3
        const val NOISE_CURVE_P256 = "prime256v1"
        const val P256_X9_62_LENGTH = 1 + 32 + 32
    }

    object FidoActions {
        const val REGISTER_FIDO: String = "ch.bfh.clavertus.authenticator.REGISTER_FIDO"
        const val AUTHENTICATE_FIDO: String =
            "ch.bfh.clavertus.authenticator.AUTHENTICATE_FIDO"
        const val DEREGISTER_FIDO: String =
            "ch.bfh.clavertus.authenticator.DEREGISTER_FIDO"
    }
}

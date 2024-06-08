package ch.bfh.clavertus.authenticator.models.ctap

/**
 * Values from https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hybrid
 */
@Suppress("MagicNumber")
enum class CtapCommand(val id: Byte) {
    MAKE_CREDENTIAL(0x01),
    GET_ASSERTION(0x02),
    GET_NEXT_ASSERTION(0x08),
    GET_INFO(0x04),
    CLIENT_PIN(0x06),
    RESET(0x07),
    BIO_ENROLLMENT(0x09),
    CREDENTIAL_MANAGEMENT(0x0A),
    SELECTION(0x0B),
    LARGE_BLOBS(0x0C),
    CONFIG(0x0D);
    companion object {
        fun fromId(id: Byte) = entries.firstOrNull { it.id == id }
    }
}

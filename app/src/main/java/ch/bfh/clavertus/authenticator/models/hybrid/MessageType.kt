package ch.bfh.clavertus.authenticator.models.hybrid

/**
 * Values from https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hybrid
 */
@Suppress("MagicNumber")
enum class MessageType(val type: Byte) {
    SHUTDOWN(0x00),
    CTAP(0x01),
    UPDATE(0x02);

    companion object {
        fun fromType(type: Byte) = entries.firstOrNull { it.type == type }
    }
}

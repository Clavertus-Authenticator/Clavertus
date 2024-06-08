package ch.bfh.clavertus.authenticator.models.hybrid

/**
 * Values from https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hybrid
 */
@Suppress("MagicNumber")
enum class KeyPurpose(val type: Int) {
    EID_KEY(1),
    TUNNEL_ID(2),
    PSK(3);

    companion object {
        fun fromType(type: Int) = entries.firstOrNull { it.type == type }
    }
}

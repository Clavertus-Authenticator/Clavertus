package ch.bfh.clavertus.authenticator.models.ctap

/**
 * Values from https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-hybrid
 */
@Suppress("MagicNumber")
enum class CtapStatusCode(val id: Byte, val codeName: String, val description: String) {
    CTAP2_OK(0x00, "CTAP1_ERR_SUCCESS, CTAP2_OK", "Indicates successful response."),
    CTAP1_ERR_INVALID_COMMAND(0x01, "CTAP1_ERR_INVALID_COMMAND", "The command is not a valid CTAP command."),
    CTAP1_ERR_INVALID_PARAMETER(0x02, "CTAP1_ERR_INVALID_PARAMETER", "The command included an invalid parameter."),
    CTAP1_ERR_INVALID_LENGTH(0x03, "CTAP1_ERR_INVALID_LENGTH", "Invalid message or item length."),
    CTAP1_ERR_INVALID_SEQ(0x04, "CTAP1_ERR_INVALID_SEQ", "Invalid message sequencing."),
    CTAP1_ERR_TIMEOUT(0x05, "CTAP1_ERR_TIMEOUT", "Message timed out."),
    CTAP1_ERR_CHANNEL_BUSY(
        0x06,
        "CTAP1_ERR_CHANNEL_BUSY",
        "Channel busy. Client SHOULD retry the request after a short delay."
    ),
    CTAP1_ERR_LOCK_REQUIRED(0x0A, "CTAP1_ERR_LOCK_REQUIRED", "Command requires channel lock."),
    CTAP1_ERR_INVALID_CHANNEL(0x0B, "CTAP1_ERR_INVALID_CHANNEL", "Command not allowed on this cid."),
    CTAP2_ERR_CBOR_UNEXPECTED_TYPE(0x11, "CTAP2_ERR_CBOR_UNEXPECTED_TYPE", "Invalid/unexpected CBOR error."),
    CTAP2_ERR_INVALID_CBOR(0x12, "CTAP2_ERR_INVALID_CBOR", "Error when parsing CBOR."),
    CTAP2_ERR_MISSING_PARAMETER(0x14, "CTAP2_ERR_MISSING_PARAMETER", "Missing non-optional parameter."),
    CTAP2_ERR_LIMIT_EXCEEDED(0x15, "CTAP2_ERR_LIMIT_EXCEEDED", "Limit for number of items exceeded."),
    CTAP2_ERR_FP_DATABASE_FULL(
        0x17,
        "CTAP2_ERR_FP_DATABASE_FULL",
        "Fingerprint database is full, e.g., during enrollment."
    ),
    CTAP2_ERR_LARGE_BLOB_STORAGE_FULL(0x18, "CTAP2_ERR_LARGE_BLOB_STORAGE_FULL", "Large blob storage is full."),
    CTAP2_ERR_CREDENTIAL_EXCLUDED(0x19, "CTAP2_ERR_CREDENTIAL_EXCLUDED", "Valid credential found in the exclude list."),
    CTAP2_ERR_PROCESSING(0x21, "CTAP2_ERR_PROCESSING", "Processing (Lengthy operation is in progress)."),
    CTAP2_ERR_INVALID_CREDENTIAL(0x22, "CTAP2_ERR_INVALID_CREDENTIAL", "Credential not valid for the authenticator."),
    CTAP2_ERR_USER_ACTION_PENDING(
        0x23,
        "CTAP2_ERR_USER_ACTION_PENDING",
        "Authentication is waiting for user interaction."
    ),
    CTAP2_ERR_OPERATION_PENDING(0x24, "CTAP2_ERR_OPERATION_PENDING", "Processing, lengthy operation is in progress."),
    CTAP2_ERR_NO_OPERATIONS(0x25, "CTAP2_ERR_NO_OPERATIONS", "No request is pending."),
    CTAP2_ERR_UNSUPPORTED_ALGORITHM(
        0x26,
        "CTAP2_ERR_UNSUPPORTED_ALGORITHM",
        "Authenticator does not support requested algorithm."
    ),
    CTAP2_ERR_OPERATION_DENIED(0x27, "CTAP2_ERR_OPERATION_DENIED", "Not authorized for requested operation."),
    CTAP2_ERR_KEY_STORE_FULL(0x28, "CTAP2_ERR_KEY_STORE_FULL", "Internal key storage is full."),
    CTAP2_ERR_UNSUPPORTED_OPTION(0x2B, "CTAP2_ERR_UNSUPPORTED_OPTION", "Unsupported option."),
    CTAP2_ERR_INVALID_OPTION(0x2C, "CTAP2_ERR_INVALID_OPTION", "Not a valid option for current operation."),
    CTAP2_ERR_KEEPALIVE_CANCEL(0x2D, "CTAP2_ERR_KEEPALIVE_CANCEL", "Pending keep alive was cancelled."),
    CTAP2_ERR_NO_CREDENTIALS(0x2E, "CTAP2_ERR_NO_CREDENTIALS", "No valid credentials provided."),
    CTAP2_ERR_USER_ACTION_TIMEOUT(0x2F, "CTAP2_ERR_USER_ACTION_TIMEOUT", "A user action timeout occurred."),
    CTAP2_ERR_NOT_ALLOWED(
        0x30,
        "CTAP2_ERR_NOT_ALLOWED",
        "Continuation command, such as authenticatorGetNextAssertion, not allowed."
    ),
    CTAP2_ERR_PIN_INVALID(0x31, "CTAP2_ERR_PIN_INVALID", "PIN Invalid."),
    CTAP2_ERR_PIN_BLOCKED(0x32, "CTAP2_ERR_PIN_BLOCKED", "PIN Blocked."),
    CTAP2_ERR_PIN_AUTH_INVALID(
        0x33,
        "CTAP2_ERR_PIN_AUTH_INVALID",
        "PIN authentication, pinUvAuthParam, verification failed."
    ),
    CTAP2_ERR_PIN_AUTH_BLOCKED(
        0x34,
        "CTAP2_ERR_PIN_AUTH_BLOCKED",
        "PIN authentication using pinUvAuthToken blocked. Requires power cycle to reset."
    ),
    CTAP2_ERR_PIN_NOT_SET(0x35, "CTAP2_ERR_PIN_NOT_SET", "No PIN has been set."),
    CTAP2_ERR_PUAT_REQUIRED(
        0x36,
        "CTAP2_ERR_PUAT_REQUIRED",
        "A pinUvAuthToken is required for the selected operation."
    ),
    CTAP2_ERR_PIN_POLICY_VIOLATION(
        0x37,
        "CTAP2_ERR_PIN_POLICY_VIOLATION",
        "PIN policy violation. Currently only enforces minimum length."
    ),
    CTAP2_ERR_REQUEST_TOO_LARGE(
        0x39,
        "CTAP2_ERR_REQUEST_TOO_LARGE",
        "Authenticator cannot handle this request due to memory constraints."
    ),
    CTAP2_ERR_ACTION_TIMEOUT(0x3A, "CTAP2_ERR_ACTION_TIMEOUT", "The current operation has timed out."),
    CTAP2_ERR_UP_REQUIRED(0x3B, "CTAP2_ERR_UP_REQUIRED", "User presence is required for the requested operation."),
    CTAP2_ERR_UV_BLOCKED(0x3C, "CTAP2_ERR_UV_BLOCKED", "Built-in user verification is disabled."),
    CTAP2_ERR_INTEGRITY_FAILURE(0x3D, "CTAP2_ERR_INTEGRITY_FAILURE", "A checksum did not match."),
    CTAP2_ERR_INVALID_SUBCOMMAND(
        0x3E,
        "CTAP2_ERR_INVALID_SUBCOMMAND",
        "The requested subcommand is either invalid or not implemented."
    ),
    CTAP2_ERR_UV_INVALID(0x3F, "CTAP2_ERR_UV_INVALID", "Built-in user verification unsuccessful."),
    CTAP2_ERR_UNAUTHORIZED_PERMISSION(
        0x40,
        "CTAP2_ERR_UNAUTHORIZED_PERMISSION",
        "The permissions parameter contains an unauthorized permission."
    ),
    CTAP1_ERR_OTHER(0x7F, "CTAP1_ERR_OTHER", "Other unspecified error."),
    CTAP2_ERR_SPEC_LAST(0xDF.toByte(), "CTAP2_ERR_SPEC_LAST", "CTAP 2 spec last error."),
    CTAP2_ERR_EXTENSION_FIRST(0xE0.toByte(), "CTAP2_ERR_EXTENSION_FIRST", "Extension specific error."),
    CTAP2_ERR_EXTENSION_LAST(0xEF.toByte(), "CTAP2_ERR_EXTENSION_LAST", "Extension specific error."),
    CTAP2_ERR_VENDOR_FIRST(0xF0.toByte(), "CTAP2_ERR_VENDOR_FIRST", "Vendor specific error."),
    CTAP2_ERR_VENDOR_LAST(0xFF.toByte(), "CTAP2_ERR_VENDOR_LAST", "Vendor specific error.");

    companion object {
        fun fromId(id: Byte): CtapStatusCode? = entries.firstOrNull { it.id == id }
    }
}

package ch.bfh.clavertus.authenticator.noise

data class TrafficKeys(val readKey: ByteArray, val writeKey: ByteArray) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as TrafficKeys

        if (!readKey.contentEquals(other.readKey)) return false
        if (!writeKey.contentEquals(other.writeKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = readKey.contentHashCode()
        result = 31 * result + writeKey.contentHashCode()
        return result
    }
}

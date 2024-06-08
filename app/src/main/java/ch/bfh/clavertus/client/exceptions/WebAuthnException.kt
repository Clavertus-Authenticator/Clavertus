package ch.bfh.clavertus.client.exceptions

class WebAuthnException : Exception {
    constructor(message: String?) : super(message)
    constructor(message: String?, e: Throwable?) : super(message, e)
}

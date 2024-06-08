package ch.bfh.clavertus.authenticator.exceptions

import android.util.Log
import ch.bfh.clavertus.authenticator.models.ctap.CtapStatusCode

class CtapException(val code: CtapStatusCode) : Exception(code.codeName) {
    init {
        Log.e("CtapException", code.codeName)
    }
}

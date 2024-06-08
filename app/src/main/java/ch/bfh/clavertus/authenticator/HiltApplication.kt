package ch.bfh.clavertus.authenticator

import android.app.Application
import androidx.preference.PreferenceManager
import ch.bfh.clavertus.R
import dagger.hilt.android.HiltAndroidApp

@HiltAndroidApp
class HiltApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        PreferenceManager.setDefaultValues(this, R.xml.userpreferences_authenticator, false)
    }
}

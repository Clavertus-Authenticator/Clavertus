package ch.bfh.clavertus.authenticator.utils

import android.app.AlertDialog
import android.content.Context
import android.util.AttributeSet
import androidx.preference.CheckBoxPreference

/**
 * This class is used for the setting where user authentication can be disabled. If the authenticator
 * also supports PIN or biometric verification, you can get high-assurance multi-factor authentication
 * in a single login step.
 * */
class CheckBoxPreferenceWarnUserAuthentication(context: Context, attrs: AttributeSet) :
    CheckBoxPreference(context, attrs) {
    override fun onClick() {
        if (isChecked) {
            showWarnDialog()
        } else {
            super.onClick()
        }
    }

    private fun showWarnDialog() {
        AlertDialog.Builder(context)
            .setTitle("Confirm disable")
            .setMessage(
                "Clavertus strongly recommends the use of user authentication.\n" +
                    "Are you sure you want to disable it?"
            )
            .setPositiveButton("Disable") { dialog, _ ->
                this.isChecked = false
                dialog.dismiss()
            }
            .setNegativeButton("Cancel") { dialog, _ ->
                dialog.dismiss()
            }
            .show()
    }
}

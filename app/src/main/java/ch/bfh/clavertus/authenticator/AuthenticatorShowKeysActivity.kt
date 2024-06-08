package ch.bfh.clavertus.authenticator

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.util.Log
import android.view.LayoutInflater
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.recyclerview.widget.DividerItemDecoration
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import ch.bfh.clavertus.R
import ch.bfh.clavertus.authenticator.db.PublicKeyCredentialSource
import ch.bfh.clavertus.authenticator.utils.Constants
import ch.bfh.clavertus.authenticator.utils.crypto.HpcUtility
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class AuthenticatorShowKeysActivity : AppCompatActivity() {

    @Inject
    lateinit var hpcUtility: HpcUtility

    @SuppressLint("NotifyDataSetChanged")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.show_keys_activity)
        setSupportActionBar(findViewById(R.id.toolbar))
        val actionBar = supportActionBar
        actionBar?.setDisplayHomeAsUpEnabled(true)
        val recyclerView = findViewById<RecyclerView>(R.id.recycler_view)
        val keyListInView: MutableList<PublicKeyCredentialSource> = mutableListOf()
        val scanResultAdapter = ScanResultAdapter(keyListInView, this)
        recyclerView.adapter = scanResultAdapter
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.addItemDecoration(
            DividerItemDecoration(
                recyclerView.context,
                DividerItemDecoration.VERTICAL
            )
        )

        val keyList = hpcUtility.getAll()
        keyList.observe(this) { publicKeyCredentialSourceList ->
            Log.i(
                "ShowKeysActivity",
                "Received keys from HpcUtility: $publicKeyCredentialSourceList"
            )
            keyListInView.clear()
            keyListInView.addAll(publicKeyCredentialSourceList)
            scanResultAdapter.notifyDataSetChanged()
        }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        when (item.itemId) {
            android.R.id.home -> {
                super.onBackPressedDispatcher.onBackPressed()
                return true
            }
        }
        return super.onOptionsItemSelected(item)
    }

    class ScanResultAdapter @Inject constructor(
        keys: List<PublicKeyCredentialSource>,
        private val context: Context
    ) :
        RecyclerView.Adapter<ViewHolder>() {

        private val keys: List<PublicKeyCredentialSource>

        init {
            this.keys = keys
        }

        override fun getItemCount(): Int {
            return keys.size
        }

        override fun onCreateViewHolder(viewGroup: ViewGroup, viewType: Int): ViewHolder {
            val view: View = LayoutInflater.from(viewGroup.context)
                .inflate(R.layout.key_row, viewGroup, false)
            return ViewHolder(view, context)
        }

        override fun onBindViewHolder(holder: ViewHolder, position: Int) {
            val key: PublicKeyCredentialSource = keys[position]
            holder.bind(key)
        }
    }

    class ViewHolder @Inject constructor(view: View, private val context: Context) :
        RecyclerView.ViewHolder(view) {

        private val rpID: TextView
        private val username: TextView
        private val properties: TextView
        private val deleteKey: Button

        init {
            rpID = view.findViewById(R.id.txt_rpID)
            username =
                view.findViewById(R.id.txt_username_row)
            properties =
                view.findViewById(R.id.txt_properties)
            deleteKey =
                view.findViewById(R.id.btn_deleteKey)
        }

        fun bind(pKey: PublicKeyCredentialSource) {
            rpID.text = pKey.rpId
            username.text = pKey.userDisplayName.ifEmpty { pKey.userName }
            properties.text = propertiesString(pKey)
            deleteKey.setOnClickListener {
                showDeleteConfirmationDialog(pKey.rpId) {
                    val intent = Intent(context, AuthenticatorActivity::class.java)
                    intent.setAction(Constants.FidoActions.DEREGISTER_FIDO)
                    intent.flags = Intent.FLAG_ACTIVITY_NEW_TASK
                    intent.putExtra("publicKey2delete", pKey.id)
                    context.startActivity(intent)
                }
            }
        }
        private fun showDeleteConfirmationDialog(item: String, onDeleteConfirmed: () -> Unit) {
            AlertDialog.Builder(context)
                .setTitle("Confirm Delete")
                .setMessage("Delete credential for $item?")
                .setPositiveButton("Delete") { _, _ ->
                    onDeleteConfirmed()
                }
                .setNegativeButton("Cancel") { dialog, _ ->
                    dialog.dismiss()
                }
                .show()
        }

        private fun propertiesString(pKey: PublicKeyCredentialSource): String {
            val passkey = if (pKey.isPasskey) "Passkey" else ""
            val biometric = if (pKey.requiresAuthentication) "Biometric" else ""
            val list = listOf(passkey, biometric)
            return list.filter { it.isNotEmpty() }.joinToString(", ")
        }
    }
}

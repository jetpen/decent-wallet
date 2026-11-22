package org.decentwallet.wallet.client

import android.app.Activity
import android.app.Application
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.decentwallet.wallet.android.AndroidWallet
import org.decentwallet.wallet.android.WalletSession
import java.io.InputStream
import java.net.URI
import java.nio.file.Files
import java.util.concurrent.Executors

/** Qualification-only host: it retains only an explicitly imported, unlocked session in memory. */
class QualificationWalletHostApplication : Application(), WalletLoginHost {
    @Volatile private var currentIdentity: WalletLoginIdentity? = null
    @Volatile private var trustConfig: NativeDisclosureTrustConfig? = null

    override fun acquireWalletLoginIdentity(activity: Activity): WalletLoginIdentity? =
        currentIdentity?.takeIf { it.session.isUnlocked }

    override fun nativeDisclosureTrust(activity: Activity): NativeDisclosureTrustConfig? {
        trustConfig?.let { return it }
        return try {
            val host = URI(BuildConfig.WALLET_LOGIN_ORIGIN).host ?: return null
            val bytes = assets.open(TRUST_CONFIG_ASSET).use { it.readBounded(MAX_TRUST_CONFIG_BYTES) }
            try {
                QualificationTrustConfig.parse(bytes, host).toNativeDisclosureTrustConfig().also { trustConfig = it }
            } finally {
                bytes.fill(0)
            }
        } catch (_: Exception) {
            null
        }
    }

    @Synchronized
    internal fun installWalletSession(identityId: String, session: WalletSession) {
        val previous = currentIdentity?.session
        currentIdentity = WalletLoginIdentity(session, identityId)
        if (previous !== session) previous?.close()
    }

    @Synchronized
    internal fun lockWalletSession() {
        val previous = currentIdentity?.session
        currentIdentity = null
        previous?.close()
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= TRIM_MEMORY_UI_HIDDEN) lockWalletSession()
    }

    override fun onTerminate() {
        lockWalletSession()
        super.onTerminate()
    }

    private companion object {
        const val TRUST_CONFIG_ASSET = "trust_config.json"
        const val MAX_TRUST_CONFIG_BYTES = 64 * 1024
    }
}

/** Setup/import Activity that preserves the incoming App Link without contacting either origin. */
class QualificationWalletSetupActivity : Activity() {
    private val main = Handler(Looper.getMainLooper())
    private var selectedContainer: Uri? = null
    private var forwarded = false
    private var walletActivityLaunched = false
    private var unlockInProgress = false
    private var foregroundLockOnResume = false
    private val worker = Executors.newSingleThreadExecutor()
    private lateinit var identityInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var status: TextView
    private lateinit var importButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        selectedContainer = savedInstanceState?.getString(STATE_CONTAINER_URI)?.let(Uri::parse)
        showSetup()
        if (savedInstanceState != null) foregroundLockOnResume = true
        else forwardIfSessionReady()
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        setIntent(intent)
        forwardIfSessionReady()
    }

    override fun onDestroy() {
        worker.shutdownNow()
        if (isFinishing && !walletActivityLaunched) (application as QualificationWalletHostApplication).lockWalletSession()
        super.onDestroy()
    }

    override fun onResume() {
        super.onResume()
        if (foregroundLockOnResume) {
            foregroundLockOnResume = false
            (application as QualificationWalletHostApplication).lockWalletSession()
            forwarded = false
            walletActivityLaunched = false
            status.text = "App returned to foreground. Unlock the wallet again before continuing."
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        selectedContainer?.toString()?.let { outState.putString(STATE_CONTAINER_URI, it) }
        super.onSaveInstanceState(outState)
    }

    private fun showSetup() {
        val application = application as QualificationWalletHostApplication
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
            layoutParams = ViewGroup.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        }
        val scroll = ScrollView(this).apply { addView(root) }
        root.addView(TextView(this).apply {
            text = "Decent Wallet Qualification\n\nImport an existing encrypted wallet container. The wallet and password are never generated or embedded in this app."
            textSize = 18f
        })
        root.addView(Button(this).apply {
            text = "Choose encrypted wallet"
            setOnClickListener { chooseContainer() }
        })
        identityInput = EditText(this).apply {
            hint = "Exact Identity ID associated with this wallet"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            setSingleLine(true)
        }
        root.addView(identityInput)
        passwordInput = EditText(this).apply {
            hint = "Wallet password (not saved)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            setSingleLine(true)
        }
        root.addView(passwordInput)
        importButton = Button(this).apply {
            text = "Unlock wallet"
            setOnClickListener { unlockSelectedContainer() }
        }
        root.addView(importButton)
        status = TextView(this).apply {
            text = if (application.nativeDisclosureTrust(this@QualificationWalletSetupActivity) == null) {
                "Issuer/RP trust is not configured. Native account disclosure will remain unavailable."
            } else {
                "Static issuer/RP trust is configured. Review the relying party in the wallet before disclosure."
            }
            textSize = 16f
        }
        root.addView(status)
        setContentView(scroll)
    }

    private fun chooseContainer() {
        if (forwarded) return
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION)
        }
        startActivityForResult(intent, REQUEST_CONTAINER)
    }

    @Deprecated("Document selection is delivered by Android's document provider")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_CONTAINER || resultCode != RESULT_OK) return
        selectedContainer = data?.data
        try {
            selectedContainer?.let { contentResolver.takePersistableUriPermission(it, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
        } catch (_: Exception) {
            selectedContainer = null
        }
        status.text = if (selectedContainer == null) "No wallet container was selected." else "Container selected. Enter its exact Identity ID and password, then unlock."
    }

    private fun unlockSelectedContainer() {
        if (forwarded || unlockInProgress) return
        val uri = selectedContainer
        val identityId = identityInput.text.toString()
        val passwordEditable = passwordInput.text
        val passwordChars = CharArray(passwordEditable?.length ?: 0) { index -> passwordEditable!![index] }
        passwordInput.text?.clear()
        if (uri == null || identityId.isEmpty() || identityId.length > MAX_IDENTITY_ID_CHARS || passwordChars.isEmpty()) {
            passwordChars.fill('\u0000')
            status.text = "Choose a wallet container and enter its exact Identity ID and password."
            return
        }
        unlockInProgress = true
        importButton.isEnabled = false
        status.text = "Unlocking wallet…"
        worker.execute {
            var container: ByteArray? = null
            var session: WalletSession? = null
            var password: String? = null
            var secretBuffer: CharArray? = null
            try {
                // AndroidWallet currently accepts String; the mutable source is wiped immediately and the String is never persisted.
                secretBuffer = passwordChars.copyOf()
                password = String(secretBuffer!!)
                secretBuffer!!.fill('\u0000')
                passwordChars.fill('\u0000')
                container = contentResolver.openInputStream(uri)?.use { it.readBounded(MAX_CONTAINER_BYTES) }
                    ?: throw IllegalArgumentException("missing input")
                val directory = filesDir.toPath().resolve(WALLET_DIRECTORY)
                Files.createDirectories(directory)
                val walletPath = WalletContainerImportPath.destination(directory, container)
                session = if (Files.exists(walletPath)) {
                    AndroidWallet.open(walletPath, checkNotNull(password))
                } else {
                    AndroidWallet.importContainer(walletPath, container, checkNotNull(password))
                }
                val opened = checkNotNull(session)
                session = null
                password = null
                main.post {
                    if (isFinishing || isDestroyed) {
                        opened.close()
                        return@post
                    }
                    (application as QualificationWalletHostApplication).installWalletSession(identityId, opened)
                    unlockInProgress = false
                    importButton.isEnabled = true
                    status.text = "Wallet unlocked in memory. The incoming App Link has not been changed."
                    forwardIfSessionReady()
                }
            } catch (_: Exception) {
                session?.close()
                main.post {
                    if (!isFinishing && !isDestroyed) {
                        unlockInProgress = false
                        importButton.isEnabled = true
                        status.text = "Wallet could not be opened with that container and password. No proof or disclosure was sent."
                    }
                }
            } finally {
                passwordChars.fill('\u0000')
                secretBuffer?.fill('\u0000')
                container?.fill(0)
                password = null
            }
        }
    }

    private fun forwardIfSessionReady() {
        val app = application as QualificationWalletHostApplication
        if (app.acquireWalletLoginIdentity(this) == null) return
        val originalUri = intent?.data ?: return
        if (forwarded) return
        forwarded = true
        startActivity(walletLoginIntent(originalUri))
        walletActivityLaunched = true
        finish()
    }

    internal fun walletLoginIntent(originalUri: Uri): Intent =
        Intent(Intent.ACTION_VIEW, originalUri, this, WalletLoginActivity::class.java)

    private companion object {
        const val REQUEST_CONTAINER = 7601
        const val STATE_CONTAINER_URI = "qualification.container_uri"
        const val WALLET_DIRECTORY = "qualification-wallets"
        const val MAX_CONTAINER_BYTES = 16 * 1024 * 1024
        const val MAX_IDENTITY_ID_CHARS = 4096
    }
}

private fun InputStream.readBounded(maxBytes: Int): ByteArray {
    val output = java.io.ByteArrayOutputStream(minOf(maxBytes, 8192))
    val buffer = ByteArray(8192)
    try {
        var total = 0
        while (true) {
            val count = read(buffer, 0, minOf(buffer.size, maxBytes - total + 1))
            if (count < 0) break
            total += count
            require(total <= maxBytes) { "input exceeds configured size limit" }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    } finally {
        buffer.fill(0)
        output.reset()
    }
}

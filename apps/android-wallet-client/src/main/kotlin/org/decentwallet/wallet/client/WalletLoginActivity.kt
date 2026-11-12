package org.decentwallet.wallet.client

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.decentwallet.wallet.android.WalletLoginProofRequest
import org.decentwallet.wallet.android.WalletSession
import java.util.concurrent.Executors

/** Host boundary: supply only an already-unlocked wallet session and exact identity identifier. */
interface WalletLoginHost {
    fun acquireWalletLoginIdentity(activity: Activity): WalletLoginIdentity?
}

data class WalletLoginIdentity(val session: WalletSession, val identityId: String)

/** Wallet-login-only app-link consent UI. It does not handle account disclosure or browser callbacks. */
class WalletLoginActivity : Activity() {
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private var terminal = false
    private var approvalGate = ApprovalAttemptGate()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showMessage("Preparing wallet login…")
        val transaction = try {
            WalletLoginTransactionUrl.parse(intent?.dataString.orEmpty(), BuildConfig.WALLET_LOGIN_ORIGIN)
        } catch (_: Exception) {
            showMessage("This wallet login request is invalid or not trusted. No proof was sent.")
            return
        }
        val identity = try { (application as? WalletLoginHost)?.acquireWalletLoginIdentity(this) } catch (_: Exception) { null }
        if (identity == null || !identity.session.isUnlocked || identity.identityId.isBlank()) {
            showMessage("An already-unlocked wallet is required. No proof was sent.")
            return
        }
        worker.execute {
            val challenge = try { NativeWalletLoginHttpClient(this).getChallenge(transaction) } catch (_: Exception) { null }
            main.post {
                if (isFinishing || isDestroyed || terminal) return@post
                if (challenge == null) showMessage("The provider request could not be verified. No proof was sent.")
                else if (challenge.isExpiredAt(nowEpochSeconds())) showMessage("The wallet login request expired. No proof was sent.")
                else showConsent(transaction, identity, challenge)
            }
        }
    }

    private fun showConsent(
        transaction: WalletLoginTransactionUrl,
        identity: WalletLoginIdentity,
        challenge: WalletLoginChallenge,
    ) {
        val layout = column()
        addText(layout, "Wallet login request")
        addText(layout, "Provider origin: ${transaction.origin}")
        addText(layout, "Identity identifier to sign exactly:\n${identity.identityId}")
        addText(layout, "Action: wallet login. No account fields will be disclosed.")

        val approve = Button(this).apply { text = "Approve wallet login" }
        val deny = Button(this).apply { text = "Deny" }
        val cancel = Button(this).apply { text = "Cancel" }
        val decisionButtons = listOf(approve, deny, cancel)
        approve.setOnClickListener {
            if (terminal) return@setOnClickListener
            decisionButtons.forEach { it.isEnabled = false }
            val gate = approvalGate
            worker.execute {
                val result = approveAndSubmit(transaction, identity, challenge, gate)
                main.post {
                    if (isFinishing || isDestroyed || gate.isCancelled) return@post
                    terminal = true
                    showMessage(when (result) {
                        ApprovalResult.SUBMITTED -> "Wallet login proof submitted. Return to the original browser to continue."
                        ApprovalResult.EXPIRED -> "The wallet login request expired. No proof was sent."
                        ApprovalResult.FAILED -> "Wallet login did not complete. Check the original browser; no retry was made."
                    })
                }
            }
        }
        deny.setOnClickListener {
            terminal = true
            approvalGate.cancel()
            worker.shutdownNow()
            showMessage("Wallet login denied. No proof was sent.")
        }
        cancel.setOnClickListener {
            terminal = true
            approvalGate.cancel()
            worker.shutdownNow()
            showMessage("Wallet login cancelled. No proof was sent.")
        }
        decisionButtons.forEach(layout::addView)
        install(layout)
    }

    private fun approveAndSubmit(
        transaction: WalletLoginTransactionUrl,
        identity: WalletLoginIdentity,
        challenge: WalletLoginChallenge,
        gate: ApprovalAttemptGate,
    ): ApprovalResult {
        var expired = false
        return try {
            gate.approve(
                createProof = {
                    if (!identity.session.isUnlocked) throw IllegalStateException()
                    if (challenge.isExpiredAt(nowEpochSeconds())) {
                        expired = true
                        throw IllegalStateException()
                    }
                    identity.session.createWalletLoginProofRequest(
                        challenge.challenge,
                        identity.identityId,
                        challenge.expiresAtEpochSeconds,
                    ) { profile, identityId ->
                        profile == "decent-wallet-login-v1" && identityId == identity.identityId
                    }
                },
                beforeSubmit = {
                    if (challenge.isExpiredAt(nowEpochSeconds())) {
                        expired = true
                        false
                    } else identity.session.isUnlocked
                },
                submit = { proof: WalletLoginProofRequest ->
                    // Gate's atomic transition immediately precedes the sole POST attempt.
                    NativeWalletLoginHttpClient(this).submitProof(transaction, proof)
                },
            )?.let { submitted -> if (submitted) ApprovalResult.SUBMITTED else ApprovalResult.FAILED }
                ?: if (expired) ApprovalResult.EXPIRED else ApprovalResult.FAILED
        } catch (_: Exception) {
            ApprovalResult.FAILED
        }
    }

    private fun nowEpochSeconds(): Long = System.currentTimeMillis() / 1000

    private fun showMessage(message: String) {
        val layout = column()
        addText(layout, message)
        install(layout)
    }

    private fun column(): LinearLayout = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        gravity = Gravity.CENTER_VERTICAL
        setPadding(32, 32, 32, 32)
    }

    private fun addText(layout: LinearLayout, value: String) {
        layout.addView(TextView(this).apply { text = value; textSize = 18f; setPadding(0, 12, 0, 12) })
    }

    private fun install(layout: LinearLayout) {
        setContentView(ScrollView(this).apply { addView(layout) })
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        recreate()
    }

    override fun onDestroy() {
        approvalGate.cancel()
        worker.shutdownNow()
        super.onDestroy()
    }

    private enum class ApprovalResult { SUBMITTED, EXPIRED, FAILED }
}

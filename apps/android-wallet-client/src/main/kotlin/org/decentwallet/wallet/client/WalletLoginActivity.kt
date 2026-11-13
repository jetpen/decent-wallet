package org.decentwallet.wallet.client

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.widget.Button
import android.widget.CheckBox
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import org.decentwallet.wallet.android.AccountPresentationSubmission
import org.decentwallet.wallet.android.PendingAccountApproval
import org.decentwallet.wallet.android.PresentationDeliveryOutcome
import org.decentwallet.wallet.android.WalletLoginProofRequest
import org.decentwallet.wallet.android.WalletSession
import java.util.concurrent.Executors

/** Host boundary: supply only an already-unlocked wallet session and exact identity identifier. */
interface WalletLoginHost {
    fun acquireWalletLoginIdentity(activity: Activity): WalletLoginIdentity?

    /** Optional, statically configured trust. Never derive these anchors from provider responses. */
    fun nativeDisclosureTrust(activity: Activity): NativeDisclosureTrustConfig? = null
}

data class WalletLoginIdentity(val session: WalletSession, val identityId: String)

/** Native login plus explicitly opted-in account-disclosure continuation UI. */
class WalletLoginActivity : Activity() {
    private val main = Handler(Looper.getMainLooper())
    private val worker = Executors.newSingleThreadExecutor()
    private var terminal = false
    private var approvalGate = ApprovalAttemptGate()
    private var nativeGate: NativeDisclosureCancellationGate? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        showMessage("Preparing wallet login…")
        val host = application as? WalletLoginHost
        val identity = try { host?.acquireWalletLoginIdentity(this) } catch (_: Exception) { null }
        if (identity == null || !identity.session.isUnlocked || identity.identityId.isBlank()) {
            val validIntent = try {
                WalletLoginTransactionUrl.parse(intent?.dataString.orEmpty(), BuildConfig.WALLET_LOGIN_ORIGIN)
                true
            } catch (_: Exception) { false }
            showMessage(if (validIntent) "An already-unlocked wallet is required. No proof was sent."
                else "This wallet login request is invalid or not trusted. No proof was sent.")
            return
        }
        val trust = try { host?.nativeDisclosureTrust(this) } catch (_: Exception) { null }

        // Resolve durable one-use state before even parsing or contacting the current intent.
        // Any recovered approval takes exclusive ownership of this Activity launch.
        val recovered = try {
            identity.session.recoverPendingAccountApproval()
        } catch (_: Exception) {
            showMessage("A saved wallet request could not be safely recovered. No proof or presentation was sent.")
            return
        }
        if (recovered != null) {
            showRecoveredApproval(identity, recovered, trust)
            return
        }

        val transaction = try {
            WalletLoginTransactionUrl.parse(intent?.dataString.orEmpty(), BuildConfig.WALLET_LOGIN_ORIGIN)
        } catch (_: Exception) {
            showMessage("This wallet login request is invalid or not trusted. No proof was sent.")
            return
        }
        worker.execute {
            val start = try {
                NativeDisclosureWorkflow(AndroidNativeDisclosureOperations(NativeDisclosureHttpClient(this), trust, NativeWalletLoginHttpClient(this)))
                    .start(transaction, identity.session, identity.identityId, trust)
            } catch (_: Exception) { null }
            val challenge = if (start == NativeDisclosureStart.LoginOnly) {
                try { NativeWalletLoginHttpClient(this).getChallenge(transaction) } catch (_: Exception) { null }
            } else null
            main.post {
                if (isFinishing || isDestroyed || terminal) return@post
                when {
                    start == null -> showMessage("The provider request could not be verified or trusted. No proof was sent.")
                    start is NativeDisclosureStart.Native -> showNativeConsent(transaction, identity, start.review)
                    challenge == null -> showMessage("The provider request could not be verified. No proof was sent.")
                    challenge.isExpiredAt(nowEpochSeconds()) -> showMessage("The wallet login request expired. No proof was sent.")
                    else -> showConsent(transaction, identity, challenge)
                }
            }
        }
    }

    private fun showRecoveredApproval(
        identity: WalletLoginIdentity,
        pending: PendingAccountApproval,
        trust: NativeDisclosureTrustConfig?,
    ) {
        val registration = trust?.relyingPartyRegistration
        if (!identity.session.isUnlocked || registration == null) {
            showMessage("A saved disclosure is waiting, but configured relying-party trust is unavailable. No presentation was sent.")
            return
        }
        // Confirm retryability for this exact static registration without disclosing the stored
        // JWS or body. The returned object is immediately wiped and never reaches the UI.
        try {
            identity.session.getAccountPresentationRetry(pending, registration).use { }
        } catch (_: Exception) {
            showMessage("A saved wallet request cannot be retried with the configured relying-party trust. No presentation was sent.")
            return
        }

        val layout = column()
        addText(layout, "Saved account presentation")
        addText(layout, "Configured relying-party origin: ${registration.origin}")
        addText(layout, "Delivery may be ambiguous. The saved submission may already have reached this relying party.")
        addText(layout, "No new proof or consent will be requested. Resending is optional and requires your explicit action.")
        val status = TextView(this).apply { textSize = 16f; setPadding(0, 12, 0, 12) }
        layout.addView(status)
        val retry = Button(this).apply { text = "Retry saved presentation" }
        retry.setOnClickListener {
            if (terminal || !retry.isEnabled) return@setOnClickListener
            retry.isEnabled = false
            worker.execute {
                val result = retrySavedPresentation(identity.session, pending, trust)
                main.post {
                    if (isFinishing || isDestroyed) return@post
                    status.text = result.message
                    if (result.accepted) {
                        terminal = true
                        retry.isEnabled = false
                    } else {
                        retry.isEnabled = true
                    }
                }
            }
        }
        layout.addView(retry)
        install(layout)
    }

    private fun retrySavedPresentation(
        wallet: WalletSession,
        pending: PendingAccountApproval,
        trust: NativeDisclosureTrustConfig,
    ): RecoveryRetryResult {
        var submission: AccountPresentationSubmission? = null
        var response: PresentationHttpResult? = null
        var postAttempted = false
        try {
            if (!wallet.isUnlocked) throw IllegalStateException()
            submission = wallet.getAccountPresentationRetry(pending, trust.relyingPartyRegistration)
            val body = submission.body
            try {
                // This is the sole POST attempt for this explicit tap. The transport validates
                // the URI against static RP trust and disables redirects/connection retries.
                postAttempted = true
                response = NativeDisclosureHttpClient(this).submitPresentationOnce(
                    submission.responseUri,
                    trust.relyingPartyRegistration.origin,
                    body,
                )
            } finally {
                body.fill(0)
            }

            val result = checkNotNull(response)
            if (result.statusCode == 200 && result.contentType?.substringBefore(';')?.trim()
                    .equals("application/json", ignoreCase = true)
            ) {
                try {
                    wallet.finishAccountPresentation(
                        pending,
                        PresentationDeliveryOutcome.ACCEPTED,
                        result.statusCode,
                        result.contentType,
                        result.body,
                    )
                    return RecoveryRetryResult(true, "The relying party verified acceptance. The saved presentation was consumed.")
                } catch (_: Exception) {
                    // A response core cannot verify is not an acceptance; retain exact bytes.
                    wallet.finishAccountPresentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
                    return RecoveryRetryResult(false, "Acceptance could not be verified. The saved presentation remains available for an explicit retry.")
                }
            }
            wallet.finishAccountPresentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
            return RecoveryRetryResult(false, "Delivery remains ambiguous. The exact saved presentation is unchanged; retry only by choosing the button again.")
        } catch (_: Exception) {
            if (postAttempted) {
                try { wallet.finishAccountPresentation(pending, PresentationDeliveryOutcome.AMBIGUOUS) } catch (_: Exception) { }
            }
            return RecoveryRetryResult(false, "Delivery could not be confirmed. No automatic retry was made; choose the button to try again.")
        } finally {
            response?.close()
            submission?.close()
        }
    }

    private data class RecoveryRetryResult(val accepted: Boolean, val message: String)

    private fun showNativeConsent(transaction: WalletLoginTransactionUrl, identity: WalletLoginIdentity, consent: NativeDisclosureReview) {
        val review = consent.review
        val layout = column()
        addText(layout, "Account information request")
        nativeDisclosureConsentLines(consent).forEach { addText(layout, it) }
        val selected = linkedSetOf<String>()
        val requiredValueUnavailable = review.claims.any { it.required && it.value == null }
        review.claims.forEach { claim ->
            if (claim.required) selected += claim.id
            layout.addView(CheckBox(this).apply {
                text = "Share ${claim.id}${if (claim.required) " (required)" else " (optional)"}"
                isChecked = claim.required
                isEnabled = !claim.required && claim.value != null
                setOnCheckedChangeListener { _, checked -> if (checked) selected.add(claim.id) else selected.remove(claim.id) }
            })
        }
        if (requiredValueUnavailable) addText(layout, "A required value is unavailable. Deny this request; partial approval is not allowed.")
        val approve = Button(this).apply { text = "Approve account request"; isEnabled = !requiredValueUnavailable }
        val deny = Button(this).apply { text = "Deny" }
        val cancel = Button(this).apply { text = "Cancel" }
        val buttons = listOf(approve, deny, cancel)
        val gate = NativeDisclosureCancellationGate()
        nativeGate = gate
        approve.setOnClickListener {
            if (terminal) return@setOnClickListener
            buttons.forEach { it.isEnabled = false }
            val selectedSnapshot = selected.toSet()
            worker.execute {
                val result = try {
                    NativeDisclosureWorkflow(AndroidNativeDisclosureOperations(NativeDisclosureHttpClient(this), consent.trust, NativeWalletLoginHttpClient(this)))
                        .approve(transaction, identity.session, identity.identityId, consent, selectedSnapshot,
                            cancelled = gate::isCancelled, beginAttempt = gate::beginAttempt)
                    "Account presentation submitted. Return to the original browser to continue."
                } catch (_: Exception) { "Account request did not complete. Check the original browser; no retry was made." }
                main.post {
                    if (isFinishing || isDestroyed || gate.isCancelled()) return@post
                    terminal = true
                    showMessage(result)
                }
            }
        }
        deny.setOnClickListener { terminal = true; gate.cancel(); showMessage("Account request denied. No proof or presentation was sent.") }
        cancel.setOnClickListener { terminal = true; gate.cancel(); showMessage("Account request cancelled. No proof or presentation was sent.") }
        buttons.forEach(layout::addView)
        install(layout)
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
        nativeGate?.cancel()
        worker.shutdownNow()
        super.onDestroy()
    }

    private enum class ApprovalResult { SUBMITTED, EXPIRED, FAILED }

}

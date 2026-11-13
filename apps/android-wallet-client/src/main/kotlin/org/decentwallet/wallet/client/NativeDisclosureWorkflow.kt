package org.decentwallet.wallet.client

import org.decentwallet.wallet.android.AccountDisclosureReview
import org.decentwallet.wallet.android.AccountPresentationSubmission
import org.decentwallet.wallet.android.NativeContinuationCapability
import org.decentwallet.wallet.android.PendingAccountApproval
import org.decentwallet.wallet.android.PresentationDeliveryOutcome
import org.decentwallet.wallet.android.TrustedWalletRelyingPartyRegistration
import org.decentwallet.wallet.android.WalletLoginProofRequest
import org.decentwallet.wallet.android.WalletSession
import java.nio.charset.StandardCharsets

/** Explicit host trust. These values are never populated from disclosure context or continuation JSON. */
data class NativeDisclosureTrustConfig(
    val expectedKeycloakIssuer: String,
    val issuerJwks: Map<*, *>,
    val relyingPartyRegistration: TrustedWalletRelyingPartyRegistration,
    val keycloakDisplayName: String = "Keycloak",
)

/** The approval screen presents this immutable core review before any approval is persisted. */
internal data class NativeDisclosureReview(
    val review: AccountDisclosureReview,
    val trust: NativeDisclosureTrustConfig,
    val providerOrigin: String,
    val challenge: WalletLoginChallenge,
)

internal sealed interface NativeDisclosureStart {
    data object LoginOnly : NativeDisclosureStart
    data class Native(val review: NativeDisclosureReview) : NativeDisclosureStart
}

/** Cancellation and irreversible submit-start decisions share a monitor. */
internal class NativeDisclosureCancellationGate {
    private var cancelled = false
    @Synchronized fun cancel() { cancelled = true }
    @Synchronized fun isCancelled(): Boolean = cancelled
    @Synchronized fun beginAttempt(): Boolean = !cancelled
}

/** Kept as a production seam so host tests exercise the same ordering used by the Activity. */
internal interface NativeDisclosureOperations {
    fun fetchContext(transaction: WalletLoginTransactionUrl): NativeDisclosureContextResponse
    fun fetchChallenge(transaction: WalletLoginTransactionUrl): WalletLoginChallenge
    fun review(wallet: WalletSession, bytes: ByteArray, transaction: WalletLoginTransactionUrl, identityId: String, trust: NativeDisclosureTrustConfig): AccountDisclosureReview
    fun approve(wallet: WalletSession, review: AccountDisclosureReview, selectedIds: Set<String>): PendingAccountApproval
    fun createProof(wallet: WalletSession, pending: PendingAccountApproval, challenge: String): WalletLoginProofRequest
    fun submitProof(transaction: WalletLoginTransactionUrl, proof: ByteArray): NativeContinuationGrant
    fun persistAndAwait(wallet: WalletSession, review: AccountDisclosureReview, pending: PendingAccountApproval, grant: NativeContinuationGrant, cancelled: () -> Boolean): ContinuationReady
    fun fetchRequestObject(ready: ContinuationReady): ByteArray
    fun prepare(wallet: WalletSession, pending: PendingAccountApproval, review: AccountDisclosureReview, trust: NativeDisclosureTrustConfig, ready: ContinuationReady, requestObjectJws: String): AccountPresentationSubmission
    fun submitPresentation(submission: AccountPresentationSubmission, review: AccountDisclosureReview): PresentationHttpResult
    fun finish(wallet: WalletSession, pending: PendingAccountApproval, result: PresentationHttpResult?, ambiguous: Boolean)
}

internal class NativeDisclosureWorkflow(
    private val operations: NativeDisclosureOperations,
    private val nowEpochSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    fun start(
        transaction: WalletLoginTransactionUrl,
        wallet: WalletSession,
        identityId: String,
        trust: NativeDisclosureTrustConfig?,
    ): NativeDisclosureStart {
        val context = operations.fetchContext(transaction)
        if (context === NativeDisclosureContextResponse.LoginOnly) return NativeDisclosureStart.LoginOnly
        val native = context as? NativeDisclosureContextResponse.NativeSignup ?: error("invalid context")
        val configured = trust ?: run { native.rawContext.fill(0); error("native trust is not configured") }
        return try {
            val challenge = operations.fetchChallenge(transaction)
            check(!challenge.isExpiredAt(nowEpochSeconds()))
            val review = operations.review(wallet, native.rawContext, transaction, identityId, configured)
            check(review.nativeContinuationEnabled) // no fallback/downgrade on absent or false marker
            check(review.keycloakIssuer == configured.expectedKeycloakIssuer)
            check(review.rpClientId == configured.relyingPartyRegistration.rpClientId)
            check(review.rpOrigin == configured.relyingPartyRegistration.origin)
            NativeDisclosureStart.Native(NativeDisclosureReview(review, configured, transaction.origin, challenge))
        } finally { native.rawContext.fill(0) }
    }

    /** One affirmative consent authorizes this complete flow; no later prompt is shown. */
    fun approve(
        transaction: WalletLoginTransactionUrl,
        wallet: WalletSession,
        identityId: String,
        consent: NativeDisclosureReview,
        selectedClaimIds: Set<String>,
        cancelled: () -> Boolean,
        beginAttempt: () -> Boolean = { !cancelled() },
    ) {
        var pending: PendingAccountApproval? = null
        var submission: AccountPresentationSubmission? = null
        var postAttempted = false
        var finishAttempted = false
        var grant: NativeContinuationGrant? = null
        var response: PresentationHttpResult? = null
        var requestBytes: ByteArray? = null
        var proofBytes: ByteArray? = null
        var body: ByteArray? = null
        try {
            check(!consent.challenge.isExpiredAt(nowEpochSeconds()))
            check(!cancelled())
            pending = operations.approve(wallet, consent.review, selectedClaimIds)
            check(!consent.challenge.isExpiredAt(nowEpochSeconds()))
            check(!cancelled())
            val proof = operations.createProof(wallet, pending, consent.challenge.challenge)
            proofBytes = proof.toJsonBytes()
            check(!consent.challenge.isExpiredAt(nowEpochSeconds()))
            check(beginAttempt())
            grant = operations.submitProof(transaction, proofBytes)
            check(!cancelled())
            val ready = operations.persistAndAwait(wallet, consent.review, pending, grant, cancelled)
            check(!cancelled())
            requestBytes = operations.fetchRequestObject(ready)
            val requestObject = decodeStrictUtf8(requestBytes!!)
            submission = operations.prepare(wallet, pending, consent.review, consent.trust, ready, requestObject)
            check(!cancelled())
            body = submission.body
            // The submit invocation is the linearization point. Never retry even if it throws.
            check(beginAttempt())
            postAttempted = true
            response = operations.submitPresentation(submission, consent.review)
            // A server error can follow acceptance; preserve the exact prepared bytes for explicit recovery.
            finishAttempted = true
            operations.finish(wallet, pending, response, ambiguous = response.statusCode >= 500)
            val mediaType = response.contentType?.substringBefore(';')?.trim()
            check(response.statusCode == 200 && mediaType.equals("application/json", ignoreCase = true)) {
                "account presentation was not accepted"
            }
        } catch (failure: Exception) {
            if (pending != null && submission != null && !finishAttempted) {
                finishAttempted = true
                try {
                    operations.finish(wallet, pending, response, ambiguous = postAttempted)
                } catch (_: Exception) { }
            }
            if (pending != null && submission == null && !postAttempted) {
                try { wallet.cancelAccountDisclosureApproval(pending) } catch (_: Exception) { }
            }
            throw failure
        } finally {
            body?.fill(0)
            requestBytes?.fill(0)
            proofBytes?.fill(0)
            response?.close()
            grant?.close()
            submission?.close()
        }
    }

    private fun decodeStrictUtf8(bytes: ByteArray): String = StandardCharsets.UTF_8.newDecoder()
        .decode(java.nio.ByteBuffer.wrap(bytes)).toString()
}

internal fun nativeDisclosureConsentLines(consent: NativeDisclosureReview): List<String> {
    val review = consent.review
    val action = when (review.action) {
        "signup" -> "signup — creates a new Keycloak identity"
        "signup_recovery" -> "signup recovery — creates an account for an existing Keycloak identity"
        else -> error("unsupported native disclosure action")
    }
    return buildList {
        add("Keycloak site: ${consent.trust.keycloakDisplayName} (${consent.providerOrigin})")
        add("Identity to sign exactly: ${review.identityId}")
        add("Relying party: ${review.rpDisplayName} (${review.rpClientId})")
        add("RP origin: ${review.rpOrigin}")
        add("Action: $action")
        add("Purpose: ${review.purpose}")
        add("Identity privacy: this exact Identity ID appears as issuer and subject. The stable Owner-Key thumbprint appears in the credential and Keycloak binding; presentations can be correlated across sites. V1 has no pairwise identifier.")
        add("The requested values are owner-asserted. Contact claims are not verified by this signature.")
        review.claims.forEach { claim ->
            add("${claim.id} — ${if (claim.required) "required" else "optional"}\nValue: ${claim.value ?: "Unavailable"}")
        }
    }
}

/** Production adapter: all parsing, trust verification and wallet state transitions stay in core. */
internal class AndroidNativeDisclosureOperations(
    private val transport: NativeDisclosureHttpClient,
    private val trust: NativeDisclosureTrustConfig?,
    private val loginTransport: NativeWalletLoginHttpClient = NativeWalletLoginHttpClient(),
) : NativeDisclosureOperations {
    override fun fetchContext(transaction: WalletLoginTransactionUrl) = transport.fetchDisclosureContext(transaction)
    override fun fetchChallenge(transaction: WalletLoginTransactionUrl) = loginTransport.getChallenge(transaction)

    override fun review(wallet: WalletSession, bytes: ByteArray, transaction: WalletLoginTransactionUrl, identityId: String, trust: NativeDisclosureTrustConfig) =
        wallet.reviewAccountDisclosure(bytes, transaction.handle, trust.expectedKeycloakIssuer, identityId)

    override fun approve(wallet: WalletSession, review: AccountDisclosureReview, selectedIds: Set<String>) =
        wallet.approveAccountDisclosure(review, selectedIds) { true }

    override fun createProof(wallet: WalletSession, pending: PendingAccountApproval, challenge: String) =
        wallet.createAccountLoginProof(pending, challenge)

    override fun submitProof(transaction: WalletLoginTransactionUrl, proof: ByteArray) = transport.submitNativeProof(transaction, proof)

    override fun persistAndAwait(wallet: WalletSession, review: AccountDisclosureReview, pending: PendingAccountApproval, grant: NativeContinuationGrant, cancelled: () -> Boolean): ContinuationReady =
        persistGrantThenAwaitNativeContinuation(
            transport, review.rpOrigin, review.transactionId, grant,
            persistCapability = { encoded, expiry -> wallet.installNativeContinuationCapability(pending, encoded, expiry) },
            cancelled = cancelled,
        )

    override fun fetchRequestObject(ready: ContinuationReady) = transport.fetchRequestObject(checkNotNull(trust).relyingPartyRegistration.origin, ready.requestUri)

    override fun prepare(wallet: WalletSession, pending: PendingAccountApproval, review: AccountDisclosureReview, trust: NativeDisclosureTrustConfig, ready: ContinuationReady, requestObjectJws: String) =
        wallet.prepareAccountPresentation(
            pending, trust.issuerJwks,
            mapOf("client_id" to ready.clientId, "request_uri" to ready.requestUri),
            requestObjectJws, trust.relyingPartyRegistration,
        )

    override fun submitPresentation(submission: AccountPresentationSubmission, review: AccountDisclosureReview): PresentationHttpResult {
        val bytes = submission.body
        return try { transport.submitPresentationOnce(submission.responseUri, review.rpOrigin, bytes) }
        finally { bytes.fill(0) }
    }

    override fun finish(wallet: WalletSession, pending: PendingAccountApproval, result: PresentationHttpResult?, ambiguous: Boolean) {
        if (ambiguous) {
            wallet.finishAccountPresentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
            return
        }
        if (result == null) {
            wallet.finishAccountPresentation(pending, PresentationDeliveryOutcome.CANCELLED)
            return
        }
        val observed = result
        val mediaType = observed.contentType?.substringBefore(';')?.trim()
        if (observed.statusCode == 200 && mediaType.equals("application/json", ignoreCase = true)) {
            wallet.finishAccountPresentation(pending, PresentationDeliveryOutcome.ACCEPTED, observed.statusCode, observed.contentType, observed.body)
        } else {
            wallet.finishAccountPresentation(pending, PresentationDeliveryOutcome.DEFINITIVE_FAILURE)
        }
    }
}

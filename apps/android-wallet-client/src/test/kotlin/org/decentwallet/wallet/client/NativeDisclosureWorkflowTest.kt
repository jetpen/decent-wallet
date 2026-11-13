package org.decentwallet.wallet.client

import org.decentwallet.wallet.android.AccountDisclosureReview
import org.decentwallet.wallet.android.AccountPresentationSubmission
import org.decentwallet.wallet.android.NativeContinuationCapability
import org.decentwallet.wallet.android.PendingAccountApproval
import org.decentwallet.wallet.android.TrustedWalletRelyingPartyRegistration
import org.decentwallet.wallet.android.WalletLoginProofRequest
import org.decentwallet.wallet.android.WalletSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

/** Host orchestration/unit evidence with scripted operations; not live or native end-to-end qualification. */
class NativeDisclosureWorkflowTest {
    @Test fun nativeContextWithoutExplicitHostTrustFailsClosedBeforeReviewOrProofAndWipesContext() {
        val directory = Files.createTempDirectory("native-workflow-test-")
        val walletFile = directory.resolve("wallet.dw")
        val wallet = org.decentwallet.wallet.android.AndroidWallet.createWithGeneratedKey(
            walletFile, "synthetic native workflow password", "synthetic native workflow password",
        )
        val context = "untrusted native context".toByteArray()
        val operations = RecordingOperations(context)
        try {
            val txn = WalletLoginTransactionUrl.parse(
                "${BuildConfig.WALLET_LOGIN_ORIGIN}/realms/demo/decent-wallet-login/v1/transactions/${"A".repeat(43)}",
                BuildConfig.WALLET_LOGIN_ORIGIN,
            )
            try {
                NativeDisclosureWorkflow(operations).start(txn, wallet, "test:identity", trust = null)
                throw AssertionError("native flow downgraded without explicit host trust")
            } catch (_: IllegalStateException) { }
            assertEquals(listOf("fetch"), operations.events)
            assertTrue(context.all { it == 0.toByte() })
        } finally {
            wallet.close()
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test fun nativeWorkflowFetchesAndUsesTheNormalChallengeBeforeConsentAndProofPost() {
        val challenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        val fixture = workflowFixture(
            challenge, now = 100L,
            reviewNonce = "UFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm8",
        )
        try {
            val consent = NativeDisclosureWorkflow(fixture.operations) { 100L }
                .start(fixture.transaction, fixture.wallet, "test:identity", fixture.trust) as NativeDisclosureStart.Native
            assertEquals(challenge, consent.review.challenge.challenge)
            assertEquals("UFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm8", consent.review.review.oidcNonce)
            val consentLines = nativeDisclosureConsentLines(consent.review)
            assertEquals("Keycloak site: Keycloak (${fixture.transaction.origin})", consentLines.first())
            assertTrue(consentLines.any { it == "Identity to sign exactly: test:identity" })
            assertTrue(consentLines.any { it == "Relying party: RP (x509_san_dns:rp.example)" })
            assertTrue(consentLines.any { it == "RP origin: https://rp.example" })
            assertTrue(consentLines.any { it.contains("signup — creates a new Keycloak identity") })
            assertTrue(consentLines.any { it == "Purpose: login" })
            assertTrue(consentLines.any { it.contains("correlated across sites") })
            assertTrue(consentLines.any { it.contains("owner-asserted") })
            assertEquals(listOf("context", "challenge", "review"), fixture.operations.events)
            val workflow = NativeDisclosureWorkflow(fixture.operations) { 100L }
            try {
                workflow.approve(fixture.transaction, fixture.wallet, "test:identity", consent.review, emptySet(), { false })
                throw AssertionError("scripted proof submission should terminate the host test")
            } catch (_: IllegalStateException) { }
            assertEquals(listOf("context", "challenge", "review", "approve", "proof:$challenge", "proof-post:$challenge"), fixture.operations.events)
            assertEquals(0, fixture.operations.presentationPosts)
        } finally { fixture.close() }
    }

    @Test fun nativeWorkflowCompletesOneConsentThroughOnePresentationPostWithoutASecondApproval() {
        val challenge = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"
        val fixture = workflowFixture(challenge, now = 100L, stopAfterProofPost = false)
        try {
            val workflow = NativeDisclosureWorkflow(fixture.operations) { 100L }
            val consent = workflow.start(fixture.transaction, fixture.wallet, "test:identity", fixture.trust) as NativeDisclosureStart.Native
            workflow.approve(fixture.transaction, fixture.wallet, "test:identity", consent.review, emptySet(), { false })
            assertEquals(
                listOf("context", "challenge", "review", "approve", "proof:$challenge", "proof-post:$challenge", "persist-capability", "poll-ready", "request-object", "prepare", "presentation-post", "finish:ACCEPTED"),
                fixture.operations.events,
            )
            assertEquals(1, fixture.operations.approvals)
            assertEquals(1, fixture.operations.proofs)
            assertEquals(1, fixture.operations.proofPosts)
            assertEquals(1, fixture.operations.presentationPosts)
        } finally { fixture.close() }
    }

    @Test fun serverErrorAfterPresentationPostIsAmbiguousAndNeverAutomaticallyRetried() {
        val fixture = workflowFixture(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", now = 100L,
            stopAfterProofPost = false, presentationStatusCode = 503,
        )
        try {
            val workflow = NativeDisclosureWorkflow(fixture.operations) { 100L }
            val consent = workflow.start(fixture.transaction, fixture.wallet, "test:identity", fixture.trust) as NativeDisclosureStart.Native
            try {
                workflow.approve(fixture.transaction, fixture.wallet, "test:identity", consent.review, emptySet(), { false })
                throw AssertionError("503 must not be reported as successful submission")
            } catch (_: IllegalStateException) { }
            assertEquals("finish:AMBIGUOUS", fixture.operations.events.last())
            assertEquals(1, fixture.operations.approvals)
            assertEquals(1, fixture.operations.proofs)
            assertEquals(1, fixture.operations.proofPosts)
            assertEquals(1, fixture.operations.presentationPosts)
        } finally { fixture.close() }
    }

    @Test fun clientErrorAfterPresentationPostIsDefinitiveAndNeverRetried() {
        val fixture = workflowFixture(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", now = 100L,
            stopAfterProofPost = false, presentationStatusCode = 400,
        )
        try {
            val workflow = NativeDisclosureWorkflow(fixture.operations) { 100L }
            val consent = workflow.start(fixture.transaction, fixture.wallet, "test:identity", fixture.trust) as NativeDisclosureStart.Native
            try {
                workflow.approve(fixture.transaction, fixture.wallet, "test:identity", consent.review, emptySet(), { false })
                throw AssertionError("400 must not be reported as successful submission")
            } catch (_: IllegalStateException) { }
            assertEquals("finish:FAILURE", fixture.operations.events.last())
            assertEquals(1, fixture.operations.approvals)
            assertEquals(1, fixture.operations.proofs)
            assertEquals(1, fixture.operations.proofPosts)
            assertEquals(1, fixture.operations.presentationPosts)
        } finally { fixture.close() }
    }

    @Test fun finalizationFailureIsNotRetried() {
        val fixture = workflowFixture(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", now = 100L,
            stopAfterProofPost = false, finishThrows = true,
        )
        try {
            val workflow = NativeDisclosureWorkflow(fixture.operations) { 100L }
            val consent = workflow.start(fixture.transaction, fixture.wallet, "test:identity", fixture.trust) as NativeDisclosureStart.Native
            try {
                workflow.approve(fixture.transaction, fixture.wallet, "test:identity", consent.review, emptySet(), { false })
                throw AssertionError("finalization failure must propagate")
            } catch (_: IllegalStateException) { }
            assertEquals(1, fixture.operations.finishCalls)
            assertEquals(1, fixture.operations.presentationPosts)
        } finally { fixture.close() }
    }

    @Test fun cancellationAfterConsentPreventsApprovalProofAndAllPosts() {
        val fixture = workflowFixture("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", now = 100L)
        try {
            val workflow = NativeDisclosureWorkflow(fixture.operations) { 100L }
            val consent = workflow.start(fixture.transaction, fixture.wallet, "test:identity", fixture.trust) as NativeDisclosureStart.Native
            try {
                workflow.approve(fixture.transaction, fixture.wallet, "test:identity", consent.review, emptySet(), { true })
                throw AssertionError("cancelled consent must not continue")
            } catch (_: IllegalStateException) { }
            assertEquals(listOf("context", "challenge", "review"), fixture.operations.events)
            assertEquals(0, fixture.operations.approvals + fixture.operations.proofs + fixture.operations.proofPosts + fixture.operations.presentationPosts)
        } finally { fixture.close() }
    }

    @Test fun challengeExpiryAfterConsentPreventsApprovalProofAndAllPosts() {
        val fixture = workflowFixture("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", now = 100L, expiry = 160L)
        var now = 100L
        try {
            val workflow = NativeDisclosureWorkflow(fixture.operations) { now }
            val consent = workflow.start(fixture.transaction, fixture.wallet, "test:identity", fixture.trust) as NativeDisclosureStart.Native
            now = 160L
            try {
                workflow.approve(fixture.transaction, fixture.wallet, "test:identity", consent.review, emptySet(), { false })
                throw AssertionError("expired consent must not continue")
            } catch (_: IllegalStateException) { }
            assertEquals(listOf("context", "challenge", "review"), fixture.operations.events)
            assertEquals(0, fixture.operations.approvals + fixture.operations.proofs + fixture.operations.proofPosts + fixture.operations.presentationPosts)
        } finally { fixture.close() }
    }

    @Test fun expiredChallengeFailsBeforeReviewApprovalProofOrAnyPost() {
        val fixture = workflowFixture("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", now = 200L, expiry = 200L)
        try {
            try {
                NativeDisclosureWorkflow(fixture.operations) { 200L }
                    .start(fixture.transaction, fixture.wallet, "test:identity", fixture.trust)
                throw AssertionError("expired challenge must fail closed")
            } catch (_: IllegalStateException) { }
            assertEquals(listOf("context", "challenge"), fixture.operations.events)
            assertEquals(0, fixture.operations.approvals + fixture.operations.proofs + fixture.operations.proofPosts + fixture.operations.presentationPosts)
        } finally { fixture.close() }
    }

    private fun workflowFixture(
        challenge: String,
        now: Long,
        expiry: Long = now + 60,
        reviewNonce: String = challenge,
        stopAfterProofPost: Boolean = true,
        presentationStatusCode: Int = 200,
        finishThrows: Boolean = false,
    ): WorkflowFixture {
        val directory = Files.createTempDirectory("native-binding-test-")
        val wallet = org.decentwallet.wallet.android.AndroidWallet.createWithGeneratedKey(
            directory.resolve("wallet.dw"), "synthetic native workflow password", "synthetic native workflow password",
        )
        val transaction = WalletLoginTransactionUrl.parse(
            "${BuildConfig.WALLET_LOGIN_ORIGIN}/realms/demo/decent-wallet-login/v1/transactions/${"A".repeat(43)}",
            BuildConfig.WALLET_LOGIN_ORIGIN,
        )
        val rp = TrustedWalletRelyingPartyRegistration("x509_san_dns:rp.example", "rp.example", "https://rp.example", "https://rp.example/response", "a".repeat(64), "x509_san_dns:rp.example")
        val trust = NativeDisclosureTrustConfig("https://issuer.example", emptyMap<String, Any>(), rp)
        val review = syntheticReview(reviewNonce, now + 100)
        val operations = WorkflowRecordingOperations(challenge, expiry, review, stopAfterProofPost, presentationStatusCode, finishThrows)
        return WorkflowFixture(directory, wallet, transaction, trust, operations)
    }

    private fun syntheticReview(nonce: String, expiry: Long): AccountDisclosureReview {
        val ctor = AccountDisclosureReview::class.java.declaredConstructors.single { it.parameterCount == 13 }
        ctor.isAccessible = true
        return ctor.newInstance("https://issuer.example", "x509_san_dns:rp.example", "RP", "https://rp.example", "signup", "request-id", "A".repeat(43), nonce, "login", emptyList<Any>(), "test:identity", expiry, true) as AccountDisclosureReview
    }

    private data class WorkflowFixture(
        val directory: java.nio.file.Path, val wallet: WalletSession,
        val transaction: WalletLoginTransactionUrl, val trust: NativeDisclosureTrustConfig, val operations: WorkflowRecordingOperations,
    ) { fun close() { wallet.close(); Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } } }

    private class WorkflowRecordingOperations(
        private val challengeValue: String,
        private val challengeExpiry: Long,
        private val reviewed: AccountDisclosureReview,
        private val stopAfterProofPost: Boolean,
        private val presentationStatusCode: Int,
        private val finishThrows: Boolean,
    ) : NativeDisclosureOperations {
        val events = mutableListOf<String>()
        var approvals = 0; private set
        var proofs = 0; private set
        var proofPosts = 0; private set
        var presentationPosts = 0; private set
        var finishCalls = 0; private set
        override fun fetchContext(transaction: WalletLoginTransactionUrl): NativeDisclosureContextResponse { events += "context"; return NativeDisclosureContextResponse.NativeSignup(byteArrayOf(1)) }
        override fun fetchChallenge(transaction: WalletLoginTransactionUrl): WalletLoginChallenge { events += "challenge"; return WalletLoginChallenge("decent-wallet-login-v1", challengeValue, challengeExpiry) }
        override fun review(wallet: WalletSession, bytes: ByteArray, transaction: WalletLoginTransactionUrl, identityId: String, trust: NativeDisclosureTrustConfig): AccountDisclosureReview { events += "review"; return reviewed }
        override fun approve(wallet: WalletSession, review: AccountDisclosureReview, selectedIds: Set<String>): PendingAccountApproval {
            events += "approve"; approvals++
            val ctor = PendingAccountApproval::class.java.declaredConstructors.single { it.parameterCount == 3 }; ctor.isAccessible = true
            return ctor.newInstance("pending", System.currentTimeMillis() / 1000 + 60, System.currentTimeMillis() / 1000) as PendingAccountApproval
        }
        override fun createProof(wallet: WalletSession, pending: PendingAccountApproval, challenge: String): WalletLoginProofRequest { events += "proof:$challenge"; proofs++; return WalletLoginProofRequest("decent-wallet-login-v1", challenge, "test:identity", java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(64))) }
        override fun submitProof(transaction: WalletLoginTransactionUrl, proof: ByteArray): NativeContinuationGrant {
            val value = StrictNativeJson.objectValue(proof)["challenge"] as String
            events += "proof-post:$value"; proofPosts++
            if (stopAfterProofPost) throw IllegalStateException("stop after observing proof post")
            val capability = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 3 })
            val expiry = System.currentTimeMillis() / 1000 + 120
            return NativeContinuationGrant.parse("""{"profile":"decent-account-disclosure-v1","decent_account_continuation_capability":"$capability","expires_at":$expiry}""".toByteArray())
        }
        override fun persistAndAwait(wallet: WalletSession, review: AccountDisclosureReview, pending: PendingAccountApproval, grant: NativeContinuationGrant, cancelled: () -> Boolean): ContinuationReady {
            events += "persist-capability"; events += "poll-ready"
            return ContinuationReady("x509_san_dns:rp.example", "https://rp.example/request")
        }
        override fun fetchRequestObject(ready: ContinuationReady): ByteArray { events += "request-object"; return "signed-request-object".toByteArray() }
        override fun prepare(wallet: WalletSession, pending: PendingAccountApproval, review: AccountDisclosureReview, trust: NativeDisclosureTrustConfig, ready: ContinuationReady, requestObjectJws: String): AccountPresentationSubmission {
            events += "prepare"
            val ctor = AccountPresentationSubmission::class.java.declaredConstructors.single { it.parameterCount == 5 }; ctor.isAccessible = true
            return ctor.newInstance(pending, "https://rp.example/response", "state", "presentation-jws", "state=state&vp_token=exact".toByteArray()) as AccountPresentationSubmission
        }
        override fun submitPresentation(submission: AccountPresentationSubmission, review: AccountDisclosureReview): PresentationHttpResult {
            events += "presentation-post"; presentationPosts++
            return PresentationHttpResult(presentationStatusCode, "application/json", "{}".toByteArray())
        }
        override fun finish(wallet: WalletSession, pending: PendingAccountApproval, result: PresentationHttpResult?, ambiguous: Boolean) {
            finishCalls++
            events += "finish:${if (ambiguous) "AMBIGUOUS" else if (result?.statusCode == 200) "ACCEPTED" else "FAILURE"}"
            if (finishThrows) throw IllegalStateException("synthetic finish failure")
        }
    }

    private class RecordingOperations(private val contextBytes: ByteArray) : NativeDisclosureOperations {
        val events = mutableListOf<String>()
        override fun fetchContext(transaction: WalletLoginTransactionUrl): NativeDisclosureContextResponse {
            events += "fetch"
            return NativeDisclosureContextResponse.NativeSignup(contextBytes)
        }
        override fun fetchChallenge(transaction: WalletLoginTransactionUrl): WalletLoginChallenge = error("unexpected challenge")
        override fun review(wallet: WalletSession, bytes: ByteArray, transaction: WalletLoginTransactionUrl, identityId: String, trust: NativeDisclosureTrustConfig): AccountDisclosureReview {
            events += "review"
            error("review must not run without explicit trust")
        }
        override fun approve(wallet: WalletSession, review: AccountDisclosureReview, selectedIds: Set<String>): PendingAccountApproval = error("unexpected approve")
        override fun createProof(wallet: WalletSession, pending: PendingAccountApproval, challenge: String): WalletLoginProofRequest = error("unexpected proof")
        override fun submitProof(transaction: WalletLoginTransactionUrl, proof: ByteArray): NativeContinuationGrant = error("unexpected proof post")
        override fun persistAndAwait(wallet: WalletSession, review: AccountDisclosureReview, pending: PendingAccountApproval, grant: NativeContinuationGrant, cancelled: () -> Boolean): ContinuationReady = error("unexpected polling")
        override fun fetchRequestObject(ready: ContinuationReady): ByteArray = error("unexpected request fetch")
        override fun prepare(wallet: WalletSession, pending: PendingAccountApproval, review: AccountDisclosureReview, trust: NativeDisclosureTrustConfig, ready: ContinuationReady, requestObjectJws: String): AccountPresentationSubmission = error("unexpected preparation")
        override fun submitPresentation(submission: AccountPresentationSubmission, review: AccountDisclosureReview): PresentationHttpResult = error("unexpected presentation post")
        override fun finish(wallet: WalletSession, pending: PendingAccountApproval, result: PresentationHttpResult?, ambiguous: Boolean) = error("unexpected finish")
    }
}

package org.decentwallet.wallet.client

import android.content.Intent
import android.net.Uri
import android.widget.CheckBox
import android.view.View
import android.view.ViewGroup
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.decentwallet.wallet.android.AndroidWallet
import org.decentwallet.wallet.android.TrustedWalletRelyingPartyRegistration
import org.decentwallet.wallet.android.WalletLoginProofRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.math.BigInteger
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import java.util.UUID
import java.util.concurrent.TimeUnit
import org.json.JSONArray
import org.json.JSONObject

@RunWith(AndroidJUnit4::class)
class NativeDisclosureActivityInstrumentedTest {
    private val walletPassword = "synthetic-native-activity-wallet-password"

    @Test
    fun nativeSignupConsentPersistsContinuationAndSubmitsOneVerifiedPresentation() {
        runNativeSignup(bindingTransactionMismatch = false)
    }

    @Test
    fun postOidcBindingTransactionMismatchSendsNoPresentation() {
        runNativeSignup(bindingTransactionMismatch = true)
    }

    @Test
    fun persistedPresentationIsRecoveredOnlyAfterExplicitRetry() {
        runNativeSignup(bindingTransactionMismatch = false, exerciseRecovery = true)
    }

    @Test
    fun definitiveRetryResponseConsumesSavedPresentation() {
        runNativeSignup(bindingTransactionMismatch = false, exerciseRecovery = true, definitiveRetry = true)
    }

    @Test
    fun acceptanceFinalizationFailureDoesNotInviteAnotherRetry() {
        runNativeSignup(bindingTransactionMismatch = false, exerciseRecovery = true, finalizationFailure = true)
    }

    private fun runNativeSignup(
        bindingTransactionMismatch: Boolean,
        exerciseRecovery: Boolean = false,
        definitiveRetry: Boolean = false,
        finalizationFailure: Boolean = false,
    ) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val walletFile = File(context.cacheDir, "wallet-native-activity-${UUID.randomUUID()}.wallet")
        val identityId = "test:native-activity-${UUID.randomUUID()}"
        var session = AndroidWallet.createWithGeneratedKey(walletFile.toPath(), walletPassword, walletPassword)
        val marker = "Ada-Activity-${UUID.randomUUID()}"
        val email = "native-${UUID.randomUUID()}@example.test"
        val ownerPublicKey = session.ownerPublicKey
        var fixture: NativeFixture? = null
        try {
            session.setMasterAccountEntity(mapOf("given_name" to marker, "email" to email))
            val activeFixture = NativeFixture(bindingTransactionMismatch, ownerPublicKey, identityId, exerciseRecovery)
            fixture = activeFixture
            activeFixture.start()
            DebugWalletLoginApplication.install(
                WalletLoginIdentity(session, identityId),
                activeFixture.trust,
            )
            ActivityScenario.launch<WalletLoginActivity>(intent(context, activeFixture.transactionPath)).use { scenario ->
                waitUntil(scenario, diagnostic = { " (requests=${activeFixture.server.requestCount})" }) { texts ->
                    texts.any { it == "Account information request" } &&
                        texts.any { it.contains(marker) } && texts.any { it.contains(email) }
                }
                scenario.onActivity { activity ->
                    findCheckBox(activity.window.decorView, "Share urn:decent:account:v1:email (optional)").performClick()
                    WalletLoginTestViews.button(activity.window.decorView, "Approve account request").performClick()
                }

                val contextGet = request(activeFixture.server)
                assertEquals("GET", contextGet.method)
                assertEquals("${activeFixture.transactionPath}/disclosure-context", contextGet.path)
                val challengeGet = request(activeFixture.server)
                assertEquals("GET", challengeGet.method)
                assertEquals(activeFixture.transactionPath, challengeGet.path)
                val proofPost = request(activeFixture.server)
                assertEquals("POST", proofPost.method)
                assertEquals(activeFixture.transactionPath, proofPost.path)
                val proofBytes = proofPost.body.readByteArray()
                try {
                    val json = JSONObject(String(proofBytes, StandardCharsets.UTF_8))
                    assertEquals(setOf("profile", "challenge", "identity_id", "signature"), json.keys().asSequence().toSet())
                    val proof = WalletLoginProofRequest(
                        json.getString("profile"), json.getString("challenge"),
                        json.getString("identity_id"), json.getString("signature"),
                    )
                    assertEquals("decent-wallet-login-v1", proof.profile)
                    assertEquals(activeFixture.challenge, proof.challenge)
                    assertEquals(identityId, proof.identityId)
                    assertTrue("native proof did not verify against the wallet key", proof.verifyAgainst(ownerPublicKey))
                } finally {
                    proofBytes.fill(0)
                }

                val poll = request(activeFixture.server)
                assertEquals("GET", poll.method)
                assertEquals("/oid4vp/continuations/${activeFixture.transactionId}", poll.path)
                assertEquals("Bearer ${activeFixture.capability}", poll.getHeader("Authorization"))
                val requestObject = request(activeFixture.server)
                assertEquals("GET", requestObject.method)
                assertEquals(activeFixture.requestPath, requestObject.path)
                assertEquals("application/oauth-authz-req+jwt", requestObject.getHeader("Accept"))

                if (bindingTransactionMismatch) {
                    waitUntil(scenario) { texts -> texts.any { it.contains("did not complete") } }
                    assertEquals("mismatched authenticated continuation produced a POST", 5, activeFixture.server.requestCount)
                    assertNoRequest(activeFixture.server)
                } else if (exerciseRecovery) {
                    val firstPresentationPost = request(activeFixture.server)
                    assertEquals("POST", firstPresentationPost.method)
                    assertEquals(activeFixture.responsePath, firstPresentationPost.path)
                    val preparedBody = firstPresentationPost.body.readByteArray()
                    try {
                        waitUntil(scenario) { texts -> texts.any { it.contains("did not complete") } }
                        assertEquals("initial flow should send exactly one presentation", 6, activeFixture.server.requestCount)
                        assertNoRequest(activeFixture.server)
                        scenario.close()
                        session.close()
                        DebugWalletLoginApplication.clear()
                        session = AndroidWallet.open(walletFile.toPath(), walletPassword)
                        DebugWalletLoginApplication.install(WalletLoginIdentity(session, identityId))
                        ActivityScenario.launch<WalletLoginActivity>(intent(context, activeFixture.transactionPath)).use { untrusted ->
                            waitUntil(untrusted) { texts -> texts.any { it.contains("trust is unavailable") } }
                            assertEquals("missing configured trust must not disclose", 6, activeFixture.server.requestCount)
                            assertNoRequest(activeFixture.server)
                        }
                        DebugWalletLoginApplication.clear()
                        val mismatchedRegistration = activeFixture.trust.relyingPartyRegistration.copy(
                            responseUri = "https://localhost:8443/oid4vp/not-the-registered-response",
                        )
                        DebugWalletLoginApplication.install(
                            WalletLoginIdentity(session, identityId),
                            activeFixture.trust.copy(relyingPartyRegistration = mismatchedRegistration),
                        )
                        ActivityScenario.launch<WalletLoginActivity>(intent(context, activeFixture.transactionPath)).use { mismatched ->
                            waitUntil(mismatched) { texts -> texts.any { it.contains("cannot be retried") } }
                            assertEquals("registration mismatch must not disclose", 6, activeFixture.server.requestCount)
                            assertNoRequest(activeFixture.server)
                        }
                        DebugWalletLoginApplication.clear()
                        DebugWalletLoginApplication.install(WalletLoginIdentity(session, identityId), activeFixture.trust)
                        activeFixture.enqueueAmbiguousRetry()
                        if (definitiveRetry) activeFixture.enqueueDefinitiveRetry()
                        else if (finalizationFailure) activeFixture.enqueueUnverifiableAcceptanceRetry()
                        else activeFixture.enqueueAcceptedRetry()
                        ActivityScenario.launch<WalletLoginActivity>(intent(context, activeFixture.transactionPath)).use { reopened ->
                            waitUntil(reopened) { texts ->
                                texts.any { it.contains("Delivery may be ambiguous") } &&
                                    texts.any { it.contains("https://localhost:8443") } &&
                                    texts.any { it.contains("Retry saved presentation") }
                            }
                            assertEquals("reopen must not automatically resend or start a new transaction", 6, activeFixture.server.requestCount)
                            assertNoRequest(activeFixture.server)
                            reopened.onActivity { activity ->
                                WalletLoginTestViews.button(activity.window.decorView, "Retry saved presentation").performClick()
                            }
                            val retry = request(activeFixture.server)
                            assertEquals("POST", retry.method)
                            assertEquals(activeFixture.responsePath, retry.path)
                            assertEquals("application/x-www-form-urlencoded", retry.getHeader("Content-Type")?.substringBefore(';'))
                            val retryBody = retry.body.readByteArray()
                            try { assertTrue("retry changed the persisted submission bytes", preparedBody.contentEquals(retryBody)) }
                            finally { retryBody.fill(0) }
                            waitUntil(reopened) { texts -> texts.any { it.contains("Delivery remains ambiguous") } }
                            assertEquals("ambiguous retry must remain recoverable with no automatic second POST", 7, activeFixture.server.requestCount)
                            assertNoRequest(activeFixture.server)
                            reopened.onActivity { activity ->
                                WalletLoginTestViews.button(activity.window.decorView, "Retry saved presentation").performClick()
                            }
                            val terminalRetry = request(activeFixture.server)
                            assertEquals("POST", terminalRetry.method)
                            assertEquals(activeFixture.responsePath, terminalRetry.path)
                            val terminalRetryBody = terminalRetry.body.readByteArray()
                            try { assertTrue("terminal retry changed the persisted submission bytes", preparedBody.contentEquals(terminalRetryBody)) }
                            finally { terminalRetryBody.fill(0) }
                            if (definitiveRetry) {
                                waitUntil(reopened) { texts -> texts.any { it.contains("rejected the presentation") } }
                                reopened.onActivity { activity ->
                                    assertTrue("definitive response left retry enabled", !WalletLoginTestViews.button(activity.window.decorView, "Retry saved presentation").isEnabled)
                                }
                                assertEquals(null, session.recoverPendingAccountApproval())
                                assertEquals("each explicit owner action must produce only one retry", 8, activeFixture.server.requestCount)
                                assertNoRequest(activeFixture.server)
                            } else if (finalizationFailure) {
                                waitUntil(reopened) { texts -> texts.any { it.contains("could not be safely confirmed") } }
                                reopened.onActivity { activity ->
                                    assertTrue("unknown finalization outcome left retry enabled", !WalletLoginTestViews.button(activity.window.decorView, "Retry saved presentation").isEnabled)
                                }
                                assertEquals("one owner tap must make one retry", 8, activeFixture.server.requestCount)
                                assertNoRequest(activeFixture.server)
                            } else {
                                waitUntil(reopened) { texts -> texts.any { it.contains("verified acceptance") } }
                                assertEquals("each explicit owner action must produce only one retry", 8, activeFixture.server.requestCount)
                                assertEquals(null, session.recoverPendingAccountApproval())
                                assertNoRequest(activeFixture.server)
                            }
                        }
                        if (!finalizationFailure) {
                            scenario.close()
                            activeFixture.enqueueNormalLoginRelaunch()
                            ActivityScenario.launch<WalletLoginActivity>(intent(context, activeFixture.transactionPath)).use { relaunched ->
                                waitUntil(relaunched) { texts -> texts.any { it == "Wallet login request" } }
                                val relaunchRequests = mutableListOf<RecordedRequest>()
                                val quietDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
                                while (System.nanoTime() < quietDeadline) {
                                    val next = activeFixture.server.takeRequest(250, TimeUnit.MILLISECONDS) ?: break
                                    relaunchRequests += next
                                }
                                assertTrue("consumed state should allow the current transaction flow to start", relaunchRequests.any {
                                    it.method == "GET" && it.path == "${activeFixture.transactionPath}/disclosure-context"
                                })
                                assertTrue("current login-only flow should fetch only its challenge", relaunchRequests.any {
                                    it.method == "GET" && it.path == activeFixture.transactionPath
                                })
                                assertTrue("consumed presentation was replayed after relaunch", relaunchRequests.all { it.method == "GET" })
                                assertEquals(null, session.recoverPendingAccountApproval())
                            }
                        }
                    } finally {
                        preparedBody.fill(0)
                    }
                } else {
                    val presentationPost = request(activeFixture.server)
                    assertEquals("POST", presentationPost.method)
                    assertEquals(activeFixture.responsePath, presentationPost.path)
                    assertEquals("application/x-www-form-urlencoded", presentationPost.getHeader("Content-Type")?.substringBefore(';'))
                    waitUntil(scenario) { texts -> texts.any { it.contains("Account presentation submitted") } }
                    assertEquals("expected one OID4VP presentation POST", 6, activeFixture.server.requestCount)
                    verifyPresentationPost(presentationPost, activeFixture, ownerPublicKey, identityId, marker, email)
                    assertNoRequest(activeFixture.server)
                }
            }
        } finally {
            DebugWalletLoginApplication.clear()
            ownerPublicKey.fill(0)
            try {
                session.close()
            } finally {
                try {
                    fixture?.close()
                } finally {
                    walletFile.delete()
                }
            }
        }
    }

    private fun verifyPresentationPost(
        request: RecordedRequest,
        fixture: NativeFixture,
        ownerPublicKey: ByteArray,
        identityId: String,
        givenName: String,
        email: String,
    ) {
        val body = request.body.readByteArray()
        try {
            val fields = body.toString(StandardCharsets.US_ASCII).split('&').map { pair ->
                val separator = pair.indexOf('=')
                require(separator > 0)
                URLDecoder.decode(pair.substring(0, separator), "UTF-8") to
                    URLDecoder.decode(pair.substring(separator + 1), "UTF-8")
            }
            assertEquals(listOf("state", "vp_token"), fields.map { it.first })
            assertEquals(fixture.oid4vpState, fields[0].second)
            val vpToken = JSONObject(fields[1].second)
            assertEquals(setOf("account"), vpToken.keys().asSequence().toSet())
            val presentations = vpToken.getJSONArray("account")
            assertEquals(1, presentations.length())
            val presentation = verifyEd25519Jws(presentations.getString(0), ownerPublicKey)
            assertEquals("decent-account-disclosure-v1", presentation.getString("profile"))
            assertEquals(identityId, presentation.getString("iss"))
            assertEquals(identityId, presentation.getString("sub"))
            assertEquals(fixture.oid4vpClientId, presentation.getString("aud"))
            assertEquals(fixture.oid4vpNonce, presentation.getString("nonce"))
            val vp = presentation.getJSONObject("vp")
            assertEquals(listOf("decent_account_presentation_v1"), vp.getJSONArray("type").toStringList())
            val credentials = vp.getJSONArray("verifiableCredential")
            assertEquals(1, credentials.length())
            val credential = verifyEd25519Jws(credentials.getString(0), ownerPublicKey)
            assertEquals(identityId, credential.getString("iss"))
            assertEquals(identityId, credential.getString("sub"))
            val claims = credential.getJSONObject("claims")
            assertEquals(setOf("urn:decent:account:v1:given_name", "urn:decent:account:v1:email"), claims.keys().asSequence().toSet())
            assertEquals(givenName, claims.getString("urn:decent:account:v1:given_name"))
            assertEquals(email, claims.getString("urn:decent:account:v1:email"))
            assertEquals("signup", credential.getString("action"))
        } finally {
            body.fill(0)
        }
    }

    private fun verifyEd25519Jws(compact: String, publicKey: ByteArray): JSONObject {
        val parts = compact.split('.')
        assertEquals(3, parts.size)
        val decoder = Base64.getUrlDecoder()
        val headerBytes = decoder.decode(parts[0])
        val payloadBytes = decoder.decode(parts[1])
        val signature = decoder.decode(parts[2])
        try {
            val header = JSONObject(String(headerBytes, StandardCharsets.UTF_8))
            assertEquals("EdDSA", header.getString("alg"))
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            val signingInput = "${parts[0]}.${parts[1]}".toByteArray(StandardCharsets.US_ASCII)
            verifier.update(signingInput, 0, signingInput.size)
            signingInput.fill(0)
            assertTrue("wallet presentation signature was invalid", verifier.verifySignature(signature))
            return JSONObject(String(payloadBytes, StandardCharsets.UTF_8))
        } finally {
            headerBytes.fill(0)
            payloadBytes.fill(0)
            signature.fill(0)
        }
    }

    private fun intent(context: android.content.Context, transactionPath: String): Intent = Intent(Intent.ACTION_VIEW)
        .setClass(context, WalletLoginActivity::class.java)
        .setData(Uri.parse("${BuildConfig.WALLET_LOGIN_ORIGIN}$transactionPath"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    private fun waitUntil(
        scenario: ActivityScenario<WalletLoginActivity>,
        diagnostic: () -> String = { "" },
        predicate: (List<String>) -> Boolean,
    ) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15)
        var lastTexts: List<String> = emptyList()
        while (System.nanoTime() < deadline) {
            scenario.onActivity { activity -> lastTexts = WalletLoginTestViews.texts(activity.window.decorView) }
            if (predicate(lastTexts)) return
            Thread.sleep(50)
        }
        throw AssertionError("expected native disclosure Activity screen did not appear; visible text=$lastTexts${diagnostic()}")
    }

    private fun findCheckBox(root: View, label: String): CheckBox {
        if (root is CheckBox && root.text == label) return root
        if (root is ViewGroup) for (index in 0 until root.childCount) {
            try { return findCheckBox(root.getChildAt(index), label) } catch (_: NoSuchElementException) { }
        }
        throw NoSuchElementException(label)
    }

    private fun request(server: MockWebServer): RecordedRequest =
        requireNotNull(server.takeRequest(15, TimeUnit.SECONDS)) { "expected HTTP request was not observed" }

    private fun assertNoRequest(server: MockWebServer) {
        assertEquals("unexpected extra HTTP request", null, server.takeRequest(300, TimeUnit.MILLISECONDS))
    }

    private inner class NativeFixture(
        private val bindingTransactionMismatch: Boolean,
        ownerPublicKey: ByteArray,
        identityId: String,
        private val ambiguousFirstPost: Boolean = false,
    ) : AutoCloseable {
        val server = MockWebServer()
        val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { (it + 41).toByte() })
        val capabilityBytes = ByteArray(32) { (it + 91).toByte() }
        val capability = Base64.getUrlEncoder().withoutPadding().encodeToString(capabilityBytes)
        val now = System.currentTimeMillis() / 1000
        val capabilityExpiry = now + 240
        val transactionHandle: String
        val transactionId: String
        val transactionPath: String
        val requestPath = "/oid4vp/requests/native-test-request"
        val responsePath = "/oid4vp/direct_post"
        val oid4vpClientId = "x509_san_dns:localhost"
        val oid4vpState: String
        val oid4vpNonce: String
        val trust: org.decentwallet.wallet.client.NativeDisclosureTrustConfig
        private val currentOwnerPublicKey = ownerPublicKey.copyOf()
        private val currentIdentityId = identityId
        private val responses: NativeResponses

        init {
            val nativeVector = assetJson("continuation_vectors.native.json")
            val positive = nativeVector.getJSONObject("positive")
            val bundle = positive.getJSONObject("bundle")
            transactionHandle = bundle.getString("transaction_handle")
            transactionId = positive.getJSONObject("context").getString("transaction_id")
            transactionPath = "/realms/demo/decent-wallet-login/v1/transactions/$transactionHandle"

            val keycloakContext = positive.getJSONObject("context")
            keycloakContext.put("rp_origin", "https://localhost:8443")
            keycloakContext.put("expires_at", now + 280)
            val contextBody = keycloakContext.toString()

            val issuerPair = KeyPairGenerator.getInstance("RSA").run {
                initialize(2048)
                generateKeyPair()
            }
            val issuerPublic = issuerPair.public as RSAPublicKey
            val proofExpiry = capabilityExpiry
            val registration = createRequestObject(bundle, keycloakContext, issuerPair.private, proofExpiry).also {
                oid4vpState = it.state
                oid4vpNonce = it.nonce
            }
            val trustJwks = mapOf(
                "keys" to listOf(
                    mapOf(
                        "kid" to "instrumentation-keycloak-signing-key",
                        "kty" to "RSA",
                        "use" to "sig",
                        "alg" to "RS256",
                        "n" to base64Url(unsigned(issuerPublic.modulus.toByteArray())),
                        "e" to base64Url(unsigned(issuerPublic.publicExponent.toByteArray())),
                    ),
                ),
            )
            trust = org.decentwallet.wallet.client.NativeDisclosureTrustConfig(
                expectedKeycloakIssuer = keycloakContext.getString("keycloak_issuer"),
                issuerJwks = trustJwks,
                relyingPartyRegistration = registration.registration,
                keycloakDisplayName = "Test Keycloak",
            )

            responses = NativeResponses(
                contextBody = contextBody,
                capabilityBody = JSONObject().put("profile", "decent-account-disclosure-v1")
                    .put("decent_account_continuation_capability", capability)
                    .put("expires_at", capabilityExpiry).toString(),
                requestObject = registration.compactJws,
            )
        }

        fun start() {
            val assets = InstrumentationRegistry.getInstrumentation().context.assets
            val certificate = assets.open("wallet_login_test_cert.pem").use {
                CertificateFactory.getInstance("X.509").generateCertificate(it) as java.security.cert.X509Certificate
            }
            val keyPem = assets.open("wallet_login_test_ca_key_pkcs8.pem").bufferedReader().use { it.readText() }
            val keyDer = Base64.getDecoder().decode(keyPem.lineSequence().filterNot { it.startsWith("---") }.joinToString(""))
            val privateKey = java.security.KeyFactory.getInstance("RSA")
                .generatePrivate(java.security.spec.PKCS8EncodedKeySpec(keyDer))
            keyDer.fill(0)
            val held = HeldCertificate(KeyPair(certificate.publicKey, privateKey), certificate)
            val serverTls = HandshakeCertificates.Builder().heldCertificate(held).build()
            server.useHttps(serverTls.sslSocketFactory(), false)
            server.enqueue(response(200, responses.contextBody, "application/json"))
            server.enqueue(response(200, JSONObject().put("profile", "decent-wallet-login-v1")
                .put("challenge", challenge).put("csrf_token", "fixture-only").toString(), "application/json"))
            server.enqueue(response(200, responses.capabilityBody, "application/json"))
            server.enqueue(response(200, JSONObject().put("client_id", oid4vpClientId)
                .put("request_uri", "https://localhost:8443$requestPath").toString(), "application/json"))
            server.enqueue(response(200, responses.requestObject, "application/oauth-authz-req+jwt"))
            val redirectCode = base64Url(ByteArray(32) { (it + 121).toByte() })
            server.enqueue(response(if (ambiguousFirstPost) 503 else 200, JSONObject().put(
                "redirect_uri", "https://localhost:8443/callback#response_code=$redirectCode",
            ).toString(), "application/json"))
            server.start(8443)
        }

        fun enqueueNormalLoginRelaunch() {
            server.enqueue(response(204, "", "application/json"))
            server.enqueue(response(200, JSONObject().put("profile", "decent-wallet-login-v1")
                .put("challenge", challenge).put("csrf_token", "fixture-only").toString(), "application/json"))
        }

        fun enqueueAmbiguousRetry() {
            server.enqueue(response(503, "{}", "application/json"))
        }

        fun enqueueDefinitiveRetry() {
            server.enqueue(response(400, "{}", "application/json"))
        }

        fun enqueueUnverifiableAcceptanceRetry() {
            server.enqueue(response(200, "{}", "application/json"))
        }

        fun enqueueAcceptedRetry() {
            val acceptedCode = base64Url(ByteArray(32) { (it + 173).toByte() })
            server.enqueue(response(200, JSONObject().put(
                "redirect_uri", "https://localhost:8443/callback#response_code=$acceptedCode",
            ).toString(), "application/json"))
        }

        private fun createRequestObject(
            bundle: JSONObject,
            context: JSONObject,
            issuerPrivateKey: java.security.PrivateKey,
            expiry: Long,
        ): RequestObject {
            val sourceJws = bundle.getString("oid4vp_request_jws")
            val sourcePayload = decodeJsonPayload(sourceJws)
            val requestId = context.getString("request_id")
            val actualTransactionId = context.getString("transaction_id")
            val bindingTransactionId = if (bindingTransactionMismatch) {
                base64Url(MessageDigest.getInstance("SHA-256").digest("different transaction".toByteArray(StandardCharsets.US_ASCII)))
            } else actualTransactionId
            val ownerKey = currentOwnerPublicKey
            val ownerX = base64Url(ownerKey)
            val ownerJwk = JSONObject().put("kty", "OKP").put("crv", "Ed25519").put("x", ownerX)
            val thumbprint = base64Url(MessageDigest.getInstance("SHA-256").digest(
                "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"$ownerX\"}".toByteArray(StandardCharsets.US_ASCII),
            ))
            val capabilityHash = base64Url(MessageDigest.getInstance("SHA-256").digest(capabilityBytes))
            val bindingPayload = JSONObject()
                .put("v", 1)
                .put("iss", context.getString("keycloak_issuer"))
                .put("aud", context.getString("rp_client_id"))
                .put("sub", "keycloak-subject-instrumentation")
                .put("identity_id", currentIdentityId)
                .put("owner_key", ownerJwk)
                .put("owner_key_thumbprint", thumbprint)
                .put("action", context.getString("action"))
                .put("transaction_id", bindingTransactionId)
                .put("request_id", requestId)
                .put("oidc_nonce", context.getString("oidc_nonce"))
                .put("iat", now)
                .put("exp", expiry)
                .put("jti", base64Url(ByteArray(32) { (it + 13).toByte() }))
                .put("continuation_capability_hash", capabilityHash)
            val binding = signJws(
                JSONObject().put("alg", "RS256").put("typ", "decent-owner-key-binding+jwt")
                    .put("kid", "instrumentation-keycloak-signing-key"),
                bindingPayload,
                issuerPrivateKey,
                "SHA256withRSA",
            )

            val extension = sourcePayload.getJSONObject("decent_account")
                .put("owner_key_binding", binding)
                .put("rp_oidc_client_id", context.getString("rp_client_id"))
                .put("action", context.getString("action"))
                .put("request_id", requestId)
                .put("transaction_id", actualTransactionId)
                .put("purpose", context.getString("purpose"))
                .put("claims", context.getJSONArray("claims"))
            val requestPair = KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"))
                generateKeyPair()
            }
            val name = X500Name("CN=localhost")
            val certificateBuilder = JcaX509v3CertificateBuilder(
                name,
                BigInteger(128, SecureRandom()).abs(),
                Date(now * 1000 - 60_000),
                Date((now + 315_360_000) * 1000),
                name,
                requestPair.public,
            )
            certificateBuilder.addExtension(
                Extension.subjectAlternativeName,
                false,
                GeneralNames(GeneralName(GeneralName.dNSName, "localhost")),
            )
            certificateBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            certificateBuilder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
            val certificate = JcaX509CertificateConverter().getCertificate(
                certificateBuilder.build(JcaContentSignerBuilder("SHA256withECDSA").build(requestPair.private)),
            )
            sourcePayload.put("aud", "https://self-issued.me/v2")
                .put("client_id", oid4vpClientId)
                .put("response_uri", "https://localhost:8443$responsePath")
                .put("iat", now)
                .put("exp", expiry)
            val header = JSONObject()
                .put("alg", "ES256")
                .put("typ", "oauth-authz-req+jwt")
                .put("x5c", JSONArray().put(Base64.getEncoder().encodeToString(certificate.encoded)))
            val compact = signJws(header, sourcePayload, requestPair.private, "SHA256withECDSA", rawEcdsa = true)
            val fingerprint = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
                .joinToString("") { "%02x".format(it) }
            val registration = TrustedWalletRelyingPartyRegistration(
                clientId = oid4vpClientId,
                x509SanDns = "localhost",
                origin = "https://localhost:8443",
                responseUri = "https://localhost:8443$responsePath",
                trustAnchorSha256 = fingerprint,
                rpClientId = context.getString("rp_client_id"),
            )
            ownerKey.fill(0)
            return RequestObject(compact, registration, sourcePayload.getString("state"), sourcePayload.getString("nonce"))
        }

        private fun response(code: Int, body: String, contentType: String): MockResponse = MockResponse()
            .setResponseCode(code)
            .setHeader("Cache-Control", "no-store")
            .setHeader("Referrer-Policy", "no-referrer")
            .setHeader("Content-Type", contentType)
            .setBody(body)

        override fun close() {
            capabilityBytes.fill(0)
            currentOwnerPublicKey.fill(0)
            server.shutdown()
        }
    }

    private data class RequestObject(
        val compactJws: String,
        val registration: TrustedWalletRelyingPartyRegistration,
        val state: String,
        val nonce: String,
    )

    private data class NativeResponses(
        val contextBody: String,
        val capabilityBody: String,
        val requestObject: String,
    )

    private fun signJws(
        header: JSONObject,
        payload: JSONObject,
        privateKey: java.security.PrivateKey,
        algorithm: String,
        rawEcdsa: Boolean = false,
    ): String {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val protected = encoder.encodeToString(header.toString().toByteArray(StandardCharsets.UTF_8))
        val body = encoder.encodeToString(payload.toString().toByteArray(StandardCharsets.UTF_8))
        val signingInput = "$protected.$body"
        val signer = Signature.getInstance(algorithm)
        signer.initSign(privateKey)
        signer.update(signingInput.toByteArray(StandardCharsets.US_ASCII))
        val der = signer.sign()
        val signature = if (rawEcdsa) {
            val sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der))
            fixed32(ASN1Integer.getInstance(sequence.getObjectAt(0)).positiveValue) +
                fixed32(ASN1Integer.getInstance(sequence.getObjectAt(1)).positiveValue)
        } else der
        return try { "$signingInput.${encoder.encodeToString(signature)}" }
        finally {
            if (rawEcdsa) signature.fill(0)
            der.fill(0)
        }
    }

    private fun fixed32(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        val unsigned = if (raw.size > 1 && raw[0] == 0.toByte()) raw.copyOfRange(1, raw.size) else raw
        try {
            require(unsigned.size <= 32)
            return ByteArray(32).also { unsigned.copyInto(it, destinationOffset = 32 - unsigned.size) }
        } finally {
            if (unsigned !== raw) unsigned.fill(0)
            raw.fill(0)
        }
    }

    private fun decodeJsonPayload(compact: String): JSONObject {
        val part = compact.split('.')[1]
        val bytes = Base64.getUrlDecoder().decode(part)
        return try { JSONObject(String(bytes, StandardCharsets.UTF_8)) } finally { bytes.fill(0) }
    }

    private fun assetJson(name: String): JSONObject =
        JSONObject(InstrumentationRegistry.getInstrumentation().context.assets.open(name).bufferedReader().use { it.readText() })

    private fun base64Url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun unsigned(bytes: ByteArray): ByteArray =
        if (bytes.size > 1 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes

    private fun JSONArray.toStringList(): List<String> = (0 until length()).map { getString(it) }
}

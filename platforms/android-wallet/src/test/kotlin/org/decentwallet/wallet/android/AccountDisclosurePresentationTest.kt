package org.decentwallet.wallet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
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
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.RSAPublicKey
import java.util.Base64
import java.util.Comparator

class AccountDisclosurePresentationTest {
    private companion object {
        const val TEST_PASSWORD = "a sufficiently long test password"
    }

    @Test
    fun publicWalletOwnedBindingAdapterAcceptsAdoptedValidRequestAndPreservesExplicitApi() {
        val adoptedFixture = fixture(publicTimeRelative = true)
        var submission: AccountPresentationSubmission? = null
        try {
            submission = adoptedFixture.wallet.prepareAccountPresentation(
                adoptedFixture.pending, adoptedFixture.issuerJwks, adoptedFixture.outerRequest,
                adoptedFixture.requestObject, adoptedFixture.registration,
            )
            assertEquals(adoptedFixture.expectedState, submission.state)
            adoptedFixture.wallet.finishAccountPresentationAt(
                adoptedFixture.pending, PresentationDeliveryOutcome.CANCELLED, nowEpochSeconds = adoptedFixture.now,
            )
            val second = fixture(publicTimeRelative = true)
            try {
                val explicitSubmission = second.wallet.prepareAccountPresentation(
                    second.pending, second.bindingJws, second.issuerJwks, second.outerRequest,
                    second.requestObject, second.registration,
                )
                try { assertEquals(second.expectedState, explicitSubmission.state) }
                finally { explicitSubmission.close() }
            } finally { second.close() }
        } finally {
            submission?.close()
            adoptedFixture.close()
        }
    }

    @Test
    fun walletOwnedBindingAdapterRejectsMissingAndDuplicateEmbeddedFields() {
        val malformedRequests = listOf(
            compactRequestWithPayload("""{"decent_account":{}}"""),
            compactRequestWithPayload("""{"decent_account":{"owner_key_binding":"not-a-jws"}}"""),
            compactRequestWithPayload(
                """{"decent_account":{"owner_key_binding":"one","owner_key_binding":"two"}}""",
            ),
        )
        for (request in malformedRequests) {
            val fixture = fixture(publicTimeRelative = true)
            var reopened: WalletSession? = null
            try {
                val validAt = fixture.pending.approvedAtEpochSeconds
                assertEquals(fixture.pending.handle, fixture.wallet.recoverPendingAccountApprovalAt(validAt)?.handle)
                assertThrows(WalletDisclosureRequestException::class.java) {
                    fixture.wallet.prepareAccountPresentation(
                        fixture.pending, fixture.issuerJwks, fixture.outerRequest, request, fixture.registration,
                    )
                }
                fixture.wallet.lock()
                reopened = AndroidWallet.open(fixture.directory.resolve("wallet.dw"), TEST_PASSWORD)
                assertEquals(null, reopened.recoverPendingAccountApprovalAt(validAt + 1))
            } finally {
                reopened?.close()
                fixture.close()
            }
        }
    }

    private fun compactRequestWithPayload(payload: String): String =
        "e30.${Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray(StandardCharsets.UTF_8))}.AA"

    @Test
    fun expiredContinuationClearsDurableApprovalAndCannotBeUsedAfterReopen() {
        val fixture = fixture(requestExpiry = 1_800_000_006L)
        var reopened: WalletSession? = null
        try {
            val expiredAt = fixture.requestExpiresAt
            assertTrue(expiredAt < fixture.pending.expiresAtEpochSeconds)
            val rawContext = WalletJson.canonicalBytes(fixture.contextForVerifier())
            val pendingContext = try {
                WalletAccountDisclosureContextParser.parse(
                    rawContext, fixture.transactionHandle,
                    "https://login.example.test/realms/site", fixture.now,
                )
            } finally { rawContext.fill(0) }
            val validBinding = WalletOwnerKeyBindingVerifier.verify(
                fixture.bindingJws, fixture.issuerJwks, pendingContext, fixture.identityId, fixture.now,
            )
            WalletOid4vpRequestVerifier.verify(
                fixture.outerRequest, fixture.requestObject, fixture.registration, pendingContext,
                fixture.bindingJws, validBinding, fixture.now,
            )
            assertThrows(WalletDisclosureRequestException::class.java) {
                fixture.wallet.prepareAccountPresentationAt(
                    fixture.pending, fixture.bindingJws, fixture.issuerJwks, fixture.outerRequest,
                    fixture.requestObject, fixture.registration, expiredAt,
                    currentTimeEpochSeconds = { expiredAt },
                )
            }
            assertEquals(null, fixture.wallet.recoverPendingAccountApprovalAt(expiredAt))
            fixture.wallet.lock()
            reopened = AndroidWallet.open(fixture.directory.resolve("wallet.dw"), TEST_PASSWORD)
            assertEquals(null, reopened.recoverPendingAccountApprovalAt(expiredAt))
            assertThrows(WalletContainerException::class.java) {
                reopened.createAccountLoginProofAt(
                    fixture.pending, fixture.expectedNonce, expiredAt,
                    currentTimeEpochSeconds = { expiredAt },
                )
            }
        } finally {
            reopened?.close()
            fixture.close()
        }
    }

    @Test
    fun trustedSignedArtifactsForDifferentPendingContextInvalidateApproval() {
        val fixture = fixture()
        var reopened: WalletSession? = null
        try {
            @Suppress("UNCHECKED_CAST")
            val mismatched = WalletJson.copyPayload(fixture.contextForVerifier()) as MutableMap<String, Any?>
            val differentId = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(16) { 0x5a })
            mismatched["request_id"] = differentId
            val raw = WalletJson.canonicalBytes(mismatched)
            val parsed = try { WalletAccountDisclosureContextParser.parse(raw,
                fixture.transactionHandle, "https://login.example.test/realms/site", fixture.now) }
                finally { raw.fill(0); WalletJson.clearByteArrays(mismatched) }
            val (binding, jwks, _) = createBinding(
                fixture.contextForVerifier().toMutableMap().apply { put("request_id", differentId) },
                fixture.ownerPublicKey, fixture.identityId, fixture.now,
            )
            val root = checkNotNull(javaClass.classLoader?.getResourceAsStream(
                "wallet-account-disclosure-v1/vectors/valid-signup.json",
            )).use { WalletJson.parse(it.readBytes(), 64 * 1024) as Map<*, *> }
            val seed = TrustedWalletRelyingPartyRegistration(
                clientId = root["oid4vp_client_id"] as String, x509SanDns = "site.example.test",
                origin = "https://site.example.test", responseUri = "https://site.example.test/oid4vp/response",
                trustAnchorSha256 = (root["rp_certificate"] as Map<*, *>)["trust_anchor_sha256"] as String,
                rpClientId = "site-client",
            )
            val (registration, request) = rebindRequest(root, seed, binding,
                fixture.contextForVerifier().toMutableMap().apply { put("request_id", differentId) }, false, null)
            val verifiedBinding = WalletOwnerKeyBindingVerifier.verify(
                binding, jwks, parsed, fixture.identityId, fixture.now,
            )
            WalletOid4vpRequestVerifier.verify(
                root["oid4vp_authorization_parameters"] as Map<*, *>, request, registration,
                parsed, binding, verifiedBinding, fixture.now,
            )
            assertThrows(WalletDisclosureRequestException::class.java) {
                fixture.wallet.prepareAccountPresentationAt(fixture.pending, binding, jwks,
                    fixture.outerRequest, request, registration, fixture.now,
                    currentTimeEpochSeconds = { fixture.now })
            }
            assertEquals(null, fixture.wallet.recoverPendingAccountApprovalAt(fixture.now))
            fixture.wallet.lock()
            reopened = AndroidWallet.open(fixture.directory.resolve("wallet.dw"), TEST_PASSWORD)
            assertEquals(null, reopened.recoverPendingAccountApprovalAt(fixture.now))
            assertThrows(WalletContainerException::class.java) {
                reopened.createAccountLoginProofAt(fixture.pending, fixture.expectedNonce, fixture.now,
                    currentTimeEpochSeconds = { fixture.now })
            }
        } finally { reopened?.close(); fixture.close() }
    }

    @Test
    fun unverifiableHttp200AcceptanceIsDurablyNonRetriableAfterReopen() {
        val fixture = fixture()
        var submission: AccountPresentationSubmission? = null
        var reopened: WalletSession? = null
        try {
            submission = fixture.wallet.prepareAccountPresentationAt(
                fixture.pending, fixture.bindingJws, fixture.issuerJwks, fixture.outerRequest,
                fixture.requestObject, fixture.registration, fixture.now,
                currentTimeEpochSeconds = { fixture.now },
            )
            val invalidReceipt = "{}".toByteArray(StandardCharsets.UTF_8)
            try {
                assertThrows(WalletDisclosureRequestException::class.java) {
                    fixture.wallet.finishAccountPresentationAt(
                        fixture.pending, PresentationDeliveryOutcome.ACCEPTED, 200,
                        "application/json", invalidReceipt, fixture.now,
                    )
                }
            } finally { invalidReceipt.fill(0) }
            assertTrue(fixture.wallet.isAccountPresentationAcceptanceUncertain(fixture.pending))
            assertThrows(WalletDisclosureRequestException::class.java) {
                fixture.wallet.getAccountPresentationRetryAt(fixture.pending, fixture.registration, fixture.now)
            }
            fixture.wallet.lock()
            reopened = AndroidWallet.open(fixture.directory.resolve("wallet.dw"), TEST_PASSWORD)
            val recovered = requireNotNull(reopened.recoverPendingAccountApprovalAt(fixture.now))
            assertTrue(reopened.isAccountPresentationAcceptanceUncertain(recovered))
            assertThrows(WalletDisclosureRequestException::class.java) {
                reopened.getAccountPresentationRetryAt(recovered, fixture.registration, fixture.now)
            }
        } finally {
            reopened?.close()
            submission?.close()
            fixture.close()
        }
    }

    @Test
    fun directPostAcceptanceConsumesOnlyOnValidatedResponseEvidence() {
        val fixture = fixture()
        var submission: AccountPresentationSubmission? = null
        try {
            submission = fixture.wallet.prepareAccountPresentationAt(
                fixture.pending, fixture.bindingJws, fixture.issuerJwks, fixture.outerRequest,
                fixture.requestObject, fixture.registration, fixture.now,
                currentTimeEpochSeconds = { fixture.now },
            )
            val code = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { it.toByte() })
            val body = """{"redirect_uri":"https://site.example.test/response#response_code=$code"}"""
                .toByteArray(StandardCharsets.UTF_8)
            val payloadBeforeAcceptance = fixture.wallet.readPayload()
            try {
                assertTrue(payloadBeforeAcceptance.containsKey("pending_account_disclosure_approval"))
            } finally { WalletJson.clearByteArrays(payloadBeforeAcceptance) }
            fixture.wallet.finishAccountPresentationAt(
                fixture.pending, PresentationDeliveryOutcome.AMBIGUOUS, nowEpochSeconds = fixture.now,
            )
            val retry = fixture.wallet.getAccountPresentationRetryAt(
                fixture.pending, fixture.registration, fixture.now,
            )
            try {
                val expected = submission.body
                val actual = retry.body
                try { assertTrue(expected.contentEquals(actual)) }
                finally { expected.fill(0); actual.fill(0) }
            } finally { retry.close() }
            fixture.wallet.finishAccountPresentationAt(
                fixture.pending, PresentationDeliveryOutcome.ACCEPTED, 200,
                "Application/Json; charset=utf-8", body, fixture.now,
            )
            val payloadAfterAcceptance = fixture.wallet.readPayload()
            try { assertFalse(payloadAfterAcceptance.containsKey("pending_account_disclosure_approval")) }
            finally { WalletJson.clearByteArrays(payloadAfterAcceptance) }
            assertEquals(null, fixture.wallet.recoverPendingAccountApprovalAt(fixture.now))
            body.fill(0)
        } finally {
            submission?.close()
            fixture.close()
        }
    }

    @Test
    fun definitiveFailureAndCancellationConsumeApproval() {
        for (outcome in listOf(PresentationDeliveryOutcome.DEFINITIVE_FAILURE, PresentationDeliveryOutcome.CANCELLED)) {
            val fixture = fixture()
            var submission: AccountPresentationSubmission? = null
            try {
                submission = fixture.wallet.prepareAccountPresentationAt(
                    fixture.pending, fixture.bindingJws, fixture.issuerJwks, fixture.outerRequest,
                    fixture.requestObject, fixture.registration, fixture.now,
                    currentTimeEpochSeconds = { fixture.now },
                )
                fixture.wallet.finishAccountPresentationAt(fixture.pending, outcome, nowEpochSeconds = fixture.now)
                val payload = fixture.wallet.readPayload()
                try { assertFalse(payload.containsKey("pending_account_disclosure_approval")) }
                finally { WalletJson.clearByteArrays(payload) }
            } finally {
                submission?.close()
                fixture.close()
            }
        }
    }

    @Test
    fun submissionCloseWipesAndDisablesRetainedBodyBytes() {
        val submission = AccountPresentationSubmission(
            PendingAccountApproval("opaque-handle", 100, 10),
            "https://site.example.test/response",
            "state",
            "compact.jws.token",
            "private presentation body".toByteArray(StandardCharsets.US_ASCII),
        )
        val returned = submission.body
        try {
            assertTrue(returned.isNotEmpty())
        } finally {
            returned.fill(0)
            submission.close()
        }
        assertThrows(IllegalStateException::class.java) { submission.body }
    }

    @Test
    fun preparedSubmissionRecoversAsAmbiguousAndIsRetryableAfterReopen() {
        val fixture = fixture(reverseClaims = true)
        var submission: AccountPresentationSubmission? = null
        var reopened: WalletSession? = null
        var retry: AccountPresentationSubmission? = null
        try {
            submission = fixture.wallet.prepareAccountPresentationAt(
                fixture.pending, fixture.bindingJws, fixture.issuerJwks, fixture.outerRequest,
                fixture.requestObject, fixture.registration, fixture.now,
                currentTimeEpochSeconds = { fixture.now },
            )
            fixture.wallet.lock()
            reopened = AndroidWallet.open(fixture.directory.resolve("wallet.dw"), TEST_PASSWORD)
            val recovered = reopened.recoverPendingAccountApprovalAt(fixture.now)
                ?: throw AssertionError("prepared approval should recover")
            val payload = reopened.readPayload()
            try {
                val record = payload["pending_account_disclosure_approval"] as Map<*, *>
                assertEquals("ambiguous", (record["presentation"] as Map<*, *>)["state"])
            } finally {
                WalletJson.clearByteArrays(payload)
            }
            retry = reopened.getAccountPresentationRetryAt(recovered, fixture.registration, fixture.now)
            assertEquals(submission.presentationJws, retry.presentationJws)
            val original = submission.body
            val replay = retry.body
            try { assertTrue(original.contentEquals(replay)) }
            finally { original.fill(0); replay.fill(0) }
        } finally {
            retry?.close()
            reopened?.close()
            submission?.close()
            fixture.close()
        }
    }

    @Test
    fun staleSessionCannotRetryAfterAnotherSessionCancelsApproval() {
        val fixture = fixture()
        var stale: WalletSession? = null
        var submission: AccountPresentationSubmission? = null
        try {
            submission = fixture.wallet.prepareAccountPresentationAt(
                fixture.pending, fixture.bindingJws, fixture.issuerJwks, fixture.outerRequest,
                fixture.requestObject, fixture.registration, fixture.now,
                currentTimeEpochSeconds = { fixture.now },
            )
            assertTrue(fixture.wallet.markAccountPresentationAmbiguousAt(fixture.pending, fixture.now))
            stale = AndroidWallet.open(fixture.directory.resolve("wallet.dw"), TEST_PASSWORD)
            assertTrue(fixture.wallet.cancelAccountDisclosureApprovalAt(fixture.pending, fixture.now))
            assertThrows(WalletContainerException::class.java) {
                stale.getAccountPresentationRetryAt(fixture.pending, fixture.registration, fixture.now)
            }
        } finally {
            stale?.close()
            submission?.close()
            fixture.close()
        }
    }

    @Test
    fun preparesOwnerSignedCredentialAndPresentationAndPersistsExactSubmissionBeforeRelease() {
        val fixture = fixture(
            reverseClaims = true,
            proofChallenge = "UFFSU1RVVldYWVpbXF1eX2BhYmNkZWZnaGlqa2xtbm8",
        )
        try {
            val submission = fixture.wallet.prepareAccountPresentationAt(
                fixture.pending, fixture.bindingJws, fixture.issuerJwks, fixture.outerRequest,
                fixture.requestObject, fixture.registration, fixture.now,
                currentTimeEpochSeconds = { fixture.now },
            )
            try {
                assertEquals(fixture.registration.responseUri, submission.responseUri)
                assertEquals(fixture.expectedState, submission.state)
                assertFalse(submission.toString().contains(submission.presentationJws))
                assertTrue(submission.presentationJws.toByteArray(StandardCharsets.UTF_8).size <= 16 * 1024)

                val vp = verifyJws(submission.presentationJws, "decent-account-presentation+jwt", fixture.ownerPublicKey, fixture.ownerKeyThumbprint)
                assertEquals(setOf("profile", "iss", "sub", "aud", "nonce", "iat", "exp", "jti", "vp"), vp.keys)
                assertEquals("decent-account-disclosure-v1", vp["profile"])
                assertEquals(fixture.identityId, vp["iss"])
                assertEquals(fixture.identityId, vp["sub"])
                assertEquals(fixture.registration.clientId, vp["aud"])
                assertEquals(fixture.expectedNonce, vp["nonce"])
                assertEquals(BigInteger.valueOf(fixture.now), vp["iat"])
                assertTrue(asLong(vp["exp"]) <= fixture.pending.expiresAtEpochSeconds)
                val vpJti = decodeJti(vp["jti"] as String)
                val vpObject = vp["vp"] as Map<*, *>
                assertEquals(setOf("type", "verifiableCredential"), vpObject.keys)
                assertEquals(listOf("decent_account_presentation_v1"), vpObject["type"])
                val credentialJws = (vpObject["verifiableCredential"] as List<*>).single() as String
                val credential = verifyJws(credentialJws, "decent-account-credential+jwt", fixture.ownerPublicKey, fixture.ownerKeyThumbprint)
                assertEquals(
                    setOf("profile", "credential_type", "iss", "sub", "iat", "exp", "jti", "action",
                        "rp_oidc_client_id", "request_id", "transaction_id", "purpose",
                        "owner_key_thumbprint", "owner_binding_jti", "claims"),
                    credential.keys,
                )
                assertEquals("decent-account-disclosure-v1", credential["profile"])
                assertEquals("decent_account_assertion_v1", credential["credential_type"])
                assertEquals(fixture.identityId, credential["iss"])
                assertEquals(fixture.identityId, credential["sub"])
                assertEquals("signup", credential["action"])
                assertEquals("site-client", credential["rp_oidc_client_id"])
                assertEquals(fixture.claimIds, (credential["claims"] as Map<*, *>).keys)
                assertEquals(
                    mapOf(
                        "urn:decent:account:v1:given_name" to "Ada",
                        "urn:decent:account:v1:email" to "ada@example.test",
                    ),
                    credential["claims"],
                )
                val credentialJti = decodeJti(credential["jti"] as String)
                assertFalse(vpJti.contentEquals(credentialJti))
                vpJti.fill(0)
                credentialJti.fill(0)

                val body = submission.body
                try {
                    assertTrue(body.isNotEmpty())
                    val params = body.toString(StandardCharsets.US_ASCII).split('&').associate { pair ->
                        val parts = pair.split('=', limit = 2)
                        URLDecoder.decode(parts[0], StandardCharsets.UTF_8) to
                            URLDecoder.decode(parts.getOrElse(1) { "" }, StandardCharsets.UTF_8)
                    }
                    assertEquals(setOf("state", "vp_token"), params.keys)
                    assertEquals(submission.state, params["state"])
                    val vpToken = WalletJson.parse(params.getValue("vp_token").toByteArray(), 16 * 1024) as Map<*, *>
                    assertEquals(mapOf("account" to listOf(submission.presentationJws)), vpToken)

                    val payload = fixture.wallet.readPayload()
                    try {
                        val approval = payload.getValue("pending_account_disclosure_approval") as Map<*, *>
                        val presentation = approval["presentation"] as Map<*, *>
                        assertEquals("prepared", presentation["state"])
                        val saved = presentation["submission"] as Map<*, *>
                        assertEquals(submission.responseUri, saved["response_uri"])
                        assertEquals(submission.state, saved["state"])
                        assertEquals(submission.presentationJws, saved["presentation_jws"])
                        assertTrue((saved["body"] as ByteArray).contentEquals(body))
                        assertEquals(asLong(vp["exp"]), asLong(saved["expires_at"]))
                    } finally {
                        WalletJson.clearByteArrays(payload)
                    }
                } finally {
                    body.fill(0)
                }
                assertThrows(WalletDisclosureRequestException::class.java) {
                    fixture.wallet.prepareAccountPresentationAt(
                        fixture.pending, fixture.bindingJws, fixture.issuerJwks, fixture.outerRequest,
                        fixture.requestObject, fixture.registration, fixture.now,
                        currentTimeEpochSeconds = { fixture.now },
                    )
                }
                assertTrue(fixture.wallet.markAccountPresentationAmbiguousAt(fixture.pending, fixture.now))
                val retry = fixture.wallet.getAccountPresentationRetryAt(
                    fixture.pending, fixture.registration, fixture.now,
                )
                try {
                    assertEquals(submission.presentationJws, retry.presentationJws)
                    val expectedRetryBody = submission.body
                    val actualRetryBody = retry.body
                    try { assertTrue(actualRetryBody.contentEquals(expectedRetryBody)) }
                    finally { expectedRetryBody.fill(0); actualRetryBody.fill(0) }
                } finally {
                    retry.close()
                }
                fixture.wallet.lock()
                val reopened = AndroidWallet.open(fixture.directory.resolve("wallet.dw"), TEST_PASSWORD)
                try {
                    val recovered = reopened.recoverPendingAccountApprovalAt(fixture.now)
                        ?: throw AssertionError("ambiguous presentation must recover after reopen")
                    val recoveredSubmission = reopened.getAccountPresentationRetryAt(
                        recovered, fixture.registration, fixture.now,
                    )
                    try {
                        assertEquals(submission.presentationJws, recoveredSubmission.presentationJws)
                        val originalBody = submission.body
                        val recoveredBody = recoveredSubmission.body
                        try { assertTrue(originalBody.contentEquals(recoveredBody)) }
                        finally { originalBody.fill(0); recoveredBody.fill(0) }
                    } finally {
                        recoveredSubmission.close()
                    }
                } finally {
                    reopened.close()
                }
                WalletJson.clearByteArrays(vp)
            } finally {
                submission.close()
            }
        } finally {
            fixture.close()
        }
    }

    private fun verifyJws(
        token: String,
        expectedType: String,
        ownerPublicKey: ByteArray,
        expectedThumbprint: String,
    ): Map<*, *> {
        val parts = token.split('.')
        assertEquals(3, parts.size)
        val headerBytes = Base64.getUrlDecoder().decode(parts[0])
        val payloadBytes = Base64.getUrlDecoder().decode(parts[1])
        val signature = Base64.getUrlDecoder().decode(parts[2])
        try {
            val header = WalletJson.parse(headerBytes, 16 * 1024) as Map<*, *>
            assertEquals(setOf("alg", "kid", "typ"), header.keys)
            assertEquals("EdDSA", header["alg"])
            assertEquals(expectedType, header["typ"])
            assertEquals(expectedThumbprint, header["kid"])
            val input = "${parts[0]}.${parts[1]}".toByteArray(StandardCharsets.US_ASCII)
            try {
                assertTrue(AndroidIdentityCrypto.verify(ownerPublicKey, input, signature))
            } finally {
                input.fill(0)
            }
            val payload = WalletJson.parse(payloadBytes, 16 * 1024) as Map<*, *>
            assertTrue(WalletJson.canonicalBytes(payload).contentEquals(payloadBytes))
            return payload
        } finally {
            headerBytes.fill(0)
            payloadBytes.fill(0)
            signature.fill(0)
        }
    }

    private fun decodeJti(value: String): ByteArray = Base64.getUrlDecoder().decode(value).also {
        assertEquals(32, it.size)
        assertEquals(value, Base64.getUrlEncoder().withoutPadding().encodeToString(it))
    }

    private data class Fixture(
        val directory: java.nio.file.Path,
        val wallet: WalletSession,
        val pending: PendingAccountApproval,
        val ownerPublicKey: ByteArray,
        val identityId: String,
        val now: Long,
        val requestExpiresAt: Long,
        val transactionHandle: String,
        val contextForVerifier: () -> Map<*, *>,
        val bindingJws: String,
        val issuerJwks: Map<String, Any?>,
        val outerRequest: Map<*, *>,
        val requestObject: String,
        val registration: TrustedWalletRelyingPartyRegistration,
        val expectedState: String,
        val expectedNonce: String,
        val claimIds: Set<String>,
        val ownerKeyThumbprint: String,
    ) : AutoCloseable {
        override fun close() {
            wallet.close()
            ownerPublicKey.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private fun fixture(
        reverseClaims: Boolean = false,
        requestExpiry: Long? = null,
        publicTimeRelative: Boolean = false,
        proofChallenge: String? = null,
    ): Fixture {
        val root = checkNotNull(javaClass.classLoader?.getResourceAsStream(
            "wallet-account-disclosure-v1/vectors/valid-signup.json",
        )).use { WalletJson.parse(it.readBytes(), 64 * 1024) as Map<*, *> }
        val now = if (publicTimeRelative) System.currentTimeMillis() / 1000 else (root["validation_time"] as BigInteger).toLong()
        @Suppress("UNCHECKED_CAST")
        val context = WalletJson.copyPayload(root["keycloak_context"] as Map<*, *>) as MutableMap<String, Any?>
        if (publicTimeRelative) context["expires_at"] = BigInteger.valueOf(now + 299)
        if (reverseClaims) context["claims"] = (context["claims"] as List<*>).reversed()
        val contextBytes = WalletJson.canonicalBytes(context)
        val identityId = "test:android-disclosure-presentation"
        val directory = Files.createTempDirectory("wallet-android-disclosure-presentation-")
        val path = directory.resolve("wallet.dw")
        val wallet = AndroidWallet.createWithGeneratedKey(path, TEST_PASSWORD, TEST_PASSWORD)
        try {
            wallet.setMasterAccountEntity(mapOf("given_name" to "Ada", "email" to "ada@example.test"))
            val ownerPublicKey = wallet.ownerPublicKey
            val review = wallet.reviewAccountDisclosureAt(
                contextBytes, root["transaction_handle"] as String,
                "https://login.example.test/realms/site", identityId, now,
            )
            val selected = setOf(
                "urn:decent:account:v1:given_name",
                "urn:decent:account:v1:email",
            )
            val pending = wallet.approveAccountDisclosureAt(
                review, selected, now, currentTimeEpochSeconds = { now },
            ) { true }
            wallet.createAccountLoginProofAt(
                pending, proofChallenge ?: context["oidc_nonce"] as String, now,
                currentTimeEpochSeconds = { now },
            )
            val (bindingJws, issuerJwks, ownerKeyThumbprint) = createBinding(context, ownerPublicKey, identityId, now)
            val certificate = root["rp_certificate"] as Map<*, *>
            val registrationSeed = TrustedWalletRelyingPartyRegistration(
                clientId = root["oid4vp_client_id"] as String,
                x509SanDns = "site.example.test",
                origin = "https://site.example.test",
                responseUri = "https://site.example.test/oid4vp/response",
                trustAnchorSha256 = certificate["trust_anchor_sha256"] as String,
                rpClientId = context["rp_client_id"] as String,
            )
            val (registration, requestToken) = rebindRequest(
                root, registrationSeed, bindingJws, context, reverseClaims,
                requestExpiry = requestExpiry ?: if (publicTimeRelative) now + 299 else null,
                requestIssuedAt = if (publicTimeRelative) now else null,
            )
            val requestPayloadBytes = Base64.getUrlDecoder().decode(requestToken.split('.')[1])
            val requestPayload = try { WalletJson.parse(requestPayloadBytes, 64 * 1024) as Map<*, *> }
                finally { requestPayloadBytes.fill(0) }
            val requestState = requestPayload["state"] as String
            val requestNonce = requestPayload["nonce"] as String
            val claims = (context["claims"] as List<*>).map { (it as Map<*, *>)["id"] as String }.toSet()
            return Fixture(
                directory, wallet, pending, ownerPublicKey, identityId, now, requestExpiry ?: now + 299,
                root["transaction_handle"] as String, { WalletJson.copyPayload(context) as Map<*, *> }, bindingJws, issuerJwks,
                root["oid4vp_authorization_parameters"] as Map<*, *>, requestToken, registration,
                requestState, requestNonce, selected, ownerKeyThumbprint,
            ).also {
                assertEquals(claims, setOf("urn:decent:account:v1:email", "urn:decent:account:v1:given_name"))
                contextBytes.fill(0)
            }
        } catch (failure: Exception) {
            wallet.close()
            contextBytes.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
            throw failure
        }
    }

    private fun rebindRequest(
        vector: Map<*, *>,
        registration: TrustedWalletRelyingPartyRegistration,
        bindingJws: String,
        context: Map<*, *>,
        reverseClaims: Boolean,
        requestExpiry: Long?,
        requestIssuedAt: Long? = null,
    ): Pair<TrustedWalletRelyingPartyRegistration, String> {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
        val pair = generator.generateKeyPair()
        val name = X500Name("CN=${registration.x509SanDns}")
        val builder = JcaX509v3CertificateBuilder(
            name, BigInteger.ONE, java.util.Date(1_735_689_600_000L), java.util.Date(1_956_528_000_000L), name, pair.public,
        )
        builder.addExtension(Extension.subjectAlternativeName, false,
            GeneralNames(GeneralName(GeneralName.dNSName, registration.x509SanDns)))
        builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
        val certificate = JcaX509CertificateConverter().getCertificate(
            builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private)),
        )
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
            .joinToString("") { "%02x".format(it) }
        val trusted = registration.copy(trustAnchorSha256 = fingerprint)
        val sourceJws = vector["oid4vp_request_jws"] as String
        val sourcePayloadBytes = Base64.getUrlDecoder().decode(sourceJws.split('.')[1])
        @Suppress("UNCHECKED_CAST")
        val payload = try {
            WalletJson.copyPayload(WalletJson.parse(sourcePayloadBytes, 64 * 1024)) as MutableMap<String, Any?>
        } finally {
            sourcePayloadBytes.fill(0)
        }
        @Suppress("UNCHECKED_CAST")
        val extension = payload["decent_account"] as MutableMap<String, Any?>
        extension["owner_key_binding"] = bindingJws
        extension["rp_oidc_client_id"] = context["rp_client_id"]
        extension["action"] = context["action"]
        extension["request_id"] = context["request_id"]
        extension["transaction_id"] = context["transaction_id"]
        extension["purpose"] = context["purpose"]
        if (requestExpiry != null) payload["exp"] = BigInteger.valueOf(requestExpiry)
        if (requestIssuedAt != null) payload["iat"] = BigInteger.valueOf(requestIssuedAt)
        extension["claims"] = context["claims"]
        if (reverseClaims) {
            @Suppress("UNCHECKED_CAST")
            val query = payload["dcql_query"] as MutableMap<String, Any?>
            val credentials = query["credentials"] as List<*>
            val credential = credentials.single() as MutableMap<String, Any?>
            credential["claims"] = (credential["claims"] as List<*>).reversed()
            credential["claim_sets"] = (credential["claim_sets"] as List<*>).map { (it as List<*>).reversed() }
        }
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val header = encoder.encodeToString(WalletJson.canonicalBytes(mapOf(
            "alg" to "ES256",
            "typ" to "oauth-authz-req+jwt",
            "x5c" to listOf(Base64.getEncoder().encodeToString(certificate.encoded)),
        )))
        val bodyBytes = WalletJson.canonicalBytes(payload)
        val body = encoder.encodeToString(bodyBytes)
        val signingInput = "$header.$body"
        val signer = Signature.getInstance("SHA256withECDSA")
        signer.initSign(pair.private)
        signer.update(signingInput.toByteArray(StandardCharsets.US_ASCII))
        val der = signer.sign()
        val sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der))
        val rawSignature = fixed32(ASN1Integer.getInstance(sequence.getObjectAt(0)).positiveValue) +
            fixed32(ASN1Integer.getInstance(sequence.getObjectAt(1)).positiveValue)
        try {
            return trusted to "$signingInput.${encoder.encodeToString(rawSignature)}"
        } finally {
            bodyBytes.fill(0)
            der.fill(0)
            rawSignature.fill(0)
            WalletJson.clearByteArrays(payload)
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

    private fun createBinding(
        context: Map<*, *>, ownerPublicKey: ByteArray, identityId: String, now: Long,
    ): Triple<String, Map<String, Any?>, String> {
        val generator = KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        val pair = generator.generateKeyPair()
        val publicKey = pair.public as RSAPublicKey
        val ownerJwk = mapOf(
            "kty" to "OKP", "crv" to "Ed25519",
            "x" to Base64.getUrlEncoder().withoutPadding().encodeToString(ownerPublicKey),
        )
        val thumbprint = Base64.getUrlEncoder().withoutPadding().encodeToString(
            MessageDigest.getInstance("SHA-256").digest(WalletJson.canonicalBytes(ownerJwk)),
        )
        val payload = mapOf(
            "v" to 1, "iss" to context["keycloak_issuer"], "aud" to context["rp_client_id"],
            "sub" to "keycloak-subject-test", "identity_id" to identityId,
            "owner_key" to ownerJwk, "owner_key_thumbprint" to thumbprint,
            "action" to context["action"], "transaction_id" to context["transaction_id"],
            "request_id" to context["request_id"], "oidc_nonce" to context["oidc_nonce"],
            "iat" to BigInteger.valueOf(now), "exp" to context["expires_at"],
            "jti" to Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { (it + 1).toByte() }),
        )
        val modulus = stripLeadingZero(publicKey.modulus.toByteArray())
        val exponent = stripLeadingZero(publicKey.publicExponent.toByteArray())
        val jwks = mapOf(
            "keys" to listOf(mapOf(
                "kty" to "RSA", "n" to Base64.getUrlEncoder().withoutPadding().encodeToString(modulus),
                "e" to Base64.getUrlEncoder().withoutPadding().encodeToString(exponent),
                "kid" to "presentation-test-rsa", "use" to "sig", "alg" to "RS256",
            )),
        )
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val protected = encoder.encodeToString(WalletJson.canonicalBytes(mapOf(
            "alg" to "RS256", "kid" to "presentation-test-rsa", "typ" to "decent-owner-key-binding+jwt",
        )))
        val body = encoder.encodeToString(WalletJson.canonicalBytes(payload))
        val signingInput = "$protected.$body"
        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(pair.private)
        signer.update(signingInput.toByteArray(StandardCharsets.US_ASCII))
        val result = "$signingInput.${encoder.encodeToString(signer.sign())}"
        modulus.fill(0)
        exponent.fill(0)
        return Triple(result, jwks, thumbprint)
    }

    private fun stripLeadingZero(bytes: ByteArray): ByteArray =
        if (bytes.size > 1 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes

    private fun asLong(value: Any?): Long = when (value) {
        is BigInteger -> value.toLong()
        is Long -> value
        is Int -> value.toLong()
        else -> error("expected integer")
    }
}

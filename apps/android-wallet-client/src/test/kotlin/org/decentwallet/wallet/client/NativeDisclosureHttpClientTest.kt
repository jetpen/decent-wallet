package org.decentwallet.wallet.client

import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.Base64
import java.util.concurrent.TimeUnit

class NativeDisclosureHttpClientTest {
    private lateinit var server: MockWebServer
    private lateinit var rpOrigin: String
    private lateinit var http: NativeDisclosureHttpClient
    private val transactionId = "A".repeat(43)
    private val capability = ByteArray(32) { 7 }
    private val bearer = Base64.getUrlEncoder().withoutPadding().encodeToString(capability)

    @Before fun setUp() {
        val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
        val serverTls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        val trusted = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        server = MockWebServer().apply { useHttps(serverTls.sslSocketFactory(), false); start() }
        rpOrigin = "https://localhost:${server.port}"
        http = NativeDisclosureHttpClient(OkHttpClient.Builder()
            .sslSocketFactory(trusted.sslSocketFactory(), trusted.trustManager).build())
    }

    @After fun tearDown() { capability.fill(0); server.shutdown() }

    @Test fun validLoginContextIsExactlyEmpty204AndKeepsLegacyProofRoute() {
        val handle = "A".repeat(43)
        val txn = WalletLoginTransactionUrl.parse(
            "https://localhost:${server.port}/realms/demo/decent-wallet-login/v1/transactions/$handle", rpOrigin,
        )
        server.enqueue(MockResponse().setResponseCode(204).setHeader("Cache-Control", "no-store")
            .setHeader("Referrer-Policy", "no-referrer"))
        assertEquals(NativeDisclosureContextResponse.LoginOnly, http.fetchDisclosureContext(txn))
        val observed = requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
        assertEquals("GET", observed.method)
        assertEquals("/realms/demo/decent-wallet-login/v1/transactions/$handle/disclosure-context", observed.path)
        assertBrowserHeadersAbsent(observed)
    }

    @Test fun contextAndNativeProofUseExpectedMethodPathAndExactCapabilityResponseShape() {
        val handle = "A".repeat(43)
        val txn = WalletLoginTransactionUrl.parse(
            "https://localhost:${server.port}/realms/demo/decent-wallet-login/v1/transactions/$handle", rpOrigin,
        )
        server.enqueue(MockResponse().setResponseCode(200).setHeader("Cache-Control", "no-store").setHeader("Referrer-Policy", "no-referrer").setHeader("Content-Type", "application/json")
            .setBody("""{"profile":"decent-account-disclosure-v1","keycloak_issuer":"https://issuer.example","decent_native_continuation":true}"""))
        val context = http.fetchDisclosureContext(txn) as NativeDisclosureContextResponse.NativeSignup
        assertTrue(String(context.rawContext).contains("\"decent_native_continuation\":true"))
        context.rawContext.fill(0)
        val get = requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
        assertEquals("GET", get.method)
        assertEquals("/realms/demo/decent-wallet-login/v1/transactions/$handle/disclosure-context", get.path)
        assertBrowserHeadersAbsent(get)

        val expiry = System.currentTimeMillis() / 1000 + 240
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(capability)
        server.enqueue(MockResponse().setResponseCode(200).setHeader("Cache-Control", "no-store").setHeader("Referrer-Policy", "no-referrer").setHeader("Content-Type", "application/json")
            .setBody("""{"profile":"decent-account-disclosure-v1","decent_account_continuation_capability":"$token","expires_at":$expiry}"""))
        val proofBody = "{\"profile\":\"decent-wallet-login-v1\",\"challenge\":\"c\",\"identity_id\":\"id\",\"signature\":\"s\"}".toByteArray()
        http.submitNativeProof(txn, proofBody).use { grant -> assertEquals(expiry, grant.expiresAtEpochSeconds) }
        val post = requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
        assertEquals("POST", post.method)
        assertEquals("/realms/demo/decent-wallet-login/v1/transactions/$handle", post.path)
        assertEquals("application/json", post.getHeader("Content-Type"))
        assertArrayEquals(proofBody, post.body.readByteArray())
        assertBrowserHeadersAbsent(post)
    }

    @Test fun capabilityExpiryIsBoundToProofAcceptanceNotResponseArrival() {
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(capability)
        val acceptedAt = System.currentTimeMillis() / 1000
        val within = """{"profile":"decent-account-disclosure-v1","decent_account_continuation_capability":"$encoded","expires_at":${acceptedAt + 300}}""".toByteArray()
        NativeContinuationGrant.parse(within, acceptedAt).close()
        val tooLate = """{"profile":"decent-account-disclosure-v1","decent_account_continuation_capability":"$encoded","expires_at":${acceptedAt + 301}}""".toByteArray()
        try {
            NativeContinuationGrant.parse(tooLate, acceptedAt)
            fail("accepted capability expiry beyond proof-acceptance window")
        } catch (_: NativeDisclosureTransportException) { }
    }

    @Test fun pollingUsesFixedSameOriginPathAndBearerOnlyInAuthorization() {
        server.enqueue(MockResponse().setResponseCode(202).setHeader("Cache-Control", "no-store").setHeader("Referrer-Policy", "no-referrer").setHeader("Retry-After", "3"))
        val pending = http.pollContinuation(rpOrigin, transactionId, capability)
        assertEquals(ContinuationPollResult.Pending(3), pending)
        val poll = requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
        assertEquals("GET", poll.method)
        assertEquals("/oid4vp/continuations/$transactionId", poll.path)
        assertEquals("Bearer $bearer", poll.getHeader("Authorization"))
        assertNull(poll.getHeader("Cookie"))
        assertNull(poll.getHeader("Origin"))
        assertNull(poll.getHeader("Referer"))
        assertNull(poll.getHeader("Sec-Fetch-Site"))
        assertEquals("", poll.body.readUtf8())
        assertFalse(poll.requestUrl.toString().contains(bearer))
    }

    @Test fun pollLoopHonorsRetryAfterExponentialJitterAndReadyShapeWithoutSecondPrompt() {
        val txn = "A".repeat(43)
        server.enqueue(MockResponse().setResponseCode(202).setHeader("Cache-Control", "no-store").setHeader("Referrer-Policy", "no-referrer").setHeader("Retry-After", "4"))
        server.enqueue(MockResponse().setResponseCode(202).setHeader("Cache-Control", "no-store").setHeader("Referrer-Policy", "no-referrer").setHeader("Retry-After", "0"))
        val locator = "/oid4vp/request/opaque"
        server.enqueue(MockResponse().setResponseCode(200).setHeader("Cache-Control", "no-store").setHeader("Referrer-Policy", "no-referrer").setHeader("Content-Type", "application/json")
            .setBody("""{"client_id":"x509_san_dns:localhost","request_uri":"$rpOrigin$locator"}"""))
        val expiry = System.currentTimeMillis() / 1000 + 200
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(capability)
        val grant = NativeContinuationGrant.parse("""{"profile":"decent-account-disclosure-v1","decent_account_continuation_capability":"$token","expires_at":$expiry}""".toByteArray())
        val sleeps = mutableListOf<Long>()
        val persistEvents = mutableListOf<String>()
        val now = System.currentTimeMillis() / 1000
        val result = persistGrantThenAwaitNativeContinuation(
            http, rpOrigin, txn, grant,
            persistCapability = { encoded, storedExpiry ->
                assertEquals(token, encoded)
                assertEquals(expiry, storedExpiry)
                persistEvents += "persisted"
            },
            cancelled = { false },
            nowEpochSeconds = { now + sleeps.sum() / 1000 },
            sleepMillis = { sleeps += it },
            jitter = { 0.5 },
        )
        assertEquals(ContinuationReady("x509_san_dns:localhost", "$rpOrigin$locator"), result)
        assertEquals(listOf("persisted"), persistEvents)
        assertEquals(listOf(4000L, 3000L), sleeps)
        repeat(3) { assertEquals("Bearer $token", requireNotNull(server.takeRequest(5, TimeUnit.SECONDS)).getHeader("Authorization")) }
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))
        grant.close()
        // There is one approval/one polling lifecycle and this handoff itself never invokes a UI prompt.
        assertFalse(result.toString().contains(token))
    }

    @Test fun strictReadyShapeAndIntegerRetryAfterRejectMalformedResponses() {
        val validRequestUri = "$rpOrigin/oid4vp/request/one"
        val badBodies = listOf(
            """{"client_id":"x509_san_dns:localhost","request_uri":"$validRequestUri","extra":1}""",
            """{"client_id":"x509_san_dns:localhost","client_id":"x509_san_dns:localhost","request_uri":"$validRequestUri"}""",
            """{"client_id":"x509_san_dns:localhost","request_uri":"https://other.example/request"}""",
            """{"client_id":"x509_san_dns:localhost","request_uri":"$validRequestUri?x=1"}""",
        )
        for ((index, body) in badBodies.withIndex()) {
            server.enqueue(MockResponse().setResponseCode(200).setHeader("Cache-Control", "no-store").setHeader("Referrer-Policy", "no-referrer").setHeader("Content-Type", "application/json").setBody(body))
            try { http.pollContinuation(rpOrigin, transactionId, capability); throw AssertionError("accepted malformed body $index") }
            catch (_: NativeDisclosureTransportException) { }
        }
        for (retryAfter in listOf("", "1.5", "-1", "Wed, 21 Oct 2015 07:28:00 GMT")) {
            server.enqueue(MockResponse().setResponseCode(202).setHeader("Cache-Control", "no-store").setHeader("Referrer-Policy", "no-referrer").setHeader("Retry-After", retryAfter))
            try { http.pollContinuation(rpOrigin, transactionId, capability); fail("accepted Retry-After $retryAfter") }
            catch (_: NativeDisclosureTransportException) { }
        }
    }

    @Test fun nonemptyPendingOrTerminalBodiesFailClosed() {
        for (status in listOf(202, 410)) {
            val response = MockResponse().setResponseCode(status).setHeader("Cache-Control", "no-store")
                .setHeader("Referrer-Policy", "no-referrer").setBody("unexpected")
            if (status == 202) response.setHeader("Retry-After", "1")
            server.enqueue(response)
            try { http.pollContinuation(rpOrigin, transactionId, capability); fail("accepted nonempty $status response") }
            catch (_: NativeDisclosureTransportException) { }
        }
        assertEquals(2, server.requestCount)
        repeat(2) { assertEquals("GET", requireNotNull(server.takeRequest(5, TimeUnit.SECONDS)).method) }
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))
    }

    @Test fun requestObjectRejectsWrongMediaTypeAndMissingCacheSafetyHeaders() {
        val jws = "header.payload.signature"
        val cases = listOf(
            Triple("application/json", "no-store", "no-referrer"),
            Triple("application/oauth-authz-req+jwt", "max-age=0", "no-referrer"),
            Triple("application/oauth-authz-req+jwt", "no-store", "same-origin"),
        )
        for ((index, headers) in cases.withIndex()) {
            val response = MockResponse().setResponseCode(200)
                .setHeader("Content-Type", headers.first)
                .setHeader("Cache-Control", headers.second)
                .setHeader("Referrer-Policy", headers.third)
                .setBody(jws)
            server.enqueue(response)
            try {
                http.fetchRequestObject(rpOrigin, "$rpOrigin/oid4vp/request/opaque")
                fail("accepted nonconforming Request Object response $index")
            } catch (_: NativeDisclosureTransportException) { }
        }
        assertEquals(3, server.requestCount)
        repeat(3) { assertEquals("GET", requireNotNull(server.takeRequest(5, TimeUnit.SECONDS)).method) }
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))
    }

    @Test fun presentationSuccessRequiresJsonAndNoStoreNoReferrer() {
        val body = "state=abc&vp_token=exact%2Bbytes".toByteArray()
        val cases = listOf(
            Triple("text/plain", "no-store", "no-referrer"),
            Triple("application/json", "max-age=0", "no-referrer"),
            Triple("application/json", "no-store", "same-origin"),
        )
        for ((index, headers) in cases.withIndex()) {
            server.enqueue(MockResponse().setResponseCode(200)
                .setHeader("Content-Type", headers.first)
                .setHeader("Cache-Control", headers.second)
                .setHeader("Referrer-Policy", headers.third)
                .setBody("{\"result\":\"observed\"}"))
            try {
                http.submitPresentationOnce("$rpOrigin/oid4vp/response", rpOrigin, body).use { }
                fail("accepted nonconforming presentation response $index")
            } catch (_: NativeDisclosureTransportException) { }
        }
        assertEquals(3, server.requestCount)
        repeat(3) {
            val post = requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
            assertEquals("POST", post.method)
            assertArrayEquals(body, post.body.readByteArray())
        }
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))
        body.fill(0)
    }

    @Test fun redirectsAreNeverFollowedAndPresentationPostIsByteExactOnce() {
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "https://elsewhere.invalid/collect"))
        try { http.fetchRequestObject(rpOrigin, "$rpOrigin/oid4vp/request/opaque"); fail("followed redirect") }
        catch (_: NativeDisclosureTransportException) { }
        assertEquals(1, server.requestCount)
        val request = requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
        assertEquals("GET", request.method)
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))

        val body = "state=abc&vp_token=exact%2Bbytes".toByteArray()
        server.enqueue(MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json")
            .setHeader("Cache-Control", "no-store").setHeader("Referrer-Policy", "no-referrer").setBody("{\"result\":\"observed\"}"))
        http.submitPresentationOnce("$rpOrigin/oid4vp/response", rpOrigin, body).use { response ->
            assertEquals(200, response.statusCode)
            assertEquals("application/json", response.contentType)
            assertEquals("{\"result\":\"observed\"}", String(response.body))
        }
        val post = requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
        assertEquals("POST", post.method)
        assertEquals("/oid4vp/response", post.path)
        assertEquals("application/x-www-form-urlencoded", post.getHeader("Content-Type"))
        assertArrayEquals(body, post.body.readByteArray())
        assertBrowserHeadersAbsent(post)
        assertEquals(2, server.requestCount)
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))
    }

    @Test fun cancellationExpiryInvalidOriginAndFailedRequestsProduceNoFurtherOutput() {
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(capability)
        val expiry = System.currentTimeMillis() / 1000 + 120
        val grant = NativeContinuationGrant.parse("""{"profile":"decent-account-disclosure-v1","decent_account_continuation_capability":"$token","expires_at":$expiry}""".toByteArray())
        try { awaitNativeContinuation(http, rpOrigin, transactionId, grant, { true }); fail("cancelled poll returned") }
        catch (_: NativeDisclosureTransportException) { }
        assertEquals(0, server.requestCount)
        try { NativeDisclosureHttpClient.continuationUrl("http://localhost", transactionId); fail("accepted cleartext") }
        catch (_: NativeDisclosureTransportException) { }
        try { NativeDisclosureHttpClient.continuationUrl(rpOrigin, "bad"); fail("accepted malformed transaction id") }
        catch (_: NativeDisclosureTransportException) { }
        server.enqueue(MockResponse().setResponseCode(503).setHeader("Cache-Control", "no-store")
            .setHeader("Referrer-Policy", "no-referrer").setBody("secret-error-response"))
        http.submitPresentationOnce("$rpOrigin/response", rpOrigin, "secret-body".toByteArray()).use { response ->
            assertEquals(503, response.statusCode)
            assertEquals("secret-error-response", String(response.body))
        }
        assertEquals(1, server.requestCount)
        assertEquals("POST", requireNotNull(server.takeRequest(5, TimeUnit.SECONDS)).method)
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))
        grant.close()
    }

    @Test fun retryScheduleHasExponentialBackoffJitterAndRetryAfterAsFloor() {
        assertEquals(1L, NativeContinuationRetry.delaySeconds(0, 0, 0.0))
        assertEquals(2L, NativeContinuationRetry.delaySeconds(0, 0, 1.0))
        assertEquals(5L, NativeContinuationRetry.delaySeconds(2, 0, 0.5))
        assertEquals(10L, NativeContinuationRetry.delaySeconds(1, 10, 1.0))
    }

    private fun assertBrowserHeadersAbsent(request: RecordedRequest) {
        listOf("Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-Fetch-User", "Cookie", "X-Decent-CSRF").forEach {
            assertNull(it, request.getHeader(it))
        }
    }
}

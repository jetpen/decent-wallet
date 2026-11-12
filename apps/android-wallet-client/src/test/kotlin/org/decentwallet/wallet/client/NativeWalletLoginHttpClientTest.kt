package org.decentwallet.wallet.client

import okhttp3.CookieJar
import okhttp3.OkHttpClient
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.mockwebserver.RecordedRequest
import okhttp3.mockwebserver.SocketPolicy
import org.decentwallet.wallet.android.WalletLoginProofRequest
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.net.CookieHandler
import java.util.Base64
import java.util.concurrent.TimeUnit

class NativeWalletLoginHttpClientTest {
    private lateinit var server: MockWebServer
    private lateinit var transaction: WalletLoginTransactionUrl
    private lateinit var client: NativeWalletLoginHttpClient
    private val challenge = "A".repeat(43)
    private val signature = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(64))
    private val path = "/realms/demo/decent-wallet-login/v1/transactions/${"A".repeat(43)}"
    private var previousCookieHandler: CookieHandler? = null

    @Before fun setUp() {
        previousCookieHandler = CookieHandler.getDefault()
        val certificate = HeldCertificate.Builder().addSubjectAlternativeName("localhost").build()
        val serverCertificates = HandshakeCertificates.Builder().heldCertificate(certificate).build()
        val trusted = HandshakeCertificates.Builder().addTrustedCertificate(certificate.certificate).build()
        server = MockWebServer().apply { useHttps(serverCertificates.sslSocketFactory(), false); start() }
        transaction = WalletLoginTransactionUrl.parse(server.url(path).toString(), "https://localhost:${server.port}")
        val testHttp = OkHttpClient.Builder()
            .sslSocketFactory(trusted.sslSocketFactory(), trusted.trustManager)
            .build()
        client = NativeWalletLoginHttpClient(testHttp)
    }

    @After fun tearDown() {
        CookieHandler.setDefault(previousCookieHandler)
        server.shutdown()
    }

    @Test fun nativeGetAndPostUseExactRouteAndKeepEveryBrowserCredentialHeaderAbsent() {
        CookieHandler.setDefault(object : CookieHandler() {
            override fun get(uri: java.net.URI, requestHeaders: Map<String, List<String>>): Map<String, List<String>> =
                mapOf("Cookie" to listOf("browser-session=never-forward"))
            override fun put(uri: java.net.URI, responseHeaders: Map<String, List<String>>) = Unit
        })
        server.enqueue(MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody(challengeJson()))
        assertEquals(challenge, client.getChallenge(transaction).challenge)
        val get = requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
        assertEquals("GET", get.method)
        assertEquals(path, get.path)
        assertBrowserMetadataAbsentIndividually(get)

        val identity = "mailto:wallet-🦊@example.org"
        val proof = WalletLoginProofRequest("decent-wallet-login-v1", challenge, identity, signature)
        server.enqueue(MockResponse().setResponseCode(202))
        assertTrue(client.submitProof(transaction, proof))
        val post = requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
        assertEquals("POST", post.method)
        assertEquals(path, post.path)
        assertEquals("application/json", post.getHeader("Content-Type"))
        assertBrowserMetadataAbsentIndividually(post)
        val exact = "{\"profile\":\"decent-wallet-login-v1\",\"challenge\":\"$challenge\",\"identity_id\":\"$identity\",\"signature\":\"$signature\"}"
        assertEquals(exact, post.body.readUtf8())
    }

    @Test fun challengeRequiresValidJsonContentType() {
        val accepted = listOf("application/json", "Application/JSON", "application/json; charset=utf-8")
        for (contentType in accepted) {
            server.enqueue(MockResponse().setResponseCode(200).setHeader("Content-Type", contentType).setBody(challengeJson()))
            assertEquals(challenge, client.getChallenge(transaction).challenge)
        }
        val rejected = listOf(null, "text/plain", "application/jsonp", "text/application/json", "application/json; charset=\"unterminated", "application/json; bad parameter")
        for (contentType in rejected) {
            val response = MockResponse().setResponseCode(200).setBody(challengeJson())
            if (contentType != null) response.setHeader("Content-Type", contentType)
            server.enqueue(response)
            try {
                client.getChallenge(transaction)
                fail("accepted invalid Content-Type: $contentType")
            } catch (_: WalletLoginTransportException) { }
        }
    }

    @Test fun oversizedKnownLengthChallengeIsRejectedByTheProductionTransport() {
        server.enqueue(MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setBody("x".repeat(16 * 1024 + 1)))
        try {
            client.getChallenge(transaction)
            fail("oversized Content-Length response must be rejected")
        } catch (_: WalletLoginTransportException) { }
        assertEquals(1, server.requestCount)
        assertEquals("GET", requireNotNull(server.takeRequest(5, TimeUnit.SECONDS)).method)
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))
    }

    @Test fun oversizedChunkedChallengeIsRejectedByTheProductionTransport() {
        server.enqueue(MockResponse().setResponseCode(200).setHeader("Content-Type", "application/json").setChunkedBody("x".repeat(16 * 1024 + 1), 257))
        try {
            client.getChallenge(transaction)
            fail("oversized unknown-length response must be rejected")
        } catch (_: WalletLoginTransportException) { }
        assertEquals(1, server.requestCount)
        assertEquals("GET", requireNotNull(server.takeRequest(5, TimeUnit.SECONDS)).method)
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))
    }

    @Test fun crossOriginRedirectIsRejectedAndNeverFollowed() {
        server.enqueue(MockResponse().setResponseCode(302).addHeader("Location", "https://elsewhere.invalid/collect"))
        assertFalse(client.submitProof(transaction, proof()))
        val observed = requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
        assertEquals("POST", observed.method)
        assertEquals(path, observed.path)
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))
    }

    @Test fun ambiguousPostFailureIsNotRetried() {
        server.enqueue(MockResponse().setSocketPolicy(SocketPolicy.DISCONNECT_AFTER_REQUEST))
        try { client.submitProof(transaction, proof()) } catch (_: WalletLoginTransportException) { }
        requireNotNull(server.takeRequest(5, TimeUnit.SECONDS))
        assertEquals(1, server.requestCount)
        assertNull(server.takeRequest(150, TimeUnit.MILLISECONDS))
    }

    @Test fun untrustedTlsPeerIsRejectedBeforeTheFixtureReceivesARequest() {
        val untrusted = NativeWalletLoginHttpClient(OkHttpClient.Builder().cookieJar(CookieJar.NO_COOKIES).build())
        try {
            untrusted.getChallenge(transaction)
            fail("untrusted TLS was accepted")
        } catch (_: WalletLoginTransportException) { }
        assertEquals(0, server.requestCount)
        assertNull(server.takeRequest(100, TimeUnit.MILLISECONDS))
    }

    @Test fun trustedButHostnameMismatchedTlsPeerIsRejectedBeforeHttp() {
        val mismatchedCertificate = HeldCertificate.Builder().addSubjectAlternativeName("other.example.test").build()
        val serverTls = HandshakeCertificates.Builder().heldCertificate(mismatchedCertificate).build()
        val trustedTls = HandshakeCertificates.Builder().addTrustedCertificate(mismatchedCertificate.certificate).build()
        val mismatchServer = MockWebServer().apply { useHttps(serverTls.sslSocketFactory(), false); start() }
        try {
            val mismatchedUrl = WalletLoginTransactionUrl.parse(
                mismatchServer.url(path).toString(),
                "https://localhost:${mismatchServer.port}",
            )
            val trustedClient = NativeWalletLoginHttpClient(OkHttpClient.Builder()
                .sslSocketFactory(trustedTls.sslSocketFactory(), trustedTls.trustManager).build())
            try { trustedClient.getChallenge(mismatchedUrl); fail("hostname mismatch was accepted") }
            catch (_: WalletLoginTransportException) { }
            assertEquals(0, mismatchServer.requestCount)
            assertNull(mismatchServer.takeRequest(100, TimeUnit.MILLISECONDS))
        } finally {
            mismatchServer.shutdown()
        }
    }

    private fun proof() = WalletLoginProofRequest("decent-wallet-login-v1", challenge, "mailto:test@example.org", signature)

    private fun challengeJson() = """{"profile":"decent-wallet-login-v1","challenge":"$challenge","csrf_token":"server-only"}"""

    private fun assertBrowserMetadataAbsentIndividually(request: RecordedRequest) {
        assertNull("Origin", request.getHeader("Origin"))
        assertNull("Sec-Fetch-Site", request.getHeader("Sec-Fetch-Site"))
        assertNull("Sec-Fetch-Mode", request.getHeader("Sec-Fetch-Mode"))
        assertNull("Sec-Fetch-Dest", request.getHeader("Sec-Fetch-Dest"))
        assertNull("Sec-Fetch-User", request.getHeader("Sec-Fetch-User"))
        assertNull("Cookie", request.getHeader("Cookie"))
        assertNull("X-Decent-CSRF", request.getHeader("X-Decent-CSRF"))
        assertNull("Authorization", request.getHeader("Authorization"))
    }
}

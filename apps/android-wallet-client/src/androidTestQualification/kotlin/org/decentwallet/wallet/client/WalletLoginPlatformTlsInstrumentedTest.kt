package org.decentwallet.wallet.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import okhttp3.EventListener
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.decentwallet.wallet.android.WalletLoginProofRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.cert.CertificateException
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException

@RunWith(AndroidJUnit4::class)
class WalletLoginPlatformTlsInstrumentedTest {
    private val path get() = "/realms/demo/decent-wallet-login/v1/transactions/${"A".repeat(43)}"

    @Test
    fun qualificationTransportAcceptsThePlatformTrustedWalletFixtureOrigin() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        assumeTrue("qualification variant must use Android platform trust", context.packageName.endsWith(".qualification"))
        val transaction = WalletLoginTransactionUrl.parse("${BuildConfig.WALLET_LOGIN_ORIGIN}$path", BuildConfig.WALLET_LOGIN_ORIGIN)

        val challenge = NativeWalletLoginHttpClient(context).getChallenge(transaction)

        assertEquals("decent-wallet-login-v1", challenge.profile)
        assertEquals("A".repeat(43), challenge.challenge)
    }

    @Test
    fun untrustedDedicatedTestCaWithMatchingSanIsRejectedBeforeHttp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue("qualification variant must use Android platform trust", context.packageName.endsWith(".qualification"))
        val testCa = HeldCertificate.Builder()
            .certificateAuthority(0)
            .commonName("Issue 80 instrumentation test CA")
            .build()
        val matchingSanLeaf = HeldCertificate.Builder()
            .commonName("localhost")
            .addSubjectAlternativeName("localhost")
            .signedBy(testCa)
            .build()
        val server = MockWebServer()
        try {
            val serverTls = HandshakeCertificates.Builder()
                .heldCertificate(matchingSanLeaf, testCa.certificate)
                .build()
            server.useHttps(serverTls.sslSocketFactory(), false)
            server.start()

            val origin = "https://localhost:${server.port}"
            val transaction = WalletLoginTransactionUrl.parse("$origin$path", origin)
            val request = Request.Builder().url(transaction.url).get().build()
            try {
                OkHttpClient().newCall(request).execute().use {
                    fail("default platform client trusted the negative certificate")
                }
            } catch (failure: SSLHandshakeException) {
                assertTrueCertificateRejection(failure)
            }
            val production = NativeWalletLoginHttpClient(context)
            try {
                production.getChallenge(transaction)
                fail("platform trust accepted a chain from the untrusted dedicated test CA")
            } catch (_: WalletLoginTransportException) {
                // The production transport intentionally exposes only a bounded failure.
            }
            assertFalse("untrusted certificate allowed proof submission", production.submitProof(transaction, syntheticProof()))
            assertEquals("untrusted certificate reached the HTTP handler", 0, server.requestCount)
            org.junit.Assert.assertNull(server.takeRequest(100, TimeUnit.MILLISECONDS))
        } finally {
            server.shutdown()
        }
    }

    @Test
    fun platformTrustedChainWithHostnameMismatchIsRejectedBeforeHttpOrProofPost() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeTrue("qualification variant must use Android platform trust", context.packageName.endsWith(".qualification"))
        val origin = BuildConfig.WALLET_LOGIN_ORIGIN
        val transaction = WalletLoginTransactionUrl.parse("$origin$path", origin)
        val baseline = OkHttpClient()
        val verifiedFixtureSessions = AtomicInteger()
        val requestHeaders = AtomicInteger()
        val http = baseline.newBuilder().retryOnConnectionFailure(false).hostnameVerifier { fixtureHost, session ->
            // Keep DNS, SNI and platform trust unchanged. Change only the name passed
            // to OkHttp's normal verifier, on the same platform-trusted TLS session.
            if (baseline.hostnameVerifier.verify(fixtureHost, session)) {
                verifiedFixtureSessions.incrementAndGet()
                baseline.hostnameVerifier.verify("wallet-mismatch.invalid", session)
            } else {
                false
            }
        }.eventListener(object : EventListener() {
            override fun requestHeadersStart(call: okhttp3.Call) {
                requestHeaders.incrementAndGet()
            }
        }).build()
        val request = Request.Builder().url("$origin$path").get().build()
        try {
            http.newCall(request).execute().use {
                fail("OkHttp accepted a platform-trusted certificate for the wrong hostname")
            }
        } catch (_: SSLPeerUnverifiedException) {
            // The ordinary hostname verifier rejects only after the trusted TLS handshake.
        }
        assertEquals("hostname control did not reach the verifier on a valid fixture session", 1, verifiedFixtureSessions.get())

        val production = NativeWalletLoginHttpClient(http)
        try {
            production.getChallenge(transaction)
            fail("production transport accepted the hostname mismatch")
        } catch (_: WalletLoginTransportException) {
            // Bounded production error; no exception details are exposed.
        }
        assertEquals("hostname mismatch allowed HTTP request headers", 0, requestHeaders.get())
        assertFalse(
            "proof POST unexpectedly succeeded despite TLS hostname mismatch",
            production.submitProof(transaction, syntheticProof()),
        )
        assertEquals("hostname rejection sent HTTP request headers or proof", 0, requestHeaders.get())
        assertEquals("each attempted call must fail hostname verification on a valid fixture session", 3, verifiedFixtureSessions.get())
    }

    private fun syntheticProof() = WalletLoginProofRequest(
        "decent-wallet-login-v1",
        "A".repeat(43),
        "synthetic:test",
        Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(64)),
    )

    private fun assertTrueCertificateRejection(failure: SSLHandshakeException) {
        org.junit.Assert.assertTrue("handshake failed without a certificate validation error",
            generateSequence<Throwable>(failure) { it.cause }.any { it is CertificateException })
    }
}

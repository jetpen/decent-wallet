package org.decentwallet.wallet.client

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.decentwallet.wallet.android.WalletLoginProofRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyPair
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.security.cert.CertificateException
import java.util.Base64
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException

@RunWith(AndroidJUnit4::class)
class WalletLoginTlsNegativeInstrumentedTest {
    private val path get() = "/realms/demo/decent-wallet-login/v1/transactions/${"A".repeat(43)}"

    @Test
    fun matchingSanCertificateFromUntrustedTestCaIsRejectedBeforeHttp() {
        val matchingSanCertificate = HeldCertificate.Builder()
            .commonName("localhost")
            .addSubjectAlternativeName("localhost")
            .build()
        assertTlsRejectedBeforeRequest(matchingSanCertificate, hostnameMismatch = false)
    }

    @Test
    fun trustedTestChainWithHostnameMismatchIsRejectedBeforeHttp() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val testRootCertificate = instrumentation.context.assets.open("wallet_login_test_cert.pem").use {
            CertificateFactory.getInstance("X.509").generateCertificate(it) as java.security.cert.X509Certificate
        }
        val keyPem = instrumentation.context.assets.open("wallet_login_test_ca_key_pkcs8.pem")
            .bufferedReader().use { it.readText() }
        val keyDer = Base64.getDecoder().decode(keyPem.lineSequence().filterNot { it.startsWith("---") }.joinToString(""))
        val privateKey = try {
            KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyDer))
        } finally {
            keyDer.fill(0)
        }
        val trustedTestRoot = HeldCertificate(KeyPair(testRootCertificate.publicKey, privateKey), testRootCertificate)
        val mismatchedCertificate = HeldCertificate.Builder()
            .commonName("other.example.test")
            .addSubjectAlternativeName("other.example.test")
            .signedBy(trustedTestRoot)
            .build()
        assertTlsRejectedBeforeRequest(mismatchedCertificate, hostnameMismatch = true)
    }

    private fun assertTlsRejectedBeforeRequest(certificate: HeldCertificate, hostnameMismatch: Boolean) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val server = MockWebServer()
        try {
            val serverTls = HandshakeCertificates.Builder().heldCertificate(certificate).build()
            server.useHttps(serverTls.sslSocketFactory(), false)
            server.start()
            val origin = "https://localhost:${server.port}"
            val transaction = WalletLoginTransactionUrl.parse("$origin$path", origin)
            val builder = OkHttpClient.Builder().retryOnConnectionFailure(false)
            DebugWalletLoginTls.configure(context, builder)
            try {
                builder.build().newCall(Request.Builder().url(transaction.url).build()).execute().use {
                    fail("debug TLS accepted the negative certificate")
                }
            } catch (failure: SSLHandshakeException) {
                assertFalse("hostname control failed before verification", hostnameMismatch)
                assertTrue("handshake failure did not originate from certificate validation",
                    generateSequence<Throwable>(failure) { it.cause }.any { it is CertificateException })
            } catch (_: SSLPeerUnverifiedException) {
                assertTrue("unknown-CA control reached hostname verification", hostnameMismatch)
            }
            val production = NativeWalletLoginHttpClient(context)
            try {
                production.getChallenge(transaction)
                fail("TLS-invalid fixture was accepted")
            } catch (_: WalletLoginTransportException) {
                // The production transport intentionally exposes a bounded failure with no cause.
            }
            assertFalse("negative fixture allowed proof submission", production.submitProof(
                transaction,
                WalletLoginProofRequest("decent-wallet-login-v1", "A".repeat(43), "synthetic:test",
                    Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(64))),
            ))
            assertEquals("TLS rejection must happen before the fixture receives HTTP", 0, server.requestCount)
            assertNull("TLS rejection unexpectedly reached an HTTP handler", server.takeRequest(100, TimeUnit.MILLISECONDS))
        } finally {
            server.shutdown()
        }
    }
}

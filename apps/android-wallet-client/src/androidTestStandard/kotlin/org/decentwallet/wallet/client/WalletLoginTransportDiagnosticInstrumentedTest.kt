package org.decentwallet.wallet.client

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyFactory
import java.security.KeyPair
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class WalletLoginTransportDiagnosticInstrumentedTest {
    @Test fun directTlsAndProductionTransportUseTheLocalFixture() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.targetContext
        val server = MockWebServer()
        var directCategory: String? = null
        var directPath: String? = null
        var productionCategory: String? = null
        var productionPath: String? = null

        try {
            val certificate = instrumentation.context.assets.open("wallet_login_test_cert.pem").use {
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
            server.useHttps(
                HandshakeCertificates.Builder()
                    .heldCertificate(HeldCertificate(KeyPair(certificate.publicKey, privateKey), certificate))
                    .build().sslSocketFactory(),
                false,
            )
            repeat(2) {
                server.enqueue(MockResponse().setResponseCode(204)
                    .setHeader("Cache-Control", "no-store")
                    .setHeader("Referrer-Policy", "no-referrer"))
            }
            server.start(8443)

            var directStage = "builder_create"
            try {
                val builder = OkHttpClient.Builder()
                directStage = "tls_configure"
                DebugWalletLoginTls.configure(context.applicationContext, builder)
                directStage = "client_build"
                val client = builder.build()
                directStage = "request_build"
                val request = Request.Builder().url("${BuildConfig.WALLET_LOGIN_ORIGIN}/tls-probe").build()
                directStage = "request_execute"
                val status = client.newCall(request).execute().use { it.code }
                if (status != 204) directCategory = "unexpected_status"
            } catch (failure: Exception) {
                directCategory = "$directStage/${failureCategory(failure)}"
            }
            directPath = server.takeRequest(1, TimeUnit.SECONDS)?.path

            val transaction = WalletLoginTransactionUrl.parse(
                "${BuildConfig.WALLET_LOGIN_ORIGIN}/realms/demo/decent-wallet-login/v1/transactions/${"A".repeat(43)}",
                BuildConfig.WALLET_LOGIN_ORIGIN,
            )
            var productionStage = "client_construct"
            try {
                val client = NativeDisclosureHttpClient(context)
                productionStage = "fetch_context"
                val response = client.fetchDisclosureContext(transaction)
                if (response !== NativeDisclosureContextResponse.LoginOnly) productionCategory = "unexpected_context"
            } catch (failure: Exception) {
                productionCategory = "$productionStage/${failureCategory(failure)}"
            }
            productionPath = server.takeRequest(1, TimeUnit.SECONDS)?.path

            val requests = server.requestCount
            assertTrue(
                "local transport diagnostic: direct=$directCategory, production=$productionCategory, requests=$requests",
                directCategory == null && directPath == "/tls-probe" &&
                    productionCategory == null && productionPath?.endsWith("/disclosure-context") == true &&
                    requests == 2,
            )
        } finally {
            server.shutdown()
        }
    }

    private fun failureCategory(failure: Throwable): String {
        val causes = generateSequence(failure) { it.cause }.take(8).toList()
        for (cause in causes.asReversed()) {
            when (cause) {
                is DebugWalletLoginTlsConfigurationFailure ->
                    return "tls_setup_${cause.stage.name.lowercase()}"
                is javax.net.ssl.SSLException,
                is java.security.cert.CertificateException -> return "tls"
                is java.net.UnknownHostException -> return "dns"
                is java.net.SocketException -> return "connect"
                is java.net.SocketTimeoutException -> return "timeout"
                is SecurityException -> return "permission"
                is ReflectiveOperationException -> return "reflection"
                is java.security.GeneralSecurityException -> return "crypto_setup"
                is android.content.res.Resources.NotFoundException -> return "resource"
                is IllegalArgumentException,
                is IllegalStateException -> return "configuration"
                is java.io.IOException -> return "io"
            }
        }
        return if (failure is NativeDisclosureTransportException) "transport" else "other"
    }
}

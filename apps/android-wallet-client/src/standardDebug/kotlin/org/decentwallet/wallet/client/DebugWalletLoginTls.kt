package org.decentwallet.wallet.client

import android.content.Context
import okhttp3.OkHttpClient
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

internal enum class DebugWalletLoginTlsConfigurationStage {
    LOAD_ROOT,
    BUILD_SYSTEM_TRUST,
    BUILD_TEST_STORE,
    BUILD_TEST_TRUST,
    BUILD_SSL_CONTEXT,
    CONFIGURE_OKHTTP,
}

internal class DebugWalletLoginTlsConfigurationFailure(
    val stage: DebugWalletLoginTlsConfigurationStage,
) : Exception("debug TLS configuration failed")

/** Debug-only additive root. OkHttp's normal hostname verifier remains in force. */
object DebugWalletLoginTls {
    @JvmStatic
    fun configure(context: Context, builder: OkHttpClient.Builder) {
        var stage = DebugWalletLoginTlsConfigurationStage.LOAD_ROOT
        try {
            val certificate = context.resources.openRawResource(
                context.resources.getIdentifier("wallet_login_test_ca", "raw", context.packageName)
            ).use {
                CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
            }
            stage = DebugWalletLoginTlsConfigurationStage.BUILD_SYSTEM_TRUST
            val system = defaultTrustManager(null)
            stage = DebugWalletLoginTlsConfigurationStage.BUILD_TEST_STORE
            val testStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
                load(null)
                setCertificateEntry("wallet-login-test-only", certificate)
            }
            stage = DebugWalletLoginTlsConfigurationStage.BUILD_TEST_TRUST
            val test = defaultTrustManager(testStore)
            val combined = object : X509TrustManager {
                override fun getAcceptedIssuers(): Array<X509Certificate> =
                    (system.acceptedIssuers.asList() + test.acceptedIssuers.asList())
                        .distinctBy { it.subjectX500Principal.name }.toTypedArray()

                override fun checkClientTrusted(chain: Array<out X509Certificate>, authType: String) =
                    system.checkClientTrusted(chain, authType)

                override fun checkServerTrusted(chain: Array<out X509Certificate>, authType: String) {
                    try {
                        system.checkServerTrusted(chain, authType)
                    } catch (_: CertificateException) {
                        test.checkServerTrusted(chain, authType)
                    }
                }
            }
            stage = DebugWalletLoginTlsConfigurationStage.BUILD_SSL_CONTEXT
            val sslContext = SSLContext.getInstance("TLS")
            sslContext.init(null, arrayOf(combined), SecureRandom())
            stage = DebugWalletLoginTlsConfigurationStage.CONFIGURE_OKHTTP
            builder.sslSocketFactory(sslContext.socketFactory, combined)
        } catch (_: Exception) {
            throw DebugWalletLoginTlsConfigurationFailure(stage)
        }
    }

    private fun defaultTrustManager(store: KeyStore?): X509TrustManager {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(store)
        return factory.trustManagers.filterIsInstance<X509TrustManager>().single()
    }
}

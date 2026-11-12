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

/** Debug-only additive root. OkHttp's normal hostname verifier remains in force. */
object DebugWalletLoginTls {
    @JvmStatic
    fun configure(context: Context, builder: OkHttpClient.Builder) {
        val certificate = context.resources.openRawResource(R.raw.wallet_login_test_ca).use {
            CertificateFactory.getInstance("X.509").generateCertificate(it) as X509Certificate
        }
        val system = defaultTrustManager(null)
        val testStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("wallet-login-test-only", certificate)
        }
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
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(null, arrayOf(combined), SecureRandom())
        builder.sslSocketFactory(sslContext.socketFactory, combined)
    }

    private fun defaultTrustManager(store: KeyStore?): X509TrustManager {
        val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        factory.init(store)
        return factory.trustManagers.filterIsInstance<X509TrustManager>().single()
    }
}

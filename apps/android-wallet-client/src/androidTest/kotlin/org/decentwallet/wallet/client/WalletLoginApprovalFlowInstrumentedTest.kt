package org.decentwallet.wallet.client

import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.decentwallet.wallet.android.AndroidWallet
import org.decentwallet.wallet.android.WalletLoginProofRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyFactory
import java.security.KeyPair
import java.security.cert.CertificateFactory
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class WalletLoginApprovalFlowInstrumentedTest {
    private val challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { it.toByte() })
    private val transactionHandle = "A".repeat(43)
    private val walletPassword = "synthetic-instrumentation-wallet-password"

    @Test fun approvalPostsExactlyOneProofVerifiableByTheFreshWalletKey() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val identityId = "test:activity-approval-${UUID.randomUUID()}"
        val walletFile = File(context.cacheDir, "wallet-login-${UUID.randomUUID()}.wallet")
        val session = AndroidWallet.createWithGeneratedKey(walletFile.toPath(), walletPassword, walletPassword)
        val publicKey = session.ownerPublicKey
        val fixture = ProviderFixture()
        try {
            fixture.start()
            DebugWalletLoginApplication.install(WalletLoginIdentity(session, identityId))
            ActivityScenario.launch<WalletLoginActivity>(intent(context)).use { scenario ->
                val get = requireNotNull(fixture.server.takeRequest(10, TimeUnit.SECONDS))
                assertEquals("GET", get.method)
                assertEquals(path, get.path)
                waitForConsent(scenario, identityId)
                scenario.onActivity { activity -> WalletLoginTestViews.button(activity.window.decorView, "Approve wallet login").performClick() }
                val post = requireNotNull(fixture.server.takeRequest(10, TimeUnit.SECONDS))
                assertEquals("POST", post.method)
                assertEquals(path, post.path)
                assertEquals(2, fixture.server.requestCount)
                val body = post.body.readByteArray()
                try {
                    val parsed = org.json.JSONObject(String(body, Charsets.UTF_8))
                    val names = parsed.keys().asSequence().toSet()
                    assertEquals(setOf("profile", "challenge", "identity_id", "signature"), names)
                    val proof = WalletLoginProofRequest(
                        parsed.getString("profile"),
                        parsed.getString("challenge"),
                        parsed.getString("identity_id"),
                        parsed.getString("signature"),
                    )
                    assertEquals("decent-wallet-login-v1", proof.profile)
                    assertEquals(challenge, proof.challenge)
                    assertEquals(identityId, proof.identityId)
                    assertTrue("proof signature did not verify against fresh wallet key", proof.verifyAgainst(publicKey))
                } finally {
                    body.fill(0)
                }
                assertNull("approval sent an extra request", fixture.server.takeRequest(300, TimeUnit.MILLISECONDS))
            }
        } finally {
            DebugWalletLoginApplication.clear()
            publicKey.fill(0)
            session.close()
            walletFile.delete()
            fixture.close()
        }
    }

    @Test fun denialSendsNoProof() = assertDecisionSendsNoProof("Deny", "Wallet login denied")

    @Test fun cancellationSendsNoProof() = assertDecisionSendsNoProof("Cancel", "Wallet login cancelled")

    private fun assertDecisionSendsNoProof(button: String, terminalText: String) {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val walletFile = File(context.cacheDir, "wallet-login-${UUID.randomUUID()}.wallet")
        val session = AndroidWallet.createWithGeneratedKey(walletFile.toPath(), walletPassword, walletPassword)
        val fixture = ProviderFixture()
        try {
            fixture.start()
            DebugWalletLoginApplication.install(WalletLoginIdentity(session, "test:activity-${UUID.randomUUID()}"))
            ActivityScenario.launch<WalletLoginActivity>(intent(context)).use { scenario ->
                val get = requireNotNull(fixture.server.takeRequest(10, TimeUnit.SECONDS))
                assertEquals("GET", get.method)
                assertEquals(path, get.path)
                waitForConsent(scenario, "test:activity-")
                scenario.onActivity { activity -> WalletLoginTestViews.button(activity.window.decorView, button).performClick() }
                waitForText(scenario, terminalText)
                assertEquals("decision sent an unexpected request", 1, fixture.server.requestCount)
                assertNull("decision sent a proof", fixture.server.takeRequest(300, TimeUnit.MILLISECONDS))
            }
        } finally {
            DebugWalletLoginApplication.clear()
            session.close()
            walletFile.delete()
            fixture.close()
        }
    }

    private val path get() = "/realms/demo/decent-wallet-login/v1/transactions/$transactionHandle"

    private fun intent(context: android.content.Context): Intent = Intent(Intent.ACTION_VIEW)
        .setClass(context, WalletLoginActivity::class.java)
        .setData(Uri.parse("${BuildConfig.WALLET_LOGIN_ORIGIN}$path"))
        .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)

    private fun waitForConsent(scenario: ActivityScenario<WalletLoginActivity>, identity: String) {
        waitUntil(scenario) { texts ->
            texts.any { it == "Approve wallet login" } && texts.any { it.contains(identity) }
        }
    }

    private fun waitForText(scenario: ActivityScenario<WalletLoginActivity>, expected: String) {
        waitUntil(scenario) { texts -> texts.any { it.contains(expected) } }
    }

    private fun waitUntil(scenario: ActivityScenario<WalletLoginActivity>, predicate: (List<String>) -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (System.nanoTime() < deadline) {
            var visible = false
            scenario.onActivity { activity -> visible = predicate(WalletLoginTestViews.texts(activity.window.decorView)) }
            if (visible) return
            Thread.sleep(50)
        }
        throw AssertionError("expected Activity screen did not appear")
    }

    private inner class ProviderFixture : AutoCloseable {
        val server = MockWebServer()

        fun start() {
            val assets = InstrumentationRegistry.getInstrumentation().context.assets
            val certificate = assets.open("wallet_login_test_cert.pem").use {
                CertificateFactory.getInstance("X.509").generateCertificate(it) as java.security.cert.X509Certificate
            }
            val keyPem = assets.open("wallet_login_test_ca_key_pkcs8.pem").bufferedReader().use { it.readText() }
            val keyDer = Base64.getDecoder().decode(keyPem.lineSequence().filterNot { it.startsWith("---") }.joinToString(""))
            val privateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyDer))
            keyDer.fill(0)
            val held = HeldCertificate(KeyPair(certificate.publicKey, privateKey), certificate)
            val serverTls = HandshakeCertificates.Builder().heldCertificate(held).build()
            server.useHttps(serverTls.sslSocketFactory(), false)
            val challengeJson = """{"profile":"decent-wallet-login-v1","challenge":"$challenge","csrf_token":"fixture-only"}"""
            server.enqueue(MockResponse().setHeader("Content-Type", "application/json").setBody(challengeJson))
            server.enqueue(MockResponse().setResponseCode(200).setBody("{}"))
            server.start(8443)
        }

        override fun close() = server.shutdown()
    }
}

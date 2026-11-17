package org.decentwallet.wallet.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import java.nio.file.Path
import org.junit.Test
import java.util.Base64

class QualificationTrustConfigTest {
    @Test fun parsesOnlyCompletePublicTrustBoundToTheConfiguredProviderHost() {
        val config = QualificationTrustConfig.parse(configJson, "login.test")
        assertEquals("https://login.test/realms/wallet", config.issuer)
        assertEquals("issuer test", config.keycloakDisplayName)
        assertEquals("x509_san_dns:rp.test", config.rp.clientId)
        assertEquals("https://rp.test/oid4vp/direct-post", config.rp.responseUri)
        assertNotNull(config.toNativeDisclosureTrustConfig())
    }

    @Test fun absentOrPlaceholderTrustNeverCreatesAConfig() {
        assertNull(QualificationTrustConfig.load(emptyMap(), "login.test"))
        assertThrows(IllegalArgumentException::class.java) {
            QualificationTrustConfig.parse(configJson.replace("https://login.test/realms/wallet", "https://login.example/realms/wallet"), "login.test")
        }
        assertThrows(IllegalArgumentException::class.java) {
            QualificationTrustConfig.parse(configJson.replace("issuer test", "replace_me"), "login.test")
        }
    }

    @Test fun rejectsPrivateJwkMaterialAndMismatchedRpOriginOrPin() {
        assertThrows(IllegalArgumentException::class.java) {
            QualificationTrustConfig.parse(configJson.replace("\"n\":\"$modulus\"", "\"n\":\"$modulus\",\"d\":\"$privateKey\""), "login.test")
        }
        assertThrows(IllegalArgumentException::class.java) {
            QualificationTrustConfig.parse(configJson.replace("https://rp.test/oid4vp/direct-post", "https://other.test/oid4vp/direct-post"), "login.test")
        }
        assertThrows(IllegalArgumentException::class.java) {
            QualificationTrustConfig.parse(configJson.replace("\"trust_anchor_sha256\":\"$pin\"", "\"trust_anchor_sha256\":\"placeholder\""), "login.test")
        }
    }

    @Test fun rejectsDuplicateMembersAtEveryJsonDepth() {
        val duplicateIssuer = configJson.replace("\"issuer\":\"https://login.test/realms/wallet\"", "\"issuer\":\"https://login.test/realms/wallet\",\"issuer\":\"https://attacker.test/realms/wallet\"")
        assertThrows(com.fasterxml.jackson.core.JsonParseException::class.java) { QualificationTrustConfig.parse(duplicateIssuer, "login.test") }
        val duplicateJwk = configJson.replace("\"kid\":\"issuer-1\"", "\"kid\":\"issuer-1\",\"kid\":\"attacker\"")
        assertThrows(com.fasterxml.jackson.core.JsonParseException::class.java) { QualificationTrustConfig.parse(duplicateJwk, "login.test") }
    }

    @Test fun conventionalSourceAssetIsIncludedInProvenanceFingerprint() {
        val gradle = Path.of(requireNotNull(System.getProperty("user.dir")).substringBefore("/apps/"), "apps/android-wallet-client/build.gradle.kts").toFile().readText()
        assertTrue("qualificationSourceTrust" in gradle.substringAfter("val trustSource ="))
        assertTrue("trustConfigFingerprint.set(providers.provider" in gradle)
        assertTrue("sourceTrustConfigPath.set(trustSource.absolutePath)" in gradle)
    }

    private val modulus = Base64.getUrlEncoder().withoutPadding().encodeToString(
        ByteArray(256).also { it[0] = 0x80.toByte(); it[it.lastIndex] = 1 },
    )
    private val privateKey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    private val pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    private val configJson get() = """
        {
          "keycloak_display_name":"issuer test",
          "issuer":"https://login.test/realms/wallet",
          "issuer_jwks":{"keys":[{"kty":"RSA","kid":"issuer-1","use":"sig","alg":"RS256","n":"$modulus","e":"AQAB"}]},
          "rp":{"client_id":"x509_san_dns:rp.test","x509_san_dns":"rp.test","origin":"https://rp.test","response_uri":"https://rp.test/oid4vp/direct-post","trust_anchor_sha256":"$pin","rp_client_id":"account-client"}
        }
    """.trimIndent()
}

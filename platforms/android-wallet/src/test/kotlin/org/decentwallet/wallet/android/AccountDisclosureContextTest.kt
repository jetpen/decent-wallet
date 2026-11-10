package org.decentwallet.wallet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test
import java.nio.file.Files
import java.util.Comparator

class AccountDisclosureContextTest {
    private val issuer = "https://login.example.test/realms/site"
    private val identityId = "test:android-disclosure-owner"
    private val entity = mapOf(
        "given_name" to "Ada",
        "family_name" to "Lovelace",
        "email" to "ada@example.test",
        "phone" to "+1-555-0100",
        "locale" to "en-GB",
    )

    @Test
    fun acceptsAllPositiveProfileContextsAndMapsExactEntityKeys() {
        val vectors = listOf(
            "valid-signup.json",
            "valid-signup-recovery.json",
            "valid-signup-optional-omitted.json",
            "valid-extensions-ignored.json",
            "valid-request-iss-ignored.json",
        )
        val directory = Files.createTempDirectory("wallet-android-disclosure-vectors-")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.createWithGeneratedKey(directory.resolve("wallet.dw"), password, password)
        try {
            wallet.setMasterAccountEntity(entity)
            for (name in vectors) {
                val root = readVector(name)
                val context = root["keycloak_context"] as Map<*, *>
                val rawContext = WalletJson.canonicalBytes(context)
                val handle = root["transaction_handle"] as String
                val now = (root["validation_time"] as java.math.BigInteger).longValueExact()
                val review = wallet.reviewAccountDisclosureAt(rawContext, handle, issuer, identityId, now)
                assertEquals(issuer, review.keycloakIssuer)
                assertEquals(context["rp_client_id"], review.rpClientId)
                assertEquals(context["rp_display_name"], review.rpDisplayName)
                assertEquals(context["rp_origin"], review.rpOrigin)
                assertEquals(context["action"], review.action)
                assertEquals(context["request_id"], review.requestId)
                assertEquals(context["transaction_id"], review.transactionId)
                assertEquals(context["oidc_nonce"], review.oidcNonce)
                assertEquals(context["purpose"], review.purpose)
                assertEquals((context["expires_at"] as java.math.BigInteger).longValueExact(), review.expiresAtEpochSeconds)
                assertEquals(identityId, review.identityId)
                val expectedIds = (context["claims"] as List<*>).map { (it as Map<*, *>)["id"] }
                assertEquals(expectedIds, review.claims.map { it.id })
                for (claim in review.claims) {
                    val key = claim.id.substringAfterLast(':')
                    assertEquals(entity[key], claim.value)
                    assertEquals((context["claims"] as List<*>).map { it as Map<*, *> }
                        .first { it["id"] == claim.id }["required"], claim.required)
                }
                assertFalse("review string must not expose claim values", review.toString().contains("ada@example.test"))
                assertFalse("claim string must not expose its value", review.claims.first { it.id.endsWith(":email") }.toString().contains("ada@example.test"))
                rawContext.fill(0)
            }
        } finally {
            wallet.close()
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun rejectsMalformedContextIssuerHandleAndExpiry() {
        val root = readVector("valid-signup.json")
        val context = root["keycloak_context"] as Map<*, *>
        val handle = root["transaction_handle"] as String
        val now = (root["validation_time"] as java.math.BigInteger).longValueExact()
        val directory = Files.createTempDirectory("wallet-android-disclosure-invalid-")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.createWithGeneratedKey(directory.resolve("wallet.dw"), password, password)
        try {
            wallet.setMasterAccountEntity(entity)
            val base = WalletJson.canonicalBytes(context)
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(base, handle, "https://attacker.example.test/realms/site", identityId, now)
            }
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(base, "A".repeat(43), issuer, identityId, now)
            }
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(base, handle, issuer, identityId, now + 300)
            }
            val duplicate = base.toString(Charsets.UTF_8).replaceFirst("{\"action\":", "{\"action\":\"signup\",\"action\":")
                .toByteArray(Charsets.UTF_8)
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(duplicate, handle, issuer, identityId, now)
            }
            val extra = LinkedHashMap(context).apply { put("claims_from_elsewhere", "must reject") }
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(WalletJson.canonicalBytes(extra), handle, issuer, identityId, now)
            }
            val invalidContexts = listOf(
                LinkedHashMap(context).apply { put("rp_origin", "https://user@site.example.test") },
                LinkedHashMap(context).apply { put("rp_origin", "https://site.example.test:443") },
                LinkedHashMap(context).apply { put("purpose", "Look\u202Ehere") },
                LinkedHashMap(context).apply { put("purpose", "   ") },
                LinkedHashMap(context).apply { put("expires_at", java.math.BigInteger.valueOf(now + 301)) },
                LinkedHashMap(context).apply { put("expires_at", java.math.BigInteger.ONE.shiftLeft(63)) },
                LinkedHashMap(context).apply { put("expires_at", java.math.BigInteger.ONE.shiftLeft(63).negate()) },
                LinkedHashMap(context).apply { put("transaction_id", "A".repeat(43)) },
                LinkedHashMap(context).apply {
                    put("claims", listOf(mapOf("id" to "urn:decent:account:v1:unknown", "required" to true)))
                },
                LinkedHashMap(context).apply {
                    put("claims", listOf(mapOf("id" to "urn:decent:account:v1:given_name", "required" to 1)))
                },
            )
            for (invalid in invalidContexts) {
                assertThrows(WalletDisclosureRequestException::class.java) {
                    wallet.reviewAccountDisclosureAt(WalletJson.canonicalBytes(invalid), handle, issuer, identityId, now)
                }
            }
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(byteArrayOf(0xc3.toByte(), 0x28), handle, issuer, identityId, now)
            }
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(ByteArray(64 * 1024 + 1), handle, issuer, identityId, now)
            }
            base.fill(0)
            duplicate.fill(0)
        } finally {
            wallet.close()
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun requiredMissingOrMalformedEntityValuesRejectAndOptionalMissingIsUnavailable() {
        val root = readVector("valid-signup.json")
        val context = root["keycloak_context"] as Map<*, *>
        val handle = root["transaction_handle"] as String
        val now = (root["validation_time"] as java.math.BigInteger).longValueExact()
        val directory = Files.createTempDirectory("wallet-android-disclosure-values-")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.createWithGeneratedKey(directory.resolve("wallet.dw"), password, password)
        val rawContext = WalletJson.canonicalBytes(context)
        try {
            wallet.setMasterAccountEntity(mapOf("given_name" to "Ada"))
            val review = wallet.reviewAccountDisclosureAt(rawContext, handle, issuer, identityId, now)
            assertEquals("Ada", review.claims.first { it.id.endsWith(":given_name") }.value)
            assertEquals(null, review.claims.first { it.id.endsWith(":email") }.value)

            wallet.setMasterAccountEntity(mapOf("given_name" to "", "email" to "ada@example.test"))
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(rawContext, handle, issuer, identityId, now)
            }
            wallet.setMasterAccountEntity(mapOf("given_name" to "x".repeat(1025), "email" to "ada@example.test"))
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(rawContext, handle, issuer, identityId, now)
            }
            val exactly1024Bytes = "é".repeat(512)
            wallet.setMasterAccountEntity(mapOf("given_name" to exactly1024Bytes, "email" to "ada@example.test"))
            assertEquals(exactly1024Bytes, wallet.reviewAccountDisclosureAt(rawContext, handle, issuer, identityId, now)
                .claims.first { it.id.endsWith(":given_name") }.value)
            wallet.setMasterAccountEntity(mapOf("given_name" to "é".repeat(513), "email" to "ada@example.test"))
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(rawContext, handle, issuer, identityId, now)
            }
            wallet.setMasterAccountEntity(mapOf("given_name" to 7, "email" to "ada@example.test"))
            assertThrows(WalletDisclosureRequestException::class.java) {
                wallet.reviewAccountDisclosureAt(rawContext, handle, issuer, identityId, now)
            }
        } finally {
            rawContext.fill(0)
            wallet.close()
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun publicReviewUsesSystemClockAndReturnsAllContextBindings() {
        val root = readVector("valid-signup.json")
        val context = LinkedHashMap(root["keycloak_context"] as Map<*, *>)
        val now = System.currentTimeMillis() / 1000
        context["expires_at"] = java.math.BigInteger.valueOf(now + 299)
        val rawContext = WalletJson.canonicalBytes(context)
        val handle = root["transaction_handle"] as String
        val directory = Files.createTempDirectory("wallet-android-disclosure-public-api-")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.createWithGeneratedKey(directory.resolve("wallet.dw"), password, password)
        try {
            wallet.setMasterAccountEntity(entity)
            val review = wallet.reviewAccountDisclosure(rawContext, handle, issuer, identityId)
            assertEquals(context["transaction_id"], review.transactionId)
            assertEquals(context["request_id"], review.requestId)
            assertEquals(context["oidc_nonce"], review.oidcNonce)
            assertEquals((context["expires_at"] as java.math.BigInteger).longValueExact(), review.expiresAtEpochSeconds)
        } finally {
            rawContext.fill(0)
            wallet.close()
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private fun readVector(name: String): Map<*, *> {
        val bytes = checkNotNull(javaClass.classLoader?.getResourceAsStream("wallet-account-disclosure-v1/vectors/$name"))
            .use { it.readBytes() }
        return WalletJson.parse(bytes, 64 * 1024) as Map<*, *>
    }
}

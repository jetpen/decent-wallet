package org.decentwallet.wallet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AccountDisclosureBindingTest {
    @Test
    fun verifiesPinnedOwnerKeyBindingAndReturnsEveryBoundField() {
        val vector = resourceMap("wallet-account-disclosure-v1/vectors/valid-signup.json")
        val contextValue = vector["keycloak_context"]!!
        val contextBytes = WalletJson.canonicalBytes(contextValue)
        val context = WalletAccountDisclosureContextParser.parse(
            raw = contextBytes,
            transactionHandle = vector.getValue("transaction_handle") as String,
            expectedKeycloakIssuer = "https://login.example.test/realms/site",
            nowEpochSeconds = 1_800_000_001L,
        )
        val result = WalletOwnerKeyBindingVerifier.verify(
            compactJws = vector.getValue("owner_key_binding_jws") as String,
            issuerJwks = vector.getValue("keycloak_jwks") as Map<*, *>,
            pendingContext = context,
            expectedIdentityId = "mailto:ada@example.test",
            nowEpochSeconds = 1_800_000_001L,
        )

        assertEquals("https://login.example.test/realms/site", result.issuer)
        assertEquals("site-client", result.audience)
        assertEquals("kc-subject-9f2a", result.subject)
        assertEquals("mailto:ada@example.test", result.identityId)
        assertEquals("signup", result.action)
        assertEquals("lCCDKDlTq8bBjwZVR19NQCqacFrzJhOEozO0hzjPZxo", result.transactionId)
        assertEquals("AAECAwQFBgcICQoLDA0ODw", result.requestId)
        assertEquals("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", result.oidcNonce)
        assertEquals("OKP", result.ownerKey.kty)
        assertEquals("Ed25519", result.ownerKey.crv)
        assertEquals("dPZCzkywe4AnlUjmnR_cSlCdKlk6rfaxs4S5jTma9wk", result.ownerKey.x)
        assertEquals("p-GGO8M2jfl0NV7PEz-ysaXEQtvajbpiTd9-pcOkGLQ", result.ownerKeyThumbprint)
        assertEquals(1_800_000_000L, result.issuedAtEpochSeconds)
        assertEquals(1_800_000_300L, result.expiresAtEpochSeconds)
        assertEquals("nnZ7X65EttgFPWidDD1hh5bNxsNxkLlGmYAuYy9Is78", result.jti)
        assertEquals(
            "fe812a1adda0130c5cabe91e1a593e090932f6606ab89213f773455106751b34",
            result.compactJwsSha256,
        )
    }

    @Test
    fun rejectsTamperedSignatureAndIdentityMismatch() {
        val vector = contextVector()
        val compact = vector.getValue("owner_key_binding_jws") as String
        val parts = compact.split('.')
        val tampered = parts.take(2).joinToString(".") + "." + parts[2].dropLast(1) +
            if (parts[2].last() == 'A') "B" else "A"
        assertThrows(WalletDisclosureRequestException::class.java) {
            verify(vector, tampered, identity = "mailto:ada@example.test")
        }
        assertThrows(WalletDisclosureRequestException::class.java) {
            verify(vector, compact, identity = "mailto:other@example.test")
        }
    }

    @Test
    fun rejectsExpiredBindingAndAmbiguousIssuerKey() {
        val vector = contextVector()
        val compact = vector.getValue("owner_key_binding_jws") as String
        assertThrows(WalletDisclosureRequestException::class.java) {
            verify(vector, compact, identity = "mailto:ada@example.test", now = 1_800_000_300L)
        }
        val jwks = vector.getValue("keycloak_jwks") as Map<*, *>
        val keys = jwks["keys"] as List<*>
        val ambiguous = mapOf("keys" to listOf(keys.single(), keys.single()))
        assertThrows(WalletDisclosureRequestException::class.java) {
            verify(vector, compact, identity = "mailto:ada@example.test", jwks = ambiguous)
        }
    }

    @Test
    fun verifiesSignedSubjectWithoutExpectingTheRelyingPartyIdentity() {
        val vector = contextVector()
        val payload = mutablePayload(vector)
        payload["sub"] = "different-but-valid-provider-subject"
        val (compact, jwks) = signPayload(payload)

        val result = verify(vector, compact, identity = "mailto:ada@example.test", jwks = jwks)

        assertEquals("different-but-valid-provider-subject", result.subject)
    }

    @Test
    fun rejectsSignedContextMismatchesAndOutOfBoundLifetime() {
        val vector = contextVector()
        val mutations = listOf(
            mapOf("action" to "signup_recovery"),
            mapOf("identity_id" to "mailto:other@example.test"),
            mapOf("oidc_nonce" to "wrong-nonce"),
            mapOf("transaction_id" to "wrong-transaction"),
            mapOf("iat" to java.math.BigInteger.valueOf(Long.MIN_VALUE)),
            mapOf("iat" to java.math.BigInteger.valueOf(1_800_000_062L)),
            mapOf("iat" to java.math.BigInteger.valueOf(Long.MAX_VALUE)),
            mapOf("iat" to java.math.BigInteger.valueOf(Long.MAX_VALUE).add(java.math.BigInteger.ONE)),
            mapOf("exp" to java.math.BigInteger.valueOf(1_800_000_301L)),
        )
        for (mutation in mutations) {
            val payload = mutablePayload(vector)
            payload.putAll(mutation)
            val (compact, jwks) = signPayload(payload)
            assertThrows(WalletDisclosureRequestException::class.java) {
                verify(vector, compact, identity = "mailto:ada@example.test", jwks = jwks)
            }
        }
    }

    @Test
    fun rejectsDuplicatePayloadMembersAndUnknownClaimsEvenWithValidSignatures() {
        val vector = contextVector()
        val (duplicate, jwks) = signRawPayload("{\"v\":1,\"v\":1}")
        assertThrows(WalletDisclosureRequestException::class.java) {
            verify(vector, duplicate, identity = "mailto:ada@example.test", jwks = jwks)
        }
        val payload = mutablePayload(vector)
        payload["unexpected"] = "value"
        val (extra, extraJwks) = signPayload(payload)
        assertThrows(WalletDisclosureRequestException::class.java) {
            verify(vector, extra, identity = "mailto:ada@example.test", jwks = extraJwks)
        }
    }

    @Test
    fun rejectsIneligibleAndPrivateIssuerJwksKeys() {
        val vector = contextVector()
        val compact = vector["owner_key_binding_jws"] as String
        val jwks = vector["keycloak_jwks"] as Map<*, *>
        val issuerKey = (jwks["keys"] as List<*>).single() as Map<*, *>
        val wrongOperations = mapOf("keys" to listOf(issuerKey + ("key_ops" to listOf("sign"))))
        val privateMaterial = mapOf("keys" to listOf(issuerKey + ("d" to "private")))
        for (candidate in listOf(wrongOperations, privateMaterial)) {
            assertThrows(WalletDisclosureRequestException::class.java) {
                verify(vector, compact, identity = "mailto:ada@example.test", jwks = candidate)
            }
        }
    }

    @Test
    fun acceptsTheIssuerKeyLimitAndRejectsOneMoreKey() {
        val vector = contextVector()
        val compact = vector["owner_key_binding_jws"] as String
        val jwks = vector["keycloak_jwks"] as Map<*, *>
        val issuerKey = (jwks["keys"] as List<*>).single()
        val unrelated = (0 until 64).map { index ->
            mapOf("kid" to "unrelated-$index", "kty" to "RSA", "use" to "enc", "alg" to "RS256")
        }
        val withinLimit = mapOf("keys" to listOf(issuerKey) + unrelated.take(63))
        val aboveLimit = mapOf("keys" to listOf(issuerKey) + unrelated)

        verify(vector, compact, identity = "mailto:ada@example.test", jwks = withinLimit)
        assertThrows(WalletDisclosureRequestException::class.java) {
            verify(vector, compact, identity = "mailto:ada@example.test", jwks = aboveLimit)
        }
    }

    private data class TestSigningKey(val privateKey: java.security.PrivateKey, val jwks: Map<String, Any?>)

    private fun signingKey(): TestSigningKey {
        val generator = java.security.KeyPairGenerator.getInstance("RSA")
        generator.initialize(2048)
        val pair = generator.generateKeyPair()
        val publicKey = pair.public as java.security.interfaces.RSAPublicKey
        val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        fun unsigned(value: java.math.BigInteger): String {
            val bytes = value.toByteArray().let { if (it.first() == 0.toByte()) it.drop(1).toByteArray() else it }
            return encoder.encodeToString(bytes)
        }
        return TestSigningKey(
            pair.private,
            mapOf(
                "keys" to listOf(
                    mapOf(
                        "kid" to "test-key",
                        "kty" to "RSA",
                        "use" to "sig",
                        "alg" to "RS256",
                        "n" to unsigned(publicKey.modulus),
                        "e" to unsigned(publicKey.publicExponent),
                    ),
                ),
            ),
        )
    }

    private fun signPayload(payload: Map<String, Any?>): Pair<String, Map<*, *>> =
        signRawPayload(String(WalletJson.canonicalBytes(payload), Charsets.UTF_8))

    private fun signRawPayload(payloadJson: String): Pair<String, Map<*, *>> {
        val key = signingKey()
        val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        val header = encoder.encodeToString(
            WalletJson.canonicalBytes(mapOf("alg" to "RS256", "kid" to "test-key", "typ" to "decent-owner-key-binding+jwt")),
        )
        val body = encoder.encodeToString(payloadJson.toByteArray(Charsets.UTF_8))
        val signingInput = "$header.$body"
        val signer = java.security.Signature.getInstance("SHA256withRSA")
        signer.initSign(key.privateKey)
        signer.update(signingInput.toByteArray(Charsets.US_ASCII))
        return "$signingInput.${encoder.encodeToString(signer.sign())}" to key.jwks
    }

    @Suppress("UNCHECKED_CAST")
    private fun mutablePayload(vector: Map<String, Any?>): MutableMap<String, Any?> {
        val compact = vector["owner_key_binding_jws"] as String
        val payloadSegment = compact.split('.')[1]
        val bytes = java.util.Base64.getUrlDecoder().decode(payloadSegment)
        return LinkedHashMap(WalletJson.parse(bytes, 16 * 1024) as Map<String, Any?>)
    }

    private fun verify(
        vector: Map<String, Any?>,
        compact: String,
        identity: String,
        now: Long = 1_800_000_001L,
        jwks: Map<*, *> = vector.getValue("keycloak_jwks") as Map<*, *>,
    ): VerifiedOwnerKeyBinding {
        val context = WalletAccountDisclosureContextParser.parse(
            raw = WalletJson.canonicalBytes(vector.getValue("keycloak_context")),
            transactionHandle = vector.getValue("transaction_handle") as String,
            expectedKeycloakIssuer = "https://login.example.test/realms/site",
            nowEpochSeconds = now,
        )
        return WalletOwnerKeyBindingVerifier.verify(compact, jwks, context, identity, now)
    }

    private fun contextVector(): Map<String, Any?> = resourceMap("wallet-account-disclosure-v1/vectors/valid-signup.json")

    @Suppress("UNCHECKED_CAST")
    private fun resourceMap(name: String): Map<String, Any?> {
        val bytes = checkNotNull(javaClass.classLoader?.getResourceAsStream(name)).use { it.readBytes() }
        return WalletJson.parse(bytes, 64 * 1024) as Map<String, Any?>
    }
}

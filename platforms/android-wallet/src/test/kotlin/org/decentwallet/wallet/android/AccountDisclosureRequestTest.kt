package org.decentwallet.wallet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyUsage
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date

class AccountDisclosureRequestTest {
    @Test
    fun verifiesPinnedRequestObjectAndReturnsEveryConsentBinding() {
        val input = prepare("valid-signup.json")
        val result = verify(input)

        assertEquals("x509_san_dns:site.example.test", result.clientId)
        assertEquals("MDEyMzQ1Njc4OTo7PD0-Pw", result.state)
        assertEquals("ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8", result.nonce)
        assertEquals("https://site.example.test/oid4vp/response", result.responseUri)
        assertEquals("Create a site account at Example Site", result.purpose)
        assertEquals("AAECAwQFBgcICQoLDA0ODw", result.requestId)
        assertEquals("lCCDKDlTq8bBjwZVR19NQCqacFrzJhOEozO0hzjPZxo", result.transactionId)
        assertEquals("signup", result.action)
        assertEquals(1_800_000_300L, result.expiresAtEpochSeconds)
        assertEquals(
            mapOf(
                "credentials" to listOf(
                    mapOf(
                        "id" to "account",
                        "format" to "decent_account_jwt_v1",
                        "multiple" to false,
                        "meta" to emptyMap<String, Any?>(),
                        "require_cryptographic_holder_binding" to true,
                        "claims" to listOf(
                            mapOf("id" to "email", "path" to listOf("claims", "urn:decent:account:v1:email")),
                            mapOf("id" to "given_name", "path" to listOf("claims", "urn:decent:account:v1:given_name")),
                        ),
                        "claim_sets" to listOf(listOf("given_name"), listOf("email", "given_name")),
                    ),
                ),
            ),
            result.dcqlQuery,
        )
    }

    @Test
    fun acceptsEveryPinnedPositiveRequestIncludingIgnoredExtensionsAndRecovery() {
        val names = listOf(
            "valid-extensions-ignored.json",
            "valid-request-iss-ignored.json",
            "valid-signup-optional-omitted.json",
            "valid-signup-recovery.json",
            "valid-signup.json",
        )
        names.forEach { name -> verify(prepare(name)) }
    }

    @Test
    fun ignoresUnknownOuterParametersButRejectsKnownUnsupportedAndHostMismatch() {
        val input = prepare("valid-signup.json")
        val original = input.vector["oid4vp_authorization_parameters"] as Map<*, *>
        val withUnknown = original.toMutableMap().apply { put("future_extension", mapOf("unused" to true)) }
        verify(input, outer = withUnknown)

        val withKnown = original.toMutableMap().apply { put("scope", "openid") }
        assertRejected { verify(input, outer = withKnown) }
        val mismatchedUri = original.toMutableMap().apply {
            put("request_uri", "https://attacker.example.test/request")
        }
        assertRejected { verify(input, outer = mismatchedUri) }
    }

    @Test
    fun rejectsStaticRegistrationWhoseResponseUriHostDoesNotMatchClientDnsName() {
        val input = prepare("valid-signup.json")
        val signer = SignedRequestFixture(input.registration.x509SanDns)
        val registration = signer.registration(input.registration).copy(
            responseUri = "https://elsewhere.example/oid4vp/response",
        )
        val changedPayload = payloadCopy(input).apply { put("response_uri", registration.responseUri) }

        assertRejected {
            verify(input, requestObject = signer.sign(changedPayload), registration = registration)
        }
    }

    @Test
    fun rejectsOversizedRequestObjectJws() {
        val input = prepare("valid-signup.json")
        assertRejected { verify(input, requestObject = "x".repeat(65_537)) }
        assertRejected { verify(input, requestObject = "é".repeat(32_769)) }
    }

    @Test
    fun rejectsTamperedSignatureWrongTrustPinAndMismatchedBindingProvenance() {
        val input = prepare("valid-signup.json")
        val token = input.vector["oid4vp_request_jws"] as String
        val tampered = token.dropLast(1) + if (token.last() == 'A') "B" else "A"
        assertRejected { verify(input, requestObject = tampered) }
        assertRejected { verify(input, registration = input.registration.copy(trustAnchorSha256 = "00".repeat(32))) }
        assertRejected { verify(input, ownerBindingJws = "different-token") }
        assertRejected {
            verify(input, binding = input.binding.copy(compactJwsSha256 = "00".repeat(32)))
        }
    }

    @Test
    fun rejectsValidlySignedSemanticMutationsAndKnownUnsupportedDcqlFields() {
        val input = prepare("valid-signup.json")
        val signer = SignedRequestFixture(input.registration.x509SanDns)
        val testRegistration = signer.registration(input.registration)
        assertEquals(input.registration.clientId, verify(input, requestObject = signer.sign(payloadCopy(input)), registration = testRegistration).clientId)
        val mutations: List<(MutableMap<String, Any?>) -> Unit> = listOf(
            { it["response_type"] = "code" },
            { it["response_mode"] = "query" },
            { it["response_uri"] = "https://elsewhere.example/response" },
            { it["client_id"] = "x509_san_dns:elsewhere.example" },
            { it["aud"] = "https://wrong.example" },
            { it["transaction_data"] = emptyList<Any>() },
            { it["state"] = "short" },
            { it["nonce"] = "not-base64!" },
            { it["exp"] = BigInteger.valueOf(input.now) },
            { it["iat"] = BigInteger.valueOf(input.now + 61) },
            {
                val metadata = it["client_metadata"] as MutableMap<String, Any?>
                val supported = metadata["vp_formats_supported"] as MutableMap<String, Any?>
                val format = supported["decent_account_jwt_v1"] as MutableMap<String, Any?>
                format["alg_values"] = listOf("ES256")
            },
            {
                val query = it["dcql_query"] as MutableMap<String, Any?>
                val credentials = query["credentials"] as MutableList<Any?>
                credentials.add(WalletJson.copyPayload(credentials.single()))
            },
            {
                val extension = it["decent_account"] as MutableMap<String, Any?>
                extension["purpose"] = "altered"
            },
            {
                val query = it["dcql_query"] as MutableMap<String, Any?>
                val credential = (query["credentials"] as List<*>).single() as MutableMap<String, Any?>
                credential.remove("meta")
            },
            {
                val query = it["dcql_query"] as MutableMap<String, Any?>
                val credential = (query["credentials"] as List<*>).single() as MutableMap<String, Any?>
                credential["claim_sets"] = emptyList<Any>()
            },
            { (it["dcql_query"] as MutableMap<String, Any?>)["credential_sets"] = emptyList<Any>() },
            {
                val query = it["dcql_query"] as MutableMap<String, Any?>
                val credential = (query["credentials"] as List<*>).single() as MutableMap<String, Any?>
                credential["trusted_authorities"] = emptyList<Any>()
            },
            {
                val query = it["dcql_query"] as MutableMap<String, Any?>
                val credential = (query["credentials"] as List<*>).single() as MutableMap<String, Any?>
                val claims = credential["claims"] as List<*>
                (claims.first() as MutableMap<String, Any?>)["values"] = listOf("private")
            },
            {
                val query = it["dcql_query"] as MutableMap<String, Any?>
                val credential = (query["credentials"] as List<*>).single() as MutableMap<String, Any?>
                val claims = credential["claims"] as List<*>
                (claims.first() as MutableMap<String, Any?>)["intent_to_retain"] = true
            },
        )
        mutations.forEach { mutation ->
            val changed = payloadCopy(input)
            mutation(changed)
            assertRejected { verify(input, requestObject = signer.sign(changed), registration = testRegistration) }
        }
        val changedOuter = (input.vector["oid4vp_authorization_parameters"] as Map<*, *>).toMutableMap()
            .apply { put("response_type", "vp_token") }
        assertRejected { verify(input, outer = changedOuter) }
    }

    @Test
    fun signsAndIgnoresUnknownStandardExtensionsButNormalizesTheReturnedQuery() {
        val input = prepare("valid-signup.json")
        val signer = SignedRequestFixture(input.registration.x509SanDns)
        val testRegistration = signer.registration(input.registration)
        val changed = payloadCopy(input)
        changed["future_root"] = mapOf("ignored" to true)
        val metadata = changed["client_metadata"] as MutableMap<String, Any?>
        metadata["future_metadata"] = "ignored"
        val query = changed["dcql_query"] as MutableMap<String, Any?>
        query["future_root"] = mapOf("ignored" to true)
        val credential = (query["credentials"] as List<*>).single() as MutableMap<String, Any?>
        credential["future_credential"] = "ignored"
        val claims = credential["claims"] as List<*>
        (claims.first() as MutableMap<String, Any?>)["future_claim"] = listOf("opaque")
        (credential["meta"] as MutableMap<String, Any?>)["future_meta"] = mapOf("ignored" to true)
        val outer = (input.vector["oid4vp_authorization_parameters"] as Map<*, *>).toMutableMap()
            .apply { put("future_outer", mapOf("nested" to 1)) }

        val result = verify(input, outer = outer, requestObject = signer.sign(changed), registration = testRegistration)
        val normalizedCredential = (result.dcqlQuery["credentials"] as List<*>).single() as Map<*, *>
        val normalizedClaim = (normalizedCredential["claims"] as List<*>).first() as Map<*, *>
        assertFalse("future_root" in result.dcqlQuery)
        assertFalse("future_credential" in normalizedCredential)
        assertFalse("future_claim" in normalizedClaim)
        assertEquals(emptyMap<String, Any?>(), normalizedCredential["meta"])
    }

    @Test
    fun rejectsDuplicateJsonInvalidUnicodeAndMalformedUtf8EvenWithValidSignatures() {
        val input = prepare("valid-signup.json")
        val signer = SignedRequestFixture(input.registration.x509SanDns)
        val testRegistration = signer.registration(input.registration)
        val json = WalletJson.canonicalBytes(payloadCopy(input))
        val original = String(json, Charsets.UTF_8)
        val duplicate = "{\"aud\":\"https://self-issued.me/v2\",\"aud\":\"https://self-issued.me/v2\"," + original.substring(1)
        assertRejected { verify(input, requestObject = signer.signRaw(duplicate.toByteArray(Charsets.UTF_8)), registration = testRegistration) }
        val surrogate = original.dropLast(1) + ",\"future\":{\"ignored\":\"\\ud800\"}}"
        assertRejected { verify(input, requestObject = signer.signRaw(surrogate.toByteArray(Charsets.UTF_8)), registration = testRegistration) }
        assertRejected { verify(input, requestObject = signer.signRaw(byteArrayOf(0xc3.toByte(), 0x28)), registration = testRegistration) }
        json.fill(0)
    }

    private data class Prepared(
        val vector: Map<String, Any?>,
        val now: Long,
        val context: WalletAccountDisclosureContext,
        val ownerBindingJws: String,
        val binding: VerifiedOwnerKeyBinding,
        val registration: TrustedWalletRelyingPartyRegistration,
    )

    private fun prepare(name: String): Prepared =
        prepare(resourceMap("wallet-account-disclosure-v1/vectors/$name"))

    private fun prepare(vector: Map<String, Any?>): Prepared {
        val now = (vector.getValue("validation_time") as java.math.BigInteger).toLong()
        val context = WalletAccountDisclosureContextParser.parse(
            raw = WalletJson.canonicalBytes(vector.getValue("keycloak_context")),
            transactionHandle = vector.getValue("transaction_handle") as String,
            expectedKeycloakIssuer = "https://login.example.test/realms/site",
            nowEpochSeconds = now,
        )
        val ownerBindingJws = vector.getValue("owner_key_binding_jws") as String
        val binding = WalletOwnerKeyBindingVerifier.verify(
            compactJws = ownerBindingJws,
            issuerJwks = vector.getValue("keycloak_jwks") as Map<*, *>,
            pendingContext = context,
            expectedIdentityId = "mailto:ada@example.test",
            nowEpochSeconds = now,
        )
        val certificate = vector.getValue("rp_certificate") as Map<*, *>
        val registration = TrustedWalletRelyingPartyRegistration(
            clientId = vector.getValue("oid4vp_client_id") as String,
            x509SanDns = "site.example.test",
            origin = context.rpOrigin,
            responseUri = "https://site.example.test/oid4vp/response",
            trustAnchorSha256 = certificate["trust_anchor_sha256"] as String,
            rpClientId = context.rpClientId,
        )
        return Prepared(vector, now, context, ownerBindingJws, binding, registration)
    }

    private fun verify(
        input: Prepared,
        outer: Map<*, *> = input.vector["oid4vp_authorization_parameters"] as Map<*, *>,
        requestObject: String = input.vector["oid4vp_request_jws"] as String,
        registration: TrustedWalletRelyingPartyRegistration = input.registration,
        ownerBindingJws: String = input.ownerBindingJws,
        binding: VerifiedOwnerKeyBinding = input.binding,
    ): VerifiedWalletOid4vpRequest = WalletOid4vpRequestVerifier.verify(
        outerAuthorizationParameters = outer,
        requestObjectJws = requestObject,
        registration = registration,
        pendingContext = input.context,
        ownerKeyBindingJws = ownerBindingJws,
        verifiedBinding = binding,
        nowEpochSeconds = input.now,
    )

    @Test
    fun appliesTheSharedNegativeBundleAtTheRequestVerifierOwningStage() {
        val root = resourceMap("wallet-account-disclosure-v1/vectors/negative.json")
        val vectors = root["vectors"] as List<*>
        assertEquals(29, vectors.size)
        val rejectedByRequest = setOf(
            "request-unsupported-transaction-data",
            "outer-unsupported-transaction-data",
            "request-response-uri-host-mismatch",
            "request-nonfinite-number-overflow",
            "dcql-missing-required-meta",
            "dcql-claim-sets-incomplete",
        )
        val passThrough = setOf(
            "presentation-wrong-nonce", "presentation-extra-claim", "claim-value-utf8-byte-limit",
            "presentation-expired", "presentation-expiry-after-credential", "presentation-owner-binding-mismatch",
            "presentation-invalid-signature", "credential-invalid-signature", "presentation-duplicate-json-member",
            "required-claim-omitted", "presentation-request-id-mismatch", "presentation-total-size-limit",
            "presentation-invalid-unicode-scalar", "direct-post-state-mismatch", "direct-post-vp-token-wrong-shape",
        )
        val owned = vectors.map { it as Map<*, *> }.filter { it["id"] in rejectedByRequest || it["id"] in passThrough }
        assertEquals(rejectedByRequest + passThrough, owned.map { it["id"] as String }.toSet())
        for (case in owned) {
            val bundle = case["bundle"] as Map<String, Any?>
            val input = prepare(bundle)
            if (case["id"] in rejectedByRequest) {
                assertRejected { verify(input) }
            } else {
                assertEquals(input.registration.clientId, verify(input).clientId)
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun payloadCopy(input: Prepared): MutableMap<String, Any?> =
        WalletJson.copyPayload(input.vector["oid4vp_request_payload"] ?: run {
            val body = (input.vector["oid4vp_request_jws"] as String).split('.')[1]
            val bytes = Base64.getUrlDecoder().decode(body)
            try { WalletJson.parse(bytes, 64 * 1024) } finally { bytes.fill(0) }
        }) as MutableMap<String, Any?>

    private class SignedRequestFixture(host: String) {
        private val encoder = Base64.getUrlEncoder().withoutPadding()
        private val pair: KeyPair
        private val certificate: X509Certificate
        private val fingerprint: String

        init {
            pair = KeyPairGenerator.getInstance("EC").apply {
                initialize(java.security.spec.ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
            val name = X500Name("CN=$host")
            val builder = JcaX509v3CertificateBuilder(
                name,
                BigInteger.ONE,
                Date(1_735_689_600_000L),
                Date(1_956_528_000_000L),
                name,
                pair.public,
            )
            builder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, host)))
            builder.addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature))
            certificate = JcaX509CertificateConverter().getCertificate(
                builder.build(JcaContentSignerBuilder("SHA256withECDSA").build(pair.private)),
            )
            fingerprint = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
                .joinToString("") { "%02x".format(it) }
        }

        fun registration(base: TrustedWalletRelyingPartyRegistration) = base.copy(trustAnchorSha256 = fingerprint)

        fun sign(payload: Map<String, Any?>): String = signRaw(WalletJson.canonicalBytes(payload))

        fun signRaw(payload: ByteArray): String {
            val header = encoder.encodeToString(
                WalletJson.canonicalBytes(
                    mapOf(
                        "alg" to "ES256",
                        "typ" to "oauth-authz-req+jwt",
                        "x5c" to listOf(Base64.getEncoder().encodeToString(certificate.encoded)),
                    ),
                ),
            )
            val body = encoder.encodeToString(payload)
            val signingInput = "$header.$body"
            val signer = Signature.getInstance("SHA256withECDSA")
            signer.initSign(pair.private)
            signer.update(signingInput.toByteArray(Charsets.US_ASCII))
            val der = signer.sign()
            val sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(der))
            val raw = fixed32(ASN1Integer.getInstance(sequence.getObjectAt(0)).positiveValue) +
                fixed32(ASN1Integer.getInstance(sequence.getObjectAt(1)).positiveValue)
            der.fill(0)
            return "$signingInput.${encoder.encodeToString(raw)}".also { raw.fill(0) }
        }

        private fun fixed32(value: BigInteger): ByteArray {
            val encoded = value.toByteArray().let { bytes ->
                if (bytes.size > 1 && bytes[0] == 0.toByte()) bytes.copyOfRange(1, bytes.size) else bytes
            }
            if (encoded.size > 32) throw AssertionError("test signature coordinate is too large")
            return ByteArray(32).also { encoded.copyInto(it, destinationOffset = 32 - encoded.size) }
        }
    }

    private fun assertRejected(block: () -> Unit) {
        val failure = assertThrows(WalletDisclosureRequestException::class.java, block)
        assertEquals("wallet disclosure request rejected", failure.message)
    }

    private fun resourceMap(name: String): Map<String, Any?> {
        val bytes = javaClass.getResourceAsStream("/$name")!!.use { it.readBytes() }
        @Suppress("UNCHECKED_CAST")
        return WalletJson.parse(bytes, 1024 * 1024) as Map<String, Any?>
    }
}

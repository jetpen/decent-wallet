package org.decentwallet.wallet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.util.Base64

class AccountDisclosurePresentationVectorTest {
    private val vectors: Path = Path.of("../../tests/vectors/wallet-account-disclosure-v1/vectors").toAbsolutePath().normalize()

    @Test
    fun acceptsAllSharedPositivePresentationVectorsAndExactClaims() {
        val expectedValues = mapOf(
            "urn:decent:account:v1:given_name" to "Ada",
            "urn:decent:account:v1:email" to "ada@example.test",
        )
        val names = listOf("valid-signup.json", "valid-signup-recovery.json", "valid-signup-optional-omitted.json",
            "valid-extensions-ignored.json", "valid-request-iss-ignored.json")
        for (name in names) {
            val vector = vector(name)
            val (context, binding, request) = verified(vector)
            val approved = vector["wallet_approved_claim_ids"] as List<*>
            val selected = approved.associate { it as String to expectedValues.getValue(it as String) }
            WalletAccountPresentationVerifier.verify(
                vector["presentation_jws"] as String, context, request, binding,
                selected, (vector["validation_time"] as BigInteger).toLong(), context.expiresAtEpochSeconds,
            )
            assertEquals("mailto:ada@example.test", binding.identityId)
            val vp = payload(vector["presentation_jws"] as String)
            val credentialJws = (((vp["vp"] as Map<*, *>)["verifiableCredential"] as List<*>).single() as String)
            assertEquals(selected, payload(credentialJws)["claims"])
            assertEquals(if (name == "valid-signup-recovery.json") "signup_recovery" else "signup", context.action)
        }
    }

    @Test
    fun rejectsAllSharedPresentationStageNegativeVectors() {
        val expectedDispositions = linkedMapOf(
            "presentation-wrong-nonce" to "presentation-nonce-mismatch",
            "presentation-extra-claim" to "unrequested-claim",
            "claim-value-utf8-byte-limit" to "invalid-claim-value",
            "presentation-expired" to "presentation-expired",
            "presentation-expiry-after-credential" to "presentation-expiry-too-late",
            "presentation-owner-binding-mismatch" to "owner-binding-mismatch",
            "presentation-invalid-signature" to "signature-invalid",
            "credential-invalid-signature" to "signature-invalid",
            "presentation-duplicate-json-member" to "duplicate-json-member",
            "required-claim-omitted" to "required-claim-missing",
            "presentation-request-id-mismatch" to "request-id-mismatch",
            "presentation-total-size-limit" to "presentation-too-large",
            "presentation-invalid-unicode-scalar" to "invalid-unicode-scalar",
        )
        val negative = WalletJson.parse(Files.readAllBytes(vectors.resolve("negative.json")), 2 * 1024 * 1024) as Map<*, *>
        val cases = (negative["vectors"] as List<*>).associateBy { (it as Map<*, *>)["id"] as String }
        for ((id, disposition) in expectedDispositions) {
            val item = cases.getValue(id) as Map<*, *>
            val bundle = item["bundle"] as Map<*, *>
            assertEquals(disposition, item["expected"])
            assertEquals("accept", bundle["expected"])
            val (context, binding, request) = verified(bundle)
            val values = approvedValues(bundle)
            assertThrows("$id (${item["expected"]})", WalletDisclosureRequestException::class.java) {
                WalletAccountPresentationVerifier.verify(
                    bundle["presentation_jws"] as String, context, request, binding, values,
                    (bundle["validation_time"] as BigInteger).toLong(), context.expiresAtEpochSeconds,
                )
            }
        }
    }

    private fun approvedValues(vector: Map<*, *>): Map<String, Any?> {
        val source = mapOf("urn:decent:account:v1:given_name" to "Ada", "urn:decent:account:v1:email" to "ada@example.test")
        return (vector["wallet_approved_claim_ids"] as List<*>).associate { it as String to source.getValue(it as String) }
    }

    private fun verified(vector: Map<*, *>): Triple<WalletAccountDisclosureContext, VerifiedOwnerKeyBinding, VerifiedWalletOid4vpRequest> {
        val now = (vector["validation_time"] as BigInteger).toLong()
        val contextMap = vector["keycloak_context"] as Map<*, *>
        val contextBytes = WalletJson.canonicalBytes(contextMap)
        val context = try {
            WalletAccountDisclosureContextParser.parse(
                contextBytes, vector["transaction_handle"] as String,
                contextMap["keycloak_issuer"] as String, now,
            )
        } finally { contextBytes.fill(0) }
        val bindingJws = vector["owner_key_binding_jws"] as String
        val binding = WalletOwnerKeyBindingVerifier.verify(
            bindingJws, vector["keycloak_jwks"] as Map<*, *>, context,
            "mailto:ada@example.test", now,
        )
        val certificate = vector["rp_certificate"] as Map<*, *>
        val dns = (vector["oid4vp_client_id"] as String).substringAfter(':')
        val registration = TrustedWalletRelyingPartyRegistration(
            vector["oid4vp_client_id"] as String, dns, context.rpOrigin,
            "https://$dns/oid4vp/response", certificate["trust_anchor_sha256"] as String,
            context.rpClientId,
        )
        val request = WalletOid4vpRequestVerifier.verify(
            vector["oid4vp_authorization_parameters"] as Map<*, *>,
            vector["oid4vp_request_jws"] as String, registration, context,
            bindingJws, binding, now,
        )
        return Triple(context, binding, request)
    }

    private fun payload(jws: String): Map<*, *> {
        val encoded = jws.split('.')[1]
        val bytes = Base64.getUrlDecoder().decode(encoded)
        return try { WalletJson.parse(bytes, 16 * 1024) as Map<*, *> } finally { bytes.fill(0) }
    }

    private fun vector(name: String): Map<*, *> =
        WalletJson.parse(Files.readAllBytes(vectors.resolve(name)), 64 * 1024) as Map<*, *>
}

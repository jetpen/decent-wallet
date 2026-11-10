package org.decentwallet.wallet.android

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.util.Base64

/** Internal self-check for the exact nested JWS pair immediately before persistence. */
internal object WalletAccountPresentationVerifier {
    private const val MAX_JWS_BYTES = 16 * 1024
    private val encoder = Base64.getUrlEncoder().withoutPadding()

    fun verify(
        presentationJws: String,
        context: WalletAccountDisclosureContext,
        request: VerifiedWalletOid4vpRequest,
        binding: VerifiedOwnerKeyBinding,
        selectedValues: Map<String, Any?>,
        now: Long,
        expiresAt: Long,
    ) {
        try {
            if (presentationJws.length > MAX_JWS_BYTES || !presentationJws.all { it.code in 0x21..0x7e }) reject()
            val parts = presentationJws.split('.')
            if (parts.size != 3) reject()
            val outer = decode(parts[1], 12 * 1024)
            val header = decode(parts[0], 1024)
            val signature = decode(parts[2], AndroidIdentityCrypto.SIGNATURE_BYTES)
            try {
                val outerClaims = canonicalObject(outer, 12 * 1024)
                val outerHeader = canonicalObject(header, 1024)
                if (outerHeader != mapOf("alg" to "EdDSA", "kid" to binding.ownerKeyThumbprint, "typ" to "decent-account-presentation+jwt")) reject()
                val publicKey = decode(binding.ownerKey.x, AndroidIdentityCrypto.KEY_BYTES)
                val signingInput = "${parts[0]}.${parts[1]}".toByteArray(StandardCharsets.US_ASCII)
                try { if (!AndroidIdentityCrypto.verify(publicKey, signingInput, signature)) reject() }
                finally { publicKey.fill(0); signingInput.fill(0) }
                exact(outerClaims, mapOf(
                    "profile" to "decent-account-disclosure-v1", "iss" to binding.identityId,
                    "sub" to binding.identityId, "aud" to request.clientId, "nonce" to request.nonce,
                ))
                val outerIat = exactLong(outerClaims["iat"])
                val outerExp = exactLong(outerClaims["exp"])
                if (outerIat < 1 || outerIat > maxFutureIat(now) || outerExp <= now || outerExp <= outerIat || outerExp - outerIat > 300 ||
                    outerExp > minOf(expiresAt, context.expiresAtEpochSeconds, request.expiresAtEpochSeconds, binding.expiresAtEpochSeconds)
                ) reject()
                val vp = outerClaims["vp"] as? Map<*, *> ?: reject()
                if (vp.keys != setOf("type", "verifiableCredential") || vp["type"] != listOf("decent_account_presentation_v1")) reject()
                val credentials = vp["verifiableCredential"] as? List<*> ?: reject()
                if (credentials.size != 1 || credentials[0] !is String) reject()
                verifyCredential(credentials[0] as String, context, request, binding, selectedValues, now, expiresAt,
                    outerExp, outerClaims["jti"] as String)
            } finally { outer.fill(0); header.fill(0); signature.fill(0) }
        } catch (_: Exception) { reject() }
    }

    private fun verifyCredential(jws: String, context: WalletAccountDisclosureContext, request: VerifiedWalletOid4vpRequest,
                                 binding: VerifiedOwnerKeyBinding, values: Map<String, Any?>, now: Long,
                                 approvalExpiry: Long, presentationExpiry: Long, presentationJti: String) {
        if (jws.length > MAX_JWS_BYTES || !jws.all { it.code in 0x21..0x7e }) reject()
        val parts = jws.split('.')
        if (parts.size != 3) reject()
        val header = decode(parts[0], 1024); val payload = decode(parts[1], 12 * 1024); val signature = decode(parts[2], 64)
        try {
            val h = canonicalObject(header, 1024)
            if (h != mapOf("alg" to "EdDSA", "kid" to binding.ownerKeyThumbprint, "typ" to "decent-account-credential+jwt")) reject()
            val publicKey = decode(binding.ownerKey.x, 32); val input = "${parts[0]}.${parts[1]}".toByteArray(StandardCharsets.US_ASCII)
            try { if (!AndroidIdentityCrypto.verify(publicKey, input, signature)) reject() } finally { publicKey.fill(0); input.fill(0) }
            val c = canonicalObject(payload, 12 * 1024)
            val expected = setOf("profile", "credential_type", "iss", "sub", "iat", "exp", "jti", "action", "rp_oidc_client_id", "request_id", "transaction_id", "purpose", "owner_key_thumbprint", "owner_binding_jti", "claims")
            if (c.keys != expected || c["profile"] != "decent-account-disclosure-v1" || c["credential_type"] != "decent_account_assertion_v1" ||
                c["iss"] != binding.identityId || c["sub"] != binding.identityId ||
                c["action"] != context.action || c["rp_oidc_client_id"] != context.rpClientId || c["request_id"] != context.requestId ||
                c["transaction_id"] != context.transactionId || c["purpose"] != context.purpose || c["owner_key_thumbprint"] != binding.ownerKeyThumbprint || c["owner_binding_jti"] != binding.jti || c["claims"] != values) reject()
            val credentialIat = exactLong(c["iat"])
            val credentialExp = exactLong(c["exp"])
            if (credentialIat < 1 || credentialIat > maxFutureIat(now) || credentialExp <= now || credentialExp <= credentialIat ||
                credentialExp - credentialIat > 300 || credentialExp > minOf(approvalExpiry, context.expiresAtEpochSeconds,
                    request.expiresAtEpochSeconds, binding.expiresAtEpochSeconds) ||
                presentationExpiry > credentialExp || !validJti(c["jti"]) || c["jti"] == presentationJti
            ) reject()
            for (claim in context.claims.filter { it.required }) if (claim.id !in values) reject()
            if (values.isEmpty() || values.size > 16 || values.keys.any { id -> context.claims.none { it.id == id } } ||
                values.values.any { value -> value !is String || value.isEmpty() || strictUtf8Length(value) > 1024 }
            ) reject()
        } finally { header.fill(0); payload.fill(0); signature.fill(0) }
    }

    private fun exact(actual: Map<*, *>, required: Map<String, Any?>) {
        if (actual.keys != (required.keys + setOf("jti", "vp", "iat", "exp"))) reject()
        for ((key, value) in required) if (actual[key] != value) reject()
        if (!validJti(actual["jti"])) reject()
    }
    private fun canonicalObject(bytes: ByteArray, maxBytes: Int): Map<*, *> {
        val value = WalletJson.parse(bytes, maxBytes) as? Map<*, *> ?: reject()
        val canonical = WalletJson.canonicalBytes(value)
        try { if (!canonical.contentEquals(bytes)) reject() } finally { canonical.fill(0) }
        return value
    }
    private fun validJti(value: Any?): Boolean {
        val text = value as? String ?: return false
        return try { decode(text, 32).let { raw -> try { raw.size == 32 } finally { raw.fill(0) } } }
        catch (_: Exception) { false }
    }

    private fun strictUtf8Length(value: String): Int = try {
        WalletJson.requireUnicodeScalars(value)
        value.toByteArray(StandardCharsets.UTF_8).size
    } catch (_: Exception) { Int.MAX_VALUE }
    internal fun exactLong(value: Any?): Long = try {
        val integer = value as? BigInteger ?: reject()
        val converted = integer.toLong()
        if (BigInteger.valueOf(converted) != integer) reject()
        converted
    } catch (_: Exception) { reject() }
    private fun maxFutureIat(now: Long): Long = if (now > Long.MAX_VALUE - 60) Long.MAX_VALUE else now + 60
    private fun decode(value: String, maxBytes: Int): ByteArray {
        if (value.isEmpty() || value.length > maxBytes * 2) reject()
        val out = try { Base64.getUrlDecoder().decode(value) } catch (_: Exception) { reject() }
        if (out.size > maxBytes || encoder.encodeToString(out) != value) { out.fill(0); reject() }
        return out
    }
    private fun reject(): Nothing = throw WalletDisclosureRequestException()
}

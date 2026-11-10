package org.decentwallet.wallet.android

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.RSAPublicKeySpec
import java.util.Base64

internal data class Ed25519OwnerPublicKey(
    val kty: String,
    val crv: String,
    val x: String,
)

internal data class VerifiedOwnerKeyBinding(
    val issuer: String,
    val audience: String,
    val subject: String,
    val identityId: String,
    val ownerKey: Ed25519OwnerPublicKey,
    val ownerKeyThumbprint: String,
    val action: String,
    val transactionId: String,
    val requestId: String,
    val oidcNonce: String,
    val issuedAtEpochSeconds: Long,
    val expiresAtEpochSeconds: Long,
    val jti: String,
    val compactJwsSha256: String,
)

/** Verifies the Keycloak-signed owner-key binding after trusted HTTPS JWKS retrieval. */
internal object WalletOwnerKeyBindingVerifier {
    private const val MAX_TOKEN_CHARS = 32_768
    private const val MAX_SEGMENT_CHARS = 16_384
    private const val BINDING_TYP = "decent-owner-key-binding+jwt"
    private const val MAX_ISSUER_JWKS_KEYS = 64
    private val base64UrlPattern = Regex("[A-Za-z0-9_-]+")
    private val headerKeys = setOf("alg", "typ", "kid")
    private val payloadKeys = setOf(
        "v", "iss", "aud", "sub", "identity_id", "owner_key", "owner_key_thumbprint",
        "action", "transaction_id", "request_id", "oidc_nonce", "iat", "exp", "jti",
    )

    fun verify(
        compactJws: String,
        issuerJwks: Map<*, *>,
        pendingContext: WalletAccountDisclosureContext,
        expectedIdentityId: String,
        nowEpochSeconds: Long,
    ): VerifiedOwnerKeyBinding {
        try {
            if (compactJws.isEmpty() || compactJws.length > MAX_TOKEN_CHARS ||
                expectedIdentityId.isEmpty() || expectedIdentityId.length > 4096 || nowEpochSeconds < 1
            ) reject()
            val firstDot = compactJws.indexOf('.')
            val secondDot = compactJws.indexOf('.', firstDot + 1)
            if (firstDot <= 0 || secondDot <= firstDot + 1 || secondDot == compactJws.lastIndex ||
                compactJws.indexOf('.', secondDot + 1) >= 0
            ) reject()
            val headerSegment = compactJws.substring(0, firstDot)
            val payloadSegment = compactJws.substring(firstDot + 1, secondDot)
            val signatureSegment = compactJws.substring(secondDot + 1)
            val header = parseObject(decodeSegment(headerSegment))
            if (header.keys != headerKeys || header["alg"] != "RS256" || header["typ"] != BINDING_TYP) reject()
            val kid = requireText(header["kid"], 256)

            val key = selectIssuerKey(issuerJwks, kid)
            val modulusBytes = decodeBase64Url(requireText(key["n"], 2048), maximumChars = 2048)
            val exponentBytes = decodeBase64Url(requireText(key["e"], 16), maximumChars = 16)
            if (modulusBytes.firstOrNull() == 0.toByte() || exponentBytes.firstOrNull() == 0.toByte()) reject()
            val modulus = BigInteger(1, modulusBytes)
            val exponent = BigInteger(1, exponentBytes)
            if (modulus.bitLength() < 2048 || !modulus.testBit(0) || exponent < BigInteger.valueOf(3) ||
                !exponent.testBit(0) || exponent >= modulus
            ) reject()
            val publicKey = KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, exponent))
            val signingInput = (headerSegment + "." + payloadSegment).toByteArray(StandardCharsets.US_ASCII)
            val verifier = Signature.getInstance("SHA256withRSA")
            verifier.initVerify(publicKey)
            verifier.update(signingInput)
            if (!verifier.verify(decodeSegment(signatureSegment))) reject()

            val payload = parseObject(decodeSegment(payloadSegment))
            if (payload.keys != payloadKeys || payload["v"] != BigInteger.ONE) reject()
            val owner = payload["owner_key"] as? Map<*, *> ?: reject()
            if (owner.keys != setOf("kty", "crv", "x") || owner["kty"] != "OKP" || owner["crv"] != "Ed25519") reject()
            val ownerX = requireText(owner["x"], 64)
            if (decodeBase64Url(ownerX, 64).size != 32) reject()
            val thumbprint = requireText(payload["owner_key_thumbprint"], 64)
            if (thumbprint != ownerThumbprint(ownerX)) reject()

            val issuer = requireText(payload["iss"])
            val audience = requireText(payload["aud"])
            val subject = requireText(payload["sub"])
            val identityId = requireText(payload["identity_id"])
            val action = requireText(payload["action"])
            val transactionId = requireText(payload["transaction_id"])
            val requestId = requireText(payload["request_id"])
            val oidcNonce = requireText(payload["oidc_nonce"])
            val jti = requireText(payload["jti"], 64)
            if (decodeBase64Url(jti, 64).size != 32) reject()
            if (issuer != pendingContext.keycloakIssuer || audience != pendingContext.rpClientId ||
                identityId != expectedIdentityId || action != pendingContext.action ||
                transactionId != pendingContext.transactionId || requestId != pendingContext.requestId ||
                oidcNonce != pendingContext.oidcNonce
            ) reject()

            val issuedAt = exactLong(payload["iat"])
            val expiresAt = exactLong(payload["exp"])
            if (expiresAt <= issuedAt || issuedAt < expiresAt - 300 ||
                (issuedAt > nowEpochSeconds && issuedAt - nowEpochSeconds > 60) ||
                nowEpochSeconds >= expiresAt || expiresAt > pendingContext.expiresAtEpochSeconds
            ) reject()

            val digest = MessageDigest.getInstance("SHA-256").digest(compactJws.toByteArray(StandardCharsets.UTF_8))
            return VerifiedOwnerKeyBinding(
                issuer = issuer,
                audience = audience,
                subject = subject,
                identityId = identityId,
                ownerKey = Ed25519OwnerPublicKey("OKP", "Ed25519", ownerX),
                ownerKeyThumbprint = thumbprint,
                action = action,
                transactionId = transactionId,
                requestId = requestId,
                oidcNonce = oidcNonce,
                issuedAtEpochSeconds = issuedAt,
                expiresAtEpochSeconds = expiresAt,
                jti = jti,
                compactJwsSha256 = digest.joinToString("") { "%02x".format(it) },
            )
        } catch (failure: WalletDisclosureRequestException) {
            throw failure
        } catch (_: Exception) {
            reject()
        }
    }

    private fun selectIssuerKey(jwks: Map<*, *>, kid: String): Map<*, *> {
        if (jwks.keys != setOf("keys")) reject()
        val keys = jwks["keys"] as? List<*> ?: reject()
        if (keys.size > MAX_ISSUER_JWKS_KEYS) reject()
        val matches = keys.filter { candidate ->
            val key = candidate as? Map<*, *> ?: return@filter false
            key["kid"] == kid && key["kty"] == "RSA" && key["use"] == "sig" && key["alg"] == "RS256"
        }
        if (matches.size != 1) reject()
        val key = matches.single() as? Map<*, *> ?: reject()
        val allowed = setOf("kid", "kty", "use", "alg", "n", "e", "key_ops")
        if (!key.keys.containsAll(setOf("kid", "kty", "use", "alg", "n", "e")) || !allowed.containsAll(key.keys)) reject()
        if ("key_ops" in key && key["key_ops"] != listOf("verify")) reject()
        return key
    }

    private fun parseObject(bytes: ByteArray): Map<*, *> {
        val value = WalletJson.parse(bytes, 16 * 1024)
        return value as? Map<*, *> ?: reject()
    }

    private fun decodeSegment(segment: String): ByteArray {
        if (segment.length > MAX_SEGMENT_CHARS) reject()
        return decodeBase64Url(segment, MAX_SEGMENT_CHARS)
    }

    private fun decodeBase64Url(value: String, maximumChars: Int): ByteArray {
        if (value.isEmpty() || value.length > maximumChars || !base64UrlPattern.matches(value)) reject()
        val decoded = try {
            Base64.getUrlDecoder().decode(value)
        } catch (_: IllegalArgumentException) {
            reject()
        }
        if (Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != value) reject()
        return decoded
    }

    private fun ownerThumbprint(x: String): String {
        val canonical = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"$x\"}"
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(StandardCharsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    private fun requireText(value: Any?, maximum: Int = 4096): String {
        val text = value as? String ?: reject()
        if (text.isEmpty() || text.length > maximum) reject()
        return text
    }

    private fun exactLong(value: Any?): Long {
        val integer = value as? BigInteger ?: reject()
        val converted = integer.toLong()
        if (BigInteger.valueOf(converted) != integer) reject()
        return converted
    }

    private fun reject(): Nothing = throw WalletDisclosureRequestException()
}

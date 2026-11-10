package org.decentwallet.wallet.android

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadFeature
import java.io.ByteArrayInputStream
import java.math.BigDecimal
import java.math.BigInteger
import java.net.URI
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Date
import java.util.Locale

data class TrustedWalletRelyingPartyRegistration(
    val clientId: String,
    val x509SanDns: String,
    val origin: String,
    val responseUri: String,
    val trustAnchorSha256: String,
    val rpClientId: String,
)

internal data class VerifiedWalletOid4vpRequest(
    val clientId: String,
    val state: String,
    val nonce: String,
    val responseUri: String,
    val dcqlQuery: Map<String, Any?>,
    val purpose: String,
    val requestId: String,
    val transactionId: String,
    val action: String,
    val expiresAtEpochSeconds: Long,
)

/** Verifies an already-fetched Request Object against caller-owned static RP trust. */
internal object WalletOid4vpRequestVerifier {
    private const val MAX_JWS_BYTES = 65_536
    private const val MAX_X5C_CERTIFICATES = 8
    private const val FORMAT = "decent_account_jwt_v1"
    private const val PROFILE = "decent-account-disclosure-v1"
    private val names = setOf("given_name", "family_name", "email", "phone", "locale")
    private val base64UrlPattern = Regex("[A-Za-z0-9_-]+")
    private val jsonFactory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .build()
    private val knownOuter = setOf(
        "client_id", "request_uri", "response_type", "response_mode", "scope", "redirect_uri",
        "response_uri", "state", "nonce", "prompt", "max_age", "login_hint", "claims", "request",
        "request_uri_method", "client_metadata", "dcql_query", "transaction_data", "code_challenge",
        "code_challenge_method",
    )
    private val p256Prime = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    private val p256A = p256Prime.subtract(BigInteger.valueOf(3))
    private val p256B = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)
    private val p256GeneratorX = BigInteger("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", 16)
    private val p256GeneratorY = BigInteger("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", 16)
    private val p256Order = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)

    fun verify(
        outerAuthorizationParameters: Map<*, *>,
        requestObjectJws: String,
        registration: TrustedWalletRelyingPartyRegistration,
        pendingContext: WalletAccountDisclosureContext,
        ownerKeyBindingJws: String,
        verifiedBinding: VerifiedOwnerKeyBinding,
        nowEpochSeconds: Long,
    ): VerifiedWalletOid4vpRequest {
        try {
            if (nowEpochSeconds < 1L || requestObjectJws.length > MAX_JWS_BYTES) reject()
            if (requestObjectJws.toByteArray(StandardCharsets.UTF_8).size > MAX_JWS_BYTES) reject()
            if (!outerAuthorizationParameters.containsKey("client_id") ||
                !outerAuthorizationParameters.containsKey("request_uri") ||
                outerAuthorizationParameters.containsKey("transaction_data")
            ) reject()
            if (outerAuthorizationParameters.keys.any { key ->
                    key is String && key in knownOuter && key !in setOf("client_id", "request_uri", "transaction_data")
                }
            ) reject()
            if (outerAuthorizationParameters["client_id"] != registration.clientId ||
                outerAuthorizationParameters["request_uri"] !is String
            ) reject()
            if (registration.clientId != outerAuthorizationParameters["client_id"] ||
                registration.rpClientId != pendingContext.rpClientId ||
                registration.origin != pendingContext.rpOrigin
            ) reject()
            if (verifiedBinding.compactJwsSha256 != sha256Hex(ownerKeyBindingJws.toByteArray(StandardCharsets.UTF_8)) ||
                verifiedBinding.issuer != pendingContext.keycloakIssuer ||
                verifiedBinding.audience != pendingContext.rpClientId ||
                verifiedBinding.action != pendingContext.action ||
                verifiedBinding.requestId != pendingContext.requestId ||
                verifiedBinding.transactionId != pendingContext.transactionId ||
                verifiedBinding.oidcNonce != pendingContext.oidcNonce ||
                verifiedBinding.expiresAtEpochSeconds > pendingContext.expiresAtEpochSeconds
            ) reject()

            val requestUri = outerAuthorizationParameters["request_uri"] as String
            val requestHost = httpsOrigin(requestUri)
            val registeredOrigin = URI(registration.origin)
            val requestUriValue = URI(requestUri)
            if (requestHost != registration.x509SanDns || requestUriValue.rawAuthority != registeredOrigin.rawAuthority) reject()

            val compact = splitCompactJws(requestObjectJws)
            val header = parseJson(compact.headerBytes) as? Map<*, *> ?: reject()
            val payload = parseJson(compact.payloadBytes) as? Map<*, *> ?: reject()
            verifySignature(header, compact, registration, nowEpochSeconds)
            if (payload.containsKey("transaction_data")) reject()
            if (payload["aud"] != "https://self-issued.me/v2" || payload["client_id"] != registration.clientId) reject()
            if (payload["response_type"] != "vp_token" || payload["response_mode"] != "direct_post" ||
                payload["response_uri"] != registration.responseUri
            ) reject()
            if (httpsOrigin(registration.origin) != registration.x509SanDns ||
                httpsOrigin(registration.responseUri) != registration.x509SanDns
            ) reject()

            val reusedContextValues = setOf(
                pendingContext.oidcNonce,
                pendingContext.requestId,
                pendingContext.transactionId,
            )
            val state = payload["state"] as? String ?: reject()
            val stateBytes = decodeBase64Url(state)
            val nonce = payload["nonce"] as? String ?: reject()
            val nonceBytes = decodeBase64Url(nonce)
            try {
                if (stateBytes.size < 16 || nonceBytes.size < 32 || state == nonce ||
                    state in reusedContextValues || nonce in reusedContextValues
                ) reject()
            } finally {
                stateBytes.fill(0)
                nonceBytes.fill(0)
            }

            val issuedAt = payload["iat"] as? BigInteger ?: reject()
            val expiresAt = payload["exp"] as? BigInteger ?: reject()
            val now = BigInteger.valueOf(nowEpochSeconds)
            if (issuedAt > now.add(BigInteger.valueOf(60)) || expiresAt <= now || expiresAt <= issuedAt ||
                expiresAt.subtract(issuedAt) > BigInteger.valueOf(300) ||
                expiresAt > BigInteger.valueOf(pendingContext.expiresAtEpochSeconds) ||
                expiresAt > BigInteger.valueOf(verifiedBinding.expiresAtEpochSeconds)
            ) reject()
            val exp = exactLong(expiresAt)
            if (payload["jti"] !is String || (payload["jti"] as String).isEmpty()) reject()

            val metadata = payload["client_metadata"] as? Map<*, *> ?: reject()
            val supportedFormats = metadata["vp_formats_supported"] as? Map<*, *> ?: reject()
            val format = supportedFormats[FORMAT] as? Map<*, *> ?: reject()
            if (format["alg_values"] != listOf("EdDSA")) reject()

            val extension = payload["decent_account"] as? Map<*, *> ?: reject()
            val extensionKeys = setOf(
                "profile", "rp_oidc_client_id", "action", "request_id", "transaction_id", "purpose",
                "owner_key_binding", "claims",
            )
            if (extension.keys != extensionKeys) reject()
            val purpose = pendingContext.purpose
            if (extension["profile"] != PROFILE || extension["rp_oidc_client_id"] != pendingContext.rpClientId ||
                extension["action"] != pendingContext.action || extension["request_id"] != pendingContext.requestId ||
                extension["transaction_id"] != pendingContext.transactionId || extension["purpose"] != purpose ||
                extension["owner_key_binding"] != ownerKeyBindingJws ||
                extension["claims"] != pendingContext.claims.map { mapOf("id" to it.id, "required" to it.required) }
            ) reject()

            val query = payload["dcql_query"] as? Map<*, *> ?: reject()
            val credentialQueries = query["credentials"] as? List<*> ?: reject()
            if (credentialQueries.size != 1 || query.containsKey("credential_sets")) reject()
            val credential = credentialQueries.single() as? Map<*, *> ?: reject()
            if (credential["id"] != "account" || credential["format"] != FORMAT ||
                credential["multiple"] != false || credential["require_cryptographic_holder_binding"] != true
            ) reject()
            if (credential["meta"] !is Map<*, *> || credential.containsKey("trusted_authorities")) reject()
            val claimQueries = credential["claims"] as? List<*> ?: reject()
            val requested = pendingContext.claims.map { it.id.substringAfterLast(':') }
            if (claimQueries.size != requested.size) reject()
            val ids = ArrayList<String>(claimQueries.size)
            val normalizedClaims = ArrayList<Map<String, Any?>>(claimQueries.size)
            for (value in claimQueries) {
                val claim = value as? Map<*, *> ?: reject()
                if (!claim.containsKey("id") || !claim.containsKey("path") ||
                    claim.containsKey("values") || claim.containsKey("intent_to_retain")
                ) reject()
                val id = claim["id"] as? String ?: reject()
                val path = claim["path"] as? List<*> ?: reject()
                if (id !in names || path != listOf("claims", "urn:decent:account:v1:$id")) reject()
                ids.add(id)
                normalizedClaims.add(mapOf("id" to id, "path" to path.toList()))
            }
            if (ids != requested) reject()
            val required = pendingContext.claims.filter { it.required }.map { it.id.substringAfterLast(':') }
            val optional = pendingContext.claims.filterNot { it.required }.map { it.id.substringAfterLast(':') }
            if (required.isEmpty() || optional.size > 4) reject()
            val expectedClaimSets = (0..optional.size).flatMap { count ->
                (0 until (1 shl optional.size)).mapNotNull { mask ->
                    val chosen = required + optional.filterIndexed { index, _ -> mask and (1 shl index) != 0 }
                    if (chosen.size != required.size + count) null else ids.filter { it in chosen }
                }
            }.distinct().sortedWith(compareBy<List<String>>({ it.size }, { set -> set.joinToString("\u0000") { ids.indexOf(it).toString().padStart(2, '0') } }))
            if (credential["claim_sets"] != expectedClaimSets) reject()
            val normalizedCredential = mapOf(
                "id" to "account",
                "format" to FORMAT,
                "multiple" to false,
                "meta" to emptyMap<String, Any?>(),
                "require_cryptographic_holder_binding" to true,
                "claims" to normalizedClaims,
                "claim_sets" to expectedClaimSets,
            )
            val normalizedQuery = mapOf("credentials" to listOf(normalizedCredential))
            return VerifiedWalletOid4vpRequest(
                clientId = registration.clientId,
                state = state,
                nonce = nonce,
                responseUri = registration.responseUri,
                dcqlQuery = normalizedQuery,
                purpose = purpose,
                requestId = pendingContext.requestId,
                transactionId = pendingContext.transactionId,
                action = pendingContext.action,
                expiresAtEpochSeconds = exp,
            )
        } catch (failure: WalletDisclosureRequestException) {
            throw failure
        } catch (_: Exception) {
            reject()
        }
    }

    private data class CompactJws(
        val headerBytes: ByteArray,
        val payloadBytes: ByteArray,
        val signatureBytes: ByteArray,
        val signingInput: ByteArray,
    )

    private fun splitCompactJws(token: String): CompactJws {
        if (token.isEmpty() || token.length > MAX_JWS_BYTES || token.any { it.code > 0x7f }) reject()
        val first = token.indexOf('.')
        val second = token.indexOf('.', first + 1)
        if (first <= 0 || second <= first + 1 || second == token.lastIndex || token.indexOf('.', second + 1) >= 0) reject()
        val header = decodeBase64Url(token.substring(0, first))
        val payload = decodeBase64Url(token.substring(first + 1, second))
        val signature = decodeBase64Url(token.substring(second + 1))
        return CompactJws(header, payload, signature, token.substring(0, second).toByteArray(StandardCharsets.US_ASCII))
    }

    private fun verifySignature(
        header: Map<*, *>,
        compact: CompactJws,
        registration: TrustedWalletRelyingPartyRegistration,
        nowEpochSeconds: Long,
    ) {
        if (header["alg"] != "ES256" || header["typ"] != "oauth-authz-req+jwt" || header.containsKey("crit")) reject()
        val encodedCertificates = header["x5c"] as? List<*> ?: reject()
        if (encodedCertificates.isEmpty() || encodedCertificates.size > MAX_X5C_CERTIFICATES) reject()
        val certificates = encodedCertificates.map { encoded ->
            val text = encoded as? String ?: reject()
            if (text.isEmpty() || text.length > MAX_JWS_BYTES) reject()
            val der = try { Base64.getDecoder().decode(text) } catch (_: IllegalArgumentException) { reject() }
            if (Base64.getEncoder().encodeToString(der) != text || der.size > MAX_JWS_BYTES) reject()
            try {
                val certificate = CertificateFactory.getInstance("X.509")
                    .generateCertificate(ByteArrayInputStream(der)) as X509Certificate
                if (!certificate.encoded.contentEquals(der)) reject()
                certificate
            } catch (failure: WalletDisclosureRequestException) {
                throw failure
            } catch (_: Exception) {
                reject()
            } finally {
                der.fill(0)
            }
        }
        verifyPinnedCertificateSequence(certificates, registration, nowEpochSeconds)
        val key = certificates.first().publicKey as? ECPublicKey ?: reject()
        if (!isP256(key)) reject()
        val derSignature = rawEcdsaSignatureToDer(compact.signatureBytes)
        try {
            val verifier = Signature.getInstance("SHA256withECDSA")
            verifier.initVerify(key)
            verifier.update(compact.signingInput)
            if (!verifier.verify(derSignature)) reject()
        } finally {
            derSignature.fill(0)
        }
    }

    private fun verifyPinnedCertificateSequence(
        certificates: List<X509Certificate>,
        registration: TrustedWalletRelyingPartyRegistration,
        nowEpochSeconds: Long,
    ) {
        val pin = registration.trustAnchorSha256.lowercase(Locale.ROOT)
        if (!pin.matches(Regex("[0-9a-f]{64}"))) reject()
        val anchorDigest = MessageDigest.getInstance("SHA-256").digest(certificates.last().encoded)
        if (hex(anchorDigest) != pin) reject()
        val validAtMillis = try { Math.multiplyExact(nowEpochSeconds, 1000L) } catch (_: ArithmeticException) { reject() }
        val validAt = Date(validAtMillis)
        certificates.forEach { certificate ->
            try { certificate.checkValidity(validAt) } catch (_: Exception) { reject() }
        }
        val sans = try { certificates.first().subjectAlternativeNames } catch (_: Exception) { reject() } ?: reject()
        if (sans.none { entry -> entry.size >= 2 && entry[0] == 2 && entry[1] == registration.x509SanDns } ||
            registration.clientId != "x509_san_dns:${registration.x509SanDns}"
        ) reject()
        for (index in 0 until certificates.lastIndex) {
            val child = certificates[index]
            val issuer = certificates[index + 1]
            if (child.issuerX500Principal != issuer.subjectX500Principal) reject()
            if (issuer.publicKey.algorithm !in setOf("RSA", "EC")) reject()
            try { child.verify(issuer.publicKey) } catch (_: Exception) { reject() }
        }
        certificates.drop(1).forEach { issuer ->
            if (issuer.basicConstraints < 0 || issuer.keyUsage?.getOrNull(5) != true) reject()
        }
    }

    private fun isP256(key: ECPublicKey): Boolean {
        val parameters = key.params ?: return false
        val field = parameters.curve.field as? ECFieldFp ?: return false
        return field.p == p256Prime && parameters.curve.a == p256A && parameters.curve.b == p256B &&
            parameters.generator.affineX == p256GeneratorX && parameters.generator.affineY == p256GeneratorY &&
            parameters.order == p256Order && parameters.cofactor == 1
    }

    private fun rawEcdsaSignatureToDer(signature: ByteArray): ByteArray {
        if (signature.size != 64) reject()
        fun integer(bytes: ByteArray): ByteArray {
            val firstNonZero = bytes.indexOfFirst { it != 0.toByte() }
            if (firstNonZero < 0) reject()
            val magnitude = bytes.copyOfRange(firstNonZero, bytes.size)
            val needsZero = magnitude[0].toInt() and 0x80 != 0
            return byteArrayOf(0x02, (magnitude.size + if (needsZero) 1 else 0).toByte()) +
                (if (needsZero) byteArrayOf(0) + magnitude else magnitude)
        }
        val r = integer(signature.copyOfRange(0, 32))
        val s = integer(signature.copyOfRange(32, 64))
        val body = r + s
        if (body.size > 127) reject()
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    private fun parseJson(bytes: ByteArray): Any? {
        if (bytes.isEmpty() || bytes.size > MAX_JWS_BYTES) reject()
        try {
            val text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString()
            if (text.startsWith('\uFEFF')) reject()
            val parser = jsonFactory.createParser(text)
            parser.use { input ->
                val first = input.nextToken() ?: reject()
                val value = readValue(input, first, 0)
                if (input.nextToken() != null) reject()
                return value
            }
        } catch (failure: WalletDisclosureRequestException) {
            throw failure
        } catch (_: Exception) {
            reject()
        }
    }

    private fun readValue(parser: JsonParser, token: JsonToken, depth: Int): Any? {
        if (depth > 64) reject()
        return when (token) {
            JsonToken.START_OBJECT -> {
                val result = LinkedHashMap<String, Any?>()
                while (true) {
                    val next = parser.nextToken() ?: reject()
                    if (next == JsonToken.END_OBJECT) break
                    if (next != JsonToken.FIELD_NAME) reject()
                    val name = parser.currentName
                    requireUnicodeScalars(name)
                    val child = parser.nextToken() ?: reject()
                    result[name] = readValue(parser, child, depth + 1)
                }
                result
            }
            JsonToken.START_ARRAY -> {
                val result = ArrayList<Any?>()
                while (true) {
                    val next = parser.nextToken() ?: reject()
                    if (next == JsonToken.END_ARRAY) break
                    result.add(readValue(parser, next, depth + 1))
                }
                result
            }
            JsonToken.VALUE_STRING -> parser.text.also(::requireUnicodeScalars)
            JsonToken.VALUE_NUMBER_INT -> parser.bigIntegerValue
            JsonToken.VALUE_NUMBER_FLOAT -> {
                val number = parser.decimalValue
                if (!number.toDouble().isFinite()) reject()
                number
            }
            JsonToken.VALUE_TRUE -> true
            JsonToken.VALUE_FALSE -> false
            JsonToken.VALUE_NULL -> null
            else -> reject()
        }
    }

    private fun httpsOrigin(value: String): String {
        val uri = URI(value)
        val host = uri.host ?: reject()
        val expectedAuthority = if (uri.port < 0) host else "$host:${uri.port}"
        if (uri.scheme != "https" || host != host.lowercase(Locale.ROOT) || uri.rawUserInfo != null ||
            uri.rawFragment != null || uri.rawAuthority != expectedAuthority
        ) reject()
        return host
    }

    private fun decodeBase64Url(value: String): ByteArray {
        if (value.isEmpty() || !base64UrlPattern.matches(value)) reject()
        val decoded = try { Base64.getUrlDecoder().decode(value) } catch (_: IllegalArgumentException) { reject() }
        if (Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != value) {
            decoded.fill(0)
            reject()
        }
        return decoded
    }

    private fun exactLong(value: BigInteger): Long {
        val result = value.toLong()
        if (BigInteger.valueOf(result) != value) reject()
        return result
    }

    private fun sha256Hex(bytes: ByteArray): String = hex(MessageDigest.getInstance("SHA-256").digest(bytes))

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private fun requireUnicodeScalars(value: String) {
        var index = 0
        while (index < value.length) {
            val char = value[index]
            when {
                Character.isHighSurrogate(char) -> {
                    if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) reject()
                    index += 2
                }
                Character.isLowSurrogate(char) -> reject()
                else -> index++
            }
        }
    }

    private fun reject(): Nothing = throw WalletDisclosureRequestException()
}

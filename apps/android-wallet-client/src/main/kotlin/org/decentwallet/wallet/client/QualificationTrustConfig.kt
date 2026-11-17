package org.decentwallet.wallet.client

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadFeature
import org.decentwallet.wallet.android.TrustedWalletRelyingPartyRegistration
import java.math.BigInteger
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Base64

/** Public trust material supplied explicitly by a qualification build maintainer. */
data class QualificationTrustConfig internal constructor(
    val keycloakDisplayName: String,
    val issuer: String,
    val issuerJwks: Map<*, *>,
    val rp: TrustedWalletRelyingPartyRegistration,
) {
    fun toNativeDisclosureTrustConfig() = NativeDisclosureTrustConfig(
        expectedKeycloakIssuer = issuer,
        issuerJwks = issuerJwks,
        relyingPartyRegistration = rp,
        keycloakDisplayName = keycloakDisplayName,
    )

    companion object {
        private const val MAX_CONFIG_BYTES = 64 * 1024
        private val placeholders = listOf(".invalid", ".example", "placeholder", "change_me", "replace_me", "example.com")
        private val rsaFields = setOf("kid", "kty", "use", "alg", "n", "e", "key_ops")
        private val privateFields = setOf("d", "p", "q", "dp", "dq", "qi", "oth")

        fun load(assets: Map<String, ByteArray>, providerHost: String): QualificationTrustConfig? =
            assets["trust_config.json"]?.let { parse(it, providerHost) }

        fun parse(text: String, providerHost: String): QualificationTrustConfig =
            parse(text.toByteArray(StandardCharsets.UTF_8), providerHost)

        fun parse(bytes: ByteArray, providerHost: String): QualificationTrustConfig {
            require(bytes.isNotEmpty() && bytes.size <= MAX_CONFIG_BYTES) { "invalid qualification trust config" }
            val root = StrictQualificationJson.parse(bytes) as? Map<*, *> ?: invalidConfig()
            require(root.keys == setOf("keycloak_display_name", "issuer", "issuer_jwks", "rp")) { "invalid qualification trust config fields" }
            val displayName = configured(root["keycloak_display_name"], "keycloak_display_name")
            val issuer = configured(root["issuer"], "issuer")
            val issuerUri = URI(issuer)
            require(issuerUri.scheme == "https" && issuerUri.host == providerHost && issuerUri.rawUserInfo == null &&
                issuerUri.rawQuery == null && issuerUri.rawFragment == null && (issuerUri.port == -1 || issuerUri.port == 443) &&
                issuerUri.rawPath.matches(Regex("/realms/[A-Za-z0-9][A-Za-z0-9._-]{0,62}"))) {
                "qualification issuer must exactly match configured HTTPS provider realm"
            }
            val jwks = root["issuer_jwks"] as? Map<*, *> ?: invalidConfig()
            require(jwks.keys == setOf("keys")) { "invalid issuer JWKS" }
            val rawKeys = jwks["keys"] as? List<*> ?: invalidConfig()
            require(rawKeys.isNotEmpty() && rawKeys.size <= 32) { "issuer JWKS must be non-empty and bounded" }
            val keys = rawKeys.mapIndexed { index, raw ->
                val key = raw as? Map<*, *> ?: invalidConfig()
                require(key.keys.none { it in privateFields } && key.keys.all { it in rsaFields } &&
                    key.keys.containsAll(setOf("kid", "kty", "use", "alg", "n", "e"))) { "issuer JWKS must contain public RSA verification keys only" }
                require(key["kty"] == "RSA" && key["use"] == "sig" && key["alg"] == "RS256") { "issuer JWK must be RS256 signing key" }
                configured(key["kid"], "issuer_jwks.keys[$index].kid")
                val modulus = jwkInteger(key["n"])
                val exponent = jwkInteger(key["e"])
                require(modulus.bitLength() in 2048..4096 && modulus.testBit(0) && exponent >= BigInteger.valueOf(3) && exponent.testBit(0) && exponent < modulus) {
                    "invalid RSA public key"
                }
                if ("key_ops" in key) require(key["key_ops"] == listOf("verify")) { "issuer JWK key_ops must be verify only" }
                key
            }
            val rp = root["rp"] as? Map<*, *> ?: invalidConfig()
            require(rp.keys == setOf("client_id", "x509_san_dns", "origin", "response_uri", "trust_anchor_sha256", "rp_client_id")) {
                "invalid relying-party registration fields"
            }
            val dns = configured(rp["x509_san_dns"], "rp.x509_san_dns")
            require(dns.length <= 253 && dns.matches(Regex("[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")) &&
                dns.split('.').all { it.isNotEmpty() && it.length <= 63 && !it.startsWith('-') && !it.endsWith('-') }) { "invalid RP DNS registration" }
            val clientId = configured(rp["client_id"], "rp.client_id")
            require(clientId == "x509_san_dns:$dns") { "RP client ID must bind its registered DNS name" }
            val origin = configured(rp["origin"], "rp.origin")
            val originUri = URI(origin)
            require(originUri.scheme == "https" && originUri.host == dns && originUri.rawUserInfo == null &&
                originUri.rawPath.isNullOrEmpty() && originUri.rawQuery == null && originUri.rawFragment == null &&
                (originUri.port == -1 || originUri.port == 443)) { "RP origin must be its exact HTTPS DNS origin" }
            val responseUri = configured(rp["response_uri"], "rp.response_uri")
            val response = URI(responseUri)
            require(response.scheme == "https" && response.host == dns && response.rawUserInfo == null &&
                response.rawPath != null && response.rawPath.isNotEmpty() && '%' !in response.rawPath && response.rawQuery == null && response.rawFragment == null &&
                (response.port == -1 || response.port == 443)) { "RP response URI must stay at its registered HTTPS DNS origin" }
            val pin = configured(rp["trust_anchor_sha256"], "rp.trust_anchor_sha256")
            require(pin.matches(Regex("[0-9a-f]{64}"))) { "invalid lowercase SHA-256 certificate pin" }
            val rpClient = configured(rp["rp_client_id"], "rp.rp_client_id")
            return QualificationTrustConfig(displayName, issuer, mapOf("keys" to keys),
                TrustedWalletRelyingPartyRegistration(clientId, dns, origin, responseUri, pin, rpClient))
        }

        private fun configured(value: Any?, field: String): String {
            val text = value as? String ?: invalidConfig()
            val normalized = text.lowercase()
            require(text.isNotBlank() && text.none { it.code < 0x20 } && placeholders.none(normalized::contains)) {
                "qualification trust $field is missing or a placeholder"
            }
            return text
        }

        private fun jwkInteger(value: Any?): BigInteger {
            val encoded = value as? String ?: invalidConfig()
            require(encoded.matches(Regex("[A-Za-z0-9_-]{1,2048}"))) { "invalid public RSA parameter" }
            val bytes = try { Base64.getUrlDecoder().decode(encoded) } catch (_: Exception) { invalidConfig() }
            try {
                require(bytes.isNotEmpty() && bytes[0] != 0.toByte() && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == encoded) {
                    "invalid public RSA parameter"
                }
                return BigInteger(1, bytes)
            } finally { bytes.fill(0) }
        }

        private fun invalidConfig(): Nothing = throw IllegalArgumentException("invalid qualification trust config")
    }
}

/** Size- and depth-bounded strict JSON parser with duplicate member rejection. */
internal object StrictQualificationJson {
    private val factory = JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build()
    fun parse(bytes: ByteArray): Any? = factory.createParser(bytes).use { parser ->
        val first = parser.nextToken() ?: throw IllegalArgumentException("invalid qualification trust config")
        val value = read(parser, first, 0)
        require(parser.nextToken() == null) { "invalid qualification trust config" }
        value
    }
    private fun read(parser: JsonParser, token: JsonToken, depth: Int): Any? {
        require(depth <= 32) { "qualification trust config is too deeply nested" }
        return when (token) {
            JsonToken.START_OBJECT -> LinkedHashMap<String, Any?>().apply {
                while (true) {
                    val next = parser.nextToken() ?: throw IllegalArgumentException("invalid qualification trust config")
                    if (next == JsonToken.END_OBJECT) break
                    require(next == JsonToken.FIELD_NAME) { "invalid qualification trust config" }
                    val key = parser.currentName
                    val child = parser.nextToken() ?: throw IllegalArgumentException("invalid qualification trust config")
                    put(key, read(parser, child, depth + 1))
                }
            }
            JsonToken.START_ARRAY -> buildList {
                while (true) {
                    val next = parser.nextToken() ?: throw IllegalArgumentException("invalid qualification trust config")
                    if (next == JsonToken.END_ARRAY) break
                    add(read(parser, next, depth + 1))
                }
            }
            JsonToken.VALUE_STRING -> parser.text
            JsonToken.VALUE_NUMBER_INT -> parser.bigIntegerValue
            JsonToken.VALUE_NUMBER_FLOAT -> parser.decimalValue
            JsonToken.VALUE_TRUE -> true
            JsonToken.VALUE_FALSE -> false
            JsonToken.VALUE_NULL -> null
            else -> throw IllegalArgumentException("invalid qualification trust config")
        }
    }
}

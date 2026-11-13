package org.decentwallet.wallet.android

import java.math.BigInteger
import java.net.URI
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64
import java.util.Collections

private fun BigInteger.toLongExactCompatible(): Long {
    val converted = toLong()
    if (BigInteger.valueOf(converted) != this) throw ArithmeticException("BigInteger does not fit in Long")
    return converted
}

class RequestedAccountClaim internal constructor(
    val id: String,
    val required: Boolean,
)

class AccountDisclosureClaimReview internal constructor(
    val id: String,
    val required: Boolean,
    val value: String?,
) {
    override fun toString(): String = "AccountDisclosureClaimReview(id=$id, required=$required, value=[redacted])"
}

/** A display-only, value-redacted snapshot; it is not consent or a signing capability. */
class AccountDisclosureReview internal constructor(
    val keycloakIssuer: String,
    val rpClientId: String,
    val rpDisplayName: String,
    val rpOrigin: String,
    val action: String,
    val requestId: String,
    val transactionId: String,
    val oidcNonce: String,
    val purpose: String,
    claims: List<AccountDisclosureClaimReview>,
    val identityId: String,
    val expiresAtEpochSeconds: Long,
    val nativeContinuationEnabled: Boolean = false,
) {
    val claims: List<AccountDisclosureClaimReview> = Collections.unmodifiableList(ArrayList(claims))

    override fun toString(): String = "AccountDisclosureReview()"
}

class PendingAccountApproval internal constructor(
    val handle: String,
    val expiresAtEpochSeconds: Long,
    internal val approvedAtEpochSeconds: Long,
) {
    override fun toString(): String = "PendingAccountApproval()"
}

class NativeContinuationCapability internal constructor(
    val expiresAtEpochSeconds: Long,
    private val monotonicExpiryNanos: Long,
    capabilityBytes: ByteArray,
) : AutoCloseable {
    private var ownedBytes: ByteArray? = capabilityBytes.copyOf()

    @Synchronized
    fun copyCapabilityBytes(): ByteArray {
        val bytes = ownedBytes ?: throw IllegalStateException("capability unavailable")
        if (
            System.currentTimeMillis() / 1000 >= expiresAtEpochSeconds ||
            System.nanoTime() - monotonicExpiryNanos >= 0
        ) {
            bytes.fill(0)
            ownedBytes = null
            throw IllegalStateException("capability unavailable")
        }
        return bytes.copyOf()
    }

    @Synchronized
    override fun close() {
        ownedBytes?.fill(0)
        ownedBytes = null
    }

    override fun toString(): String = "NativeContinuationCapability()"
}

enum class PresentationDeliveryOutcome {
    AMBIGUOUS,
    ACCEPTED,
    DEFINITIVE_FAILURE,
    CANCELLED,
}

class AccountPresentationSubmission internal constructor(
    val pending: PendingAccountApproval,
    val responseUri: String,
    val state: String,
    val presentationJws: String,
    body: ByteArray,
) : AutoCloseable {
    private var encodedBody: ByteArray? = body.copyOf()
    val body: ByteArray
        @Synchronized get() = encodedBody?.copyOf() ?: throw IllegalStateException("submission closed")

    @Synchronized
    override fun close() {
        encodedBody?.fill(0)
        encodedBody = null
    }

    override fun toString(): String = "AccountPresentationSubmission()"
}

class WalletDisclosureRequestException :
    WalletContainerException("wallet disclosure request rejected")

internal class WalletAccountDisclosureContext(
    val keycloakIssuer: String,
    val rpClientId: String,
    val rpDisplayName: String,
    val rpOrigin: String,
    val action: String,
    val requestId: String,
    val transactionId: String,
    val oidcNonce: String,
    val purpose: String,
    val claims: List<RequestedAccountClaim>,
    val expiresAtEpochSeconds: Long,
    val nativeContinuationEnabled: Boolean = false,
)

internal object WalletAccountDisclosureContextParser {
    internal const val MAX_CONTEXT_BYTES = 64 * 1024
    private const val PROFILE = "decent-account-disclosure-v1"
    private const val MAX_LIFETIME_SECONDS = 300L
    private const val CLAIM_PREFIX = "urn:decent:account:v1:"
    private val contextKeys = setOf(
        "profile", "keycloak_issuer", "rp_client_id", "rp_display_name", "rp_origin",
        "action", "request_id", "transaction_id", "oidc_nonce", "purpose", "claims", "expires_at",
    )
    private val nativeContextKeys = contextKeys + "decent_native_continuation"
    private val claimKeys = setOf("id", "required")
    private val allowedClaims = setOf("given_name", "family_name", "email", "phone", "locale")
    private val bidiControls = setOf(0x061C, 0x200E, 0x200F) + (0x202A..0x202E) + (0x2066..0x2069)
    private val base64UrlPattern = Regex("[A-Za-z0-9_-]+")
    private val dnsLabelPattern = Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

    fun parse(
        raw: ByteArray,
        transactionHandle: String,
        expectedKeycloakIssuer: String,
        nowEpochSeconds: Long,
    ): WalletAccountDisclosureContext {
        try {
            if (raw.isEmpty() || raw.size > MAX_CONTEXT_BYTES || nowEpochSeconds < 1) reject()
            val parsed = WalletJson.parse(raw, MAX_CONTEXT_BYTES) as? Map<*, *> ?: reject()
            val nativeContinuationEnabled = when (parsed.keys) {
                contextKeys -> false
                nativeContextKeys -> {
                    if (parsed["decent_native_continuation"] != true) reject()
                    true
                }
                else -> reject()
            }
            if (parsed["profile"] != PROFILE) reject()

            val issuer = text(parsed["keycloak_issuer"], 2048)
            val expectedIssuer = text(expectedKeycloakIssuer, 2048)
            validateIssuer(issuer)
            validateIssuer(expectedIssuer)
            if (issuer != expectedIssuer) reject()

            val clientId = text(parsed["rp_client_id"], 256)
            val displayName = text(parsed["rp_display_name"], 128)
            val origin = text(parsed["rp_origin"], 2048)
            validateOrigin(origin)

            val action = parsed["action"] as? String ?: reject()
            if (action !in setOf("signup", "signup_recovery")) reject()
            val requestId = text(parsed["request_id"], 128)
            decodeBase64Url(requestId, 16).fill(0)
            val transactionId = text(parsed["transaction_id"], 128)
            decodeBase64Url(transactionId, 32).fill(0)
            val nonce = text(parsed["oidc_nonce"], 128)
            val nonceBytes = decodeBase64Url(nonce, null)
            if (nonceBytes.size !in 16..96) reject()
            nonceBytes.fill(0)
            validateHandleAndTransactionId(transactionHandle, transactionId)

            val purpose = text(parsed["purpose"], 160)
            validatePurpose(purpose)
            val claims = parseClaims(parsed["claims"])
            val expiry = parsed["expires_at"] as? BigInteger ?: reject()
            val expiresAt = try {
                expiry.toLongExactCompatible()
            } catch (_: ArithmeticException) {
                reject()
            }
            if (expiresAt < 1 || expiresAt <= nowEpochSeconds || expiresAt - nowEpochSeconds > MAX_LIFETIME_SECONDS) reject()

            return WalletAccountDisclosureContext(
                issuer, clientId, displayName, origin, action, requestId, transactionId,
                nonce, purpose, Collections.unmodifiableList(claims), expiresAt, nativeContinuationEnabled,
            )
        } catch (failure: WalletDisclosureRequestException) {
            throw failure
        } catch (_: Exception) {
            reject()
        }
    }

    private fun parseClaims(value: Any?): List<RequestedAccountClaim> {
        val items = value as? List<*> ?: reject()
        if (items.size !in 1..16) reject()
        val result = ArrayList<RequestedAccountClaim>(items.size)
        val seen = HashSet<String>()
        var requiredCount = 0
        var optionalCount = 0
        for (item in items) {
            val claim = item as? Map<*, *> ?: reject()
            if (claim.keys != claimKeys) reject()
            val id = text(claim["id"], 128)
            if (!id.startsWith(CLAIM_PREFIX)) reject()
            val key = id.removePrefix(CLAIM_PREFIX)
            if (key !in allowedClaims || !seen.add(id)) reject()
            val required = claim["required"] as? Boolean ?: reject()
            if (required) requiredCount++ else optionalCount++
            result.add(RequestedAccountClaim(id, required))
        }
        if (requiredCount < 1 || optionalCount > 4) reject()
        return result
    }

    private fun validateHandleAndTransactionId(handle: String, transactionId: String) {
        text(handle, 128)
        val handleBytes = decodeBase64Url(handle, 32)
        val ascii = try {
            handle.toByteArray(StandardCharsets.US_ASCII).also {
                if (String(it, StandardCharsets.US_ASCII) != handle) reject()
            }
        } catch (_: Exception) {
            handleBytes.fill(0)
            reject()
        }
        try {
            val derived = Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(ascii),
            )
            if (derived != transactionId) reject()
        } finally {
            ascii.fill(0)
            handleBytes.fill(0)
        }
    }

    private fun validateIssuer(value: String) {
        val uri = URI(value)
        val host = uri.host
        if (uri.scheme != "https" || host.isNullOrEmpty() || host != host.lowercase() ||
            uri.rawUserInfo != null || uri.rawQuery != null || uri.rawFragment != null ||
            value.contains('?') || value.contains('#')
        ) reject()
    }

    private fun validateOrigin(value: String) {
        val uri = URI(value)
        val host = uri.host ?: reject()
        if (uri.scheme != "https" || host != host.lowercase() || uri.rawUserInfo != null ||
            uri.path !in listOf("", "/") || uri.rawQuery != null || uri.rawFragment != null ||
            value.contains('?') || value.contains('#') || value.endsWith('/') || host.endsWith('.') ||
            host.length > 253 || uri.port == 443 || uri.port == 0 || uri.port > 65535
        ) reject()
        if (host.any { it.code > 0x7f } || host.split('.').any { !dnsLabelPattern.matches(it) }) reject()
        val expectedAuthority = if (uri.port == -1) host else "$host:${uri.port}"
        if (uri.rawAuthority != expectedAuthority) reject()
    }

    private fun validatePurpose(value: String) {
        val points = value.codePoints().toArray()
        if (points.isEmpty() || points.size > 160 || points.none { !Character.isWhitespace(it) && !Character.isSpaceChar(it) }) reject()
        if (points.any { it <= 0x1f || it in 0x7f..0x9f || it in bidiControls }) reject()
    }

    private fun text(value: Any?, maximumCodePoints: Int): String {
        val result = value as? String ?: reject()
        val bytes = try {
            StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .encode(java.nio.CharBuffer.wrap(result))
        } catch (_: Exception) {
            reject()
        }
        val codePoints = result.codePointCount(0, result.length)
        val validLength = codePoints in 1..maximumCodePoints
        if (bytes.hasArray()) bytes.array().fill(0)
        if (!validLength) reject()
        return result
    }

    private fun decodeBase64Url(value: String, expectedBytes: Int?): ByteArray {
        if (!base64UrlPattern.matches(value)) reject()
        val decoded = try {
            Base64.getUrlDecoder().decode(value)
        } catch (_: IllegalArgumentException) {
            reject()
        }
        if (Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != value ||
            (expectedBytes != null && decoded.size != expectedBytes)
        ) {
            decoded.fill(0)
            reject()
        }
        return decoded
    }

    private fun reject(): Nothing = throw WalletDisclosureRequestException()
}

internal fun strictUtf8ByteLength(value: String): Int {
    val bytes = try {
        StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(java.nio.CharBuffer.wrap(value))
    } catch (_: Exception) {
        throw WalletDisclosureRequestException()
    }
    return try {
        bytes.remaining()
    } finally {
        if (bytes.hasArray()) bytes.array().fill(0)
    }
}

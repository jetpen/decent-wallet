package org.decentwallet.wallet.client

import android.content.Context
import okhttp3.CookieJar
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.MediaType.Companion.toMediaType
import okio.Buffer
import java.net.URI
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.TimeUnit
import kotlin.math.min
import kotlin.random.Random

/** HTTP boundary for the adopted native continuation; never logs URLs or response data. */
internal class NativeDisclosureHttpClient(
    private val client: OkHttpClient = secureClient(),
) {
    constructor(context: Context) : this(secureClient(context))
    fun fetchDisclosureContext(transaction: WalletLoginTransactionUrl): NativeDisclosureContextResponse {
        val url = transaction.url + "/disclosure-context"
        val response = execute(Request.Builder().url(url).get().header("Accept", "application/json").build())
        if (!response.isNoStore || !response.isNoReferrer) {
            response.body.fill(0)
            throw NativeDisclosureTransportException()
        }
        if (response.code == 204) {
            if (response.body.isNotEmpty()) {
                response.body.fill(0)
                throw NativeDisclosureTransportException()
            }
            return NativeDisclosureContextResponse.LoginOnly
        }
        if (response.code != 200 || !response.hasMediaType("application/json")) {
            response.body.fill(0)
            throw NativeDisclosureTransportException()
        }
        return NativeDisclosureContextResponse.NativeSignup(response.body)
    }

    /** Must be called once only after proof creation; a lost response is deliberately unrecoverable. */
    fun submitNativeProof(transaction: WalletLoginTransactionUrl, proof: ByteArray): NativeContinuationGrant {
        // Capture the acceptance window immediately before the only proof POST attempt.
        val proofAcceptanceStartedAt = System.currentTimeMillis() / 1000
        val response = execute(Request.Builder().url(transaction.url)
            .post(proof.toRequestBody(JSON)).header("Accept", "application/json").build())
        if (response.code != 200 || !response.hasMediaType("application/json") || !response.isNoStore || !response.isNoReferrer) {
            response.body.fill(0)
            throw NativeDisclosureTransportException()
        }
        return try { NativeContinuationGrant.parse(response.body, proofAcceptanceStartedAt) }
        finally { response.body.fill(0) }
    }

    fun pollContinuation(
        rpOrigin: String,
        transactionId: String,
        capability: ByteArray,
    ): ContinuationPollResult {
        val url = continuationUrl(rpOrigin, transactionId)
        val token = try { Base64.getUrlEncoder().withoutPadding().encodeToString(capability) }
        catch (_: Exception) { throw NativeDisclosureTransportException() }
        if (capability.size != 32 || !token.matches(Regex("[A-Za-z0-9_-]{43}"))) {
            throw NativeDisclosureTransportException()
        }
        val response = execute(Request.Builder().url(url).get()
            .header("Authorization", "Bearer $token")
            .header("Accept", "application/json").build())
        return when (response.code) {
            202 -> {
                val retryValues = response.retryAfterValues
                val emptyBody = response.body.isEmpty()
                response.body.fill(0)
                if (!response.isNoStore || !response.isNoReferrer || !emptyBody || retryValues.size != 1) throw NativeDisclosureTransportException()
                ContinuationPollResult.Pending(parseRetryAfter(retryValues.single()))
            }
            200 -> try {
                if (!response.isNoStore || !response.isNoReferrer || !response.hasMediaType("application/json")) throw NativeDisclosureTransportException()
                ContinuationPollResult.Ready(parseContinuationReady(response.body, rpOrigin))
            } finally { response.body.fill(0) }
            410 -> {
                val emptyBody = response.body.isEmpty()
                response.body.fill(0)
                if (!response.isNoStore || !response.isNoReferrer || !emptyBody) throw NativeDisclosureTransportException()
                ContinuationPollResult.Terminal
            }
            else -> { response.body.fill(0); throw NativeDisclosureTransportException() }
        }
    }

    fun fetchRequestObject(rpOrigin: String, requestUri: String): ByteArray {
        val origin = canonicalHttpsOrigin(rpOrigin)
        val request = parseSameOriginHttpsUrl(requestUri, origin, allowPath = true)
        val response = execute(Request.Builder().url(request).get()
            .header("Accept", "application/oauth-authz-req+jwt").build())
        if (response.code != 200 || response.body.isEmpty() || !response.isNoStore || !response.isNoReferrer ||
            !response.hasExactContentType("application/oauth-authz-req+jwt")
        ) {
            response.body.fill(0)
            throw NativeDisclosureTransportException()
        }
        return response.body
    }

    /** Sends the core-persisted form body byte-for-byte exactly once. */
    fun submitPresentationOnce(
        responseUri: String,
        expectedRpOrigin: String,
        persistedBody: ByteArray,
    ): PresentationHttpResult {
        val origin = canonicalHttpsOrigin(expectedRpOrigin)
        val uri = parseSameOriginHttpsUrl(responseUri, origin, allowPath = true)
        val response = execute(Request.Builder().url(uri)
            .post(persistedBody.toRequestBody(FORM))
            .header("Accept", "application/json").build())
        if (!response.isNoStore || !response.isNoReferrer ||
            (response.code == 200 && !response.hasMediaType("application/json"))
        ) {
            response.body.fill(0)
            throw NativeDisclosureTransportException()
        }
        return PresentationHttpResult(response.code, response.contentType, response.body)
    }

    private fun execute(request: Request): NativeDisclosureResponse {
        try {
            client.newCall(request).execute().use { response ->
                val body = response.body
                val contentType = body?.contentType()?.toString()
                val contentTypeValues = response.headers.values("Content-Type")
                val retryAfterValues = response.headers.values("Retry-After")
                val cacheControlValues = response.headers.values("Cache-Control")
                val referrerPolicyValues = response.headers.values("Referrer-Policy")
                val bytes = body?.let(::readBounded) ?: ByteArray(0)
                return NativeDisclosureResponse(response.code, contentType, contentTypeValues, retryAfterValues, cacheControlValues, referrerPolicyValues, bytes)
            }
        } catch (_: Exception) {
            throw NativeDisclosureTransportException()
        }
    }

    private fun readBounded(body: okhttp3.ResponseBody): ByteArray {
        if (body.contentLength() > MAX_RESPONSE_BYTES) throw NativeDisclosureTransportException()
        val source = body.source()
        val buffer = Buffer()
        try {
            while (buffer.size <= MAX_RESPONSE_BYTES) {
                val remaining = MAX_RESPONSE_BYTES + 1L - buffer.size
                if (remaining <= 0 || source.read(buffer, remaining) == -1L) break
            }
            if (buffer.size > MAX_RESPONSE_BYTES) throw NativeDisclosureTransportException()
            return buffer.readByteArray()
        } finally { buffer.clear() }
    }

    private fun parseRetryAfter(value: String?): Long {
        if (value == null || value.isEmpty() || value.any { it !in '0'..'9' }) throw NativeDisclosureTransportException()
        return value.toLongOrNull()?.takeIf { it >= 0 } ?: throw NativeDisclosureTransportException()
    }

    private fun parseContinuationReady(bytes: ByteArray, expectedOrigin: String): ContinuationReady {
        try {
            val map = StrictNativeJson.objectValue(bytes)
            if (map.keys != setOf("client_id", "request_uri")) throw NativeDisclosureTransportException()
            val clientId = map["client_id"] as? String ?: throw NativeDisclosureTransportException()
            val requestUri = map["request_uri"] as? String ?: throw NativeDisclosureTransportException()
            if (!clientId.matches(Regex("x509_san_dns:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?"))) throw NativeDisclosureTransportException()
            val validatedUri = parseSameOriginHttpsUrl(requestUri, canonicalHttpsOrigin(expectedOrigin), allowPath = true)
            if (URI(validatedUri).host.lowercase(java.util.Locale.ROOT) != clientId.removePrefix("x509_san_dns:")) {
                throw NativeDisclosureTransportException()
            }
            return ContinuationReady(clientId, validatedUri)
        } catch (_: NativeDisclosureTransportException) { throw NativeDisclosureTransportException() }
        catch (_: Exception) { throw NativeDisclosureTransportException() }
    }

    companion object {
        private const val MAX_RESPONSE_BYTES = 64 * 1024
        private val JSON = "application/json".toMediaType()
        private val FORM = "application/x-www-form-urlencoded".toMediaType()

        fun continuationUrl(rpOrigin: String, transactionId: String): String {
            if (!transactionId.matches(Regex("[A-Za-z0-9_-]{43}"))) throw NativeDisclosureTransportException()
            val decoded = try { Base64.getUrlDecoder().decode(transactionId) }
            catch (_: Exception) { throw NativeDisclosureTransportException() }
            try {
                if (decoded.size != 32 || Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != transactionId) {
                    throw NativeDisclosureTransportException()
                }
            } finally { decoded.fill(0) }
            return canonicalHttpsOrigin(rpOrigin) + "/oid4vp/continuations/" + transactionId
        }

        private fun parseSameOriginHttpsUrl(value: String, origin: String, allowPath: Boolean): String {
            try {
                val uri = URI(value)
                if (!uri.isAbsolute || uri.isOpaque || !uri.scheme.equals("https", true) || uri.rawUserInfo != null ||
                    uri.rawQuery != null || uri.rawFragment != null || uri.rawPath.isNullOrEmpty() || '%' in uri.rawPath ||
                    canonicalHttpsOrigin("https://${uri.rawAuthority}") != origin || (!allowPath && uri.rawPath != "/")
                ) throw NativeDisclosureTransportException()
                return uri.toASCIIString()
            } catch (_: NativeDisclosureTransportException) { throw NativeDisclosureTransportException() }
            catch (_: Exception) { throw NativeDisclosureTransportException() }
        }

        private fun canonicalHttpsOrigin(value: String): String {
            try {
                val uri = URI(value)
                if (!uri.isAbsolute || !uri.scheme.equals("https", true) || uri.isOpaque || uri.rawUserInfo != null ||
                    uri.rawQuery != null || uri.rawFragment != null || !uri.rawPath.isNullOrEmpty() || uri.host.isNullOrBlank() ||
                    (uri.port != -1 && uri.port !in 1..65535)
                ) throw NativeDisclosureTransportException()
                val host = uri.host.lowercase(java.util.Locale.ROOT)
                val port = if (uri.port == -1 || uri.port == 443) "" else ":${uri.port}"
                return "https://$host$port"
            } catch (_: NativeDisclosureTransportException) { throw NativeDisclosureTransportException() }
            catch (_: Exception) { throw NativeDisclosureTransportException() }
        }

        private fun secureClient(context: Context? = null): OkHttpClient = OkHttpClient.Builder()
            .cookieJar(CookieJar.NO_COOKIES)
            .authenticator(okhttp3.Authenticator.NONE)
            .proxyAuthenticator(okhttp3.Authenticator.NONE)
            .followRedirects(false)
            .followSslRedirects(false)
            .retryOnConnectionFailure(false)
            .cache(null)
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .apply {
                if (BuildConfig.DEBUG && context != null) {
                    val tls = Class.forName("org.decentwallet.wallet.client.DebugWalletLoginTls")
                    tls.getMethod("configure", Context::class.java, OkHttpClient.Builder::class.java)
                        .invoke(null, context.applicationContext, this)
                }
            }
            .build()
    }
}

internal sealed interface NativeDisclosureContextResponse {
    data object LoginOnly : NativeDisclosureContextResponse
    data class NativeSignup(val rawContext: ByteArray) : NativeDisclosureContextResponse
}

internal data class PresentationHttpResult(
    val statusCode: Int,
    val contentType: String?,
    val body: ByteArray,
) : AutoCloseable {
    override fun close() = body.fill(0)
}
internal data class NativeDisclosureResponse(
    val code: Int,
    val contentType: String?,
    val contentTypeValues: List<String>,
    val retryAfterValues: List<String>,
    val cacheControlValues: List<String>,
    val referrerPolicyValues: List<String>,
    val body: ByteArray,
) {
    fun hasMediaType(expected: String): Boolean = contentTypeValues.size == 1 &&
        contentTypeValues.single().substringBefore(';').trim().equals(expected, ignoreCase = true)

    fun hasExactContentType(expected: String): Boolean = contentTypeValues.size == 1 &&
        contentTypeValues.single().trim().equals(expected, ignoreCase = true)

    val isNoStore: Boolean get() = cacheControlValues.any { value ->
        value.split(',').any { it.trim().equals("no-store", ignoreCase = true) }
    }
    val isNoReferrer: Boolean get() = referrerPolicyValues.size == 1 &&
        referrerPolicyValues.single().trim().equals("no-referrer", ignoreCase = true)
}
internal sealed interface ContinuationPollResult {
    data class Pending(val retryAfterSeconds: Long) : ContinuationPollResult
    data class Ready(val result: ContinuationReady) : ContinuationPollResult
    data object Terminal : ContinuationPollResult
}
internal data class ContinuationReady(val clientId: String, val requestUri: String)
internal class NativeDisclosureTransportException : Exception("native disclosure request failed")

/** Redacted owner of the exact 32-byte capability returned by the accepted proof POST. */
internal class NativeContinuationGrant private constructor(
    val expiresAtEpochSeconds: Long,
    encodedCapability: String,
) : AutoCloseable {
    private var bytes: ByteArray? = Base64.getUrlDecoder().decode(encodedCapability)
    @Synchronized fun copyCapability(): ByteArray {
        val value = bytes ?: throw NativeDisclosureTransportException()
        if (System.currentTimeMillis() / 1000 >= expiresAtEpochSeconds) {
            close()
            throw NativeDisclosureTransportException()
        }
        return value.copyOf()
    }
    @Synchronized fun capabilityForEncryptedWalletPersistence(): String {
        val value = copyCapability()
        return try { Base64.getUrlEncoder().withoutPadding().encodeToString(value) }
        finally { value.fill(0) }
    }
    @Synchronized override fun close() { bytes?.fill(0); bytes = null }
    override fun toString(): String = "NativeContinuationGrant()"

    companion object {
        fun parse(
            bytes: ByteArray,
            proofAcceptedAtEpochSeconds: Long = System.currentTimeMillis() / 1000,
        ): NativeContinuationGrant {
            try {
                if (proofAcceptedAtEpochSeconds < 1 || proofAcceptedAtEpochSeconds > Long.MAX_VALUE - 300) {
                    throw NativeDisclosureTransportException()
                }
                val map = StrictNativeJson.objectValue(bytes)
                if (map.keys != setOf("profile", "decent_account_continuation_capability", "expires_at") ||
                    map["profile"] != "decent-account-disclosure-v1") throw NativeDisclosureTransportException()
                val capability = map["decent_account_continuation_capability"] as? String ?: throw NativeDisclosureTransportException()
                val expiryRaw = map["expires_at"] as? Long ?: throw NativeDisclosureTransportException()
                val decoded = try { Base64.getUrlDecoder().decode(capability) }
                catch (_: Exception) { throw NativeDisclosureTransportException() }
                try {
                    if (decoded.size != 32 || Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != capability ||
                        expiryRaw <= System.currentTimeMillis() / 1000 ||
                        expiryRaw > proofAcceptedAtEpochSeconds + 300
                    ) throw NativeDisclosureTransportException()
                } finally { decoded.fill(0) }
                return NativeContinuationGrant(expiryRaw, capability)
            } catch (_: NativeDisclosureTransportException) { throw NativeDisclosureTransportException() }
            catch (_: Exception) { throw NativeDisclosureTransportException() }
        }
    }
}

internal object NativeContinuationRetry {
    /** Exponential minimum plus bounded jitter; Retry-After is always a lower bound. */
    fun delaySeconds(attempt: Int, retryAfterSeconds: Long, jitterUnit: Double): Long {
        if (attempt < 0 || retryAfterSeconds < 0 || jitterUnit !in 0.0..1.0) throw NativeDisclosureTransportException()
        val exponent = min(attempt, 8)
        val base = 1L shl exponent
        val jitter = if (jitterUnit == 0.0) 0L else kotlin.math.ceil(base * 0.25 * jitterUnit).toLong()
        return maxOf(retryAfterSeconds, base + jitter)
    }
}

internal fun persistGrantThenAwaitNativeContinuation(
    transport: NativeDisclosureHttpClient,
    rpOrigin: String,
    transactionId: String,
    grant: NativeContinuationGrant,
    persistCapability: (encodedCapability: String, expiresAtEpochSeconds: Long) -> Unit,
    cancelled: () -> Boolean,
    nowEpochSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
    sleepMillis: (Long) -> Unit = { Thread.sleep(it) },
    jitter: () -> Double = { Random.nextDouble() },
): ContinuationReady {
    if (cancelled() || nowEpochSeconds() >= grant.expiresAtEpochSeconds) throw NativeDisclosureTransportException()
    persistCapability(grant.capabilityForEncryptedWalletPersistence(), grant.expiresAtEpochSeconds)
    if (cancelled()) throw NativeDisclosureTransportException()
    return awaitNativeContinuation(transport, rpOrigin, transactionId, grant, cancelled, nowEpochSeconds, sleepMillis, jitter)
}

/** One polling loop used by production and deterministic host tests. */
internal fun awaitNativeContinuation(
    transport: NativeDisclosureHttpClient,
    rpOrigin: String,
    transactionId: String,
    grant: NativeContinuationGrant,
    cancelled: () -> Boolean,
    nowEpochSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
    sleepMillis: (Long) -> Unit = { Thread.sleep(it) },
    jitter: () -> Double = { Random.nextDouble() },
): ContinuationReady {
    var attempt = 0
    while (true) {
        if (cancelled() || nowEpochSeconds() >= grant.expiresAtEpochSeconds) throw NativeDisclosureTransportException()
        val capability = grant.copyCapability()
        val result = try { transport.pollContinuation(rpOrigin, transactionId, capability) }
        finally { capability.fill(0) }
        when (result) {
            is ContinuationPollResult.Ready -> return result.result
            ContinuationPollResult.Terminal -> throw NativeDisclosureTransportException()
            is ContinuationPollResult.Pending -> {
                val delay = NativeContinuationRetry.delaySeconds(attempt++, result.retryAfterSeconds, jitter())
                val remaining = grant.expiresAtEpochSeconds - nowEpochSeconds()
                if (remaining <= 0 || delay >= remaining || cancelled()) throw NativeDisclosureTransportException()
                sleepMillis(delay * 1000)
                if (cancelled() || nowEpochSeconds() >= grant.expiresAtEpochSeconds) throw NativeDisclosureTransportException()
            }
        }
    }
}

/** Strict duplicate-rejecting JSON object parser for native transport DTOs. */
internal object StrictNativeJson {
    private val factory = com.fasterxml.jackson.core.JsonFactory.builder()
        .enable(com.fasterxml.jackson.core.StreamReadFeature.STRICT_DUPLICATE_DETECTION).build()

    fun objectValue(bytes: ByteArray): Map<String, Any> {
        if (bytes.isEmpty() || bytes.size > 64 * 1024) throw NativeDisclosureTransportException()
        val out = LinkedHashMap<String, Any>()
        factory.createParser(bytes).use { parser ->
            if (parser.nextToken() != com.fasterxml.jackson.core.JsonToken.START_OBJECT) throw NativeDisclosureTransportException()
            while (parser.nextToken() != com.fasterxml.jackson.core.JsonToken.END_OBJECT) {
                if (parser.currentToken != com.fasterxml.jackson.core.JsonToken.FIELD_NAME) throw NativeDisclosureTransportException()
                val key = parser.currentName
                when (parser.nextToken()) {
                    com.fasterxml.jackson.core.JsonToken.VALUE_STRING -> out[key] = parser.text
                    com.fasterxml.jackson.core.JsonToken.VALUE_NUMBER_INT -> out[key] = parser.longValue
                    else -> throw NativeDisclosureTransportException()
                }
            }
            if (parser.nextToken() != null) throw NativeDisclosureTransportException()
        }
        return out
    }
}

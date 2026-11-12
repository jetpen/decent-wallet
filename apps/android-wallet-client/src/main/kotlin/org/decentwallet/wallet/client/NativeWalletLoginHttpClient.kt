package org.decentwallet.wallet.client

import android.content.Context
import okhttp3.Authenticator
import okhttp3.CookieJar
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okio.Buffer
import org.decentwallet.wallet.android.WalletLoginProofRequest
import java.util.concurrent.TimeUnit

/** Isolated native transport: no browser cookies, CSRF, authorization, or redirect-following. */
internal class NativeWalletLoginHttpClient internal constructor(
    private val client: OkHttpClient = createClient(),
) {
    constructor(context: Context) : this(createClient(context))

    fun getChallenge(transaction: WalletLoginTransactionUrl): WalletLoginChallenge {
        try {
            val request = Request.Builder().url(transaction.url)
                .get().header("Accept", "application/json").build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful || !hasJsonContentType(response.header("Content-Type"))) {
                    throw WalletLoginTransportException()
                }
                val body = response.body ?: throw WalletLoginTransportException()
                if (body.contentLength() > MAX_RESPONSE_BYTES) throw WalletLoginTransportException()
                val source = body.source()
                val buffer = Buffer()
                try {
                    while (buffer.size <= MAX_RESPONSE_BYTES) {
                        val remaining = MAX_RESPONSE_BYTES + 1L - buffer.size
                        if (remaining <= 0L || source.read(buffer, remaining) == -1L) break
                    }
                    if (buffer.size > MAX_RESPONSE_BYTES) throw WalletLoginTransportException()
                    val bytes = buffer.readByteArray()
                    try {
                        return WalletLoginChallenge.parse(bytes)
                    } finally {
                        bytes.fill(0)
                    }
                } finally {
                    buffer.clear()
                }
            }
        } catch (_: WalletLoginTransportException) {
            throw WalletLoginTransportException()
        } catch (_: Exception) {
            throw WalletLoginTransportException()
        }
    }

    /** A thrown/failed POST is terminal here; callers must never retry an ambiguous outcome. */
    fun submitProof(transaction: WalletLoginTransactionUrl, proof: WalletLoginProofRequest): Boolean {
        val bytes = try { proof.toJsonBytes() } catch (_: Exception) { throw WalletLoginTransportException() }
        try {
            val request = Request.Builder().url(transaction.url)
                .post(bytes.toRequestBody(JSON))
                .header("Accept", "application/json")
                .build()
            client.newCall(request).execute().use { return it.isSuccessful }
        } catch (_: Exception) {
            return false
        } finally {
            bytes.fill(0)
        }
    }

    companion object {
        private const val MAX_RESPONSE_BYTES = 16 * 1024
        private val JSON = "application/json".toMediaType()

        private fun hasJsonContentType(value: String?): Boolean {
            if (value == null || value.any { it.code !in 0x20..0x7e }) return false
            val mediaType = value.toMediaTypeOrNull() ?: return false
            return mediaType.type.equals("application", ignoreCase = true) &&
                mediaType.subtype.equals("json", ignoreCase = true)
        }

        private fun createClient(context: Context? = null): OkHttpClient {
            // Context is accepted for host-app construction, but no WebView or global cookie state is used.
            @Suppress("UNUSED_VARIABLE") val appContext = context?.applicationContext
            return OkHttpClient.Builder()
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
                        try {
                            val tls = Class.forName("org.decentwallet.wallet.client.DebugWalletLoginTls")
                            tls.getMethod("configure", Context::class.java, OkHttpClient.Builder::class.java)
                                .invoke(null, context, this)
                        } catch (failure: ReflectiveOperationException) {
                            throw IllegalStateException("debug wallet-login TLS configuration unavailable", failure)
                        }
                    }
                }
                .build()
        }
    }
}

internal class WalletLoginTransportException : Exception("wallet login request failed")

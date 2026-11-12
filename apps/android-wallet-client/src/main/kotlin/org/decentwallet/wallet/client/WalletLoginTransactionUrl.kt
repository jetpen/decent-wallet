package org.decentwallet.wallet.client

import java.net.URI
import java.util.Base64
import java.util.Locale

internal class WalletLoginTransactionUrl(
    val origin: String,
    val realm: String,
    val handle: String,
    val path: String,
    val url: String,
) {
    companion object {
        private val transactionPath = Regex("/realms/([A-Za-z0-9][A-Za-z0-9._-]{0,62})/decent-wallet-login/v1/transactions/([A-Za-z0-9_-]{43})")

        fun parse(rawUrl: String, configuredOrigin: String): WalletLoginTransactionUrl {
            require(rawUrl.isNotBlank() && rawUrl.length <= 2048 && rawUrl.none { it <= ' ' || it == '\\' })
            val expectedOrigin = parseOrigin(configuredOrigin)
            val uri = try { URI(rawUrl) } catch (_: Exception) { throw IllegalArgumentException("invalid transaction URL") }
            require(uri.isAbsolute && !uri.isOpaque && uri.scheme.equals("https", ignoreCase = true))
            require(uri.rawUserInfo == null && uri.rawFragment == null && uri.rawQuery == null)
            require(uri.rawAuthority != null && uri.host != null && uri.rawPath != null && '%' !in uri.rawPath)
            val actualOrigin = canonicalOrigin(uri)
            require(actualOrigin == expectedOrigin)
            val path = uri.rawPath
            val match = transactionPath.matchEntire(path) ?: throw IllegalArgumentException("invalid transaction route")
            val handle = match.groupValues[2]
            val bytes = try { Base64.getUrlDecoder().decode(handle) } catch (_: Exception) {
                throw IllegalArgumentException("invalid transaction handle")
            }
            try {
                require(bytes.size == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(bytes) == handle)
            } finally {
                bytes.fill(0)
            }
            return WalletLoginTransactionUrl(actualOrigin, match.groupValues[1], handle, path, actualOrigin + path)
        }

        private fun parseOrigin(value: String): String {
            require(value.isNotBlank() && value.none { it <= ' ' || it == '\\' })
            val uri = try { URI(value) } catch (_: Exception) { throw IllegalArgumentException("invalid configured provider origin") }
            require(uri.isAbsolute && !uri.isOpaque && uri.scheme.equals("https", ignoreCase = true))
            require(uri.rawUserInfo == null && uri.rawQuery == null && uri.rawFragment == null)
            require(uri.rawPath.isNullOrEmpty() && uri.rawAuthority != null && uri.host != null)
            return canonicalOrigin(uri)
        }

        private fun canonicalOrigin(uri: URI): String {
            val host = uri.host?.lowercase(Locale.ROOT) ?: throw IllegalArgumentException("invalid host")
            require(host.isNotBlank() && (uri.port == -1 || uri.port in 1..65535) && uri.rawAuthority?.contains('@') != true)
            val port = if (uri.port == -1 || uri.port == 443) "" else ":${uri.port}"
            return "https://$host$port"
        }
    }
}

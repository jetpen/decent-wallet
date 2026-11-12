package org.decentwallet.wallet.client

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadFeature
import java.util.Base64

internal data class WalletLoginChallenge(
    val profile: String,
    val challenge: String,
    val expiresAtEpochSeconds: Long,
) {
    fun isExpiredAt(nowEpochSeconds: Long): Boolean = nowEpochSeconds >= expiresAtEpochSeconds

    companion object {
        private const val MAX_RESPONSE_BYTES = 16 * 1024
        private val json = JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build()

        fun parse(bytes: ByteArray, receivedAtEpochSeconds: Long = System.currentTimeMillis() / 1000): WalletLoginChallenge {
            require(bytes.isNotEmpty() && bytes.size <= MAX_RESPONSE_BYTES)
            try {
                var profile: String? = null
                var challenge: String? = null
                var csrfToken: String? = null
                var seen = 0
                json.createParser(bytes).use { parser ->
                    require(parser.nextToken() == JsonToken.START_OBJECT)
                    while (parser.nextToken() != JsonToken.END_OBJECT) {
                        require(parser.currentToken == JsonToken.FIELD_NAME)
                        val name = parser.currentName
                        require(parser.nextToken() == JsonToken.VALUE_STRING)
                        val value = parser.text
                        when (name) {
                            "profile" -> { require(seen and 1 == 0); seen = seen or 1; profile = value }
                            "challenge" -> { require(seen and 2 == 0); seen = seen or 2; challenge = value }
                            "csrf_token" -> { require(seen and 4 == 0); seen = seen or 4; csrfToken = value }
                            else -> throw IllegalArgumentException("invalid challenge")
                        }
                    }
                    require(seen == 7 && parser.nextToken() == null)
                }
                val profileValue = checkNotNull(profile)
                val challengeValue = checkNotNull(challenge)
                val csrfValue = checkNotNull(csrfToken)
                require(profileValue == "decent-wallet-login-v1")
                require(csrfValue.isNotBlank() && csrfValue.length <= 4096)
                val decoded = Base64.getUrlDecoder().decode(challengeValue)
                try {
                    require(decoded.size == 32 && Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) == challengeValue)
                } finally {
                    decoded.fill(0)
                }
                val expiry = Math.addExact(receivedAtEpochSeconds, 300L)
                return WalletLoginChallenge(profileValue, challengeValue, expiry)
            } catch (_: Exception) {
                throw IllegalArgumentException("invalid challenge response")
            }
        }
    }
}

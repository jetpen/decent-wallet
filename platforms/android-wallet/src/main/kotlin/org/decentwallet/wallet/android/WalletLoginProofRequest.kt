package org.decentwallet.wallet.android

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadFeature
import java.io.ByteArrayOutputStream
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64

/** Strict wallet-login-v1 request. The proof contains no seed or bearer credential. */
data class WalletLoginProofRequest(
    val profile: String,
    val challenge: String,
    val identityId: String,
    val signature: String,
) {
    init {
        StrictWalletLoginJson.validateFields(profile, challenge, identityId, signature)
    }

    fun toJsonBytes(): ByteArray = StrictWalletLoginJson.encode(this)

    fun verifyAgainst(publicKey: ByteArray): Boolean {
        val signingBytes = StrictWalletLoginJson.signingBytes(profile, challenge, identityId)
        val signatureBytes = StrictWalletLoginJson.parseBase64Url(signature, AndroidIdentityCrypto.SIGNATURE_BYTES)
        return try {
            AndroidIdentityCrypto.verify(publicKey, signingBytes, signatureBytes)
        } finally {
            signingBytes.fill(0)
            signatureBytes.fill(0)
        }
    }
}

internal object StrictWalletLoginJson {
    private const val MAX_PROOF_BYTES = 8 * 1024
    private val factory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .build()

    fun parse(bytes: ByteArray): WalletLoginProofRequest {
        if (bytes.isEmpty() || bytes.size > MAX_PROOF_BYTES) throw WalletLoginProofRejectedException()
        return try {
            var profile: String? = null
            var challenge: String? = null
            var identityId: String? = null
            var signature: String? = null
            var seen = 0
            factory.createParser(bytes).use { parser ->
                if (parser.nextToken() != JsonToken.START_OBJECT) throw WalletLoginProofRejectedException()
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    if (parser.currentToken != JsonToken.FIELD_NAME) throw WalletLoginProofRejectedException()
                    val name = parser.currentName
                    if (parser.nextToken() != JsonToken.VALUE_STRING) throw WalletLoginProofRejectedException()
                    val value = parser.text
                    when (name) {
                        "profile" -> { if (seen and 1 != 0) throw WalletLoginProofRejectedException(); seen = seen or 1; profile = value }
                        "challenge" -> { if (seen and 2 != 0) throw WalletLoginProofRejectedException(); seen = seen or 2; challenge = value }
                        "identity_id" -> { if (seen and 4 != 0) throw WalletLoginProofRejectedException(); seen = seen or 4; identityId = value }
                        "signature" -> { if (seen and 8 != 0) throw WalletLoginProofRejectedException(); seen = seen or 8; signature = value }
                        else -> throw WalletLoginProofRejectedException()
                    }
                }
                if (seen != 15 || parser.nextToken() != null) throw WalletLoginProofRejectedException()
            }
            val id = checkNotNull(identityId)
            val profileValue = checkNotNull(profile)
            val challengeValue = checkNotNull(challenge)
            val signatureValue = checkNotNull(signature)
            validateFields(profileValue, challengeValue, id, signatureValue)
            WalletLoginProofRequest(profileValue, challengeValue, id, signatureValue)
        } catch (_: WalletLoginProofRejectedException) {
            throw WalletLoginProofRejectedException()
        } catch (_: Exception) {
            throw WalletLoginProofRejectedException()
        }
    }

    fun encode(proof: WalletLoginProofRequest): ByteArray {
        validateFields(proof.profile, proof.challenge, proof.identityId, proof.signature)
        val signed = signingBytes(proof.profile, proof.challenge, proof.identityId)
        val out = ByteArrayOutputStream()
        try {
            out.write('{'.code)
            writeString(out, "profile")
            out.write(':'.code)
            writeString(out, proof.profile)
            out.write(','.code)
            writeString(out, "challenge")
            out.write(':'.code)
            writeString(out, proof.challenge)
            out.write(','.code)
            writeString(out, "identity_id")
            out.write(':'.code)
            writeString(out, proof.identityId)
            out.write(','.code)
            writeString(out, "signature")
            out.write(':'.code)
            writeString(out, proof.signature)
            out.write('}'.code)
            val encoded = out.toByteArray()
            if (encoded.size > MAX_PROOF_BYTES) {
                encoded.fill(0)
                throw WalletLoginProofRejectedException()
            }
            return encoded
        } finally {
            signed.fill(0)
        }
    }

    fun validateFields(profile: String, challenge: String, identityId: String, signature: String) {
        if (profile != "decent-wallet-login-v1") throw WalletLoginProofRejectedException()
        val challengeBytes = parseBase64Url(challenge, 32)
        val signatureBytes = try {
            parseBase64Url(signature, AndroidIdentityCrypto.SIGNATURE_BYTES)
        } catch (failure: Exception) {
            challengeBytes.fill(0)
            throw failure
        }
        try {
            strictUtf8(identityId)
        } finally {
            challengeBytes.fill(0)
            signatureBytes.fill(0)
        }
    }

    fun signingBytes(profile: String, challenge: String, identityId: String): ByteArray {
        if (profile != "decent-wallet-login-v1") throw WalletLoginProofRejectedException()
        val fields = listOf("challenge" to challenge, "identity_id" to identityId, "profile" to profile)
        val out = ByteArrayOutputStream()
        out.write('{'.code)
        fields.forEachIndexed { index, (key, value) ->
            if (index > 0) out.write(','.code)
            writeString(out, key)
            out.write(':'.code)
            writeString(out, value)
        }
        out.write('}'.code)
        return out.toByteArray().also { bytes ->
            if (bytes.size > MAX_PROOF_BYTES) {
                bytes.fill(0)
                throw WalletLoginProofRejectedException()
            }
        }
    }

    fun parseBase64Url(value: String, expectedBytes: Int): ByteArray {
        if (value.isEmpty() || value.contains('=') || !value.matches(Regex("[A-Za-z0-9_-]+"))) {
            throw WalletLoginProofRejectedException()
        }
        val decoded = try { Base64.getUrlDecoder().decode(value) } catch (_: Exception) {
            throw WalletLoginProofRejectedException()
        }
        if (decoded.size != expectedBytes || Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != value) {
            decoded.fill(0)
            throw WalletLoginProofRejectedException()
        }
        return decoded
    }

    private fun writeString(out: ByteArrayOutputStream, value: String) {
        out.write('"'.code)
        var index = 0
        while (index < value.length) {
            val c = value[index]
            when {
                c == '"' -> out.write("\\\"".toByteArray(StandardCharsets.US_ASCII))
                c == '\\' -> out.write("\\\\".toByteArray(StandardCharsets.US_ASCII))
                c == '\b' -> out.write("\\b".toByteArray(StandardCharsets.US_ASCII))
                c == '\u000c' -> out.write("\\f".toByteArray(StandardCharsets.US_ASCII))
                c == '\n' -> out.write("\\n".toByteArray(StandardCharsets.US_ASCII))
                c == '\r' -> out.write("\\r".toByteArray(StandardCharsets.US_ASCII))
                c == '\t' -> out.write("\\t".toByteArray(StandardCharsets.US_ASCII))
                c < ' ' -> out.write(String.format("\\u%04x", c.code).toByteArray(StandardCharsets.US_ASCII))
                Character.isHighSurrogate(c) -> {
                    if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) throw WalletLoginProofRejectedException()
                    out.write(strictUtf8(value.substring(index, index + 2)))
                    index++
                }
                Character.isLowSurrogate(c) -> throw WalletLoginProofRejectedException()
                else -> out.write(strictUtf8(c.toString()))
            }
            index++
        }
        out.write('"'.code)
    }

    private fun strictUtf8(value: String): ByteArray = StandardCharsets.UTF_8.newEncoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .encode(java.nio.CharBuffer.wrap(value))
        .let { encoded -> ByteArray(encoded.remaining()).also(encoded::get) }
}

internal class WalletLoginProofRejectedException : WalletContainerException("wallet-login proof request rejected")

package org.decentwallet.interop

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadFeature
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.LinkedHashMap

internal enum class FailureStage {
    GENERAL,
    ENVELOPE,
    KDF,
    WRAP_AUTHENTICATION,
    PAYLOAD_AAD,
    PAYLOAD_AUTHENTICATION,
    TYPED_PAYLOAD,
}

internal class VerificationFailure(
    val stage: FailureStage = FailureStage.GENERAL,
) : IllegalArgumentException("wallet-container v2 verification failed")

internal fun verificationFailure(stage: FailureStage = FailureStage.GENERAL): Nothing =
    throw VerificationFailure(stage)

internal object StrictJson {
    private val factory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .build()

    fun parseUtf8(bytes: ByteArray, maxBytes: Int): Any? {
        if (bytes.size > maxBytes) verificationFailure()
        try {
            val decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            val text = decoder.decode(ByteBuffer.wrap(bytes)).toString()
            if (text.startsWith('\uFEFF')) verificationFailure()
            return factory.createParser(text).use { parser ->
                val first = parser.nextToken() ?: verificationFailure()
                val result = readValue(parser, first, 0)
                if (parser.nextToken() != null) verificationFailure()
                result
            }
        } catch (failure: VerificationFailure) {
            throw failure
        } catch (_: Exception) {
            verificationFailure()
        }
    }

    private fun readValue(parser: com.fasterxml.jackson.core.JsonParser, token: JsonToken, depth: Int): Any? {
        if (depth > 64) verificationFailure()
        return when (token) {
            JsonToken.START_OBJECT -> {
                val result = LinkedHashMap<String, Any?>()
                while (true) {
                    val next = parser.nextToken() ?: verificationFailure()
                    if (next == JsonToken.END_OBJECT) break
                    if (next != JsonToken.FIELD_NAME) verificationFailure()
                    val name = parser.text
                    requireUnicodeScalars(name)
                    val valueToken = parser.nextToken() ?: verificationFailure()
                    result[name] = readValue(parser, valueToken, depth + 1)
                }
                result
            }
            JsonToken.START_ARRAY -> {
                val result = ArrayList<Any?>()
                while (true) {
                    val next = parser.nextToken() ?: verificationFailure()
                    if (next == JsonToken.END_ARRAY) break
                    result.add(readValue(parser, next, depth + 1))
                }
                result
            }
            JsonToken.VALUE_STRING -> parser.text.also(::requireUnicodeScalars)
            JsonToken.VALUE_NUMBER_INT -> parser.bigIntegerValue
            JsonToken.VALUE_TRUE -> true
            JsonToken.VALUE_FALSE -> false
            JsonToken.VALUE_NULL -> null
            else -> verificationFailure()
        }
    }
}

internal object CanonicalJson {
    fun bytes(value: Any?): ByteArray = text(value).toByteArray(StandardCharsets.UTF_8)

    fun text(value: Any?): String = encode(value)

    fun compareCodePointOrder(left: String, right: String): Int {
        requireUnicodeScalars(left)
        requireUnicodeScalars(right)
        var leftIndex = 0
        var rightIndex = 0
        while (leftIndex < left.length && rightIndex < right.length) {
            val leftPoint = left.codePointAt(leftIndex)
            val rightPoint = right.codePointAt(rightIndex)
            if (leftPoint != rightPoint) return leftPoint.compareTo(rightPoint)
            leftIndex += Character.charCount(leftPoint)
            rightIndex += Character.charCount(rightPoint)
        }
        return when {
            leftIndex == left.length && rightIndex == right.length -> 0
            leftIndex == left.length -> -1
            else -> 1
        }
    }

    private fun encode(value: Any?): String = when (value) {
        null -> "null"
        is Boolean -> if (value) "true" else "false"
        is String -> quote(value)
        is BigInteger -> value.toString()
        is Byte, is Short, is Int, is Long -> value.toString()
        is List<*> -> value.joinToString(prefix = "[", postfix = "]", separator = ",") { encode(it) }
        is Map<*, *> -> {
            val entries = value.entries.map { entry ->
                val key = entry.key as? String ?: verificationFailure()
                requireUnicodeScalars(key)
                key to entry.value
            }.sortedWith { left, right -> compareCodePointOrder(left.first, right.first) }
            entries.joinToString(prefix = "{", postfix = "}", separator = ",") { (key, item) ->
                "${quote(key)}:${encode(item)}"
            }
        }
        else -> verificationFailure()
    }

    private fun quote(value: String): String {
        requireUnicodeScalars(value)
        val output = StringBuilder(value.length + 2)
        output.append('"')
        var index = 0
        while (index < value.length) {
            val point = value.codePointAt(index)
            when (point) {
                0x22 -> output.append("\\\"")
                0x5c -> output.append("\\\\")
                0x08 -> output.append("\\b")
                0x09 -> output.append("\\t")
                0x0a -> output.append("\\n")
                0x0c -> output.append("\\f")
                0x0d -> output.append("\\r")
                in 0x00..0x1f -> {
                    output.append("\\u00")
                    output.append(HEX[(point shr 4) and 0xf])
                    output.append(HEX[point and 0xf])
                }
                else -> output.append(value, index, index + Character.charCount(point))
            }
            index += Character.charCount(point)
        }
        output.append('"')
        return output.toString()
    }

    private const val HEX = "0123456789abcdef"
}

internal fun requireUnicodeScalars(value: String) {
    var index = 0
    while (index < value.length) {
        val current = value[index]
        when {
            Character.isHighSurrogate(current) -> {
                if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                    verificationFailure()
                }
                index += 2
            }
            Character.isLowSurrogate(current) -> verificationFailure()
            else -> index += 1
        }
    }
}

internal fun decodeCanonicalBase64(value: Any?, expectedLength: Int? = null): ByteArray {
    val text = value as? String ?: verificationFailure()
    val decoded = try {
        Base64.getDecoder().decode(text)
    } catch (_: IllegalArgumentException) {
        verificationFailure()
    }
    if (Base64.getEncoder().encodeToString(decoded) != text) verificationFailure()
    if (expectedLength != null && decoded.size != expectedLength) verificationFailure()
    return decoded
}

internal fun decodeHex(value: Any?): ByteArray {
    val text = value as? String ?: verificationFailure()
    if (text.length % 2 != 0) verificationFailure()
    val output = ByteArray(text.length / 2)
    for (index in output.indices) {
        val high = Character.digit(text[index * 2], 16)
        val low = Character.digit(text[index * 2 + 1], 16)
        if (high < 0 || low < 0) verificationFailure()
        output[index] = ((high shl 4) or low).toByte()
    }
    return output
}

internal fun encodeHex(value: ByteArray): String {
    val alphabet = "0123456789abcdef"
    val output = CharArray(value.size * 2)
    for (index in value.indices) {
        val octet = value[index].toInt() and 0xff
        output[index * 2] = alphabet[octet ushr 4]
        output[index * 2 + 1] = alphabet[octet and 0x0f]
    }
    return String(output)
}

internal fun semanticValuesEqual(left: Any?, right: Any?): Boolean = when {
    left is ByteArray && right is ByteArray -> left.contentEquals(right)
    left is Map<*, *> && right is Map<*, *> ->
        left.keys == right.keys && left.keys.all { key -> semanticValuesEqual(left[key], right[key]) }
    left is List<*> && right is List<*> ->
        left.size == right.size && left.indices.all { index -> semanticValuesEqual(left[index], right[index]) }
    else -> left == right
}

internal fun clearByteArrays(value: Any?) {
    when (value) {
        is ByteArray -> value.fill(0)
        is Map<*, *> -> value.values.forEach(::clearByteArrays)
        is List<*> -> value.forEach(::clearByteArrays)
    }
}

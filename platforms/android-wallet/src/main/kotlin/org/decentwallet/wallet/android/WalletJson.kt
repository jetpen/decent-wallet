package org.decentwallet.wallet.android

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadFeature
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.util.Base64

internal object WalletJson {
    private const val MAX_DEPTH = 64
    private val factory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .build()

    fun parse(bytes: ByteArray, maxBytes: Int): Any? {
        if (bytes.size > maxBytes) invalidContainer()
        try {
            val decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
            val text = decoder.decode(ByteBuffer.wrap(bytes)).toString()
            if (text.startsWith('\uFEFF')) invalidContainer()
            return factory.createParser(text).use { parser ->
                val first = parser.nextToken() ?: invalidContainer()
                val result = readValue(parser, first, 0)
                if (parser.nextToken() != null) invalidContainer()
                result
            }
        } catch (failure: WalletContainerException) {
            throw failure
        } catch (_: Exception) {
            invalidContainer()
        }
    }

    fun canonicalBytes(value: Any?): ByteArray =
        canonicalText(value).toByteArray(StandardCharsets.UTF_8)

    fun encodePayload(payload: Map<String, Any?>): ByteArray =
        canonicalBytes(encodeTyped(payload, 0))

    fun decodePayload(bytes: ByteArray): MutableMap<String, Any?> {
        val typed = parse(bytes, MAX_CONTAINER_BYTES)
        if (!canonicalBytes(typed).contentEquals(bytes)) unlockFailed()
        val decoded = decodeTyped(typed, 0)
        @Suppress("UNCHECKED_CAST")
        return (decoded as? Map<String, Any?>)?.let(::mutableCopyMap) ?: unlockFailed()
    }

    fun decodeBase64(value: Any?, expectedLength: Int? = null): ByteArray {
        val text = value as? String ?: invalidContainer()
        val decoded = try {
            Base64.getDecoder().decode(text)
        } catch (_: IllegalArgumentException) {
            invalidContainer()
        }
        if (Base64.getEncoder().encodeToString(decoded) != text) invalidContainer()
        if (expectedLength != null && decoded.size != expectedLength) invalidContainer()
        return decoded
    }

    fun encodeBase64(value: ByteArray): String = Base64.getEncoder().encodeToString(value)

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

    fun copyPayload(value: Any?): Any? = when (value) {
        is ByteArray -> value.copyOf()
        is Map<*, *> -> {
            val result = LinkedHashMap<String, Any?>()
            for ((key, item) in value) {
                val name = key as? String ?: invalidContainer()
                result[name] = copyPayload(item)
            }
            result
        }
        is List<*> -> value.map(::copyPayload)
        else -> value
    }

    fun clearByteArrays(value: Any?) {
        when (value) {
            is ByteArray -> value.fill(0)
            is Map<*, *> -> value.values.forEach(::clearByteArrays)
            is List<*> -> value.forEach(::clearByteArrays)
        }
    }

    private fun readValue(parser: com.fasterxml.jackson.core.JsonParser, token: JsonToken, depth: Int): Any? {
        if (depth > MAX_DEPTH) invalidContainer()
        return when (token) {
            JsonToken.START_OBJECT -> {
                val result = LinkedHashMap<String, Any?>()
                while (true) {
                    val next = parser.nextToken() ?: invalidContainer()
                    if (next == JsonToken.END_OBJECT) break
                    if (next != JsonToken.FIELD_NAME) invalidContainer()
                    val name = parser.text
                    requireUnicodeScalars(name)
                    val child = parser.nextToken() ?: invalidContainer()
                    result[name] = readValue(parser, child, depth + 1)
                }
                result
            }
            JsonToken.START_ARRAY -> {
                val result = ArrayList<Any?>()
                while (true) {
                    val next = parser.nextToken() ?: invalidContainer()
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
            else -> invalidContainer()
        }
    }

    private fun canonicalText(value: Any?): String = when (value) {
        null -> "null"
        is Boolean -> if (value) "true" else "false"
        is String -> quote(value)
        is BigInteger -> value.toString()
        is Byte, is Short, is Int, is Long -> value.toString()
        is List<*> -> value.joinToString(prefix = "[", postfix = "]", separator = ",") {
            canonicalText(it)
        }
        is Map<*, *> -> {
            val entries = value.entries.map { entry ->
                val key = entry.key as? String ?: invalidContainer()
                requireUnicodeScalars(key)
                key to entry.value
            }.sortedWith { left, right -> compareCodePointOrder(left.first, right.first) }
            entries.joinToString(prefix = "{", postfix = "}", separator = ",") { (key, item) ->
                "${quote(key)}:${canonicalText(item)}"
            }
        }
        else -> invalidContainer()
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

    private fun encodeTyped(value: Any?, depth: Int): Any? {
        if (depth > MAX_DEPTH) invalidContainer()
        return when (value) {
            null -> mapOf("t" to "null")
            is Boolean -> mapOf("t" to "bool", "v" to value)
            is String -> {
                requireUnicodeScalars(value)
                mapOf("t" to "str", "v" to value)
            }
            is ByteArray -> mapOf("t" to "bytes", "v" to encodeBase64(value))
            is BigInteger, is Byte, is Short, is Int, is Long ->
                mapOf("t" to "int", "v" to value)
            is List<*> -> mapOf("t" to "list", "v" to value.map { encodeTyped(it, depth + 1) })
            is Map<*, *> -> {
                val entries = value.entries.map { entry ->
                    val key = entry.key as? String ?: invalidContainer()
                    requireUnicodeScalars(key)
                    key to entry.value
                }.sortedWith { left, right -> compareCodePointOrder(left.first, right.first) }
                val pairs = entries.map { (key, item) -> listOf(key, encodeTyped(item, depth + 1)) }
                mapOf("t" to "map", "v" to pairs)
            }
            else -> invalidContainer()
        }
    }

    private fun decodeTyped(value: Any?, depth: Int): Any? {
        if (depth > MAX_DEPTH) unlockFailed()
        val typed = value as? Map<*, *> ?: unlockFailed()
        val type = typed["t"] as? String ?: unlockFailed()
        return when (type) {
            "null" -> {
                requireTypedKeys(typed, setOf("t"))
                null
            }
            "bool" -> {
                requireTypedKeys(typed, setOf("t", "v"))
                typed["v"] as? Boolean ?: unlockFailed()
            }
            "str" -> {
                requireTypedKeys(typed, setOf("t", "v"))
                (typed["v"] as? String)?.also(::requireUnicodeScalars) ?: unlockFailed()
            }
            "int" -> {
                requireTypedKeys(typed, setOf("t", "v"))
                typed["v"] as? BigInteger ?: unlockFailed()
            }
            "bytes" -> {
                requireTypedKeys(typed, setOf("t", "v"))
                decodeBase64(typed["v"])
            }
            "list" -> {
                requireTypedKeys(typed, setOf("t", "v"))
                val items = typed["v"] as? List<*> ?: unlockFailed()
                items.map { decodeTyped(it, depth + 1) }
            }
            "map" -> {
                requireTypedKeys(typed, setOf("t", "v"))
                val entries = typed["v"] as? List<*> ?: unlockFailed()
                val result = LinkedHashMap<String, Any?>()
                var previous: String? = null
                for (entry in entries) {
                    val pair = entry as? List<*> ?: unlockFailed()
                    if (pair.size != 2) unlockFailed()
                    val key = pair[0] as? String ?: unlockFailed()
                    requireUnicodeScalars(key)
                    if (previous != null && compareCodePointOrder(previous, key) >= 0) unlockFailed()
                    result[key] = decodeTyped(pair[1], depth + 1)
                    previous = key
                }
                result
            }
            else -> unlockFailed()
        }
    }

    private fun requireTypedKeys(value: Map<*, *>, expected: Set<String>) {
        if (value.keys != expected) unlockFailed()
    }

    private fun mutableCopyMap(value: Map<String, Any?>): MutableMap<String, Any?> {
        val result = LinkedHashMap<String, Any?>()
        for ((key, item) in value) result[key] = copyPayload(item)
        return result
    }

    internal fun requireUnicodeScalars(value: String) {
        var index = 0
        while (index < value.length) {
            val current = value[index]
            when {
                Character.isHighSurrogate(current) -> {
                    if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                        invalidContainer()
                    }
                    index += 2
                }
                Character.isLowSurrogate(current) -> invalidContainer()
                else -> index += 1
            }
        }
    }

    private const val HEX = "0123456789abcdef"
    private const val MAX_CONTAINER_BYTES = 16 * 1024 * 1024
}

internal fun invalidContainer(): Nothing = throw WalletInvalidContainerException()

internal fun unlockFailed(): Nothing = throw WalletUnlockException()

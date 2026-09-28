package org.decentwallet.wallet.android

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

internal object IdentityCbor {
    const val MAX_ENCODED_BYTES = 1024 * 1024
    private const val MAX_DEPTH = 32
    private const val MAX_ITEMS = 10_000
    private val UINT64_MAX = BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)
    private val ZERO = BigInteger.ZERO
    private val ONE = BigInteger.ONE

    fun decodeCanonical(bytes: ByteArray): Any? {
        if (bytes.isEmpty() || bytes.size > MAX_ENCODED_BYTES) invalidIdentityState()
        return try {
            Decoder(bytes).decode()
        } catch (failure: WalletInvalidIdentityStateException) {
            throw failure
        } catch (_: Exception) {
            invalidIdentityState()
        }
    }

    fun encodeCanonical(value: Any?): ByteArray {
        return try {
            ByteArrayOutputStream().also { output -> writeValue(output, value, 0) }.toByteArray()
        } catch (failure: WalletInvalidIdentityStateException) {
            throw failure
        } catch (_: Exception) {
            invalidIdentityState()
        }
    }

    fun encodeUtf8(value: String): ByteArray = try {
        val encoded = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(java.nio.CharBuffer.wrap(value))
        ByteArray(encoded.remaining()).also(encoded::get)
    } catch (_: Exception) {
        invalidIdentityState()
    }

    fun requireValidUtf8(value: ByteArray) {
        try {
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value))
        } catch (_: Exception) {
            invalidIdentityState()
        }
    }

    private fun writeValue(output: ByteArrayOutputStream, value: Any?, depth: Int) {
        if (depth > MAX_DEPTH) invalidIdentityState()
        when (value) {
            null -> writeByte(output, 0xf6)
            is Boolean -> writeByte(output, if (value) 0xf5 else 0xf4)
            is ByteArray -> {
                writeHeader(output, 2, BigInteger.valueOf(value.size.toLong()))
                writeRaw(output, value)
            }
            is String -> {
                val encoded = encodeUtf8(value)
                writeHeader(output, 3, BigInteger.valueOf(encoded.size.toLong()))
                writeRaw(output, encoded)
                encoded.fill(0)
            }
            is BigInteger -> writeInteger(output, value)
            is Byte, is Short, is Int, is Long -> writeInteger(output, BigInteger.valueOf((value as Number).toLong()))
            is List<*> -> {
                if (value.size > MAX_ITEMS) invalidIdentityState()
                writeHeader(output, 4, BigInteger.valueOf(value.size.toLong()))
                for (item in value) writeValue(output, item, depth + 1)
            }
            is Map<*, *> -> {
                if (value.size > MAX_ITEMS) invalidIdentityState()
                val entries = value.entries.map { entry ->
                    val key = entry.key as? BigInteger ?: invalidIdentityState()
                    EncodedEntry(encodeCanonical(key), entry.value)
                }.sortedWith { left, right -> compareCanonical(left.encodedKey, right.encodedKey) }
                for (index in 1 until entries.size) {
                    if (entries[index - 1].encodedKey.contentEquals(entries[index].encodedKey)) {
                        invalidIdentityState()
                    }
                }
                writeHeader(output, 5, BigInteger.valueOf(entries.size.toLong()))
                for (entry in entries) {
                    writeRaw(output, entry.encodedKey)
                    writeValue(output, entry.value, depth + 1)
                    entry.encodedKey.fill(0)
                }
            }
            else -> invalidIdentityState()
        }
        if (output.size() > MAX_ENCODED_BYTES) invalidIdentityState()
    }

    private fun writeInteger(output: ByteArrayOutputStream, value: BigInteger) {
        if (value.signum() >= 0) {
            if (value <= UINT64_MAX) {
                writeHeader(output, 0, value)
            } else {
                writeByte(output, 0xc2)
                val magnitude = unsignedBytes(value)
                writeHeader(output, 2, BigInteger.valueOf(magnitude.size.toLong()))
                writeRaw(output, magnitude)
                magnitude.fill(0)
            }
        } else {
            val encoded = value.negate().subtract(ONE)
            if (encoded <= UINT64_MAX) {
                writeHeader(output, 1, encoded)
            } else {
                writeByte(output, 0xc3)
                val magnitude = unsignedBytes(encoded)
                writeHeader(output, 2, BigInteger.valueOf(magnitude.size.toLong()))
                writeRaw(output, magnitude)
                magnitude.fill(0)
            }
        }
    }

    private fun unsignedBytes(value: BigInteger): ByteArray {
        val encoded = value.toByteArray()
        return if (encoded.size > 1 && encoded[0] == 0.toByte()) {
            encoded.copyOfRange(1, encoded.size).also { encoded.fill(0) }
        } else {
            encoded
        }
    }

    private fun writeHeader(output: ByteArrayOutputStream, major: Int, argument: BigInteger) {
        if (argument.signum() < 0 || argument > UINT64_MAX) invalidIdentityState()
        when {
            argument < BigInteger.valueOf(24) -> writeByte(output, (major shl 5) or argument.toInt())
            argument <= BigInteger.valueOf(0xff) -> {
                writeByte(output, (major shl 5) or 24)
                writeByte(output, argument.toInt())
            }
            argument <= BigInteger.valueOf(0xffff) -> {
                writeByte(output, (major shl 5) or 25)
                writeUnsigned(output, argument, 2)
            }
            argument <= BigInteger("ffffffff", 16) -> {
                writeByte(output, (major shl 5) or 26)
                writeUnsigned(output, argument, 4)
            }
            else -> {
                writeByte(output, (major shl 5) or 27)
                writeUnsigned(output, argument, 8)
            }
        }
    }

    private fun writeUnsigned(output: ByteArrayOutputStream, value: BigInteger, bytes: Int) {
        for (shift in (bytes - 1) * 8 downTo 0 step 8) {
            writeByte(output, value.shiftRight(shift).and(BigInteger.valueOf(0xff)).toInt())
        }
    }

    private fun writeByte(output: ByteArrayOutputStream, value: Int) {
        if (output.size() >= MAX_ENCODED_BYTES) invalidIdentityState()
        output.write(value)
    }

    private fun writeRaw(output: ByteArrayOutputStream, bytes: ByteArray) {
        if (output.size().toLong() + bytes.size > MAX_ENCODED_BYTES) invalidIdentityState()
        output.write(bytes)
    }

    private fun compareCanonical(left: ByteArray, right: ByteArray): Int {
        if (left.size != right.size) return left.size.compareTo(right.size)
        for (index in left.indices) {
            val comparison = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
            if (comparison != 0) return comparison
        }
        return 0
    }

    private data class EncodedEntry(val encodedKey: ByteArray, val value: Any?)

    private class Decoder(private val bytes: ByteArray) {
        private var offset = 0
        private var itemCount = 0

        fun decode(): Any? {
            val value = readValue(0)
            if (offset != bytes.size) invalidIdentityState()
            val canonical = encodeCanonical(value)
            try {
                if (!canonical.contentEquals(bytes)) invalidIdentityState()
            } finally {
                canonical.fill(0)
            }
            return value
        }

        private fun readValue(depth: Int): Any? {
            if (depth > MAX_DEPTH || ++itemCount > MAX_ITEMS) invalidIdentityState()
            val initial = readByte()
            val major = initial ushr 5
            val additional = initial and 31
            return when (major) {
                0 -> readArgument(additional)
                1 -> ONE.negate().subtract(readArgument(additional))
                2 -> readBytes(readLength(additional))
                3 -> decodeText(readBytes(readLength(additional)))
                4 -> {
                    val size = readLength(additional)
                    List(size) { readValue(depth + 1) }
                }
                5 -> {
                    val size = readLength(additional)
                    val values = LinkedHashMap<BigInteger, Any?>(size)
                    repeat(size) {
                        val key = readValue(depth + 1) as? BigInteger ?: invalidIdentityState()
                        if (values.containsKey(key)) invalidIdentityState()
                        values[key] = readValue(depth + 1)
                    }
                    values
                }
                6 -> readBigNumber(additional, depth)
                7 -> when (additional) {
                    20 -> false
                    21 -> true
                    22 -> null
                    else -> invalidIdentityState()
                }
                else -> invalidIdentityState()
            }
        }

        private fun readBigNumber(additional: Int, depth: Int): BigInteger {
            val tag = readArgument(additional)
            if (tag != BigInteger.valueOf(2) && tag != BigInteger.valueOf(3)) invalidIdentityState()
            val magnitudeBytes = readValue(depth + 1) as? ByteArray ?: invalidIdentityState()
            try {
                if (magnitudeBytes.isEmpty() || magnitudeBytes[0] == 0.toByte()) invalidIdentityState()
                val magnitude = BigInteger(1, magnitudeBytes)
                if (magnitude <= UINT64_MAX) invalidIdentityState()
                return if (tag == BigInteger.valueOf(2)) magnitude else ONE.negate().subtract(magnitude)
            } finally {
                magnitudeBytes.fill(0)
            }
        }

        private fun readArgument(additional: Int): BigInteger = when {
            additional < 24 -> BigInteger.valueOf(additional.toLong())
            additional == 24 -> readBytes(1).let { BigInteger(1, it).also { _ -> it.fill(0) } }
            additional == 25 -> readBytes(2).let { BigInteger(1, it).also { _ -> it.fill(0) } }
            additional == 26 -> readBytes(4).let { BigInteger(1, it).also { _ -> it.fill(0) } }
            additional == 27 -> readBytes(8).let { BigInteger(1, it).also { _ -> it.fill(0) } }
            else -> invalidIdentityState()
        }

        private fun readLength(additional: Int): Int {
            val length = readArgument(additional)
            if (length > BigInteger.valueOf(MAX_ENCODED_BYTES.toLong())) invalidIdentityState()
            return length.toInt()
        }

        private fun readByte(): Int {
            if (offset >= bytes.size) invalidIdentityState()
            return bytes[offset++].toInt() and 0xff
        }

        private fun readBytes(length: Int): ByteArray {
            if (length < 0 || length > bytes.size - offset) invalidIdentityState()
            return bytes.copyOfRange(offset, offset + length).also { offset += length }
        }

        private fun decodeText(encoded: ByteArray): String {
            return try {
                StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(encoded)).toString()
            } catch (_: Exception) {
                invalidIdentityState()
            } finally {
                encoded.fill(0)
            }
        }
    }

    private fun invalidIdentityState(): Nothing = throw WalletInvalidIdentityStateException()
}

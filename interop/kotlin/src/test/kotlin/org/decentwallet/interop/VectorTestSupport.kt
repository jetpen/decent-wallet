package org.decentwallet.interop

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonToken
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.modes.XChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.KeyParameter
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.util.Base64
import java.util.LinkedHashMap

internal object VectorTestSupport {
    private val jsonFactory = JsonFactory()
    private val fixturePath = Paths.get("../../tests/vectors/wallet-container-v2.json").normalize()

    fun readVector(): ByteArray = Files.readAllBytes(fixturePath)

    fun readUniqueStringField(json: ByteArray, name: String): String {
        val parser = jsonFactory.createParser(json)
        parser.use {
            var result: String? = null
            while (parser.nextToken() != null) {
                if (parser.currentToken == JsonToken.FIELD_NAME && parser.text == name) {
                    check(result == null) { "fixture field is not unique" }
                    check(parser.nextToken() == JsonToken.VALUE_STRING) { "fixture field has the wrong type" }
                    result = parser.text
                }
            }
            return checkNotNull(result) { "fixture field is missing" }
        }
    }

    fun containerBytes(vector: ByteArray): ByteArray = decodeHex(readUniqueStringField(vector, "container_json_utf8_hex"))

    fun reorderAndSpaceEnvelope(canonical: ByteArray): ByteArray {
        val members = LinkedHashMap<String, ByteArray>()
        val parser = jsonFactory.createParser(canonical)
        parser.use {
            check(parser.nextToken() == JsonToken.START_OBJECT)
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                val name = parser.text
                check(parser.nextToken() != null)
                val captured = ByteArrayOutputStream()
                val generator = jsonFactory.createGenerator(captured)
                generator.use { it.copyCurrentStructure(parser) }
                members[name] = captured.toByteArray()
            }
        }

        val output = ByteArrayOutputStream()
        val generator = jsonFactory.createGenerator(output)
        generator.useDefaultPrettyPrinter()
        generator.use {
            it.writeStartObject()
            for (name in listOf("payload", "format", "wrap", "kdf", "version")) {
                it.writeFieldName(name)
                it.writeRawValue(String(checkNotNull(members[name]), StandardCharsets.UTF_8))
            }
            it.writeEndObject()
        }
        return output.toByteArray()
    }

    fun mutateStringFieldInObject(
        json: ByteArray,
        objectName: String,
        fieldName: String,
        transform: (String) -> String,
    ): ByteArray {
        val text = String(json, StandardCharsets.UTF_8)
        val objectStart = text.indexOf("\"$objectName\":{")
        check(objectStart >= 0) { "target object is missing" }
        val fieldMarker = "\"$fieldName\":\""
        val fieldStart = text.indexOf(fieldMarker, objectStart)
        check(fieldStart >= 0) { "target string field is missing" }
        val valueStart = fieldStart + fieldMarker.length
        val valueEnd = text.indexOf('"', valueStart)
        check(valueEnd >= 0) { "target string field is malformed" }
        val replacement = transform(text.substring(valueStart, valueEnd))
        return (text.substring(0, valueStart) + replacement + text.substring(valueEnd)).toByteArray(StandardCharsets.UTF_8)
    }

    fun readStringFieldInObject(json: ByteArray, objectName: String, fieldName: String): String {
        val text = String(json, StandardCharsets.UTF_8)
        val objectStart = text.indexOf("\"$objectName\":{")
        check(objectStart >= 0) { "target object is missing" }
        val fieldMarker = "\"$fieldName\":\""
        val fieldStart = text.indexOf(fieldMarker, objectStart)
        check(fieldStart >= 0) { "target string field is missing" }
        val valueStart = fieldStart + fieldMarker.length
        val valueEnd = text.indexOf('"', valueStart)
        check(valueEnd >= 0) { "target string field is malformed" }
        return text.substring(valueStart, valueEnd)
    }

    fun replaceTopLevelInteger(json: ByteArray, fieldName: String, replacement: BigInteger): ByteArray {
        val text = String(json, StandardCharsets.UTF_8)
        val fieldMarker = "\"$fieldName\":"
        val fieldStart = text.indexOf(fieldMarker)
        check(fieldStart >= 0) { "target integer field is missing" }
        val valueStart = fieldStart + fieldMarker.length
        var valueEnd = valueStart
        while (valueEnd < text.length && (text[valueEnd] == '-' || text[valueEnd].isDigit())) valueEnd += 1
        check(valueEnd > valueStart) { "target integer field is malformed" }
        return (text.substring(0, valueStart) + replacement.toString() + text.substring(valueEnd))
            .toByteArray(StandardCharsets.UTF_8)
    }

    fun duplicateTopLevelFormat(json: ByteArray): ByteArray {
        val text = String(json, StandardCharsets.UTF_8)
        val original = "\"format\":\"decent-wallet\","
        check(text.contains(original))
        return text.replaceFirst(
            original,
            "\"format\":\"decent-wallet\",\"format\":\"decent-wallet\",",
        ).toByteArray(StandardCharsets.UTF_8)
    }

    fun flipFirstByteBase64(value: String): String {
        val bytes = Base64.getDecoder().decode(value)
        check(bytes.isNotEmpty())
        bytes[0] = (bytes[0].toInt() xor 1).toByte()
        return Base64.getEncoder().encodeToString(bytes)
    }

    fun decodeBase64(value: String): ByteArray = Base64.getDecoder().decode(value)

    fun encodeBase64(value: ByteArray): String = Base64.getEncoder().encodeToString(value)

    fun decodeHex(value: String): ByteArray {
        check(value.length % 2 == 0)
        val result = ByteArray(value.length / 2)
        for (index in result.indices) {
            val high = Character.digit(value[index * 2], 16)
            val low = Character.digit(value[index * 2 + 1], 16)
            check(high >= 0 && low >= 0)
            result[index] = ((high shl 4) or low).toByte()
        }
        return result
    }

    fun deriveKek(password: ByteArray, salt: ByteArray): ByteArray {
        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(65_536)
            .withIterations(3)
            .withParallelism(4)
            .withSalt(salt)
            .build()
        return try {
            ByteArray(32).also { output ->
                Argon2BytesGenerator().apply { init(parameters) }.generateBytes(password, output)
            }
        } finally {
            parameters.clear()
        }
    }

    fun encryptAead(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        plaintext: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        val cipher = XChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
        val output = ByteArray(cipher.getOutputSize(plaintext.size))
        try {
            val written = cipher.processBytes(plaintext, 0, plaintext.size, output, 0)
            val finalWritten = cipher.doFinal(output, written)
            val combined = output.copyOf(written + finalWritten)
            check(combined.size >= 16)
            return Pair(combined.copyOfRange(0, combined.size - 16), combined.copyOfRange(combined.size - 16, combined.size))
                .also { combined.fill(0) }
        } finally {
            output.fill(0)
        }
    }

    fun decryptAndDiscard(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
        tag: ByteArray,
    ) {
        val combined = ciphertext + tag
        val cipher = XChaCha20Poly1305()
        var output: ByteArray? = null
        try {
            cipher.init(false, AEADParameters(KeyParameter(key), 128, nonce, aad))
            output = ByteArray(cipher.getOutputSize(combined.size))
            val written = cipher.processBytes(combined, 0, combined.size, output, 0)
            cipher.doFinal(output, written)
        } finally {
            combined.fill(0)
            output?.fill(0)
        }
    }
}

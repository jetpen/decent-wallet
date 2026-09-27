package org.decentwallet.interop

import android.os.Build
import android.util.Log
import androidx.test.platform.app.InstrumentationRegistry
import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonGenerator
import com.fasterxml.jackson.core.JsonToken
import org.bouncycastle.crypto.modes.XChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.LinkedHashMap

class WalletContainerV2InstrumentationTest {
    @Test
    fun runtimeMatchesExactIssue36TargetAndLogsFingerprint() {
        val api = Build.VERSION.SDK_INT
        val abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
        assertTrue("unexpected Android API/ABI: api=$api abi=$abi",
            (api == 26 && abi == "x86") || (api == 37 && abi == "x86_64"))
        assertTrue("empty runtime build fingerprint", Build.FINGERPRINT.isNotBlank())
        Log.i(
            "WalletV2Conformance",
            "api=$api abi=$abi abis=${Build.SUPPORTED_ABIS.toList()} " +
                "fingerprint=${Build.FINGERPRINT}",
        )
    }

    @Test
    fun verifiesCanonicalVectorAndReturnsItsExpectedPublicKey() {
        val vector = AndroidVectorSupport.readVector()
        try {
            val expectedPublicKey = AndroidVectorSupport.readUniqueStringField(vector, "public_key_hex")
            val result = WalletContainerV2Verifier.verify(vector)
            assertEquals(expectedPublicKey, result.publicKeyHex)
        } finally {
            vector.fill(0)
        }
    }

    @Test
    fun acceptsOuterWhitespaceAndMemberOrderVariations() {
        val vector = AndroidVectorSupport.readVector()
        val canonical = AndroidVectorSupport.containerBytes(vector)
        val reordered = AndroidVectorSupport.reorderAndSpaceEnvelope(canonical)
        try {
            val expectedPublicKey = AndroidVectorSupport.readUniqueStringField(vector, "public_key_hex")
            val result = WalletContainerV2Verifier.verify(vector, reordered)
            assertEquals(expectedPublicKey, result.publicKeyHex)
        } finally {
            reordered.fill(0)
            canonical.fill(0)
            vector.fill(0)
        }
    }

    @Test
    fun rejectsKdfSaltTamperingBeforeAeadAuthentication() {
        val vector = AndroidVectorSupport.readVector()
        val canonical = AndroidVectorSupport.containerBytes(vector)
        val tampered = AndroidVectorSupport.mutateStringFieldInObject(canonical, "kdf", "salt") {
            AndroidVectorSupport.flipFirstByteBase64(it)
        }
        try {
            val failure = assertThrows(VerificationFailure::class.java) {
                WalletContainerV2Verifier.verify(vector, tampered)
            }
            assertEquals(FailureStage.KDF, failure.stage)
            assertEquals("wallet-container v2 verification failed", failure.message)
        } finally {
            tampered.fill(0)
            canonical.fill(0)
            vector.fill(0)
        }
    }

    @Test
    fun rejectsPayloadNonceTamperingAtPayloadAuthentication() {
        val vector = AndroidVectorSupport.readVector()
        val canonical = AndroidVectorSupport.containerBytes(vector)
        val tampered = AndroidVectorSupport.mutateStringFieldInObject(canonical, "payload", "nonce") {
            AndroidVectorSupport.flipFirstByteBase64(it)
        }
        try {
            val failure = assertThrows(VerificationFailure::class.java) {
                WalletContainerV2Verifier.verify(vector, tampered)
            }
            assertEquals(FailureStage.PAYLOAD_AUTHENTICATION, failure.stage)
            assertEquals("wallet-container v2 verification failed", failure.message)
        } finally {
            tampered.fill(0)
            canonical.fill(0)
            vector.fill(0)
        }
    }

    @Test
    fun rejectsPayloadTagTamperingAtPayloadAuthentication() {
        val vector = AndroidVectorSupport.readVector()
        val canonical = AndroidVectorSupport.containerBytes(vector)
        val tampered = AndroidVectorSupport.mutateStringFieldInObject(canonical, "payload", "tag") {
            AndroidVectorSupport.flipFirstByteBase64(it)
        }
        try {
            val failure = assertThrows(VerificationFailure::class.java) {
                WalletContainerV2Verifier.verify(vector, tampered)
            }
            assertEquals(FailureStage.PAYLOAD_AUTHENTICATION, failure.stage)
            assertEquals("wallet-container v2 verification failed", failure.message)
        } finally {
            tampered.fill(0)
            canonical.fill(0)
            vector.fill(0)
        }
    }

    @Test
    fun rejectsWrapTagTamperingWithValueFreeDiagnostics() {
        val vector = AndroidVectorSupport.readVector()
        val canonical = AndroidVectorSupport.containerBytes(vector)
        val tampered = AndroidVectorSupport.mutateStringFieldInObject(canonical, "wrap", "tag") {
            AndroidVectorSupport.flipFirstByteBase64(it)
        }
        try {
            val failure = assertThrows(VerificationFailure::class.java) {
                WalletContainerV2Verifier.verify(vector, tampered)
            }
            assertEquals(FailureStage.WRAP_AUTHENTICATION, failure.stage)
            assertEquals("wallet-container v2 verification failed", failure.message)
            for (name in listOf("password", "dek_hex", "kek_hex")) {
                val fixtureValue = AndroidVectorSupport.readUniqueStringField(vector, name)
                if (fixtureValue.isNotEmpty()) assertFalse(failure.message!!.contains(fixtureValue))
            }
        } finally {
            tampered.fill(0)
            canonical.fill(0)
            vector.fill(0)
        }
    }

    @Test
    fun rejectsDuplicateNamesAndUnsupportedContainerVersions() {
        val vector = AndroidVectorSupport.readVector()
        val canonical = AndroidVectorSupport.containerBytes(vector)
        val duplicateName = AndroidVectorSupport.duplicateTopLevelFormat(canonical)
        val versionOne = AndroidVectorSupport.replaceTopLevelInteger(canonical, "version", 1)
        val unsupportedVersion = AndroidVectorSupport.replaceTopLevelInteger(canonical, "version", 3)
        try {
            assertFailure(vector, duplicateName, FailureStage.GENERAL)
            assertFailure(vector, versionOne, FailureStage.ENVELOPE)
            assertFailure(vector, unsupportedVersion, FailureStage.ENVELOPE)
        } finally {
            unsupportedVersion.fill(0)
            versionOne.fill(0)
            duplicateName.fill(0)
            canonical.fill(0)
            vector.fill(0)
        }
    }

    @Test
    fun rejectsAuthenticatedMalformedTypedPayloadAfterPayloadAuthentication() {
        val vector = AndroidVectorSupport.readVector()
        var canonical: ByteArray? = null
        var originalNonce: ByteArray? = null
        var newNonce: ByteArray? = null
        var aad: ByteArray? = null
        var malformedAad: ByteArray? = null
        var fixtureDek: ByteArray? = null
        var malformedPayload: ByteArray? = null
        var encrypted: Pair<ByteArray, ByteArray>? = null
        var tampered: ByteArray? = null
        try {
            val container = AndroidVectorSupport.containerBytes(vector).also { canonical = it }
            val containerNonce = AndroidVectorSupport.decodeBase64(
                AndroidVectorSupport.readStringFieldInObject(container, "payload", "nonce"),
            ).also { originalNonce = it }
            val changedNonce = containerNonce.copyOf().also { newNonce = it }
            changedNonce[0] = (changedNonce[0].toInt() xor 0x40).toByte()
            val oldNonceBase64 = AndroidVectorSupport.encodeBase64(containerNonce)
            val newNonceBase64 = AndroidVectorSupport.encodeBase64(changedNonce)
            val aadBytes = AndroidVectorSupport.decodeHex(
                AndroidVectorSupport.readUniqueStringField(vector, "payload_aad_utf8_hex"),
            ).also { aad = it }
            val aadText = String(aadBytes, Charsets.UTF_8)
            val changedAadText = aadText.replace(oldNonceBase64, newNonceBase64)
            check(changedAadText != aadText)
            val changedAad = changedAadText.toByteArray(Charsets.UTF_8).also { malformedAad = it }
            val dek = AndroidVectorSupport.decodeHex(
                AndroidVectorSupport.readUniqueStringField(vector, "dek_hex"),
            ).also { fixtureDek = it }
            val invalidTypedPayload = "{\"t\":\"map\",\"v\":[[\"bad\",{\"t\":\"unknown\"}]]}"
                .toByteArray(Charsets.UTF_8).also { malformedPayload = it }
            val ciphertextAndTag = AndroidVectorSupport.encryptAead(dek, changedNonce, changedAad, invalidTypedPayload)
                .also { encrypted = it }
            var candidate = AndroidVectorSupport.mutateStringFieldInObject(container, "payload", "nonce") {
                newNonceBase64
            }
            candidate = AndroidVectorSupport.mutateStringFieldInObject(candidate, "payload", "ciphertext") {
                AndroidVectorSupport.encodeBase64(ciphertextAndTag.first)
            }
            candidate = AndroidVectorSupport.mutateStringFieldInObject(candidate, "payload", "tag") {
                AndroidVectorSupport.encodeBase64(ciphertextAndTag.second)
            }
            tampered = candidate
            assertFailure(vector, candidate, FailureStage.TYPED_PAYLOAD)
        } finally {
            tampered?.fill(0)
            encrypted?.first?.fill(0)
            encrypted?.second?.fill(0)
            malformedPayload?.fill(0)
            fixtureDek?.fill(0)
            malformedAad?.fill(0)
            aad?.fill(0)
            newNonce?.fill(0)
            originalNonce?.fill(0)
            canonical?.fill(0)
            vector.fill(0)
        }
    }

    private fun assertFailure(vector: ByteArray, container: ByteArray, stage: FailureStage) {
        val failure = assertThrows(VerificationFailure::class.java) {
            WalletContainerV2Verifier.verify(vector, container)
        }
        assertEquals(stage, failure.stage)
        assertEquals("wallet-container v2 verification failed", failure.message)
    }

    private fun ByteArray.decodeUtf8(): String = String(this, StandardCharsets.UTF_8)

    private fun ByteArray.fill(value: Byte = 0) {
        java.util.Arrays.fill(this, value)
    }

    private object AndroidVectorSupport {
        private const val VECTOR_ASSET = "wallet-container-v2.json"

        fun readVector(): ByteArray {
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            return instrumentation.context.assets.open(VECTOR_ASSET).use { it.readBytes() }
        }

        fun readUniqueStringField(bytes: ByteArray, field: String): String {
            val parser = JsonFactory().createParser(bytes)
            parser.use {
                var value: String? = null
                while (parser.nextToken() != null) {
                    if (parser.currentToken == JsonToken.FIELD_NAME && parser.text == field) {
                        require(value == null && parser.nextToken() == JsonToken.VALUE_STRING)
                        value = parser.text
                    }
                }
                return checkNotNull(value) { "fixture field is missing" }
            }
        }

        fun containerBytes(vector: ByteArray): ByteArray =
            AndroidVectorSupport.decodeHex(readUniqueStringField(vector, "container_json_utf8_hex"))

        fun readStringFieldInObject(bytes: ByteArray, outer: String, field: String): String {
            val top = parseObject(bytes)
            val inner = parseObject((top[outer] as Map<*, *>).let { encodeObject(it) })
            return inner[field] as String
        }

        fun reorderAndSpaceEnvelope(canonical: ByteArray): ByteArray {
            val entries = parseObject(canonical).entries.toList().reversed()
            return encodeObject(LinkedHashMap<String, Any?>().apply { entries.forEach { put(it.key, it.value) } }, pretty = true)
        }

        fun mutateStringFieldInObject(bytes: ByteArray, outer: String, field: String, change: (String) -> String): ByteArray {
            val top = parseObject(bytes)
            val nested = LinkedHashMap(parseObject(encodeObject((top[outer] as Map<*, *>))))
            nested[field] = change(nested[field] as String)
            top[outer] = nested
            return encodeObject(top)
        }

        fun replaceTopLevelInteger(bytes: ByteArray, field: String, value: Int): ByteArray {
            val top = parseObject(bytes)
            top[field] = value
            return encodeObject(top)
        }

        fun duplicateTopLevelFormat(bytes: ByteArray): ByteArray {
            val text = String(bytes, StandardCharsets.UTF_8)
            val match = Regex("\\\"format\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"").find(text)
                ?: error("format field missing from vector fixture")
            val fragment = match.value
            val insertAt = match.range.last + 1
            return (text.substring(0, insertAt) + "," + fragment + text.substring(insertAt))
                .toByteArray(StandardCharsets.UTF_8)
        }

        fun flipFirstByteBase64(value: String): String {
            val bytes = decodeBase64(value)
            require(bytes.isNotEmpty())
            bytes[0] = (bytes[0].toInt() xor 1).toByte()
            return encodeBase64(bytes).also { bytes.fill(0) }
        }

        fun decodeBase64(value: String): ByteArray = Base64.getDecoder().decode(value)

        fun encodeBase64(value: ByteArray): String = Base64.getEncoder().encodeToString(value)

        fun decodeHex(value: String): ByteArray {
            require(value.length % 2 == 0)
            return ByteArray(value.length / 2) { index ->
                value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
            }
        }

        fun encryptAead(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): Pair<ByteArray, ByteArray> {
            val cipher = XChaCha20Poly1305()
            cipher.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
            val combined = ByteArray(cipher.getOutputSize(plaintext.size))
            val written = cipher.processBytes(plaintext, 0, plaintext.size, combined, 0)
            val count = written + cipher.doFinal(combined, written)
            require(count >= 16)
            return combined.copyOfRange(0, count - 16) to combined.copyOfRange(count - 16, count)
        }

        private fun parseObject(bytes: ByteArray): LinkedHashMap<String, Any?> {
            val result = LinkedHashMap<String, Any?>()
            val parser = JsonFactory().createParser(bytes)
            parser.use {
                require(parser.nextToken() == JsonToken.START_OBJECT)
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    val key = parser.currentName ?: error("missing JSON object key")
                    require(!result.containsKey(key))
                    val token = parser.nextToken()
                    result[key] = when (token) {
                        JsonToken.START_OBJECT -> parseNestedObject(parser)
                        JsonToken.START_ARRAY -> parseArray(parser)
                        JsonToken.VALUE_STRING -> parser.text
                        JsonToken.VALUE_NUMBER_INT -> parser.longValue
                        JsonToken.VALUE_TRUE -> true
                        JsonToken.VALUE_FALSE -> false
                        JsonToken.VALUE_NULL -> null
                        else -> error("unsupported JSON token")
                    }
                }
            }
            return result
        }

        private fun parseNestedObject(parser: com.fasterxml.jackson.core.JsonParser): LinkedHashMap<String, Any?> {
            val value = LinkedHashMap<String, Any?>()
            while (parser.nextToken() != JsonToken.END_OBJECT) {
                val key = parser.currentName ?: error("missing JSON object key")
                require(!value.containsKey(key))
                val token = parser.nextToken()
                value[key] = when (token) {
                    JsonToken.START_OBJECT -> parseNestedObject(parser)
                    JsonToken.START_ARRAY -> parseArray(parser)
                    JsonToken.VALUE_STRING -> parser.text
                    JsonToken.VALUE_NUMBER_INT -> parser.longValue
                    JsonToken.VALUE_TRUE -> true
                    JsonToken.VALUE_FALSE -> false
                    JsonToken.VALUE_NULL -> null
                    else -> error("unsupported JSON token")
                }
            }
            return value
        }

        private fun parseArray(parser: com.fasterxml.jackson.core.JsonParser): List<Any?> {
            val values = ArrayList<Any?>()
            while (parser.nextToken() != JsonToken.END_ARRAY) {
                values += when (parser.currentToken()) {
                    JsonToken.START_OBJECT -> parseNestedObject(parser)
                    JsonToken.START_ARRAY -> parseArray(parser)
                    JsonToken.VALUE_STRING -> parser.text
                    JsonToken.VALUE_NUMBER_INT -> parser.longValue
                    JsonToken.VALUE_TRUE -> true
                    JsonToken.VALUE_FALSE -> false
                    JsonToken.VALUE_NULL -> null
                    else -> error("unsupported JSON token")
                }
            }
            return values
        }

        private fun encodeObject(value: Map<*, *>, pretty: Boolean = false): ByteArray {
            val out = ByteArrayOutputStream()
            val generator = JsonFactory().createGenerator(out)
            generator.use {
                if (pretty) generator.useDefaultPrettyPrinter()
                writeObject(generator, value)
            }
            return out.toByteArray()
        }

        private fun writeObject(generator: JsonGenerator, value: Map<*, *>) {
            generator.writeStartObject()
            for ((rawKey, item) in value) {
                val key = rawKey as String
                generator.writeFieldName(key)
                writeValue(generator, item)
            }
            generator.writeEndObject()
        }

        private fun writeValue(generator: JsonGenerator, value: Any?) {
            when (value) {
                null -> generator.writeNull()
                is String -> generator.writeString(value)
                is Int -> generator.writeNumber(value)
                is Long -> generator.writeNumber(value)
                is Boolean -> generator.writeBoolean(value)
                is Map<*, *> -> writeObject(generator, value)
                is List<*> -> {
                    generator.writeStartArray()
                    for (item in value) writeValue(generator, item)
                    generator.writeEndArray()
                }
                else -> error("unsupported JSON value type")
            }
        }
    }
}

package org.decentwallet.interop

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.modes.XChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.math.BigInteger
import java.nio.charset.StandardCharsets

internal data class VerifiedPublicResult(val publicKeyHex: String)

internal object WalletContainerV2Verifier {
    private const val MAX_VECTOR_BYTES = 1024 * 1024
    private const val MAX_CONTAINER_BYTES = 16 * 1024 * 1024
    private const val ARGON2_MEMORY_KIB = 65_536
    private const val ARGON2_TIME_COST = 3
    private const val ARGON2_PARALLELISM = 4
    private const val AEAD_TAG_BITS = 128

    fun verify(vectorBytes: ByteArray, containerOverride: ByteArray? = null): VerifiedPublicResult {
        try {
            return verifyInternal(vectorBytes, containerOverride)
        } catch (failure: VerificationFailure) {
            throw failure
        } catch (_: Exception) {
            verificationFailure()
        }
    }

    private fun verifyInternal(vectorBytes: ByteArray, containerOverride: ByteArray?): VerifiedPublicResult {
        val vector = objectValue(StrictJson.parseUtf8(vectorBytes, MAX_VECTOR_BYTES))
        if (vector["schema"] != "decent-wallet-container-v2-kat" ||
            vector["schema_version"] != BigInteger.ONE ||
            vector["test_only"] != true
        ) {
            verificationFailure()
        }
        val notice = stringValue(vector["notice"])
        if (!notice.contains("public synthetic") || !notice.contains("Never use with a real wallet")) {
            verificationFailure()
        }

        val inputs = objectValue(vector["input"])
        val expected = objectValue(vector["expected"])
        val expectedContainer = objectValue(expected["container"])
        val expectedContainerBytes = decodeHex(expected["container_json_utf8_hex"])
        val containerBytes = containerOverride ?: expectedContainerBytes
        val envelope = objectValue(StrictJson.parseUtf8(containerBytes, MAX_CONTAINER_BYTES))
        if (containerOverride == null &&
            (!CanonicalJson.bytes(expectedContainer).contentEquals(expectedContainerBytes) ||
                !CanonicalJson.bytes(envelope).contentEquals(expectedContainerBytes) ||
                !semanticValuesEqual(envelope, expectedContainer))
        ) {
            verificationFailure()
        }
        requireExactKeys(envelope, setOf("format", "version", "kdf", "wrap", "payload"))
        if (envelope["format"] != "decent-wallet" || envelope["version"] != BigInteger.valueOf(2)) {
            verificationFailure(FailureStage.ENVELOPE)
        }

        val kdf = objectValue(envelope["kdf"])
        requireExactKeys(kdf, setOf("algorithm", "memory_kib", "time_cost", "parallelism", "salt"))
        if (kdf["algorithm"] != "argon2id" ||
            kdf["memory_kib"] != BigInteger.valueOf(ARGON2_MEMORY_KIB.toLong()) ||
            kdf["time_cost"] != BigInteger.valueOf(ARGON2_TIME_COST.toLong()) ||
            kdf["parallelism"] != BigInteger.valueOf(ARGON2_PARALLELISM.toLong())
        ) {
            verificationFailure(FailureStage.KDF)
        }
        val salt = decodeCanonicalBase64(kdf["salt"], 16)

        val wrap = objectValue(envelope["wrap"])
        requireExactKeys(wrap, setOf("algorithm", "nonce", "ciphertext", "tag"))
        if (wrap["algorithm"] != "xchacha20-poly1305") verificationFailure()
        val wrapNonce = decodeCanonicalBase64(wrap["nonce"], 24)
        val wrappedDek = decodeCanonicalBase64(wrap["ciphertext"], 32)
        val wrapTag = decodeCanonicalBase64(wrap["tag"], 16)

        val payloadEnvelope = objectValue(envelope["payload"])
        requireExactKeys(payloadEnvelope, setOf("algorithm", "nonce", "ciphertext", "tag"))
        if (payloadEnvelope["algorithm"] != "xchacha20-poly1305") verificationFailure()
        val payloadNonce = decodeCanonicalBase64(payloadEnvelope["nonce"], 24)
        val payloadCiphertext = decodeCanonicalBase64(payloadEnvelope["ciphertext"])
        val payloadTag = decodeCanonicalBase64(payloadEnvelope["tag"], 16)

        val password = stringValue(inputs["password"])
        requireUnicodeScalars(password)
        val passwordBytes = password.toByteArray(StandardCharsets.UTF_8)
        var kek: ByteArray? = null
        var recoveredDek: ByteArray? = null
        var payloadPlaintext: ByteArray? = null
        var expectedPayload: Any? = null
        var decodedPayload: Any? = null
        try {
            kek = deriveKek(passwordBytes, salt)
            if (encodeHex(kek) != stringValue(expected["kek_hex"])) verificationFailure(FailureStage.KDF)

            val wrapAad = CanonicalJson.bytes(
                mapOf("format" to "decent-wallet", "version" to BigInteger.valueOf(2), "kdf" to kdf),
            )
            if (encodeHex(wrapAad) != stringValue(expected["wrap_aad_utf8_hex"])) {
                verificationFailure(FailureStage.WRAP_AUTHENTICATION)
            }

            recoveredDek = decryptAead(
                kek,
                wrapNonce,
                wrapAad,
                wrappedDek,
                wrapTag,
                FailureStage.WRAP_AUTHENTICATION,
            )
            val fixtureDek = decodeHex(inputs["dek_hex"])
            try {
                if (recoveredDek.size != 32 || !recoveredDek.contentEquals(fixtureDek)) verificationFailure()
            } finally {
                fixtureDek.fill(0)
            }

            val payloadAad = CanonicalJson.bytes(
                mapOf(
                    "format" to "decent-wallet",
                    "version" to BigInteger.valueOf(2),
                    "payload" to mapOf(
                        "algorithm" to "xchacha20-poly1305",
                        "nonce" to stringValue(payloadEnvelope["nonce"]),
                    ),
                ),
            )
            if (containerOverride == null &&
                encodeHex(payloadAad) != stringValue(expected["payload_aad_utf8_hex"])
            ) {
                verificationFailure(FailureStage.PAYLOAD_AAD)
            }

            // Use only the recovered DEK for payload decryption; the fixture DEK is an assertion value.
            payloadPlaintext = decryptAead(
                recoveredDek,
                payloadNonce,
                payloadAad,
                payloadCiphertext,
                payloadTag,
                FailureStage.PAYLOAD_AUTHENTICATION,
            )
            if (containerOverride == null &&
                encodeHex(payloadPlaintext) != stringValue(expected["typed_payload_json_utf8_hex"])
            ) {
                verificationFailure(FailureStage.TYPED_PAYLOAD)
            }

            try {
                val typedJson = StrictJson.parseUtf8(payloadPlaintext, MAX_CONTAINER_BYTES)
                decodedPayload = decodeTypedValue(typedJson, 0)
                if (decodedPayload !is Map<*, *>) verificationFailure()
                if (!CanonicalJson.bytes(typedJson).contentEquals(payloadPlaintext)) verificationFailure()
                expectedPayload = decodeFixtureValue(inputs["payload"])
                if (!semanticValuesEqual(decodedPayload, expectedPayload)) verificationFailure()
            } catch (failure: VerificationFailure) {
                throw VerificationFailure(FailureStage.TYPED_PAYLOAD)
            } catch (_: Exception) {
                verificationFailure(FailureStage.TYPED_PAYLOAD)
            }

            val payloadMap = stringKeyedObject(decodedPayload)
            val seed = byteArrayValue(payloadMap["private_seed"], 32)
            val payloadPublicKey = byteArrayValue(payloadMap["public_key"], 32)
            val expectedPublicKey = decodeHex(expected["public_key_hex"])
            try {
                if (!payloadPublicKey.contentEquals(expectedPublicKey)) verificationFailure()
                val derivedPublicKey = Ed25519PrivateKeyParameters(seed, 0).generatePublicKey().encoded
                try {
                    if (!derivedPublicKey.contentEquals(expectedPublicKey)) verificationFailure()
                    return VerifiedPublicResult(encodeHex(derivedPublicKey))
                } finally {
                    derivedPublicKey.fill(0)
                }
            } finally {
                seed.fill(0)
                payloadPublicKey.fill(0)
                expectedPublicKey.fill(0)
            }
        } finally {
            passwordBytes.fill(0)
            kek?.fill(0)
            recoveredDek?.fill(0)
            payloadPlaintext?.fill(0)
            clearByteArrays(expectedPayload)
            clearByteArrays(decodedPayload)
        }
    }

    private fun deriveKek(password: ByteArray, salt: ByteArray): ByteArray {
        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(ARGON2_MEMORY_KIB)
            .withIterations(ARGON2_TIME_COST)
            .withParallelism(ARGON2_PARALLELISM)
            .withSalt(salt)
            .build()
        val output = ByteArray(32)
        try {
            Argon2BytesGenerator().apply { init(parameters) }.generateBytes(password, output)
            return output
        } catch (failure: Exception) {
            output.fill(0)
            verificationFailure()
        } finally {
            parameters.clear()
        }
    }

    private fun decryptAead(
        key: ByteArray,
        nonce: ByteArray,
        aad: ByteArray,
        ciphertext: ByteArray,
        tag: ByteArray,
        failureStage: FailureStage,
    ): ByteArray {
        if (key.size != 32 || nonce.size != 24 || tag.size != 16) verificationFailure()
        val combined = ByteArray(ciphertext.size + tag.size)
        ciphertext.copyInto(combined)
        tag.copyInto(combined, ciphertext.size)
        val cipher = XChaCha20Poly1305()
        var output: ByteArray? = null
        try {
            cipher.init(false, AEADParameters(KeyParameter(key), AEAD_TAG_BITS, nonce, aad))
            output = ByteArray(cipher.getOutputSize(combined.size))
            val written = cipher.processBytes(combined, 0, combined.size, output, 0)
            val finalWritten = cipher.doFinal(output, written)
            return output.copyOf(written + finalWritten)
        } catch (_: InvalidCipherTextException) {
            verificationFailure(failureStage)
        } catch (_: Exception) {
            verificationFailure(failureStage)
        } finally {
            combined.fill(0)
            output?.fill(0)
        }
    }

    private fun decodeTypedValue(value: Any?, depth: Int): Any? {
        if (depth > 64) verificationFailure()
        val typed = objectValue(value)
        return when (val type = stringValue(typed["t"])) {
            "null" -> {
                requireExactKeys(typed, setOf("t"))
                null
            }
            "bool" -> {
                requireExactKeys(typed, setOf("t", "v"))
                typed["v"] as? Boolean ?: verificationFailure()
            }
            "str" -> {
                requireExactKeys(typed, setOf("t", "v"))
                stringValue(typed["v"]).also(::requireUnicodeScalars)
            }
            "int" -> {
                requireExactKeys(typed, setOf("t", "v"))
                typed["v"] as? BigInteger ?: verificationFailure()
            }
            "bytes" -> {
                requireExactKeys(typed, setOf("t", "v"))
                decodeCanonicalBase64(typed["v"])
            }
            "list" -> {
                requireExactKeys(typed, setOf("t", "v"))
                val items = typed["v"] as? List<*> ?: verificationFailure()
                items.map { item -> decodeTypedValue(item, depth + 1) }
            }
            "map" -> {
                requireExactKeys(typed, setOf("t", "v"))
                val entries = typed["v"] as? List<*> ?: verificationFailure()
                val result = LinkedHashMap<String, Any?>()
                var previous: String? = null
                for (entry in entries) {
                    val pair = entry as? List<*> ?: verificationFailure()
                    if (pair.size != 2) verificationFailure()
                    val key = stringValue(pair[0])
                    requireUnicodeScalars(key)
                    if (previous != null && CanonicalJson.compareCodePointOrder(previous, key) >= 0) {
                        verificationFailure()
                    }
                    result[key] = decodeTypedValue(pair[1], depth + 1)
                    previous = key
                }
                result
            }
            else -> {
                type.length // keep type handling value-free and avoid leaking it in diagnostics
                verificationFailure()
            }
        }
    }

    private fun decodeFixtureValue(value: Any?): Any? = when (value) {
        is Map<*, *> -> {
            val marker = value["\u0024bytes_hex"]
            if (value.size == 1 && marker is String) {
                decodeHex(marker)
            } else {
                val result = LinkedHashMap<String, Any?>()
                for ((key, item) in value) {
                    val name = key as? String ?: verificationFailure()
                    result[name] = decodeFixtureValue(item)
                }
                result
            }
        }
        is List<*> -> value.map(::decodeFixtureValue)
        else -> value
    }

    private fun objectValue(value: Any?): Map<String, Any?> {
        val objectValue = value as? Map<*, *> ?: verificationFailure()
        val result = LinkedHashMap<String, Any?>()
        for ((key, item) in objectValue) {
            val name = key as? String ?: verificationFailure()
            result[name] = item
        }
        return result
    }

    private fun stringKeyedObject(value: Any?): Map<String, Any?> = objectValue(value)

    private fun requireExactKeys(value: Map<String, Any?>, expected: Set<String>) {
        if (value.keys != expected) verificationFailure()
    }

    private fun stringValue(value: Any?): String = value as? String ?: verificationFailure()

    private fun byteArrayValue(value: Any?, expectedLength: Int): ByteArray {
        val bytes = value as? ByteArray ?: verificationFailure()
        if (bytes.size != expectedLength) verificationFailure()
        return bytes.copyOf()
    }
}

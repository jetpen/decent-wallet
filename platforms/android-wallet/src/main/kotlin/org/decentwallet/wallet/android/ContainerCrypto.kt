package org.decentwallet.wallet.android

import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.modes.XChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.KeyParameter
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.SecureRandom

internal data class OpenedContainer(
    val dek: ByteArray,
    val payload: MutableMap<String, Any?>,
)

internal data class CreatedContainer(
    val bytes: ByteArray,
    val dek: ByteArray,
    val payload: MutableMap<String, Any?>,
)

internal object ContainerCrypto {
    const val CURRENT_VERSION = 2
    const val LEGACY_VERSION = 1
    const val MAX_CONTAINER_BYTES = 16 * 1024 * 1024
    private const val FORMAT = "decent-wallet"
    private const val MEMORY_KIB = 65_536
    private const val TIME_COST = 3
    private const val PARALLELISM = 4
    private const val KEY_BYTES = 32
    private const val SALT_BYTES = 16
    private const val NONCE_BYTES = 24
    private const val TAG_BYTES = 16
    private val random = SecureRandom()

    fun open(raw: ByteArray, password: String, version: Int = CURRENT_VERSION): OpenedContainer {
        val envelope = parseEnvelope(raw, version)
        val kdf = objectValue(envelope["kdf"])
        val wrap = objectValue(envelope["wrap"])
        val payloadEnvelope = objectValue(envelope["payload"])
        val salt = WalletJson.decodeBase64(kdf["salt"], SALT_BYTES)
        val kek = deriveKey(password, salt, onFailure = ::unlockFailed)
        var dek: ByteArray? = null
        var plaintext: ByteArray? = null
        try {
            val wrapAad = WalletJson.canonicalBytes(
                mapOf("format" to FORMAT, "version" to BigInteger.valueOf(version.toLong()), "kdf" to kdf),
            )
            dek = decrypt(
                kek,
                WalletJson.decodeBase64(wrap["nonce"], NONCE_BYTES),
                wrapAad,
                WalletJson.decodeBase64(wrap["ciphertext"], KEY_BYTES),
                WalletJson.decodeBase64(wrap["tag"], TAG_BYTES),
            )
            if (dek.size != KEY_BYTES) unlockFailed()
            val payloadInfo = mapOf(
                "algorithm" to "xchacha20-poly1305",
                "nonce" to payloadEnvelope["nonce"],
            )
            val payloadAad = WalletJson.canonicalBytes(
                mapOf(
                    "format" to FORMAT,
                    "version" to BigInteger.valueOf(version.toLong()),
                    "payload" to payloadInfo,
                ),
            )
            plaintext = decrypt(
                dek,
                WalletJson.decodeBase64(payloadEnvelope["nonce"], NONCE_BYTES),
                payloadAad,
                WalletJson.decodeBase64(payloadEnvelope["ciphertext"]),
                WalletJson.decodeBase64(payloadEnvelope["tag"], TAG_BYTES),
            )
            val payload = WalletJson.decodePayload(plaintext)
            try {
                validateDispatchPayload(payload, version)
            } catch (_: Exception) {
                WalletJson.clearByteArrays(payload)
                throw WalletInvalidContainerException()
            }
            return OpenedContainer(dek, payload).also { dek = null }
        } catch (failure: WalletContainerException) {
            throw failure
        } catch (_: Exception) {
            unlockFailed()
        } finally {
            kek.fill(0)
            dek?.fill(0)
            plaintext?.fill(0)
        }
    }

    private fun validateDispatchPayload(payload: Map<String, Any?>, version: Int) {
        if (!payload.containsKey("rotation_dispatch_intent")) return
        if (version != CURRENT_VERSION) invalidContainer()
        val intent = OwnerKeyRotationDispatchIntent.fromPayload(payload["rotation_dispatch_intent"])
        fun keyPair(seedField: String, publicField: String): ByteArray {
            val seed = payload[seedField] as? ByteArray ?: invalidContainer()
            val public = payload[publicField] as? ByteArray ?: invalidContainer()
            if (seed.size != KEY_BYTES || public.size != KEY_BYTES) invalidContainer()
            val derived = AndroidIdentityCrypto.publicKeyFromSeed(seed)
            try { if (!derived.contentEquals(public)) invalidContainer() } finally { derived.fill(0) }
            return public
        }
        val active = keyPair("private_seed", "public_key")
        val pending = keyPair("pending_private_seed", "pending_public_key")
        if (active.contentEquals(pending) || !active.contentEquals(intent.predecessorOwnerPublicKey) ||
            !pending.contentEquals(intent.successorOwnerPublicKey)) invalidContainer()
    }

    fun create(password: String, confirmation: String, payload: Map<String, Any?>): CreatedContainer {
        validatePassword(password, confirmation)
        @Suppress("UNCHECKED_CAST")
        val payloadCopy = WalletJson.copyPayload(payload) as? MutableMap<String, Any?> ?: invalidContainer()
        val dek = randomBytes(KEY_BYTES)
        return try {
            buildV2(password, dek, makeKdfHeader(randomBytes(SALT_BYTES)), payloadCopy)
        } catch (failure: WalletContainerException) {
            dek.fill(0)
            WalletJson.clearByteArrays(payloadCopy)
            throw failure
        } catch (_: Exception) {
            dek.fill(0)
            WalletJson.clearByteArrays(payloadCopy)
            throw WalletStorageException()
        }
    }

    fun resealPayload(raw: ByteArray, dek: ByteArray, payload: Map<String, Any?>): ByteArray {
        if (dek.size != KEY_BYTES) invalidContainer()
        val envelope = parseEnvelope(raw, CURRENT_VERSION)
        var typedPayload: ByteArray? = null
        var payloadNonce: ByteArray? = null
        var payloadAad: ByteArray? = null
        var payloadCiphertext: ByteArray? = null
        var payloadTag: ByteArray? = null
        try {
            val encodedPayload = WalletJson.encodePayload(payload)
            typedPayload = encodedPayload
            val freshNonce = randomBytes(NONCE_BYTES)
            payloadNonce = freshNonce
            val nonceText = WalletJson.encodeBase64(freshNonce)
            val aad = WalletJson.canonicalBytes(
                mapOf(
                    "format" to FORMAT,
                    "version" to BigInteger.valueOf(CURRENT_VERSION.toLong()),
                    "payload" to mapOf("algorithm" to "xchacha20-poly1305", "nonce" to nonceText),
                ),
            )
            payloadAad = aad
            val sealed = encrypt(dek, freshNonce, aad, encodedPayload)
            val ciphertext = sealed.first
            val tag = sealed.second
            payloadCiphertext = ciphertext
            payloadTag = tag
            val updatedEnvelope = envelope.toMutableMap()
            updatedEnvelope["payload"] = mapOf(
                "algorithm" to "xchacha20-poly1305",
                "nonce" to nonceText,
                "ciphertext" to WalletJson.encodeBase64(ciphertext),
                "tag" to WalletJson.encodeBase64(tag),
            )
            val bytes = WalletJson.canonicalBytes(updatedEnvelope)
            if (bytes.size > MAX_CONTAINER_BYTES) {
                bytes.fill(0)
                invalidContainer()
            }
            return bytes
        } catch (failure: WalletContainerException) {
            throw failure
        } catch (_: Exception) {
            throw WalletStorageException()
        } finally {
            typedPayload?.fill(0)
            payloadNonce?.fill(0)
            payloadAad?.fill(0)
            payloadCiphertext?.fill(0)
            payloadTag?.fill(0)
        }
    }

    fun migrate(password: String, v1Bytes: ByteArray): CreatedContainer {
        val opened = open(v1Bytes, password, LEGACY_VERSION)
        val envelope = objectValue(WalletJson.parse(v1Bytes, MAX_CONTAINER_BYTES))
        val kdf = objectValue(envelope["kdf"])
        return try {
            buildV2(password, opened.dek, kdf, opened.payload)
        } catch (failure: WalletContainerException) {
            opened.dek.fill(0)
            WalletJson.clearByteArrays(opened.payload)
            throw failure
        } catch (_: Exception) {
            opened.dek.fill(0)
            WalletJson.clearByteArrays(opened.payload)
            throw WalletStorageException()
        }
    }

    private fun buildV2(
        password: String,
        dek: ByteArray,
        kdf: Map<String, Any?>,
        payload: MutableMap<String, Any?>,
    ): CreatedContainer {
        val kdfBytes = WalletJson.decodeBase64(kdf["salt"], SALT_BYTES)
        var kek: ByteArray? = null
        var typedPayload: ByteArray? = null
        try {
            kek = deriveKey(password, kdfBytes, onFailure = { throw WalletStorageException() })
            val wrapNonce = randomBytes(NONCE_BYTES)
            val wrapAad = WalletJson.canonicalBytes(
                mapOf("format" to FORMAT, "version" to BigInteger.valueOf(CURRENT_VERSION.toLong()), "kdf" to kdf),
            )
            val wrapped = encrypt(kek, wrapNonce, wrapAad, dek)
            val payloadNonce = randomBytes(NONCE_BYTES)
            typedPayload = WalletJson.encodePayload(payload)
            val payloadAad = WalletJson.canonicalBytes(
                mapOf(
                    "format" to FORMAT,
                    "version" to BigInteger.valueOf(CURRENT_VERSION.toLong()),
                    "payload" to mapOf(
                        "algorithm" to "xchacha20-poly1305",
                        "nonce" to WalletJson.encodeBase64(payloadNonce),
                    ),
                ),
            )
            val sealedPayload = encrypt(dek, payloadNonce, payloadAad, typedPayload)
            val envelope = mapOf(
                "format" to FORMAT,
                "version" to BigInteger.valueOf(CURRENT_VERSION.toLong()),
                "kdf" to kdf,
                "wrap" to mapOf(
                    "algorithm" to "xchacha20-poly1305",
                    "nonce" to WalletJson.encodeBase64(wrapNonce),
                    "ciphertext" to WalletJson.encodeBase64(wrapped.first),
                    "tag" to WalletJson.encodeBase64(wrapped.second),
                ),
                "payload" to mapOf(
                    "algorithm" to "xchacha20-poly1305",
                    "nonce" to WalletJson.encodeBase64(payloadNonce),
                    "ciphertext" to WalletJson.encodeBase64(sealedPayload.first),
                    "tag" to WalletJson.encodeBase64(sealedPayload.second),
                ),
            )
            val bytes = WalletJson.canonicalBytes(envelope)
            if (bytes.size > MAX_CONTAINER_BYTES) {
                bytes.fill(0)
                invalidContainer()
            }
            return CreatedContainer(bytes, dek, payload)
        } finally {
            kdfBytes.fill(0)
            kek?.fill(0)
            typedPayload?.fill(0)
        }
    }

    private fun parseEnvelope(raw: ByteArray, expectedVersion: Int): Map<String, Any?> {
        val envelope = objectValue(WalletJson.parse(raw, MAX_CONTAINER_BYTES))
        requireKeys(envelope, setOf("format", "version", "kdf", "wrap", "payload"))
        if (envelope["format"] != FORMAT) invalidContainer()
        if (envelope["version"] != BigInteger.valueOf(expectedVersion.toLong())) {
            throw WalletUnsupportedFormatException()
        }
        val kdf = objectValue(envelope["kdf"])
        requireKeys(kdf, setOf("algorithm", "memory_kib", "time_cost", "parallelism", "salt"))
        if (kdf["algorithm"] != "argon2id" ||
            kdf["memory_kib"] != BigInteger.valueOf(MEMORY_KIB.toLong()) ||
            kdf["time_cost"] != BigInteger.valueOf(TIME_COST.toLong()) ||
            kdf["parallelism"] != BigInteger.valueOf(PARALLELISM.toLong())
        ) {
            throw WalletUnsupportedFormatException()
        }
        WalletJson.decodeBase64(kdf["salt"], SALT_BYTES).fill(0)
        for (field in listOf("wrap", "payload")) {
            val item = objectValue(envelope[field])
            requireKeys(item, setOf("algorithm", "nonce", "ciphertext", "tag"))
            if (item["algorithm"] != "xchacha20-poly1305") throw WalletUnsupportedFormatException()
            WalletJson.decodeBase64(item["nonce"], NONCE_BYTES).fill(0)
            val cipher = WalletJson.decodeBase64(item["ciphertext"], if (field == "wrap") KEY_BYTES else null)
            if (field == "payload" && cipher.size > MAX_CONTAINER_BYTES) invalidContainer()
            cipher.fill(0)
            WalletJson.decodeBase64(item["tag"], TAG_BYTES).fill(0)
        }
        return envelope
    }

    private fun makeKdfHeader(salt: ByteArray): Map<String, Any?> = mapOf(
        "algorithm" to "argon2id",
        "memory_kib" to BigInteger.valueOf(MEMORY_KIB.toLong()),
        "time_cost" to BigInteger.valueOf(TIME_COST.toLong()),
        "parallelism" to BigInteger.valueOf(PARALLELISM.toLong()),
        "salt" to WalletJson.encodeBase64(salt),
    ).also { salt.fill(0) }

    private fun deriveKey(password: String, salt: ByteArray, onFailure: () -> Nothing): ByteArray {
        val passwordBytes = password.toByteArray(StandardCharsets.UTF_8)
        val output = ByteArray(KEY_BYTES)
        val parameters = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withMemoryAsKB(MEMORY_KIB)
            .withIterations(TIME_COST)
            .withParallelism(PARALLELISM)
            .withSalt(salt)
            .build()
        try {
            Argon2BytesGenerator().apply { init(parameters) }.generateBytes(passwordBytes, output)
            return output
        } catch (_: Exception) {
            output.fill(0)
            onFailure()
        } finally {
            passwordBytes.fill(0)
            parameters.clear()
        }
    }

    private fun encrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, plain: ByteArray): Pair<ByteArray, ByteArray> {
        val cipher = XChaCha20Poly1305()
        var output: ByteArray? = null
        try {
            cipher.init(true, AEADParameters(KeyParameter(key), TAG_BYTES * 8, nonce, aad))
            output = ByteArray(cipher.getOutputSize(plain.size))
            val written = cipher.processBytes(plain, 0, plain.size, output, 0)
            val finalWritten = cipher.doFinal(output, written)
            val size = written + finalWritten
            if (size < TAG_BYTES) throw WalletStorageException()
            return output.copyOfRange(0, size - TAG_BYTES) to output.copyOfRange(size - TAG_BYTES, size)
        } catch (failure: WalletContainerException) {
            throw failure
        } catch (_: Exception) {
            throw WalletStorageException()
        } finally {
            output?.fill(0)
        }
    }

    private fun decrypt(key: ByteArray, nonce: ByteArray, aad: ByteArray, cipherText: ByteArray, tag: ByteArray): ByteArray {
        val combined = ByteArray(cipherText.size + tag.size)
        cipherText.copyInto(combined)
        tag.copyInto(combined, cipherText.size)
        val cipher = XChaCha20Poly1305()
        var output: ByteArray? = null
        try {
            cipher.init(false, AEADParameters(KeyParameter(key), TAG_BYTES * 8, nonce, aad))
            output = ByteArray(cipher.getOutputSize(combined.size))
            val written = cipher.processBytes(combined, 0, combined.size, output, 0)
            val finalWritten = cipher.doFinal(output, written)
            return output.copyOf(written + finalWritten)
        } catch (_: InvalidCipherTextException) {
            unlockFailed()
        } catch (_: Exception) {
            unlockFailed()
        } finally {
            combined.fill(0)
            output?.fill(0)
        }
    }

    private fun randomBytes(length: Int): ByteArray = ByteArray(length).also(random::nextBytes)

    internal fun validatePassword(password: String, confirmation: String? = null) {
        val count = password.codePointCount(0, password.length)
        if (count < MIN_PASSWORD_CODE_POINTS || (confirmation != null && password != confirmation)) {
            throw WalletPasswordPolicyException()
        }
        var index = 0
        while (index < password.length) {
            val current = password[index]
            if (Character.isHighSurrogate(current)) {
                if (index + 1 >= password.length || !Character.isLowSurrogate(password[index + 1])) {
                    throw WalletPasswordPolicyException()
                }
                index += 2
            } else if (Character.isLowSurrogate(current)) {
                throw WalletPasswordPolicyException()
            } else {
                index++
            }
        }
    }

    private fun objectValue(value: Any?): Map<String, Any?> {
        val map = value as? Map<*, *> ?: invalidContainer()
        val result = LinkedHashMap<String, Any?>()
        for ((key, child) in map) result[key as? String ?: invalidContainer()] = child
        return result
    }

    private fun requireKeys(value: Map<String, Any?>, expected: Set<String>) {
        if (value.keys != expected) invalidContainer()
    }

    private const val MIN_PASSWORD_CODE_POINTS = 16
}

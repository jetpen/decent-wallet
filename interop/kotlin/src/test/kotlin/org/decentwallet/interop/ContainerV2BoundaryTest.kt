package org.decentwallet.interop

import org.bouncycastle.crypto.InvalidCipherTextException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.math.BigInteger
import java.nio.charset.StandardCharsets

class ContainerV2BoundaryTest {
    @Test
    fun `accepts outer whitespace and member-order variations`() {
        val vector = VectorTestSupport.readVector()
        val canonical = VectorTestSupport.containerBytes(vector)
        val reordered = VectorTestSupport.reorderAndSpaceEnvelope(canonical)

        val actual = WalletContainerV2Verifier.verify(vector, reordered)

        assertEquals(VectorTestSupport.readUniqueStringField(vector, "public_key_hex"), actual.publicKeyHex)
    }

    @Test
    fun `wrap tag tampering fails at wrap authentication without exposing fixture secrets`() {
        val vector = VectorTestSupport.readVector()
        val canonical = VectorTestSupport.containerBytes(vector)
        val tampered = VectorTestSupport.mutateStringFieldInObject(canonical, "wrap", "tag") {
            VectorTestSupport.flipFirstByteBase64(it)
        }

        val failure = assertStage(vector, tampered, FailureStage.WRAP_AUTHENTICATION)
        val diagnostic = checkNotNull(failure.message)
        assertEquals("wallet-container v2 verification failed", diagnostic)
        for (name in listOf("password", "dek_hex", "kek_hex")) {
            val fixtureValue = VectorTestSupport.readUniqueStringField(vector, name)
            if (fixtureValue.isNotEmpty()) assertFalse(diagnostic.contains(fixtureValue))
        }
    }

    @Test
    fun `KDF salt tampering fails before either AEAD payload boundary`() {
        val vector = VectorTestSupport.readVector()
        val canonical = VectorTestSupport.containerBytes(vector)
        val tampered = VectorTestSupport.mutateStringFieldInObject(canonical, "kdf", "salt") {
            VectorTestSupport.flipFirstByteBase64(it)
        }

        assertStage(vector, tampered, FailureStage.KDF)
    }

    @Test
    fun `payload tag tampering fails at payload authentication`() {
        val vector = VectorTestSupport.readVector()
        val canonical = VectorTestSupport.containerBytes(vector)
        val tampered = VectorTestSupport.mutateStringFieldInObject(canonical, "payload", "tag") {
            VectorTestSupport.flipFirstByteBase64(it)
        }

        assertStage(vector, tampered, FailureStage.PAYLOAD_AUTHENTICATION)
    }

    @Test
    fun `payload nonce tampering fails before typed-payload decoding`() {
        val vector = VectorTestSupport.readVector()
        val canonical = VectorTestSupport.containerBytes(vector)
        val tampered = VectorTestSupport.mutateStringFieldInObject(canonical, "payload", "nonce") {
            VectorTestSupport.flipFirstByteBase64(it)
        }

        assertStage(vector, tampered, FailureStage.PAYLOAD_AUTHENTICATION)
    }

    @Test
    fun `duplicate envelope names fail closed`() {
        val vector = VectorTestSupport.readVector()
        val duplicate = VectorTestSupport.duplicateTopLevelFormat(VectorTestSupport.containerBytes(vector))

        assertStage(vector, duplicate, FailureStage.GENERAL)
    }

    @Test
    fun `v1 relabeling and unsupported versions fail closed`() {
        val vector = VectorTestSupport.readVector()
        val canonical = VectorTestSupport.containerBytes(vector)

        assertStage(
            vector,
            VectorTestSupport.replaceTopLevelInteger(canonical, "version", BigInteger.ONE),
            FailureStage.ENVELOPE,
        )
        assertStage(
            vector,
            VectorTestSupport.replaceTopLevelInteger(canonical, "version", BigInteger.valueOf(3)),
            FailureStage.ENVELOPE,
        )
    }

    @Test
    fun `v2 wrapped DEK does not authenticate under v1 wrap AAD`() {
        val vector = VectorTestSupport.readVector()
        val canonical = VectorTestSupport.containerBytes(vector)
        val wrapAadV2 = VectorTestSupport.decodeHex(
            VectorTestSupport.readUniqueStringField(vector, "wrap_aad_utf8_hex"),
        )
        val wrapAadV2Text = String(wrapAadV2, StandardCharsets.UTF_8)
        val version2Suffix = "\"version\":2}"
        val version1Suffix = "\"version\":1}"
        val suffixIndex = wrapAadV2Text.lastIndexOf(version2Suffix)
        check(suffixIndex >= 0)
        val wrapAadV1 = (wrapAadV2Text.substring(0, suffixIndex) + version1Suffix)
            .toByteArray(StandardCharsets.UTF_8)

        val password = VectorTestSupport.readUniqueStringField(vector, "password")
        val passwordBytes = password.toByteArray(StandardCharsets.UTF_8)
        val salt = VectorTestSupport.decodeBase64(
            VectorTestSupport.readStringFieldInObject(canonical, "kdf", "salt"),
        )
        val wrapNonce = VectorTestSupport.decodeBase64(
            VectorTestSupport.readStringFieldInObject(canonical, "wrap", "nonce"),
        )
        val wrapCiphertext = VectorTestSupport.decodeBase64(
            VectorTestSupport.readStringFieldInObject(canonical, "wrap", "ciphertext"),
        )
        val wrapTag = VectorTestSupport.decodeBase64(
            VectorTestSupport.readStringFieldInObject(canonical, "wrap", "tag"),
        )
        val kek = VectorTestSupport.deriveKek(passwordBytes, salt)
        try {
            assertThrows(InvalidCipherTextException::class.java) {
                VectorTestSupport.decryptAndDiscard(kek, wrapNonce, wrapAadV1, wrapCiphertext, wrapTag)
            }
        } finally {
            passwordBytes.fill(0)
            salt.fill(0)
            wrapNonce.fill(0)
            wrapCiphertext.fill(0)
            wrapTag.fill(0)
            wrapAadV2.fill(0)
            wrapAadV1.fill(0)
            kek.fill(0)
        }
    }

    @Test
    fun `authenticated malformed typed payload is rejected after payload authentication`() {
        val vector = VectorTestSupport.readVector()
        val canonical = VectorTestSupport.containerBytes(vector)
        val originalNonce = VectorTestSupport.decodeBase64(
            VectorTestSupport.readStringFieldInObject(canonical, "payload", "nonce"),
        )
        val newNonce = originalNonce.copyOf()
        newNonce[0] = (newNonce[0].toInt() xor 0x40).toByte()
        val newNonceBase64 = VectorTestSupport.encodeBase64(newNonce)
        val oldNonceBase64 = VectorTestSupport.encodeBase64(originalNonce)

        val aadV2 = VectorTestSupport.decodeHex(
            VectorTestSupport.readUniqueStringField(vector, "payload_aad_utf8_hex"),
        )
        val aadText = String(aadV2, StandardCharsets.UTF_8)
        val malformedAadText = aadText.replace(oldNonceBase64, newNonceBase64)
        check(malformedAadText != aadText)
        val malformedAad = malformedAadText.toByteArray(StandardCharsets.UTF_8)

        val fixtureDek = VectorTestSupport.decodeHex(
            VectorTestSupport.readUniqueStringField(vector, "dek_hex"),
        )
        val malformedPayload = "{\"t\":\"map\",\"v\":[[\"bad\",{\"t\":\"unknown\"}]]}"
            .toByteArray(StandardCharsets.UTF_8)
        val (ciphertext, tag) = VectorTestSupport.encryptAead(fixtureDek, newNonce, malformedAad, malformedPayload)
        try {
            var tampered = VectorTestSupport.mutateStringFieldInObject(canonical, "payload", "nonce") {
                newNonceBase64
            }
            tampered = VectorTestSupport.mutateStringFieldInObject(tampered, "payload", "ciphertext") {
                VectorTestSupport.encodeBase64(ciphertext)
            }
            tampered = VectorTestSupport.mutateStringFieldInObject(tampered, "payload", "tag") {
                VectorTestSupport.encodeBase64(tag)
            }

            assertStage(vector, tampered, FailureStage.TYPED_PAYLOAD)
        } finally {
            originalNonce.fill(0)
            newNonce.fill(0)
            aadV2.fill(0)
            malformedAad.fill(0)
            fixtureDek.fill(0)
            malformedPayload.fill(0)
            ciphertext.fill(0)
            tag.fill(0)
        }
    }

    private fun assertStage(
        vector: ByteArray,
        container: ByteArray,
        expectedStage: FailureStage,
    ): VerificationFailure {
        val failure = assertThrows(VerificationFailure::class.java) {
            WalletContainerV2Verifier.verify(vector, container)
        }
        assertEquals(expectedStage, failure.stage)
        assertEquals("wallet-container v2 verification failed", failure.message)
        return failure
    }
}

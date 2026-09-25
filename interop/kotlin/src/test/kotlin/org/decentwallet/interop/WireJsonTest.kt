package org.decentwallet.interop

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets

class WireJsonTest {
    @Test
    fun `canonical JSON sorts keys by Unicode code point rather than UTF-16 unit`() {
        val bmpKey = "\uE000"
        val supplementaryKey = "\uD800\uDC00"
        val value = linkedMapOf(supplementaryKey to "supplementary", bmpKey to "bmp")

        assertTrue(CanonicalJson.compareCodePointOrder(bmpKey, supplementaryKey) < 0)
        assertTrue(bmpKey.compareTo(supplementaryKey) > 0)
        assertEquals(
            "{\"$bmpKey\":\"bmp\",\"$supplementaryKey\":\"supplementary\"}",
            CanonicalJson.text(value),
        )
    }

    @Test
    fun `canonical JSON does not normalize Unicode strings`() {
        val composed = "\u00e9"
        val decomposed = "e\u0301"

        assertNotEquals(CanonicalJson.text(composed), CanonicalJson.text(decomposed))
    }

    @Test
    fun `strict parser rejects duplicate object names`() {
        val json = "{\"name\":1,\"name\":2}".toByteArray(StandardCharsets.UTF_8)

        val failure = assertThrows(VerificationFailure::class.java) {
            StrictJson.parseUtf8(json, 1024)
        }

        assertEquals("wallet-container v2 verification failed", failure.message)
    }

    @Test
    fun `strict parser rejects invalid UTF-8 and unpaired escaped surrogates`() {
        val malformedUtf8 = byteArrayOf(0x22, 0xc3.toByte(), 0x28, 0x22)
        val loneSurrogate = "\"\\uD800\"".toByteArray(StandardCharsets.UTF_8)

        assertThrows(VerificationFailure::class.java) { StrictJson.parseUtf8(malformedUtf8, 1024) }
        assertThrows(VerificationFailure::class.java) { StrictJson.parseUtf8(loneSurrogate, 1024) }
    }
}

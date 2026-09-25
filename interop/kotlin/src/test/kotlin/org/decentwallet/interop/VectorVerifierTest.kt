package org.decentwallet.interop

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonToken
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.file.Files
import java.nio.file.Paths

class VectorVerifierTest {
    @Test
    fun `verifies the canonical v2 vector and recovers its expected public key`() {
        val vectorPath = Paths.get("../../tests/vectors/wallet-container-v2.json").normalize()
        val vectorBytes = Files.readAllBytes(vectorPath)
        val expectedPublicKey = readUniqueStringField(vectorBytes, "public_key_hex")

        val result = WalletContainerV2Verifier.verify(vectorBytes)

        assertEquals(expectedPublicKey, result.publicKeyHex)
    }

    private fun readUniqueStringField(json: ByteArray, name: String): String {
        val parser = JsonFactory().createParser(json)
        parser.use {
            var result: String? = null
            while (parser.nextToken() != null) {
                if (parser.currentToken == JsonToken.FIELD_NAME && parser.text == name) {
                    check(result == null) { "expected fixture field is not unique" }
                    check(parser.nextToken() == JsonToken.VALUE_STRING) {
                        "expected fixture field has the wrong type"
                    }
                    result = parser.text
                }
            }
            return checkNotNull(result) { "expected fixture field is missing" }
        }
    }
}

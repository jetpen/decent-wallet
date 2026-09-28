package org.decentwallet.wallet.android

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class AndroidRegistryDhtKeyTest {
    @Test
    fun identityKeyMatchesRegistryOwnerNameNamespace() {
        val ownerName = "alice@example.test".toByteArray(StandardCharsets.UTF_8)
        val objectKey = MessageDigest.getInstance("SHA-256").digest(ownerName)
        val expected = "/decent-registry/identity/${objectKey.joinToString("") { "%02x".format(it) }}"
            .toByteArray(StandardCharsets.US_ASCII)

        assertArrayEquals(expected, AndroidRegistryDhtKey.identity(ownerName))
    }

    @Test
    fun historyKeyUsesRawObjectAndStateHashes() {
        val ownerName = "alice@example.test".toByteArray(StandardCharsets.UTF_8)
        val objectKey = MessageDigest.getInstance("SHA-256").digest(ownerName)
        val stateHash = ByteArray(32) { (it + 1).toByte() }
        val expected = "/decent-registry/history/".toByteArray(StandardCharsets.US_ASCII) + objectKey + stateHash

        assertArrayEquals(expected, AndroidRegistryDhtKey.history(ownerName, stateHash))
    }
}

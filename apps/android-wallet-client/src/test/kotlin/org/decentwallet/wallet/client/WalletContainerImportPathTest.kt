package org.decentwallet.wallet.client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class WalletContainerImportPathTest {
    @Test fun mapsExactEncryptedBytesToStablePrivateDestinationWithoutUsingIdentityOrPassword() {
        val directory = Files.createTempDirectory("wallet-import-path-")
        val bytes = ByteArray(256) { it.toByte() }
        val duplicate = bytes.copyOf()
        try {
            val first = WalletContainerImportPath.destination(directory, bytes)
            val second = WalletContainerImportPath.destination(directory, duplicate)
            assertEquals(first, second)
            assertTrue(first.startsWith(directory))
            assertTrue(first.fileName.toString().startsWith("wallet-"))
            assertTrue(first.fileName.toString().endsWith(".dw"))
            duplicate[duplicate.lastIndex] = (duplicate.last().toInt() xor 1).toByte()
            assertNotEquals(first, WalletContainerImportPath.destination(directory, duplicate))
        } finally {
            bytes.fill(0)
            duplicate.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test fun rejectsEmptyAndOversizedContainersBeforeBuildingPath() {
        assertRejected(ByteArray(0))
        assertRejected(ByteArray(16 * 1024 * 1024 + 1))
    }

    private fun assertRejected(bytes: ByteArray) {
        val directory = Files.createTempDirectory("wallet-import-path-invalid-")
        try {
            assertThrows(IllegalArgumentException::class.java) { WalletContainerImportPath.destination(directory, bytes) }
        } finally {
            bytes.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }
}

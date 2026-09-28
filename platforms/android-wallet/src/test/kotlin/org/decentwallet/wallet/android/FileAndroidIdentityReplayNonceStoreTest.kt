package org.decentwallet.wallet.android

import java.io.File
import java.io.IOException
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class FileAndroidIdentityReplayNonceStoreTest {
    @Test
    fun consumedDigestSurvivesStoreRecreation() {
        withTemporaryDirectory { directory ->
            val digest = ByteArray(32) { it.toByte() }
            val firstStore = FileAndroidIdentityReplayNonceStore(directory)
            val recreatedStore = FileAndroidIdentityReplayNonceStore(directory)

            assertTrue(firstStore.consume(digest))
            assertFalse(recreatedStore.consume(digest))
        }
    }

    @Test
    fun concurrentStoreInstancesConsumeDigestAtMostOnce() {
        withTemporaryDirectory { directory ->
            val digest = ByteArray(32) { (it * 3).toByte() }
            val stores = (0 until 12).map { FileAndroidIdentityReplayNonceStore(directory) }
            val start = CountDownLatch(1)
            val pool = Executors.newFixedThreadPool(stores.size)
            try {
                val results = stores.map { store ->
                    pool.submit<Boolean> {
                        assertTrue(start.await(5, TimeUnit.SECONDS))
                        store.consume(digest)
                    }
                }
                start.countDown()
                assertEquals(1, results.count { it.get(10, TimeUnit.SECONDS) })
            } finally {
                pool.shutdownNow()
            }
        }
    }

    @Test
    fun malformedDigestIsRejectedWithoutCreatingStoreFiles() {
        withTemporaryDirectory { directory ->
            val store = FileAndroidIdentityReplayNonceStore(directory)

            assertThrows(IllegalArgumentException::class.java) {
                store.consume(byteArrayOf(1, 2, 3))
            }
            assertFalse(File(directory, "identity-rotation-replay-nonces.bin").exists())
        }
    }

    @Test
    fun corruptJournalFailsClosed() {
        withTemporaryDirectory { directory ->
            val store = FileAndroidIdentityReplayNonceStore(directory)
            val firstDigest = ByteArray(32) { (it + 7).toByte() }
            assertTrue(store.consume(firstDigest))
            val journal = File(directory, "identity-rotation-replay-nonces.bin")
            Files.newByteChannel(journal.toPath(), StandardOpenOption.WRITE).use { channel ->
                channel.position(channel.size() - 1)
                channel.write(java.nio.ByteBuffer.wrap(byteArrayOf(0x55)))
            }

            assertThrows(IOException::class.java) {
                store.consume(ByteArray(32) { (it + 19).toByte() })
            }
        }
    }

    private fun withTemporaryDirectory(block: (File) -> Unit) {
        val directory = Files.createTempDirectory("wallet-replay-nonces-").toFile()
        try {
            block(directory)
        } finally {
            Files.walk(directory.toPath()).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }
}

package org.decentwallet.wallet.android

import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import java.util.zip.CRC32
import kotlin.concurrent.withLock

/**
 * Durable replay-nonce store for Android hosts. Pass the application's private internal-storage
 * directory (for example, `Context.filesDir`); the store persists only 32-byte digests, never raw
 * consent nonces. A successful consume is fsynced before it returns, and a file lock serializes
 * separate store instances and processes sharing the same directory.
 */
class FileAndroidIdentityReplayNonceStore(private val privateDirectory: File) :
    AndroidIdentityReplayNonceStore {
    private val directory = privateDirectory.canonicalFile
    private val journal = File(directory, JOURNAL_NAME)
    private val lockFile = File(directory, LOCK_NAME)
    private val processLock = processLocks.computeIfAbsent(lockFile.canonicalPath) { ReentrantLock() }

    override fun consume(nonceDigest: ByteArray): Boolean {
        require(nonceDigest.size == DIGEST_BYTES) { "nonce digest must be 32 bytes" }
        val digest = nonceDigest.copyOf()
        try {
            return processLock.withLock {
                ensurePrivateDirectory()
                withExclusiveFileLock {
                    consumeUnderLock(digest)
                }
            }
        } finally {
            digest.fill(0)
        }
    }

    private fun consumeUnderLock(digest: ByteArray): Boolean {
        if (journal.exists() && isSymbolicLink(journal)) {
            throw IOException("replay-nonce journal must not be a symbolic link")
        }
        FileChannel.open(
            journal.toPath(),
            StandardOpenOption.CREATE,
            StandardOpenOption.READ,
            StandardOpenOption.WRITE,
            LinkOption.NOFOLLOW_LINKS,
        ).use { channel ->
            val size = channel.size()
            if (size % RECORD_BYTES != 0L || size / RECORD_BYTES > MAX_RECORDS) {
                throw IOException("replay-nonce journal has an invalid size")
            }
            val recordCount = (size / RECORD_BYTES).toInt()
            val recordBuffer = ByteBuffer.allocate(RECORD_BYTES)
            for (index in 0 until recordCount) {
                recordBuffer.clear()
                channel.position(index.toLong() * RECORD_BYTES)
                readFully(channel, recordBuffer)
                recordBuffer.flip()

                val magic = ByteArray(MAGIC.size)
                val existingDigest = ByteArray(DIGEST_BYTES)
                try {
                    recordBuffer.get(magic)
                    recordBuffer.get(existingDigest)
                    val storedCrc = recordBuffer.int
                    if (!magic.contentEquals(MAGIC) || storedCrc != recordCrc(existingDigest)) {
                        throw IOException("replay-nonce journal is corrupt")
                    }
                    if (MessageDigest.isEqual(existingDigest, digest)) return false
                } finally {
                    existingDigest.fill(0)
                }
            }
            if (recordCount >= MAX_RECORDS) {
                throw IOException("replay-nonce journal is full")
            }

            val append = ByteBuffer.allocate(RECORD_BYTES)
                .put(MAGIC)
                .put(digest)
                .putInt(recordCrc(digest))
            append.flip()
            channel.position(size)
            while (append.hasRemaining()) channel.write(append)
            channel.force(true)
            return true
        }
    }

    private fun withExclusiveFileLock(action: () -> Boolean): Boolean {
        if (lockFile.exists() && isSymbolicLink(lockFile)) {
            throw IOException("replay-nonce lock must not be a symbolic link")
        }
        FileChannel.open(
            lockFile.toPath(),
            StandardOpenOption.CREATE,
            StandardOpenOption.WRITE,
            LinkOption.NOFOLLOW_LINKS,
        ).use { channel ->
            channel.lock().use { return action() }
        }
    }

    private fun ensurePrivateDirectory() {
        if (!directory.exists() && !directory.mkdirs()) {
            throw IOException("could not create replay-nonce storage directory")
        }
        if (!directory.isDirectory) {
            throw IOException("replay-nonce storage path is not a directory")
        }
    }

    private fun readFully(channel: FileChannel, buffer: ByteBuffer) {
        while (buffer.hasRemaining()) {
            if (channel.read(buffer) < 0) throw IOException("replay-nonce journal is truncated")
        }
    }

    private fun recordCrc(digest: ByteArray): Int {
        val crc = CRC32()
        crc.update(MAGIC)
        crc.update(digest)
        return crc.value.toInt()
    }

    private fun isSymbolicLink(file: File): Boolean =
        java.nio.file.Files.isSymbolicLink(file.toPath())

    private companion object {
        const val DIGEST_BYTES = 32
        const val RECORD_BYTES = 40
        const val MAX_RECORDS = 1_000_000
        const val JOURNAL_NAME = "identity-rotation-replay-nonces.bin"
        const val LOCK_NAME = "identity-rotation-replay-nonces.lock"
        val MAGIC = byteArrayOf(0x44, 0x57, 0x4e, 0x52)
        val processLocks = ConcurrentHashMap<String, ReentrantLock>()
    }
}

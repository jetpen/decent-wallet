package org.decentwallet.wallet.android

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

internal object AtomicWalletFiles {
    private val testDirectorySync = ThreadLocal<Pair<Path, (Path) -> Unit>>()

    /** Scoped internal test seam; never a public API or process-wide fault switch. */
    internal fun <T> withDirectorySyncForTest(
        directory: Path,
        directorySync: (Path) -> Unit,
        action: () -> T,
    ): T {
        val prior = testDirectorySync.get()
        testDirectorySync.set(directory.toAbsolutePath().normalize() to directorySync)
        return try {
            action()
        } finally {
            if (prior == null) testDirectorySync.remove() else testDirectorySync.set(prior)
        }
    }

    fun read(path: Path): ByteArray = withPathLock(path) { readLocked(path) }

    private fun readLocked(path: Path): ByteArray {
        try {
            if (!Files.isRegularFile(path, NOFOLLOW_LINKS)) throw WalletStorageException()
            val size = Files.size(path)
            if (size > ContainerCrypto.MAX_CONTAINER_BYTES) invalidContainer()
            Files.newInputStream(path).use { input ->
                val output = ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                try {
                    var total = 0
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        total += count
                        if (total > ContainerCrypto.MAX_CONTAINER_BYTES) invalidContainer()
                        output.write(buffer, 0, count)
                    }
                    return output.toByteArray()
                } finally {
                    buffer.fill(0)
                }
            }
        } catch (failure: WalletContainerException) {
            throw failure
        } catch (_: Exception) {
            throw WalletStorageException()
        }
    }

    fun createNew(path: Path, bytes: ByteArray) = withPathLock(path) { createNewLocked(path, bytes) }

    private fun createNewLocked(path: Path, bytes: ByteArray) {
        if (bytes.size > ContainerCrypto.MAX_CONTAINER_BYTES) invalidContainer()
        val target = path.toAbsolutePath().normalize()
        val parent = target.parent ?: throw WalletStorageException()
        var staged: Path? = null
        var installed = false
        try {
            if (!Files.isDirectory(parent) || Files.exists(target, NOFOLLOW_LINKS)) {
                throw WalletStorageException()
            }
            staged = stage(parent, bytes)
            if (Files.exists(target, NOFOLLOW_LINKS)) throw WalletStorageException()
            Files.move(staged, target, ATOMIC_MOVE)
            staged = null
            installed = true
            fsyncDirectory(parent)
            val persisted = readLocked(target)
            val verified = persisted.contentEquals(bytes)
            persisted.fill(0)
            if (!verified) throw IOException()
        } catch (failure: WalletContainerException) {
            cleanupStage(staged)
            if (!installed) throw failure
            if (!removeCreatedFile(target, parent, bytes)) throw WalletStorageOutcomeUnknownException()
            throw failure
        } catch (_: Exception) {
            cleanupStage(staged)
            if (!installed) throw WalletStorageException()
            if (!removeCreatedFile(target, parent, bytes)) throw WalletStorageOutcomeUnknownException()
            throw WalletStorageException()
        }
    }

    fun replace(path: Path, bytes: ByteArray, expectedOriginal: ByteArray) =
        replaceWithSync(path, bytes, expectedOriginal, ::fsyncDirectory)

    internal fun replaceForTest(
        path: Path,
        bytes: ByteArray,
        expectedOriginal: ByteArray,
        directorySync: (Path) -> Unit,
    ) = replaceWithSync(path, bytes, expectedOriginal, directorySync)

    private fun replaceWithSync(
        path: Path,
        bytes: ByteArray,
        expectedOriginal: ByteArray,
        directorySync: (Path) -> Unit,
    ) = withPathLock(path) {
        replaceLocked(path, bytes, expectedOriginal, directorySync)
    }

    private fun replaceLocked(
        path: Path,
        bytes: ByteArray,
        expectedOriginal: ByteArray,
        directorySync: (Path) -> Unit,
    ) {
        if (bytes.size > ContainerCrypto.MAX_CONTAINER_BYTES) invalidContainer()
        val target = path.toAbsolutePath().normalize()
        val parent = target.parent ?: throw WalletStorageException()
        val current = read(target)
        if (!current.contentEquals(expectedOriginal)) {
            current.fill(0)
            throw WalletInvalidContainerException()
        }
        current.fill(0)
        var staged: Path? = null
        var installed = false
        try {
            staged = stage(parent, bytes)
            Files.move(staged, target, ATOMIC_MOVE, REPLACE_EXISTING)
            staged = null
            installed = true
            directorySync(parent)
            val persisted = read(target)
            val verified = persisted.contentEquals(bytes)
            persisted.fill(0)
            if (!verified) throw IOException()
        } catch (failure: WalletContainerException) {
            cleanupStage(staged)
            if (!installed) throw failure
            val restored = restore(target, parent, expectedOriginal, directorySync)
            if (!restored) throw WalletStorageOutcomeUnknownException()
            throw failure
        } catch (_: Exception) {
            cleanupStage(staged)
            if (!installed) throw WalletStorageException()
            val restored = restore(target, parent, expectedOriginal, directorySync)
            if (!restored) throw WalletStorageOutcomeUnknownException()
            throw WalletStorageException()
        }
    }

    private fun stage(parent: Path, bytes: ByteArray): Path {
        val path = Files.createTempFile(parent, ".decent-wallet-", ".tmp")
        try {
            try {
                Files.setPosixFilePermissions(
                    path,
                    setOf(
                        java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                        java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                    ),
                )
            } catch (_: UnsupportedOperationException) {
                // Android app-private directories already restrict access to the application UID.
            }
            FileChannel.open(path, WRITE).use { channel ->
                val buffer = ByteBuffer.wrap(bytes)
                while (buffer.hasRemaining()) channel.write(buffer)
                channel.force(true)
            }
            return path
        } catch (_: Exception) {
            try {
                Files.deleteIfExists(path)
            } catch (_: Exception) {
                throw WalletStorageOutcomeUnknownException()
            }
            throw WalletStorageException()
        }
    }

    private fun restore(
        target: Path,
        parent: Path,
        original: ByteArray,
        directorySync: (Path) -> Unit,
    ): Boolean {
        var staged: Path? = null
        return try {
            staged = stage(parent, original)
            Files.move(staged, target, ATOMIC_MOVE, REPLACE_EXISTING)
            staged = null
            directorySync(parent)
            val persisted = read(target)
            val result = persisted.contentEquals(original)
            persisted.fill(0)
            result
        } catch (_: Exception) {
            cleanupStage(staged)
            false
        }
    }

    private fun fsyncDirectory(directory: Path) {
        val scoped = testDirectorySync.get()
        if (scoped != null && scoped.first == directory.toAbsolutePath().normalize()) {
            scoped.second(directory)
            return
        }
        FileChannel.open(directory, READ).use { it.force(true) }
    }

    private fun removeCreatedFile(target: Path, parent: Path, bytes: ByteArray): Boolean {
        return try {
            if (Files.exists(target, NOFOLLOW_LINKS)) {
                val persisted = readLocked(target)
                val matches = persisted.contentEquals(bytes)
                persisted.fill(0)
                if (!matches) return false
                Files.delete(target)
            }
            fsyncDirectory(parent)
            !Files.exists(target, NOFOLLOW_LINKS)
        } catch (_: Exception) {
            false
        }
    }

    private fun cleanupStage(path: Path?) {
        if (path == null) return
        try {
            Files.deleteIfExists(path)
        } catch (_: Exception) {
            throw WalletStorageOutcomeUnknownException()
        }
    }

    private val pathLocks = ConcurrentHashMap<String, ReentrantLock>()

    private fun <T> withPathLock(path: Path, action: () -> T): T {
        val key = path.toAbsolutePath().normalize().toString()
        return pathLocks.computeIfAbsent(key) { ReentrantLock() }.withLock(action)
    }
}

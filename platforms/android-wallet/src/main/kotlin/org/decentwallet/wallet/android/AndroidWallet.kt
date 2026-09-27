package org.decentwallet.wallet.android

import java.nio.file.Path

object AndroidWallet {
    fun create(
        path: Path,
        password: String,
        confirmation: String,
        payload: Map<String, Any?>,
    ): WalletSession {
        val created = ContainerCrypto.create(password, confirmation, payload)
        return try {
            AtomicWalletFiles.createNew(path, created.bytes)
            WalletSession(path, created.bytes, created.dek, created.payload)
        } catch (failure: WalletContainerException) {
            created.bytes.fill(0)
            created.dek.fill(0)
            WalletJson.clearByteArrays(created.payload)
            throw failure
        } catch (_: Exception) {
            created.bytes.fill(0)
            created.dek.fill(0)
            WalletJson.clearByteArrays(created.payload)
            throw WalletStorageException()
        }
    }

    fun importContainer(path: Path, data: ByteArray, password: String): WalletSession {
        validatePasswordForOpen(password)
        if (data.size > ContainerCrypto.MAX_CONTAINER_BYTES) throw WalletInvalidContainerException()
        val raw = data.copyOf()
        val opened = try {
            ContainerCrypto.open(raw, password)
        } catch (failure: WalletContainerException) {
            raw.fill(0)
            throw failure
        } catch (_: Exception) {
            raw.fill(0)
            throw WalletStorageException()
        }
        try {
            AtomicWalletFiles.createNew(path, raw)
            return WalletSession(path, raw, opened.dek, opened.payload)
        } catch (failure: WalletContainerException) {
            raw.fill(0)
            opened.dek.fill(0)
            WalletJson.clearByteArrays(opened.payload)
            throw failure
        } catch (_: Exception) {
            raw.fill(0)
            opened.dek.fill(0)
            WalletJson.clearByteArrays(opened.payload)
            throw WalletStorageException()
        }
    }

    fun migrateContainer(path: Path, password: String): WalletSession {
        validatePasswordForOpen(password)
        val original = AtomicWalletFiles.read(path)
        try {
            val converted = ContainerCrypto.migrate(password, original)
            try {
                AtomicWalletFiles.replace(path, converted.bytes, original)
                return WalletSession(path, converted.bytes, converted.dek, converted.payload)
            } catch (failure: WalletContainerException) {
                converted.bytes.fill(0)
                converted.dek.fill(0)
                WalletJson.clearByteArrays(converted.payload)
                throw failure
            } catch (_: Exception) {
                converted.bytes.fill(0)
                converted.dek.fill(0)
                WalletJson.clearByteArrays(converted.payload)
                throw WalletStorageException()
            }
        } finally {
            original.fill(0)
        }
    }

    fun open(path: Path, password: String): WalletSession {
        validatePasswordForOpen(password)
        val raw = AtomicWalletFiles.read(path)
        val opened = try {
            ContainerCrypto.open(raw, password)
        } catch (failure: WalletContainerException) {
            raw.fill(0)
            throw failure
        } catch (_: Exception) {
            raw.fill(0)
            throw WalletStorageException()
        }
        return WalletSession(path, raw, opened.dek, opened.payload)
    }

    private fun validatePasswordForOpen(password: String) = ContainerCrypto.validatePassword(password)
}

class WalletSession internal constructor(
    private val path: Path,
    rawBytes: ByteArray,
    dek: ByteArray,
    payload: MutableMap<String, Any?>,
) : AutoCloseable {
    private var rawContainer: ByteArray? = rawBytes
    private var dataEncryptionKey: ByteArray? = dek
    private var walletPayload: MutableMap<String, Any?>? = payload

    val isUnlocked: Boolean
        @Synchronized get() = dataEncryptionKey != null

    @Synchronized
    internal fun readPayload(): Map<String, Any?> {
        ensureUnlocked()
        @Suppress("UNCHECKED_CAST")
        return WalletJson.copyPayload(walletPayload) as Map<String, Any?>
    }

    @Synchronized
    fun exportContainer(): ByteArray {
        ensureUnlocked()
        val stored = checkNotNull(rawContainer)
        val current = AtomicWalletFiles.read(path)
        if (!current.contentEquals(stored)) {
            current.fill(0)
            throw WalletInvalidContainerException()
        }
        return current
    }

    @Synchronized
    fun lock() {
        dataEncryptionKey?.fill(0)
        dataEncryptionKey = null
        walletPayload?.let(WalletJson::clearByteArrays)
        walletPayload?.clear()
        walletPayload = null
        rawContainer?.fill(0)
        rawContainer = null
    }

    fun background() = lock()

    override fun close() = lock()

    private fun ensureUnlocked() {
        if (dataEncryptionKey == null || walletPayload == null || rawContainer == null) {
            throw WalletLockedException()
        }
    }
}

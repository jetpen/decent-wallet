package org.decentwallet.wallet.client

import java.nio.file.Path
import java.security.MessageDigest

/** Maps a container to a deterministic app-private filename without exposing its password or identity. */
internal object WalletContainerImportPath {
    private const val MAX_CONTAINER_BYTES = 16 * 1024 * 1024

    fun destination(privateDirectory: Path, encryptedContainer: ByteArray): Path {
        require(encryptedContainer.isNotEmpty() && encryptedContainer.size <= MAX_CONTAINER_BYTES) {
            "invalid encrypted wallet container"
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(encryptedContainer)
        try {
            val name = digest.joinToString("") { "%02x".format(it) }
            return privateDirectory.resolve("wallet-$name.dw")
        } finally {
            digest.fill(0)
        }
    }
}

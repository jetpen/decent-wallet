package org.decentwallet.wallet.android

import java.nio.charset.StandardCharsets

internal object AndroidRegistryDhtKey {
    private val IDENTITY_PREFIX = "/decent-registry/identity/".toByteArray(StandardCharsets.US_ASCII)
    private val HISTORY_PREFIX = "/decent-registry/history/".toByteArray(StandardCharsets.US_ASCII)
    private const val HEX_DIGITS = "0123456789abcdef"

    fun identity(ownerName: ByteArray): ByteArray {
        require(ownerName.isNotEmpty()) { "owner name must not be empty" }
        val objectKey = AndroidIdentityCrypto.sha256(ownerName)
        return try {
            val hex = buildString(objectKey.size * 2) {
                objectKey.forEach { byte ->
                    val value = byte.toInt() and 0xff
                    append(HEX_DIGITS[value ushr 4])
                    append(HEX_DIGITS[value and 0x0f])
                }
            }.toByteArray(StandardCharsets.US_ASCII)
            IDENTITY_PREFIX + hex
        } finally {
            objectKey.fill(0)
        }
    }

    fun history(ownerName: ByteArray, stateHash: ByteArray): ByteArray {
        require(ownerName.isNotEmpty()) { "owner name must not be empty" }
        require(stateHash.size == AndroidIdentityCrypto.KEY_BYTES) { "state hash must be 32 bytes" }
        val objectKey = AndroidIdentityCrypto.sha256(ownerName)
        return try {
            HISTORY_PREFIX + objectKey + stateHash
        } finally {
            objectKey.fill(0)
        }
    }
}

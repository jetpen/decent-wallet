package org.decentwallet.wallet.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.nio.file.Files

class MasterAccountEntityTest {
    @Test
    fun entityValuesAreEncryptedInTheExistingContainerAndSurviveReopenAndImport() {
        val directory = Files.createTempDirectory("wallet-master-account-entity-")
        val path = directory.resolve("wallet.dw")
        val importedPath = directory.resolve("imported.dw")
        val password = "a sufficiently long test password"
        val expected = linkedMapOf<String, Any?>(
            "display_name" to "Ada Lovelace",
            "locale" to "en-GB",
            "preferences" to mapOf("newsletter" to false, "topics" to listOf("math", "computing")),
        )
        val wallet = AndroidWallet.createWithGeneratedKey(path, password, password)
        try {
            wallet.setMasterAccountEntity(expected)
            val returned = wallet.getMasterAccountEntity()
            assertEquals(expected, returned)
            @Suppress("UNCHECKED_CAST")
            ((returned["preferences"] as Map<String, Any?>)["topics"] as MutableList<String>).add("caller mutation")
            assertEquals(expected, wallet.getMasterAccountEntity())

            val raw = wallet.exportContainer()
            val outer = WalletJson.parse(raw, ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>
            assertEquals(setOf("format", "version", "kdf", "wrap", "payload"), outer.keys)
            assertEquals(BigInteger.valueOf(2), outer["version"])
            assertEquals(setOf("algorithm", "memory_kib", "time_cost", "parallelism", "salt"), (outer["kdf"] as Map<*, *>).keys)
            assertEquals(setOf("algorithm", "nonce", "ciphertext", "tag"), (outer["wrap"] as Map<*, *>).keys)
            assertEquals(setOf("algorithm", "nonce", "ciphertext", "tag"), (outer["payload"] as Map<*, *>).keys)
            // Ciphertext is opaque: this checks envelope confinement, not plaintext absence.
            val entityMethods = WalletSession::class.java.methods
                .filter { it.name.contains("master", ignoreCase = true) }
            assertEquals(2, entityMethods.size)
            val getter = entityMethods.single { it.name == "getMasterAccountEntity" }
            val setter = entityMethods.single { it.name == "setMasterAccountEntity" }
            assertEquals(0, getter.parameterCount)
            assertEquals(Map::class.java, getter.returnType)
            assertEquals(listOf(Map::class.java), setter.parameterTypes.toList())
            assertEquals(Void.TYPE, setter.returnType)
            wallet.close()

            val reopened = AndroidWallet.open(path, password)
            try {
                assertEquals(expected, reopened.getMasterAccountEntity())
                reopened.setMasterAccountEntity(mapOf("display_name" to "Ada Byron"))
                val updated = reopened.exportContainer()
                reopened.close()

                val imported = AndroidWallet.importContainer(importedPath, updated, password)
                try {
                    assertEquals(mapOf("display_name" to "Ada Byron"), imported.getMasterAccountEntity())
                    assertArrayEquals(updated, imported.exportContainer())
                } finally {
                    imported.close()
                    updated.fill(0)
                }
            } finally {
                reopened.close()
            }
        } finally {
            wallet.close()
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun exportedV2PayloadContainsEntityOnlyAtWalletEntityKey() {
        val directory = Files.createTempDirectory("wallet-master-account-entity-payload-")
        val path = directory.resolve("wallet.dw")
        val importedPath = directory.resolve("imported.dw")
        val password = "a sufficiently long test password"
        val marker = "ANDROID_ENTITY_PLAINTEXT_MARKER_" + "z".repeat(160)
        val expected = mapOf("display_name" to marker, "locale" to "en-GB")
        val wallet = AndroidWallet.createWithGeneratedKey(path, password, password)
        var raw: ByteArray? = null
        try {
            val initialPayload = wallet.readPayload()
            val initialPayloadKeys = try {
                assertEquals(setOf("private_seed", "public_key"), initialPayload.keys)
                initialPayload.keys.toSet()
            } finally {
                WalletJson.clearByteArrays(initialPayload)
            }
            wallet.setMasterAccountEntity(expected)
            val updatedPayload = wallet.readPayload()
            try {
                assertEquals(initialPayloadKeys + "master_account_entity", updatedPayload.keys)
                assertEquals(expected, updatedPayload["master_account_entity"])
            } finally {
                WalletJson.clearByteArrays(updatedPayload)
            }
            val exported = wallet.exportContainer()
            raw = exported
            assertFalse(exported.toString(Charsets.UTF_8).contains(marker))
            val imported = AndroidWallet.importContainer(importedPath, exported, password)
            try {
                val payload = imported.readPayload()
                try {
                    assertEquals(initialPayloadKeys + "master_account_entity", payload.keys)
                    assertEquals(expected, payload["master_account_entity"])
                } finally {
                    WalletJson.clearByteArrays(payload)
                }
            } finally {
                imported.close()
            }
        } finally {
            raw?.fill(0)
            wallet.close()
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun lockedWalletCannotReadOrWriteMasterAccountEntity() {
        val directory = Files.createTempDirectory("wallet-master-account-entity-locked-")
        val path = directory.resolve("wallet.dw")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.createWithGeneratedKey(path, password, password)
        val expected = mapOf("locked_marker_long_private_value_9f6c3b1a" to "secret")
        wallet.setMasterAccountEntity(expected)
        val persistedBeforeClose = Files.readAllBytes(path)
        wallet.close()
        try {
            assertThrows(WalletLockedException::class.java) { wallet.getMasterAccountEntity() }
            assertThrows(WalletLockedException::class.java) { wallet.setMasterAccountEntity(mapOf("x" to "y")) }
            assertArrayEquals(persistedBeforeClose, Files.readAllBytes(path))
            val reopened = AndroidWallet.open(path, password)
            try {
                assertEquals(expected, reopened.getMasterAccountEntity())
            } finally {
                reopened.close()
            }
        } finally {
            persistedBeforeClose.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun entityRejectsUnsupportedJsonValuesWithoutChangingStoredState() {
        val directory = Files.createTempDirectory("wallet-master-account-entity-invalid-")
        val path = directory.resolve("wallet.dw")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.createWithGeneratedKey(path, password, password)
        val expected = mapOf("name" to "Ada")
        try {
            wallet.setMasterAccountEntity(expected)
            val before = wallet.exportContainer()
            val invalid = listOf(
                mapOf(1 to "numeric key"),
                mapOf("float" to 1.5),
                mapOf("bytes" to byteArrayOf(1, 2, 3)),
                mapOf("unsupported" to Any()),
            )
            for (candidate in invalid) {
                assertThrows(WalletInvalidContainerException::class.java) {
                    @Suppress("UNCHECKED_CAST")
                    wallet.setMasterAccountEntity(candidate as Map<String, Any?>)
                }
                assertArrayEquals(before, wallet.exportContainer())
                assertEquals(expected, wallet.getMasterAccountEntity())
            }
            before.fill(0)
        } finally {
            wallet.close()
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }
}

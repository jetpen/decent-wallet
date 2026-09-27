package org.decentwallet.wallet.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.math.BigInteger
import java.nio.file.Files
import java.util.LinkedHashMap

class AndroidWalletTest {
    @Test
    fun opensSharedVectorAndLocksItsSession() {
        val vector = resource("/wallet-container-v2.json")
        val container = vectorContainer(vector)
        val directory = Files.createTempDirectory("wallet-android-test-")
        val path = directory.resolve("wallet.dw")
        Files.write(path, container)

        val wallet = AndroidWallet.open(path, "public-test-only: wallet-v2-vector")
        try {
            assertTrue(wallet.isUnlocked)
            val payload = wallet.readPayload()
            try {
                assertEquals(BigInteger.valueOf(7), payload["count"])
                assertEquals("wallet-container-v2-interop-café", payload["label"])
                assertArrayEquals(byteArrayOf(0, -1, 16), payload["opaque"] as ByteArray)
                assertArrayEquals(
                    decodeHex("2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"),
                    payload["public_key"] as ByteArray,
                )
                assertArrayEquals(container, wallet.exportContainer())
            } finally {
                WalletJson.clearByteArrays(payload)
            }
        } finally {
            wallet.lock()
            vector.fill(0)
            container.fill(0)
        }

        assertFalse(wallet.isUnlocked)
        org.junit.Assert.assertThrows(WalletLockedException::class.java) {
            wallet.readPayload()
        }
        directory.toFile().deleteRecursively()
    }

    @Test
    fun createsAndReopensRandomizedV2Container() {
        val directory = Files.createTempDirectory("wallet-android-create-")
        val path = directory.resolve("wallet.dw")
        val payload = mapOf("owner" to "alice", "opaque" to byteArrayOf(4, 5, 6))
        val wallet = AndroidWallet.create(path, "a sufficiently long test password", "a sufficiently long test password", payload)
        val bytes = wallet.exportContainer()
        System.getenv("ANDROID_WALLET_INTEROP_FILE")?.let { output ->
            val outputPath = java.nio.file.Paths.get(output)
            outputPath.parent?.let(Files::createDirectories)
            Files.write(outputPath, bytes)
        }
        val second = AndroidWallet.create(
            directory.resolve("second.dw"),
            "a sufficiently long test password",
            "a sufficiently long test password",
            payload,
        )
        try {
            assertFalse(String(bytes, Charsets.UTF_8).contains("alice"))
            val firstPayload = wallet.readPayload()
            try {
                assertEquals(payload.keys, firstPayload.keys)
            } finally {
                WalletJson.clearByteArrays(firstPayload)
            }
            assertFalse(bytes.contentEquals(second.exportContainer()))
        } finally {
            wallet.lock()
            second.lock()
        }

        val reopened = AndroidWallet.open(path, "a sufficiently long test password")
        try {
            val reopenedPayload = reopened.readPayload()
            try {
                assertEquals("alice", reopenedPayload["owner"])
                assertArrayEquals(byteArrayOf(4, 5, 6), reopenedPayload["opaque"] as ByteArray)
            } finally {
                WalletJson.clearByteArrays(reopenedPayload)
            }
        } finally {
            reopened.close()
            bytes.fill(0)
            Files.walk(directory).sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    @Test
    fun createDoesNotReplaceAnInitializedWallet() {
        val directory = Files.createTempDirectory("wallet-android-no-overwrite-")
        val path = directory.resolve("wallet.dw")
        val existing = AndroidWallet.create(path, "a sufficiently long test password", "a sufficiently long test password", mapOf("owner" to "existing"))
        val before = existing.exportContainer()
        existing.close()

        org.junit.Assert.assertThrows(WalletStorageException::class.java) {
            AndroidWallet.create(path, "a sufficiently long test password", "a sufficiently long test password", mapOf("owner" to "replacement"))
        }
        assertArrayEquals(before, Files.readAllBytes(path))
        val reopened = AndroidWallet.open(path, "a sufficiently long test password")
        try {
            assertEquals("existing", reopened.readPayload()["owner"])
        } finally {
            reopened.close()
            before.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun importCopiesExactEncryptedBytesAndNeverOverwrites() {
        val directory = Files.createTempDirectory("wallet-android-import-")
        val source = directory.resolve("source.dw")
        val destination = directory.resolve("imported.dw")
        val password = "a sufficiently long test password"
        val sourceWallet = AndroidWallet.create(source, password, password, mapOf("owner" to "alice"))
        val exported = sourceWallet.exportContainer()
        sourceWallet.close()

        val imported = AndroidWallet.importContainer(destination, exported, password)
        try {
            assertArrayEquals(exported, Files.readAllBytes(destination))
            assertEquals("alice", imported.readPayload()["owner"])
        } finally {
            imported.close()
        }

        val before = Files.readAllBytes(destination)
        org.junit.Assert.assertThrows(WalletStorageException::class.java) {
            AndroidWallet.importContainer(destination, exported, password)
        }
        assertArrayEquals(before, Files.readAllBytes(destination))
        val reopened = AndroidWallet.open(destination, password)
        try {
            assertEquals("alice", reopened.readPayload()["owner"])
        } finally {
            reopened.close()
            exported.fill(0)
            before.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun explicitMigrationAuthenticatesV1AndWritesV2WithoutChangingPayload() {
        val directory = Files.createTempDirectory("wallet-android-migrate-")
        val path = directory.resolve("wallet.dw")
        val original = resource("/wallet-v1-pending-rotation.dw")
        Files.write(path, original)
        val password = "correct horse battery staple"
        org.junit.Assert.assertThrows(WalletUnsupportedFormatException::class.java) {
            AndroidWallet.open(path, password)
        }

        val migrated = AndroidWallet.migrateContainer(path, password)
        try {
            val currentBytes = Files.readAllBytes(path)
            val envelope = WalletJson.parse(currentBytes, ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>
            assertEquals(BigInteger.valueOf(2), envelope["version"])
            assertFalse(original.contentEquals(currentBytes))
            val payload = migrated.readPayload()
            assertArrayEquals(
                decodeHex("9f8544ce97a2bae6d53c788ca472ca29a58f156ab7cf481f8a6512af86f3c68e"),
                payload["public_key"] as ByteArray,
            )
            assertArrayEquals(
                decodeHex("abd600e02eec04f20e14c73c8c1744a201f5745fa9b00aa85b1c48119d2e4cd9"),
                payload["pending_public_key"] as ByteArray,
            )
            assertEquals(32, (payload["private_seed"] as ByteArray).size)
            assertEquals(32, (payload["pending_private_seed"] as ByteArray).size)
            WalletJson.clearByteArrays(payload)
            currentBytes.fill(0)
        } finally {
            migrated.close()
            original.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun importRejectsLegacyV1WithoutCreatingDestination() {
        val directory = Files.createTempDirectory("wallet-android-import-v1-")
        val source = resource("/wallet-v1-pending-rotation.dw")
        val destination = directory.resolve("wallet.dw")
        org.junit.Assert.assertThrows(WalletUnsupportedFormatException::class.java) {
            AndroidWallet.importContainer(destination, source, "correct horse battery staple")
        }
        assertFalse(Files.exists(destination))
        source.fill(0)
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    @Test
    fun migrationIsOneWayAndDoesNotRewriteAnAlreadyCurrentContainer() {
        val directory = Files.createTempDirectory("wallet-android-migrate-once-")
        val path = directory.resolve("wallet.dw")
        val original = resource("/wallet-v1-pending-rotation.dw")
        Files.write(path, original)
        val migrated = AndroidWallet.migrateContainer(path, "correct horse battery staple")
        migrated.close()
        val v2Bytes = Files.readAllBytes(path)
        org.junit.Assert.assertThrows(WalletUnsupportedFormatException::class.java) {
            AndroidWallet.migrateContainer(path, "correct horse battery staple")
        }
        assertArrayEquals(v2Bytes, Files.readAllBytes(path))
        original.fill(0)
        v2Bytes.fill(0)
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    @Test
    fun wrongPasswordTamperingAndUnknownVersionFailBeforeImportWrite() {
        val directory = Files.createTempDirectory("wallet-android-reject-")
        val source = directory.resolve("source.dw")
        val destination = directory.resolve("imported.dw")
        val password = "a sufficiently long test password"
        val sourceWallet = AndroidWallet.create(source, password, password, mapOf("owner" to "alice"))
        val raw = sourceWallet.exportContainer()
        sourceWallet.close()

        org.junit.Assert.assertThrows(WalletUnlockException::class.java) {
            AndroidWallet.open(source, "a different sufficiently long password")
        }
        org.junit.Assert.assertThrows(WalletUnlockException::class.java) {
            AndroidWallet.importContainer(destination, raw, "a different sufficiently long password")
        }
        assertFalse(Files.exists(destination))

        @Suppress("UNCHECKED_CAST")
        val tamperedEnvelope = WalletJson.parse(raw, ContainerCrypto.MAX_CONTAINER_BYTES) as MutableMap<String, Any?>
        @Suppress("UNCHECKED_CAST")
        val encryptedPayload = tamperedEnvelope["payload"] as MutableMap<String, Any?>
        val ciphertext = encryptedPayload["ciphertext"] as String
        encryptedPayload["ciphertext"] = (if (ciphertext[0] == 'A') "B" else "A") + ciphertext.substring(1)
        val tampered = WalletJson.canonicalBytes(tamperedEnvelope)
        org.junit.Assert.assertThrows(WalletUnlockException::class.java) {
            AndroidWallet.importContainer(destination, tampered, password)
        }
        assertFalse(Files.exists(destination))

        val unsupportedEnvelope = LinkedHashMap(tamperedEnvelope)
        unsupportedEnvelope["version"] = BigInteger.valueOf(3)
        val unsupported = WalletJson.canonicalBytes(unsupportedEnvelope)
        org.junit.Assert.assertThrows(WalletUnsupportedFormatException::class.java) {
            AndroidWallet.importContainer(destination, unsupported, password)
        }
        assertFalse(Files.exists(destination))

        raw.fill(0)
        tampered.fill(0)
        unsupported.fill(0)
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    @Test
    fun duplicateJsonMembersAreRejectedBeforeImportWrite() {
        val vector = resource("/wallet-container-v2.json")
        val container = vectorContainer(vector)
        val text = String(container, Charsets.UTF_8)
        val duplicateText = text.replaceFirst(
            "\"format\":\"decent-wallet\"",
            "\"format\":\"decent-wallet\",\"format\":\"decent-wallet\"",
        )
        val duplicate = duplicateText.toByteArray(Charsets.UTF_8)
        val destination = Files.createTempDirectory("wallet-android-duplicate-").resolve("wallet.dw")
        org.junit.Assert.assertThrows(WalletInvalidContainerException::class.java) {
            AndroidWallet.importContainer(destination, duplicate, "public-test-only: wallet-v2-vector")
        }
        assertFalse(Files.exists(destination))
        vector.fill(0)
        container.fill(0)
        duplicate.fill(0)
        Files.walk(destination.parent).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    @Test
    fun malformedUtf8IsRejectedAsInvalidContainer() {
        val directory = Files.createTempDirectory("wallet-android-invalid-utf8-")
        val path = directory.resolve("wallet.dw")
        val malformed = byteArrayOf(0x7b, 0x22, 0x78, 0x22, 0x3a, 0xc3.toByte(), 0x28, 0x7d)
        Files.write(path, malformed)
        org.junit.Assert.assertThrows(WalletInvalidContainerException::class.java) {
            AndroidWallet.open(path, "a sufficiently long test password")
        }
        malformed.fill(0)
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    @Test
    fun openAndImportRejectIllFormedPasswordUtf16BeforeKdf() {
        val directory = Files.createTempDirectory("wallet-android-password-")
        val path = directory.resolve("wallet.dw")
        val source = AndroidWallet.create(
            path,
            "a sufficiently long test password",
            "a sufficiently long test password",
            mapOf("owner" to "alice"),
        )
        val raw = source.exportContainer()
        source.close()
        val illFormedPassword = "123456789012345\uD800"
        org.junit.Assert.assertThrows(WalletPasswordPolicyException::class.java) {
            AndroidWallet.open(path, illFormedPassword)
        }
        org.junit.Assert.assertThrows(WalletPasswordPolicyException::class.java) {
            AndroidWallet.importContainer(directory.resolve("imported.dw"), raw, illFormedPassword)
        }
        assertFalse(Files.exists(directory.resolve("imported.dw")))
        raw.fill(0)
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    @Test
    fun recoverableMigrationStorageFailureRestoresPriorV1Bytes() {
        val directory = Files.createTempDirectory("wallet-android-migrate-storage-")
        val path = directory.resolve("wallet.dw")
        val original = resource("/wallet-v1-pending-rotation.dw")
        Files.write(path, original)
        val candidate = AndroidWallet.create(
            directory.resolve("candidate.dw"),
            "a sufficiently long test password",
            "a sufficiently long test password",
            mapOf("owner" to "candidate"),
        )
        val replacement = candidate.exportContainer()
        candidate.close()
        var syncCalls = 0
        org.junit.Assert.assertThrows(WalletStorageException::class.java) {
            AtomicWalletFiles.replaceForTest(path, replacement, original) {
                if (syncCalls++ == 0) throw IOException()
            }
        }
        assertArrayEquals(original, Files.readAllBytes(path))
        org.junit.Assert.assertThrows(WalletUnsupportedFormatException::class.java) {
            AndroidWallet.open(path, "correct horse battery staple")
        }
        original.fill(0)
        replacement.fill(0)
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    @Test
    fun unverifiableMigrationRollbackReturnsValueFreeUnknownOutcome() {
        val directory = Files.createTempDirectory("wallet-android-unknown-storage-")
        val path = directory.resolve("wallet.dw")
        val original = resource("/wallet-v1-pending-rotation.dw")
        Files.write(path, original)
        val candidate = AndroidWallet.create(
            directory.resolve("candidate.dw"),
            "a sufficiently long test password",
            "a sufficiently long test password",
            mapOf("owner" to "candidate"),
        )
        val replacement = candidate.exportContainer()
        candidate.close()
        val failure = org.junit.Assert.assertThrows(WalletStorageOutcomeUnknownException::class.java) {
            AtomicWalletFiles.replaceForTest(path, replacement, original) { throw IOException() }
        }
        assertEquals("wallet storage outcome is unknown", failure.message)
        assertFalse(Files.list(directory).use { paths -> paths.anyMatch { it.fileName.toString().endsWith(".tmp") } })
        original.fill(0)
        replacement.fill(0)
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    @Test
    fun failedMigrationAuthenticationPreservesOriginalV1Bytes() {
        val directory = Files.createTempDirectory("wallet-android-migrate-failure-")
        val path = directory.resolve("wallet.dw")
        val original = resource("/wallet-v1-pending-rotation.dw")
        Files.write(path, original)
        org.junit.Assert.assertThrows(WalletUnlockException::class.java) {
            AndroidWallet.migrateContainer(path, "a different sufficiently long password")
        }
        assertArrayEquals(original, Files.readAllBytes(path))
        original.fill(0)
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    @Test
    fun backgroundLocksSessionAndPreventsPayloadAccess() {
        val directory = Files.createTempDirectory("wallet-android-background-")
        val wallet = AndroidWallet.create(
            directory.resolve("wallet.dw"),
            "a sufficiently long test password",
            "a sufficiently long test password",
            mapOf("owner" to "alice"),
        )
        wallet.background()
        assertFalse(wallet.isUnlocked)
        org.junit.Assert.assertThrows(WalletLockedException::class.java) { wallet.readPayload() }
        Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
    }

    private fun decodeHex(value: String): ByteArray = ByteArray(value.length / 2) { index ->
        value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

    private fun resource(name: String): ByteArray =
        checkNotNull(javaClass.getResourceAsStream(name)).use { it.readBytes() }

    private fun vectorContainer(vector: ByteArray): ByteArray {
        val text = String(vector, Charsets.UTF_8)
        val match = Regex("\\\"container_json_utf8_hex\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
            .find(text) ?: error("known-answer vector container is missing")
        val hex = match.groupValues[1]
        return ByteArray(hex.length / 2) { index ->
            hex.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}

package org.decentwallet.wallet.android

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.math.BigInteger
import java.nio.file.Files
import java.util.LinkedHashMap

class AndroidWalletTest {
    @Test
    fun generatedSigningWalletPersistsOnePendingSuccessorAcrossReopen() {
        val directory = Files.createTempDirectory("wallet-android-pending-key-")
        val path = directory.resolve("wallet.dw")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.createWithGeneratedKey(path, password, password)
        val activeBefore = wallet.ownerPublicKey
        val originalBytes = wallet.exportContainer()
        val pending = wallet.prepareSigningKeyRotation()
        val storedBytes = wallet.exportContainer()
        try {
            assertArrayEquals(activeBefore, wallet.ownerPublicKey)
            assertArrayEquals(pending, checkNotNull(wallet.pendingOwnerPublicKey))
            assertArrayEquals(pending, wallet.prepareSigningKeyRotation())
            assertArrayEquals(Files.readAllBytes(path), storedBytes)
            assertTrue(storedBytes.isNotEmpty())
            val originalEnvelope = WalletJson.parse(originalBytes, ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>
            val updatedEnvelope = WalletJson.parse(storedBytes, ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>
            assertEquals(originalEnvelope["kdf"], updatedEnvelope["kdf"])
            assertEquals(originalEnvelope["wrap"], updatedEnvelope["wrap"])
            val originalPayload = originalEnvelope["payload"] as Map<*, *>
            val updatedPayload = updatedEnvelope["payload"] as Map<*, *>
            assertNotEquals(originalPayload["nonce"], updatedPayload["nonce"])
        } finally {
            wallet.close()
        }

        val reopened = AndroidWallet.open(path, password)
        try {
            assertArrayEquals(activeBefore, reopened.ownerPublicKey)
            assertArrayEquals(pending, checkNotNull(reopened.pendingOwnerPublicKey))
            assertArrayEquals(storedBytes, reopened.exportContainer())
        } finally {
            reopened.close()
        }

        val imported = AndroidWallet.importContainer(
            directory.resolve("imported.dw"),
            storedBytes,
            password,
        )
        try {
            assertArrayEquals(activeBefore, imported.ownerPublicKey)
            assertArrayEquals(pending, checkNotNull(imported.pendingOwnerPublicKey))
            assertArrayEquals(storedBytes, imported.exportContainer())
        } finally {
            imported.close()
            originalBytes.fill(0)
            activeBefore.fill(0)
            pending.fill(0)
            storedBytes.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun generatedWalletRejectsCsrngFailureWithoutCreatingFile() {
        val directory = Files.createTempDirectory("wallet-android-csrng-failure-")
        val path = directory.resolve("wallet.dw")
        val failure = org.junit.Assert.assertThrows(WalletKeyGenerationException::class.java) {
            AndroidWallet.createWithGeneratedKeyForTest(
                path,
                "a sufficiently long test password",
                "a sufficiently long test password",
                object : java.security.SecureRandom() {
                    override fun nextBytes(bytes: ByteArray) {
                        throw IllegalStateException("synthetic entropy failure")
                    }
                },
            )
        }
        assertEquals("key generation failed", failure.message)
        assertFalse(Files.exists(path))
        Files.walk(directory).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    @Test
    fun generatedWalletRequestsExactlyOneEd25519SeedFromCsrng() {
        val directory = Files.createTempDirectory("wallet-android-exact-seed-")
        val path = directory.resolve("wallet.dw")
        val password = "a sufficiently long test password"
        val seed = syntheticSeed(128)
        val requests = mutableListOf<Int>()
        val random = object : java.security.SecureRandom() {
            override fun nextBytes(bytes: ByteArray) {
                requests += bytes.size
                seed.copyInto(bytes)
            }
        }
        val wallet = AndroidWallet.createWithGeneratedKeyForTest(path, password, password, random)
        val expectedPublic = AndroidIdentityCrypto.publicKeyFromSeed(seed)
        try {
            assertEquals(listOf(AndroidIdentityCrypto.KEY_BYTES), requests)
            assertArrayEquals(expectedPublic, wallet.ownerPublicKey)
        } finally {
            wallet.close()
            seed.fill(0)
            expectedPublic.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun pendingKeyCsrngFailureLeavesContainerUnchanged() {
        val directory = Files.createTempDirectory("wallet-android-pending-csrng-failure-")
        val path = directory.resolve("wallet.dw")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.createWithGeneratedKey(path, password, password)
        val active = wallet.ownerPublicKey
        val before = wallet.exportContainer()
        try {
            org.junit.Assert.assertThrows(WalletKeyGenerationException::class.java) {
                wallet.prepareSigningKeyRotation(
                    object : java.security.SecureRandom() {
                        override fun nextBytes(bytes: ByteArray) {
                            throw IllegalStateException("synthetic entropy failure")
                        }
                    },
                )
            }
            assertArrayEquals(before, wallet.exportContainer())
            assertArrayEquals(active, wallet.ownerPublicKey)
            assertEquals(null, wallet.pendingOwnerPublicKey)
        } finally {
            wallet.close()
            active.fill(0)
            before.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun unresolvedDispatchIntentBlocksPreparingAnotherSuccessor() {
        val directory = Files.createTempDirectory("wallet-android-latched-rotation-")
        val path = directory.resolve("wallet.dw")
        val password = "a sufficiently long test password"
        val seed = ByteArray(32) { (it + 1).toByte() }
        val publicKey = AndroidIdentityCrypto.publicKeyFromSeed(seed)
        val wallet = AndroidWallet.create(
            path,
            password,
            password,
            mapOf(
                "private_seed" to seed,
                "public_key" to publicKey,
                "pending_private_seed" to ByteArray(32) { (it + 32).toByte() },
                "pending_public_key" to AndroidIdentityCrypto.publicKeyFromSeed(ByteArray(32) { (it + 32).toByte() }),
                "rotation_dispatch_intent" to OwnerKeyRotationDispatchIntent(
                    ownerNameBytes = "synthetic-owner".toByteArray(),
                    predecessorOwnerPublicKey = publicKey,
                    successorOwnerPublicKey = AndroidIdentityCrypto.publicKeyFromSeed(ByteArray(32) { (it + 32).toByte() }),
                    predecessorStateHash = ByteArray(32) { 3 }, sequence = java.math.BigInteger.ONE,
                    environment = "testnet", envelopeHash = ByteArray(32) { 4 },
                ).toPayload(),
            ),
        )
        try {
            org.junit.Assert.assertThrows(WalletRotationInProgressException::class.java) {
                wallet.prepareSigningKeyRotation()
            }
            org.junit.Assert.assertThrows(WalletRotationInProgressException::class.java) {
                wallet.cancelSigningKeyRotation()
            }
            assertArrayEquals(publicKey, wallet.ownerPublicKey)
            assertArrayEquals(AndroidIdentityCrypto.publicKeyFromSeed(ByteArray(32) { (it + 32).toByte() }), wallet.pendingOwnerPublicKey)
        } finally {
            wallet.close()
            seed.fill(0)
            publicKey.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun cancellationPersistsAndKeepsTheActiveKeyAcrossReopen() {
        val directory = Files.createTempDirectory("wallet-android-cancel-key-")
        val path = directory.resolve("wallet.dw")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.createWithGeneratedKey(path, password, password)
        val active = wallet.ownerPublicKey
        val pending = wallet.prepareSigningKeyRotation()
        var cancelledBytes = ByteArray(0)
        try {
            assertTrue(wallet.cancelSigningKeyRotation())
            assertEquals(null, wallet.pendingOwnerPublicKey)
            assertFalse(wallet.cancelSigningKeyRotation())
            assertArrayEquals(active, wallet.ownerPublicKey)
            cancelledBytes = wallet.exportContainer()
            assertArrayEquals(Files.readAllBytes(path), cancelledBytes)
        } finally {
            wallet.close()
        }

        val reopened = AndroidWallet.open(path, password)
        try {
            assertArrayEquals(active, reopened.ownerPublicKey)
            assertEquals(null, reopened.pendingOwnerPublicKey)
            assertArrayEquals(cancelledBytes, reopened.exportContainer())
        } finally {
            reopened.close()
            active.fill(0)
            pending.fill(0)
            cancelledBytes.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun failedCancellationRollsBackAndKeepsPendingKeyUsable() {
        val directory = Files.createTempDirectory("wallet-android-cancel-rollback-")
        val path = directory.resolve("wallet.dw")
        val password = "a sufficiently long test password"
        val setup = AndroidWallet.createWithGeneratedKey(path, password, password)
        val active = setup.ownerPublicKey
        val pending = setup.prepareSigningKeyRotation()
        setup.close()
        val before = Files.readAllBytes(path)
        var syncCalls = 0
        val wallet = openWithFileReplacement(path, password) { target, bytes, expected ->
            AtomicWalletFiles.replaceForTest(target, bytes, expected) {
                syncCalls++
                if (syncCalls == 1) throw IOException("synthetic directory sync failure")
            }
        }
        try {
            org.junit.Assert.assertThrows(WalletStorageException::class.java) {
                wallet.cancelSigningKeyRotation()
            }
            assertTrue(wallet.isUnlocked)
            assertArrayEquals(active, wallet.ownerPublicKey)
            assertArrayEquals(pending, checkNotNull(wallet.pendingOwnerPublicKey))
            assertArrayEquals(before, Files.readAllBytes(path))
        } finally {
            wallet.close()
        }
        val reopened = AndroidWallet.open(path, password)
        try {
            assertArrayEquals(active, reopened.ownerPublicKey)
            assertArrayEquals(pending, checkNotNull(reopened.pendingOwnerPublicKey))
        } finally {
            reopened.close()
            active.fill(0)
            pending.fill(0)
            before.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun unknownCancellationOutcomeLocksAndClearsTheSession() {
        val directory = Files.createTempDirectory("wallet-android-cancel-unknown-")
        val path = directory.resolve("wallet.dw")
        val password = "a sufficiently long test password"
        val setup = AndroidWallet.createWithGeneratedKey(path, password, password)
        setup.prepareSigningKeyRotation().fill(0)
        setup.close()
        val wallet = openWithFileReplacement(path, password) { target, bytes, expected ->
            AtomicWalletFiles.replaceForTest(target, bytes, expected) {
                throw IOException("synthetic directory sync failure")
            }
        }
        org.junit.Assert.assertThrows(WalletStorageOutcomeUnknownException::class.java) {
            wallet.cancelSigningKeyRotation()
        }
        assertFalse(wallet.isUnlocked)
        org.junit.Assert.assertThrows(WalletLockedException::class.java) {
            wallet.ownerPublicKey
        }
        wallet.close()
        Files.walk(directory).use { paths ->
            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    @Test
    fun verifiedLegacyOperation5VectorProducesExactUpdateAndEnvelope() {
        val vector = resource("/identity-owner-key-rotation-legacy.json")
        val vectorText = String(vector, Charsets.UTF_8)
        val ownerName = decodeHex(jsonHexField(vectorText, "owner_name_utf8_hex"))
        val predecessorEnvelope = decodeHex(jsonHexField(vectorText, "predecessor_envelope_cbor_hex"))
        val expectedStateHash = decodeHex(jsonHexField(vectorText, "predecessor_state_hash_hex"))
        val expectedUpdate = decodeHex(jsonHexField(vectorText, "candidate_signed_update_cbor_hex"))
        val expectedEnvelope = decodeHex(jsonHexField(vectorText, "candidate_envelope_cbor_hex"))
        val activeSeed = syntheticSeed(0)
        val successorSeed = syntheticSeed(32)
        val bobSeed = syntheticSeed(64)
        val carolSeed = syntheticSeed(96)
        val activePublic = AndroidIdentityCrypto.publicKeyFromSeed(activeSeed)
        val successorPublic = AndroidIdentityCrypto.publicKeyFromSeed(successorSeed)
        val bobPublic = AndroidIdentityCrypto.publicKeyFromSeed(bobSeed)
        val carolPublic = AndroidIdentityCrypto.publicKeyFromSeed(carolSeed)
        val directory = Files.createTempDirectory("wallet-android-operation5-vector-")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.create(
            directory.resolve("wallet.dw"),
            password,
            password,
            mapOf(
                "private_seed" to activeSeed,
                "public_key" to activePublic,
                "pending_private_seed" to successorSeed,
                "pending_public_key" to successorPublic,
            ),
        )
        try {
            val draft = wallet.createLegacyOwnerKeyRotationDraft(
                ownerName,
                predecessorEnvelope,
                listOf(
                    IdentityRotationSigner("alice-next", successorPublic),
                    IdentityRotationSigner("bob", bobPublic),
                    IdentityRotationSigner("carol", carolPublic),
                ),
            )
            assertArrayEquals(ownerName, draft.ownerNameBytes)
            assertArrayEquals(expectedStateHash, draft.predecessorStateHash)
            assertEquals(BigInteger.valueOf(8), draft.sequence)
            assertArrayEquals(successorPublic, draft.successorOwnerPublicKey)
            assertArrayEquals(expectedUpdate, draft.signedUpdateBytes)
            assertArrayEquals(expectedEnvelope, draft.envelopeBytes)
            assertArrayEquals(activePublic, wallet.ownerPublicKey)
            assertArrayEquals(successorPublic, checkNotNull(wallet.pendingOwnerPublicKey))
        } finally {
            wallet.close()
            vector.fill(0)
            ownerName.fill(0)
            predecessorEnvelope.fill(0)
            expectedStateHash.fill(0)
            expectedUpdate.fill(0)
            expectedEnvelope.fill(0)
            activeSeed.fill(0)
            successorSeed.fill(0)
            bobSeed.fill(0)
            carolSeed.fill(0)
            activePublic.fill(0)
            successorPublic.fill(0)
            bobPublic.fill(0)
            carolPublic.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun legacyRotationDraftRejectsDifferentOwnerNameBytes() {
        val vector = resource("/identity-owner-key-rotation-legacy.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = decodeHex(jsonHexField(text, "owner_name_utf8_hex"))
        val predecessor = decodeHex(jsonHexField(text, "predecessor_envelope_cbor_hex"))
        val mismatchedName = ownerName.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        val directory = Files.createTempDirectory("wallet-android-owner-name-mismatch-")
        val wallet = createRotationTestWallet(directory)
        try {
            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                wallet.createLegacyOwnerKeyRotationDraft(mismatchedName, predecessor, rotationSigners())
            }
        } finally {
            wallet.close()
            vector.fill(0)
            ownerName.fill(0)
            predecessor.fill(0)
            mismatchedName.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun legacyRotationDraftRejectsInvalidPredecessorSignature() {
        val vector = resource("/identity-owner-key-rotation-legacy.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = decodeHex(jsonHexField(text, "owner_name_utf8_hex"))
        val predecessor = decodeHex(jsonHexField(text, "predecessor_envelope_cbor_hex"))
        val tampered = predecessor.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        val directory = Files.createTempDirectory("wallet-android-bad-predecessor-")
        val wallet = createRotationTestWallet(directory)
        try {
            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                wallet.createLegacyOwnerKeyRotationDraft(ownerName, tampered, rotationSigners())
            }
        } finally {
            wallet.close()
            vector.fill(0)
            ownerName.fill(0)
            predecessor.fill(0)
            tampered.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun legacyRotationDraftRequiresThePersistedPendingKey() {
        val vector = resource("/identity-owner-key-rotation-legacy.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = decodeHex(jsonHexField(text, "owner_name_utf8_hex"))
        val predecessor = decodeHex(jsonHexField(text, "predecessor_envelope_cbor_hex"))
        val directory = Files.createTempDirectory("wallet-android-no-pending-key-")
        val wallet = createRotationTestWallet(directory, pendingSeedStart = null)
        try {
            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                wallet.createLegacyOwnerKeyRotationDraft(ownerName, predecessor, rotationSigners())
            }
        } finally {
            wallet.close()
            vector.fill(0)
            ownerName.fill(0)
            predecessor.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun legacyRotationDraftRequiresTheActiveKeyToAuthorizePredecessor() {
        val vector = resource("/identity-owner-key-rotation-legacy.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = decodeHex(jsonHexField(text, "owner_name_utf8_hex"))
        val predecessor = decodeHex(jsonHexField(text, "predecessor_envelope_cbor_hex"))
        val directory = Files.createTempDirectory("wallet-android-wrong-active-key-")
        val wallet = createRotationTestWallet(directory, activeSeedStart = 64, pendingSeedStart = 32)
        try {
            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                wallet.createLegacyOwnerKeyRotationDraft(ownerName, predecessor, rotationSigners())
            }
        } finally {
            wallet.close()
            vector.fill(0)
            ownerName.fill(0)
            predecessor.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun legacyRotationDraftRejectsDuplicateSignerIds() {
        val vector = resource("/identity-owner-key-rotation-legacy.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = decodeHex(jsonHexField(text, "owner_name_utf8_hex"))
        val predecessor = decodeHex(jsonHexField(text, "predecessor_envelope_cbor_hex"))
        val signers = rotationSigners()
        val duplicateIds = listOf(
            signers[0],
            signers[1],
            IdentityRotationSigner("bob", signers[2].publicKey),
        )
        val directory = Files.createTempDirectory("wallet-android-duplicate-signer-id-")
        val wallet = createRotationTestWallet(directory)
        try {
            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                wallet.createLegacyOwnerKeyRotationDraft(ownerName, predecessor, duplicateIds)
            }
        } finally {
            wallet.close()
            vector.fill(0)
            ownerName.fill(0)
            predecessor.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun legacyRotationDraftRejectsNonCanonicalPredecessorEncoding() {
        val vector = resource("/identity-owner-key-rotation-legacy.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = decodeHex(jsonHexField(text, "owner_name_utf8_hex"))
        val predecessor = decodeHex(jsonHexField(text, "predecessor_envelope_cbor_hex"))
        val nonCanonical = byteArrayOf(0xb9.toByte(), 0, 2) + predecessor.copyOfRange(1, predecessor.size)
        val directory = Files.createTempDirectory("wallet-android-noncanonical-predecessor-")
        val wallet = createRotationTestWallet(directory)
        try {
            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                wallet.createLegacyOwnerKeyRotationDraft(ownerName, nonCanonical, rotationSigners())
            }
        } finally {
            wallet.close()
            vector.fill(0)
            ownerName.fill(0)
            predecessor.fill(0)
            nonCanonical.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun legacyRotationDraftRejectsVersionOnePredecessorWithoutFullHistory() {
        val vector = resource("/identity-owner-key-rotation-legacy.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = decodeHex(jsonHexField(text, "owner_name_utf8_hex"))
        val versionOneEnvelope = decodeHex(jsonHexField(text, "candidate_envelope_cbor_hex"))
        val directory = Files.createTempDirectory("wallet-android-v1-predecessor-")
        val wallet = createRotationTestWallet(directory)
        try {
            org.junit.Assert.assertThrows(WalletUnsupportedIdentityStateException::class.java) {
                wallet.createLegacyOwnerKeyRotationDraft(ownerName, versionOneEnvelope, rotationSigners())
            }
        } finally {
            wallet.close()
            vector.fill(0)
            ownerName.fill(0)
            versionOneEnvelope.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

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

    private fun createRotationTestWallet(
        directory: java.nio.file.Path,
        activeSeedStart: Int = 0,
        pendingSeedStart: Int? = 32,
    ): WalletSession {
        val activeSeed = syntheticSeed(activeSeedStart)
        val activePublic = AndroidIdentityCrypto.publicKeyFromSeed(activeSeed)
        val payload = mutableMapOf<String, Any?>(
            "private_seed" to activeSeed,
            "public_key" to activePublic,
        )
        val pendingSeed = pendingSeedStart?.let(::syntheticSeed)
        val pendingPublic = pendingSeed?.let(AndroidIdentityCrypto::publicKeyFromSeed)
        if (pendingSeed != null && pendingPublic != null) {
            payload["pending_private_seed"] = pendingSeed
            payload["pending_public_key"] = pendingPublic
        }
        return try {
            AndroidWallet.create(
                directory.resolve("wallet.dw"),
                "a sufficiently long test password",
                "a sufficiently long test password",
                payload,
            )
        } finally {
            WalletJson.clearByteArrays(payload)
            payload.clear()
        }
    }

    private fun rotationSigners(): List<IdentityRotationSigner> {
        val seeds = listOf(syntheticSeed(32), syntheticSeed(64), syntheticSeed(96))
        val publicKeys = seeds.map(AndroidIdentityCrypto::publicKeyFromSeed)
        return try {
            listOf(
                IdentityRotationSigner("alice-next", publicKeys[0]),
                IdentityRotationSigner("bob", publicKeys[1]),
                IdentityRotationSigner("carol", publicKeys[2]),
            )
        } finally {
            seeds.forEach { it.fill(0) }
            publicKeys.forEach { it.fill(0) }
        }
    }

    private fun syntheticSeed(start: Int): ByteArray = ByteArray(32) { index -> (start + index).toByte() }

    private fun jsonHexField(source: String, name: String): String =
        Regex("\\\"${Regex.escape(name)}\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
            .find(source)?.groupValues?.get(1) ?: error("missing public rotation-vector field")

    private fun openWithFileReplacement(
        path: java.nio.file.Path,
        password: String,
        replaceFile: (java.nio.file.Path, ByteArray, ByteArray) -> Unit,
    ): WalletSession {
        val raw = AtomicWalletFiles.read(path)
        val opened = ContainerCrypto.open(raw, password)
        return WalletSession(path, raw, opened.dek, opened.payload, replaceFile)
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

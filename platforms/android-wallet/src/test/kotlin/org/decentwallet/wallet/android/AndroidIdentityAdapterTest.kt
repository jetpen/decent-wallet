package org.decentwallet.wallet.android

import java.nio.file.Files
import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidIdentityAdapterTest {
    @Test
    fun consentLatchConditionalDispatchAndFreshReadbackPromoteSuccessor() {
        val directory = Files.createTempDirectory("wallet-android-registry-")
        val vector = resource("/identity-owner-key-rotation-legacy.json")
        val vectorText = String(vector, Charsets.UTF_8)
        val ownerName = hexField(vectorText, "owner_name_utf8_hex")
        val predecessor = hexField(vectorText, "predecessor_envelope_cbor_hex")
        val expectedEnvelope = hexField(vectorText, "candidate_envelope_cbor_hex")
        val predecessorHash = hexField(vectorText, "predecessor_state_hash_hex")
        val activeSeed = syntheticSeed(0)
        val pendingSeed = syntheticSeed(32)
        val activePublic = AndroidIdentityCrypto.publicKeyFromSeed(activeSeed)
        val pendingPublic = AndroidIdentityCrypto.publicKeyFromSeed(pendingSeed)
        val signerSeeds = listOf(syntheticSeed(32), syntheticSeed(64), syntheticSeed(96))
        val signerKeys = signerSeeds.map(AndroidIdentityCrypto::publicKeyFromSeed)
        val payload = mutableMapOf<String, Any?>(
            "private_seed" to activeSeed,
            "public_key" to activePublic.copyOf(),
            "pending_private_seed" to pendingSeed,
            "pending_public_key" to pendingPublic.copyOf(),
        )
        val path = directory.resolve("wallet.dw")
        val wallet = try {
            AndroidWallet.create(
                path,
                TEST_PASSWORD,
                TEST_PASSWORD,
                payload,
            )
        } finally {
            WalletJson.clearByteArrays(payload)
            signerSeeds.forEach { it.fill(0) }
            activeSeed.fill(0)
            pendingSeed.fill(0)
        }
        val signers = listOf(
            IdentityRotationSigner("alice-next", signerKeys[0]),
            IdentityRotationSigner("bob", signerKeys[1]),
            IdentityRotationSigner("carol", signerKeys[2]),
        )
        signerKeys.forEach { it.fill(0) }

        try {
            val draft = wallet.createLegacyOwnerKeyRotationDraft(ownerName, predecessor, signers)
            assertArrayEquals(expectedEnvelope, draft.envelopeBytes)
            val transport = FakeIdentityTransport(ownerName, predecessor, predecessorHash)
            transport.beforeWrite = { assertNotNull(wallet.ownerKeyRotationDispatchIntent) }
            val adapter = AndroidIdentityAdapter(transport, InMemoryReplayNonceStore())
            var reviewedEnvelope: ByteArray? = null
            var consentTranscript: OwnerKeyRotationConsentTranscript? = null
            val publication = adapter.prepareOwnerKeyRotationPublication(
                draft = draft,
                consent = { transcript ->
                    consentTranscript = transcript
                    reviewedEnvelope = transcript.reviewEnvelopeBytes
                    true
                },
                authenticatedOrigin = "https://wallet.example",
                environment = "testnet",
                purpose = "publish owner-key rotation",
                capability = "identity.rotate-owner-key",
                expiresAt = 2_000_000_000L,
                replayNonce = hexField(vectorText, "consent_replay_nonce_hex"),
            )

            assertArrayEquals(expectedEnvelope, reviewedEnvelope)
            val transcript = checkNotNull(consentTranscript)
            assertArrayEquals(
                hexField(vectorText, "consent_transcript_cbor_hex"),
                transcript.canonicalBytes(),
            )
            assertArrayEquals(
                hexField(vectorText, "consent_transcript_digest_hex"),
                transcript.digest(),
            )
            assertArrayEquals(expectedEnvelope, publication.envelopeBytes)
            assertEquals(0, transport.writeCount)
            assertNull(wallet.ownerKeyRotationDispatchIntent)

            val permit = wallet.latchOwnerKeyRotationDispatchIntent(publication)
            val intent = permit.intent
            assertNotNull(wallet.ownerKeyRotationDispatchIntent)
            assertArrayEquals(expectedEnvelope.let(AndroidIdentityCrypto::sha256), intent.envelopeHash)
            val encryptedContainer = wallet.exportContainer()
            try {
                assertTrue(!String(encryptedContainer, Charsets.UTF_8).contains("rotation_dispatch_intent"))
            } finally {
                encryptedContainer.fill(0)
            }

            val result = adapter.dispatchOwnerKeyRotation(publication, permit)
            assertEquals(OwnerKeyRotationDispatchStatus.CONFIRMED, result.status)
            assertEquals(1, transport.writeCount)
            assertEquals(1, transport.remoteReadCount)
            val confirmation = checkNotNull(result.confirmation)
            assertEquals(activePublic.toList(), wallet.ownerPublicKey.toList())
            assertEquals(pendingPublic.toList(), wallet.pendingOwnerPublicKey?.toList())
            assertEquals(intent, wallet.ownerKeyRotationDispatchIntent)

            wallet.finalizeSigningKeyRotation(confirmation)
            assertArrayEquals(pendingPublic, wallet.ownerPublicKey)
            assertNull(wallet.pendingOwnerPublicKey)
            assertNull(wallet.ownerKeyRotationDispatchIntent)
            assertTrue(transport.remoteEnvelope!!.contentEquals(expectedEnvelope))
        } finally {
            wallet.close()
            vector.fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun ambiguousDispatchRemainsLatchedAndReopenUsesOnlyFreshReadback() {
        val fixture = createFixture()
        var reopened: WalletSession? = null
        try {
            fixture.transport.dropWrites = true
            val publication = prepare(fixture, "ambiguous-dispatch")
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            val intent = permit.intent

            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)
            assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
            assertNull(result.confirmation)
            assertNull(result.rejection)
            assertEquals(1, fixture.transport.writeCount)
            assertEquals(intent, fixture.wallet.ownerKeyRotationDispatchIntent)
            assertArrayEquals(fixture.activePublicKey, fixture.wallet.ownerPublicKey)
            assertArrayEquals(fixture.successorPublicKey, fixture.wallet.pendingOwnerPublicKey)

            fixture.wallet.close()
            reopened = AndroidWallet.open(fixture.path, TEST_PASSWORD)
            val persistedIntent = checkNotNull(reopened.ownerKeyRotationDispatchIntent)
            assertEquals("testnet", persistedIntent.environment)
            assertEquals(intent, persistedIntent)
            assertNull(fixture.adapter.confirmOwnerKeyRotation(persistedIntent))
            assertEquals(1, fixture.transport.writeCount)

            val corruptedRemote = fixture.expectedEnvelope.copyOf()
            corruptedRemote[corruptedRemote.lastIndex] = (corruptedRemote.last().toInt() xor 1).toByte()
            fixture.transport.setRemoteEnvelope(corruptedRemote)
            corruptedRemote.fill(0)
            assertNull(fixture.adapter.confirmOwnerKeyRotation(persistedIntent))

            // Advance only the independent remote peer; the transport's local head remains old.
            fixture.transport.setRemoteEnvelope(fixture.expectedEnvelope)
            fixture.transport.hideHistory = true
            assertNull(fixture.adapter.confirmOwnerKeyRotation(persistedIntent))
            fixture.transport.hideHistory = false
            val confirmation = checkNotNull(fixture.adapter.confirmOwnerKeyRotation(persistedIntent))
            reopened.finalizeSigningKeyRotation(confirmation)
            assertArrayEquals(fixture.successorPublicKey, reopened.ownerPublicKey)
            assertNull(reopened.pendingOwnerPublicKey)
            assertNull(reopened.ownerKeyRotationDispatchIntent)
            assertArrayEquals(fixture.predecessorEnvelope, fixture.transport.getIdentityEnvelope(fixture.ownerName))
            assertEquals(1, fixture.transport.writeCount)
        } finally {
            reopened?.close()
            fixture.close()
        }
    }

    @Test
    fun alreadyAcceptedCandidateFromAnotherCopyConfirmsInsteadOfIssuingClearableRejection() {
        val fixture = createFixture()
        try {
            val publication = prepare(fixture, "same-candidate-other-copy")
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            fixture.transport.setCurrentEnvelope(fixture.expectedEnvelope)
            fixture.transport.setRemoteEnvelope(fixture.expectedEnvelope)

            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)

            assertEquals(OwnerKeyRotationDispatchStatus.CONFIRMED, result.status)
            assertNotNull(result.confirmation)
            assertNull(result.rejection)
            assertEquals(0, fixture.transport.writeCount)
            assertEquals(1, fixture.transport.remoteReadCount)
            fixture.wallet.finalizeSigningKeyRotation(checkNotNull(result.confirmation))
            assertArrayEquals(fixture.successorPublicKey, fixture.wallet.ownerPublicKey)
            assertNull(fixture.wallet.pendingOwnerPublicKey)
        } finally {
            fixture.close()
        }
    }

    @Test
    fun conditionalPreconditionReadbackOfExactCandidateConfirmsWithoutRetry() {
        val fixture = createFixture()
        try {
            val publication = prepare(fixture, "conditional-copy-readback")
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            fixture.transport.rejectConditional = true
            fixture.transport.setRemoteEnvelope(fixture.expectedEnvelope)

            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)

            assertEquals(OwnerKeyRotationDispatchStatus.CONFIRMED, result.status)
            assertNotNull(result.confirmation)
            assertNull(result.rejection)
            assertEquals(1, fixture.transport.writeCount)
            assertEquals(1, fixture.transport.remoteReadCount)
            fixture.wallet.finalizeSigningKeyRotation(checkNotNull(result.confirmation))
            assertArrayEquals(fixture.successorPublicKey, fixture.wallet.ownerPublicKey)
            assertNull(fixture.wallet.pendingOwnerPublicKey)
        } finally {
            fixture.close()
        }
    }

    @Test
    fun candidateWithoutPredecessorHistoryRemainsUnknownAfterConditionalPrecondition() {
        val fixture = createFixture()
        try {
            val publication = prepare(fixture, "conditional-candidate-history-hidden")
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            fixture.transport.rejectConditional = true
            fixture.transport.setRemoteEnvelope(fixture.expectedEnvelope)
            fixture.transport.hideHistory = true

            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)

            assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
            assertNull(result.confirmation)
            assertNull(result.rejection)
            assertEquals(1, fixture.transport.writeCount)
            assertEquals(1, fixture.transport.remoteReadCount)
            assertEquals(permit.intent, fixture.wallet.ownerKeyRotationDispatchIntent)
        } finally {
            fixture.close()
        }
    }

    @Test
    fun conditionalPreconditionWithoutCandidateReadbackRemainsLatched() {
        val fixture = createFixture()
        try {
            val publication = prepare(fixture, "conditional-other-copy-not-visible")
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            fixture.transport.rejectConditional = true

            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)

            assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
            assertNull(result.rejection)
            assertEquals(1, fixture.transport.writeCount)
            assertEquals(1, fixture.transport.remoteReadCount)
            assertEquals(permit.intent, fixture.wallet.ownerKeyRotationDispatchIntent)
            org.junit.Assert.assertThrows(WalletRotationInProgressException::class.java) {
                fixture.wallet.cancelSigningKeyRotation()
            }
        } finally {
            fixture.close()
        }
    }

    @Test
    fun prewriteExpiryRejectionClearsOnlyItsPermitAndRequiresNewConsent() {
        val fixture = createFixture()
        try {
            fixture.transport.rejectExpired = true
            val firstPublication = prepare(fixture, "first-prewrite-attempt")
            val firstPermit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(firstPublication)
            val firstRejection = checkNotNull(
                fixture.adapter.dispatchOwnerKeyRotation(firstPublication, firstPermit).rejection,
            )
            assertEquals(OwnerKeyRotationDispatchStatus.EXPIRED, firstRejection.status)
            assertEquals(firstPermit.intent, fixture.wallet.ownerKeyRotationDispatchIntent)

            fixture.wallet.resolveOwnerKeyRotationDispatchRejection(firstRejection)
            assertNull(fixture.wallet.ownerKeyRotationDispatchIntent)
            assertArrayEquals(fixture.activePublicKey, fixture.wallet.ownerPublicKey)
            assertArrayEquals(fixture.successorPublicKey, fixture.wallet.pendingOwnerPublicKey)

            val nextPublication = prepare(fixture, "second-prewrite-attempt")
            val nextPermit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(nextPublication)
            assertEquals(firstPermit.intent, nextPermit.intent)
            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                fixture.wallet.resolveOwnerKeyRotationDispatchRejection(firstRejection)
            }
            assertEquals(nextPermit.intent, fixture.wallet.ownerKeyRotationDispatchIntent)

            val secondRejection = checkNotNull(
                fixture.adapter.dispatchOwnerKeyRotation(nextPublication, nextPermit).rejection,
            )
            fixture.wallet.resolveOwnerKeyRotationDispatchRejection(secondRejection)
            assertNull(fixture.wallet.ownerKeyRotationDispatchIntent)
            assertEquals(2, fixture.transport.writeCount)
        } finally {
            fixture.close()
        }
    }

    @Test
    fun lostPrewriteRejectionAfterReopenRemainsFailClosed() {
        val fixture = createFixture()
        var reopened: WalletSession? = null
        try {
            fixture.transport.rejectExpired = true
            val publication = prepare(fixture, "lost-rejection")
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)
            assertEquals(OwnerKeyRotationDispatchStatus.EXPIRED, result.status)
            assertNotNull(result.rejection)

            // Simulate losing the one-use local rejection capability before resolving it.
            fixture.wallet.close()
            reopened = AndroidWallet.open(fixture.path, TEST_PASSWORD)
            val intent = checkNotNull(reopened.ownerKeyRotationDispatchIntent)
            assertEquals(permit.intent, intent)
            assertNull(fixture.adapter.confirmOwnerKeyRotation(intent))
            org.junit.Assert.assertThrows(WalletRotationInProgressException::class.java) {
                reopened.cancelSigningKeyRotation()
            }
            assertArrayEquals(fixture.activePublicKey, reopened.ownerPublicKey)
            assertArrayEquals(fixture.successorPublicKey, reopened.pendingOwnerPublicKey)
            assertEquals(1, fixture.transport.writeCount)
        } finally {
            reopened?.close()
            fixture.close()
        }
    }

    @Test
    fun latchedIntentCannotDispatchOrConfirmOnDifferentEnvironment() {
        val fixture = createFixture()
        try {
            val publication = prepare(fixture, "environment-binding")
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            fixture.transport.registryEnvironment = "mainnet"

            assertNull(fixture.adapter.confirmOwnerKeyRotation(permit.intent))
            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)
            assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
            assertNull(result.rejection)
            assertEquals(0, fixture.transport.writeCount)
            assertEquals(0, fixture.transport.remoteReadCount)
            assertEquals(permit.intent, fixture.wallet.ownerKeyRotationDispatchIntent)

            fixture.transport.registryEnvironment = "testnet"
            assertNull(fixture.adapter.confirmOwnerKeyRotation(permit.intent))
            org.junit.Assert.assertThrows(WalletRotationInProgressException::class.java) {
                fixture.wallet.cancelSigningKeyRotation()
            }
        } finally {
            fixture.close()
        }
    }

    @Test
    fun transientCapabilityChangeDoesNotMintClearableRejection() {
        val fixture = createFixture()
        try {
            val publication = prepare(fixture, "transient-capability-change")
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            fixture.transport.supportReadSequence = mutableListOf(false, true)

            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)

            assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
            assertNull(result.rejection)
            assertEquals(0, fixture.transport.writeCount)
            assertEquals(1, fixture.transport.remoteReadCount)
            assertEquals(permit.intent, fixture.wallet.ownerKeyRotationDispatchIntent)
        } finally {
            fixture.close()
        }
    }

    @Test
    fun transientEnvironmentChangeDoesNotMintClearableRejection() {
        val fixture = createFixture()
        try {
            val publication = prepare(fixture, "transient-environment-change")
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            fixture.transport.environmentReadSequence = mutableListOf("mainnet", "testnet")

            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)

            assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
            assertNull(result.rejection)
            assertEquals(0, fixture.transport.writeCount)
            assertEquals(1, fixture.transport.remoteReadCount)
            assertEquals(permit.intent, fixture.wallet.ownerKeyRotationDispatchIntent)
        } finally {
            fixture.close()
        }
    }

    @Test
    fun unsupportedTransportAndTamperedCandidateFailBeforeConsent() {
        val fixture = createFixture()
        try {
            var consentCalls = 0
            fixture.transport.supportsOwnerKeyRotation = false
            org.junit.Assert.assertThrows(WalletRotationTransportUnavailableException::class.java) {
                fixture.adapter.prepareOwnerKeyRotationPublication(
                    draft = fixture.draft,
                    consent = { consentCalls += 1; true },
                    authenticatedOrigin = "https://wallet.example",
                    environment = "testnet",
                    purpose = "publish owner-key rotation",
                    capability = "identity.rotate-owner-key",
                    expiresAt = System.currentTimeMillis() / 1000 + 3600,
                    replayNonce = ByteArray(32) { (it + 71).toByte() },
                )
            }
            assertEquals(0, consentCalls)
            fixture.transport.supportsOwnerKeyRotation = true
            fixture.transport.registryEnvironment = "mainnet"
            org.junit.Assert.assertThrows(WalletIdentityEnvironmentMismatchException::class.java) {
                fixture.adapter.prepareOwnerKeyRotationPublication(
                    draft = fixture.draft,
                    consent = { consentCalls += 1; true },
                    authenticatedOrigin = "https://wallet.example",
                    environment = "testnet",
                    purpose = "publish owner-key rotation",
                    capability = "identity.rotate-owner-key",
                    expiresAt = System.currentTimeMillis() / 1000 + 3600,
                    replayNonce = ByteArray(32) { (it + 77).toByte() },
                )
            }
            assertEquals(0, consentCalls)
            fixture.transport.registryEnvironment = "testnet"

            val corruptedEnvelope = fixture.draft.envelopeBytes
            corruptedEnvelope[corruptedEnvelope.lastIndex] =
                (corruptedEnvelope.last().toInt() xor 1).toByte()
            val invalidDraft = OwnerKeyRotationDraft(
                ownerNameBytes = fixture.draft.ownerNameBytes,
                predecessorOwnerPublicKey = fixture.draft.predecessorOwnerPublicKey,
                successorOwnerPublicKey = fixture.draft.successorOwnerPublicKey,
                predecessorStateHash = fixture.draft.predecessorStateHash,
                sequence = fixture.draft.sequence,
                signedUpdateBytes = fixture.draft.signedUpdateBytes,
                envelopeBytes = corruptedEnvelope,
            )
            corruptedEnvelope.fill(0)
            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                fixture.adapter.prepareOwnerKeyRotationPublication(
                    draft = invalidDraft,
                    consent = { consentCalls += 1; true },
                    authenticatedOrigin = "https://wallet.example",
                    environment = "testnet",
                    purpose = "publish owner-key rotation",
                    capability = "identity.rotate-owner-key",
                    expiresAt = System.currentTimeMillis() / 1000 + 3600,
                    replayNonce = ByteArray(32) { (it + 83).toByte() },
                )
            }
            assertEquals(0, consentCalls)
            assertEquals(0, fixture.transport.writeCount)
            assertNull(fixture.wallet.ownerKeyRotationDispatchIntent)
        } finally {
            fixture.close()
        }
    }

    @Test
    fun latchPersistenceFailureDoesNotAllowNetworkWriteOrLeaveIntent() {
        val fixture = createFixture()
        var failingWallet: WalletSession? = null
        var reopened: WalletSession? = null
        try {
            val publication = prepare(fixture, "latch-storage-failure")
            fixture.wallet.close()
            failingWallet = openWithFileReplacement(fixture.path) { _, _, _ ->
                throw WalletStorageException()
            }
            org.junit.Assert.assertThrows(WalletStorageException::class.java) {
                failingWallet.latchOwnerKeyRotationDispatchIntent(publication)
            }
            assertNull(failingWallet.ownerKeyRotationDispatchIntent)
            assertArrayEquals(fixture.activePublicKey, failingWallet.ownerPublicKey)
            assertArrayEquals(fixture.successorPublicKey, failingWallet.pendingOwnerPublicKey)
            assertEquals(0, fixture.transport.writeCount)

            failingWallet.close()
            reopened = AndroidWallet.open(fixture.path, TEST_PASSWORD)
            assertNull(reopened.ownerKeyRotationDispatchIntent)
            assertArrayEquals(fixture.activePublicKey, reopened.ownerPublicKey)
            assertArrayEquals(fixture.successorPublicKey, reopened.pendingOwnerPublicKey)
        } finally {
            failingWallet?.close()
            reopened?.close()
            fixture.close()
        }
    }

    @Test
    fun promotionStorageFailurePreservesBothKeysAndLatchedIntent() {
        val fixture = createFixture()
        var failingWallet: WalletSession? = null
        var reopened: WalletSession? = null
        var originalContainer: ByteArray? = null
        try {
            val publication = prepare(fixture, "promotion-storage-failure")
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)
            val confirmation = checkNotNull(result.confirmation)
            originalContainer = fixture.wallet.exportContainer()
            fixture.wallet.close()

            failingWallet = openWithFileReplacement(fixture.path) { _, _, _ ->
                throw WalletStorageException()
            }
            org.junit.Assert.assertThrows(WalletStorageException::class.java) {
                failingWallet.finalizeSigningKeyRotation(confirmation)
            }
            assertArrayEquals(originalContainer, failingWallet.exportContainer())
            assertArrayEquals(fixture.activePublicKey, failingWallet.ownerPublicKey)
            assertArrayEquals(fixture.successorPublicKey, failingWallet.pendingOwnerPublicKey)
            assertEquals(permit.intent, failingWallet.ownerKeyRotationDispatchIntent)

            failingWallet.close()
            reopened = AndroidWallet.open(fixture.path, TEST_PASSWORD)
            reopened.finalizeSigningKeyRotation(confirmation)
            assertArrayEquals(fixture.successorPublicKey, reopened.ownerPublicKey)
            assertNull(reopened.pendingOwnerPublicKey)
            assertNull(reopened.ownerKeyRotationDispatchIntent)
        } finally {
            originalContainer?.fill(0)
            failingWallet?.close()
            reopened?.close()
            fixture.close()
        }
    }

    @Test
    fun stateChangeDuringConsentPreventsPublicationAndDeniedNonceCannotBeReplayed() {
        val fixture = createFixture()
        try {
            val nonce = ByteArray(32) { (it + 17).toByte() }
            val deniedNonce = ByteArray(32) { (it + 49).toByte() }
            var consentCalls = 0
            org.junit.Assert.assertThrows(WalletIdentityStateChangedException::class.java) {
                fixture.adapter.prepareOwnerKeyRotationPublication(
                    draft = fixture.draft,
                    consent = {
                        consentCalls += 1
                        fixture.transport.setCurrentEnvelope(byteArrayOf(0x00))
                        true
                    },
                    authenticatedOrigin = "https://wallet.example",
                    environment = "testnet",
                    purpose = "publish owner-key rotation",
                    capability = "identity.rotate-owner-key",
                    expiresAt = System.currentTimeMillis() / 1000 + 3600,
                    replayNonce = nonce,
                )
            }
            assertEquals(1, consentCalls)
            assertNull(fixture.wallet.ownerKeyRotationDispatchIntent)
            assertEquals(0, fixture.transport.writeCount)

            fixture.transport.setCurrentEnvelope(fixture.predecessorEnvelope)
            org.junit.Assert.assertThrows(WalletRotationConsentRejectedException::class.java) {
                fixture.adapter.prepareOwnerKeyRotationPublication(
                    draft = fixture.draft,
                    consent = { false },
                    authenticatedOrigin = "https://wallet.example",
                    environment = "testnet",
                    purpose = "publish owner-key rotation",
                    capability = "identity.rotate-owner-key",
                    expiresAt = System.currentTimeMillis() / 1000 + 3600,
                    replayNonce = deniedNonce,
                )
            }
            org.junit.Assert.assertThrows(WalletIdentityReplayRejectedException::class.java) {
                fixture.adapter.prepareOwnerKeyRotationPublication(
                    draft = fixture.draft,
                    consent = { true },
                    authenticatedOrigin = "https://wallet.example",
                    environment = "testnet",
                    purpose = "publish owner-key rotation",
                    capability = "identity.rotate-owner-key",
                    expiresAt = System.currentTimeMillis() / 1000 + 3600,
                    replayNonce = deniedNonce,
                )
            }
            assertNull(fixture.wallet.ownerKeyRotationDispatchIntent)
            assertEquals(0, fixture.transport.writeCount)
        } finally {
            fixture.close()
        }
    }

    private class InMemoryReplayNonceStore : AndroidIdentityReplayNonceStore {
        private val consumed = HashSet<String>()

        @Synchronized
        override fun consume(nonceDigest: ByteArray): Boolean =
            consumed.add(Base64.getEncoder().encodeToString(nonceDigest))
    }

    private data class TestFixture(
        val directory: java.nio.file.Path,
        val path: java.nio.file.Path,
        val ownerName: ByteArray,
        val predecessorEnvelope: ByteArray,
        val expectedEnvelope: ByteArray,
        val activePublicKey: ByteArray,
        val successorPublicKey: ByteArray,
        val wallet: WalletSession,
        val draft: OwnerKeyRotationDraft,
        val transport: FakeIdentityTransport,
        val adapter: AndroidIdentityAdapter,
    ) : AutoCloseable {
        override fun close() {
            wallet.close()
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private fun createFixture(): TestFixture {
        val directory = Files.createTempDirectory("wallet-android-registry-edge-")
        val vector = resource("/identity-owner-key-rotation-legacy.json")
        val vectorText = String(vector, Charsets.UTF_8)
        val ownerName = hexField(vectorText, "owner_name_utf8_hex")
        val predecessor = hexField(vectorText, "predecessor_envelope_cbor_hex")
        val expectedEnvelope = hexField(vectorText, "candidate_envelope_cbor_hex")
        val predecessorHash = hexField(vectorText, "predecessor_state_hash_hex")
        val activeSeed = syntheticSeed(0)
        val pendingSeed = syntheticSeed(32)
        val activePublic = AndroidIdentityCrypto.publicKeyFromSeed(activeSeed)
        val pendingPublic = AndroidIdentityCrypto.publicKeyFromSeed(pendingSeed)
        val signerSeeds = listOf(syntheticSeed(32), syntheticSeed(64), syntheticSeed(96))
        val signerKeys = signerSeeds.map(AndroidIdentityCrypto::publicKeyFromSeed)
        val payload = mutableMapOf<String, Any?>(
            "private_seed" to activeSeed,
            "public_key" to activePublic.copyOf(),
            "pending_private_seed" to pendingSeed,
            "pending_public_key" to pendingPublic.copyOf(),
        )
        val path = directory.resolve("wallet.dw")
        val wallet = try {
            AndroidWallet.create(path, TEST_PASSWORD, TEST_PASSWORD, payload)
        } finally {
            WalletJson.clearByteArrays(payload)
            signerSeeds.forEach { it.fill(0) }
            activeSeed.fill(0)
            pendingSeed.fill(0)
        }
        val signers = listOf(
            IdentityRotationSigner("alice-next", signerKeys[0]),
            IdentityRotationSigner("bob", signerKeys[1]),
            IdentityRotationSigner("carol", signerKeys[2]),
        )
        signerKeys.forEach { it.fill(0) }
        val draft = wallet.createLegacyOwnerKeyRotationDraft(ownerName, predecessor, signers)
        val transport = FakeIdentityTransport(ownerName, predecessor, predecessorHash)
        val adapter = AndroidIdentityAdapter(transport, InMemoryReplayNonceStore())
        vector.fill(0)
        return TestFixture(
            directory, path, ownerName, predecessor, expectedEnvelope, activePublic, pendingPublic,
            wallet, draft, transport, adapter,
        )
    }

    private fun prepare(fixture: TestFixture, nonceLabel: String): OwnerKeyRotationPublication =
        fixture.adapter.prepareOwnerKeyRotationPublication(
            draft = fixture.draft,
            consent = { true },
            authenticatedOrigin = "https://wallet.example",
            environment = "testnet",
            purpose = "publish owner-key rotation",
            capability = "identity.rotate-owner-key",
            expiresAt = System.currentTimeMillis() / 1000 + 3600,
            replayNonce = nonceLabel.toByteArray(Charsets.UTF_8).let { bytes ->
                ByteArray(32) { index -> bytes[index % bytes.size] }
            },
        )

    private class FakeIdentityTransport(
        private val ownerName: ByteArray,
        predecessor: ByteArray,
        predecessorHash: ByteArray,
    ) : AndroidIdentityTransport {
        private var configuredRegistryEnvironment: String = "testnet"
        var environmentReadSequence: MutableList<String>? = null
        override var registryEnvironment: String
            get() = environmentReadSequence?.takeIf { it.isNotEmpty() }?.removeAt(0)
                ?: configuredRegistryEnvironment
            set(value) {
                configuredRegistryEnvironment = value
            }

        private var configuredRotationSupport: Boolean = true
        var supportReadSequence: MutableList<Boolean>? = null
        override var supportsOwnerKeyRotation: Boolean
            get() = supportReadSequence?.takeIf { it.isNotEmpty() }?.removeAt(0)
                ?: configuredRotationSupport
            set(value) {
                configuredRotationSupport = value
            }
        private var currentEnvelope: ByteArray? = predecessor.copyOf()
        private var predecessorEnvelope: ByteArray? = predecessor.copyOf()
        private val acceptedHistory = predecessorHash.copyOf()
        var remoteEnvelope: ByteArray? = predecessor.copyOf()
            private set
        var writeCount: Int = 0
            private set
        var remoteReadCount: Int = 0
            private set
        var beforeWrite: (() -> Unit)? = null
        var dropWrites: Boolean = false
        var rejectConditional: Boolean = false
        var rejectExpired: Boolean = false
        var hideHistory: Boolean = false

        fun setCurrentEnvelope(value: ByteArray) {
            currentEnvelope = value.copyOf()
        }

        fun setRemoteEnvelope(value: ByteArray) {
            remoteEnvelope = value.copyOf()
        }

        override fun getIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray? {
            require(ownerNameBytes.contentEquals(ownerName))
            return currentEnvelope?.copyOf()
        }

        override fun getIdentityEnvelopeByHash(
            ownerNameBytes: ByteArray,
            stateHash: ByteArray,
        ): ByteArray? {
            require(ownerNameBytes.contentEquals(ownerName))
            return if (!hideHistory && stateHash.contentEquals(acceptedHistory)) {
                predecessorEnvelope?.copyOf()
            } else {
                null
            }
        }

        override fun getRemoteIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray? {
            require(ownerNameBytes.contentEquals(ownerName))
            remoteReadCount += 1
            return remoteEnvelope?.copyOf()
        }

        override fun putIdentityEnvelopeIfCurrent(
            ownerNameBytes: ByteArray,
            envelopeBytes: ByteArray,
            expectedStateHash: ByteArray,
            expiresAt: Long,
        ) {
            require(ownerNameBytes.contentEquals(ownerName))
            require(expectedStateHash.contentEquals(acceptedHistory))
            require(expiresAt > System.currentTimeMillis() / 1000)
            beforeWrite?.invoke()
            writeCount += 1
            if (rejectExpired) throw AndroidIdentityWriteExpiredException()
            if (rejectConditional) throw AndroidIdentityPreconditionFailedException()
            if (!dropWrites) {
                predecessorEnvelope = currentEnvelope?.copyOf()
                currentEnvelope = envelopeBytes.copyOf()
                remoteEnvelope = envelopeBytes.copyOf()
            }
            if (dropWrites) throw java.io.IOException()
        }
    }

    private fun openWithFileReplacement(
        path: java.nio.file.Path,
        replaceFile: (java.nio.file.Path, ByteArray, ByteArray) -> Unit,
    ): WalletSession {
        val raw = AtomicWalletFiles.read(path)
        val opened = ContainerCrypto.open(raw, TEST_PASSWORD)
        return WalletSession(path, raw, opened.dek, opened.payload, replaceFile)
    }

    private fun syntheticSeed(start: Int): ByteArray = ByteArray(32) { index -> (start + index).toByte() }

    private fun hexField(source: String, name: String): ByteArray {
        val value = Regex("\\\"${Regex.escape(name)}\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
            .find(source)?.groupValues?.get(1) ?: error("missing vector field: $name")
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }

    private fun resource(name: String): ByteArray =
        checkNotNull(javaClass.getResourceAsStream(name)).use { it.readBytes() }

    private companion object {
        const val TEST_PASSWORD = "a sufficiently long test password"
    }
}

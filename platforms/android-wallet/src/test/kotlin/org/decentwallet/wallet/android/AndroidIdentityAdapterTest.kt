package org.decentwallet.wallet.android

import java.math.BigInteger
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
    fun versionedPredecessorUsesExternalThresholdProofsForOperationFivePromotion() {
        val directory = Files.createTempDirectory("wallet-android-versioned-rotation-")
        val vectorText = String(
            resource("/identity-owner-key-rotation-v1-predecessor-separate-owner.json"),
            Charsets.UTF_8,
        )
        val ownerName = hexField(vectorText, "owner_name_utf8_hex")
        val genesis = hexField(vectorText, "genesis_envelope_cbor_hex")
        val genesisHash = hexField(vectorText, "genesis_state_hash_hex")
        val predecessor = hexField(vectorText, "predecessor_envelope_cbor_hex")
        val predecessorHash = hexField(vectorText, "predecessor_state_hash_hex")
        val ownerSeed = syntheticSeed(200)
        val pendingSeed = syntheticSeed(160)
        val signerSeeds = listOf(syntheticSeed(0), syntheticSeed(32), syntheticSeed(64))
        val ownerPublic = AndroidIdentityCrypto.publicKeyFromSeed(ownerSeed)
        val pendingPublic = AndroidIdentityCrypto.publicKeyFromSeed(pendingSeed)
        val payload = mutableMapOf<String, Any?>(
            "private_seed" to ownerSeed.copyOf(),
            "public_key" to ownerPublic.copyOf(),
            "pending_private_seed" to pendingSeed.copyOf(),
            "pending_public_key" to pendingPublic.copyOf(),
        )
        val wallet = AndroidWallet.create(
            directory.resolve("wallet.dw"),
            TEST_PASSWORD,
            TEST_PASSWORD,
            payload,
        )
        WalletJson.clearByteArrays(payload)
        val signerPublics = signerSeeds.map(AndroidIdentityCrypto::publicKeyFromSeed)
        val transport = VersionedIdentityTransport(
            ownerName,
            predecessor,
            predecessorHash,
            mapOf(genesisHash to genesis, predecessorHash to predecessor),
        )
        val adapter = AndroidIdentityAdapter(transport, InMemoryReplayNonceStore())
        try {
            assertArrayEquals(hexField(vectorText, "owner_public_key_hex"), ownerPublic)
            val versionedDraft = adapter.createVersionedOwnerKeyRotationDraft(wallet, ownerName)
            assertEquals(BigInteger.valueOf(3), versionedDraft.sequence)
            assertArrayEquals(pendingPublic, versionedDraft.successorOwnerPublicKey)

            val signedUpdate = versionedDraft.signedUpdateBytes
            val digest = AndroidIdentityCrypto.sha256(signedUpdate)
            val aliceSignature = AndroidIdentityCrypto.sign(signerSeeds[0], digest)
            val bobSignature = AndroidIdentityCrypto.sign(signerSeeds[1], digest)
            val finalizedDraft = try {
                versionedDraft.finalizeWithProofs(
                    listOf(
                        OwnerKeyRotationProof("alice", aliceSignature),
                        OwnerKeyRotationProof("bob", bobSignature),
                    ),
                )
            } finally {
                signedUpdate.fill(0)
                digest.fill(0)
                aliceSignature.fill(0)
                bobSignature.fill(0)
            }
            val expectedCandidate = hexField(vectorText, "candidate_envelope_cbor_hex")
            try {
                assertArrayEquals(expectedCandidate, finalizedDraft.envelopeBytes)
            } finally {
                expectedCandidate.fill(0)
            }

            val payloadSnapshot = wallet.readPayload()
            try {
                assertArrayEquals(ownerSeed, payloadSnapshot["private_seed"] as ByteArray)
                assertArrayEquals(pendingSeed, payloadSnapshot["pending_private_seed"] as ByteArray)
                assertTrue(payloadSnapshot.keys.none { it.contains("signer", ignoreCase = true) })
            } finally {
                WalletJson.clearByteArrays(payloadSnapshot)
            }

            val publication = adapter.prepareOwnerKeyRotationPublication(
                draft = finalizedDraft,
                consent = { true },
                authenticatedOrigin = "https://wallet.example",
                environment = "testnet",
                purpose = "publish owner-key rotation",
                capability = "identity.rotate-owner-key",
                expiresAt = 2_000_000_000L,
                replayNonce = ByteArray(32) { (it + 1).toByte() },
            )
            val permit = wallet.latchOwnerKeyRotationDispatchIntent(publication)
            val result = adapter.dispatchOwnerKeyRotation(publication, permit)

            assertEquals(OwnerKeyRotationDispatchStatus.CONFIRMED, result.status)
            assertEquals(1, transport.writeCount)
            wallet.finalizeSigningKeyRotation(checkNotNull(result.confirmation))
            assertArrayEquals(pendingPublic, wallet.ownerPublicKey)
            assertEquals(null, wallet.pendingOwnerPublicKey)
            assertArrayEquals(ownerName, transport.lastOwnerName)
        } finally {
            wallet.close()
            ownerSeed.fill(0)
            pendingSeed.fill(0)
            signerSeeds.forEach { it.fill(0) }
            ownerPublic.fill(0)
            pendingPublic.fill(0)
            signerPublics.forEach { it.fill(0) }
            genesis.fill(0)
            genesisHash.fill(0)
            predecessor.fill(0)
            predecessorHash.fill(0)
            ownerName.fill(0)
            vectorText.toByteArray(Charsets.UTF_8).fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    @Test
    fun rejectsUnderThresholdProofSetForVersionedRotation() {
        val fixture = createVersionedTestFixture()
        val draft = fixture.adapter.createVersionedOwnerKeyRotationDraft(fixture.wallet, fixture.ownerName)
        try {
            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                draft.finalizeWithProofs(listOf(ownerKeyRotationProof(draft, "alice", fixture.signerSeeds[0])))
            }
        } finally {
            fixture.close()
        }
    }

    @Test
    fun rejectsOutsiderProofForVersionedRotation() {
        val fixture = createVersionedTestFixture()
        val draft = fixture.adapter.createVersionedOwnerKeyRotationDraft(fixture.wallet, fixture.ownerName)
        try {
            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                draft.finalizeWithProofs(
                    listOf(
                        ownerKeyRotationProof(draft, "mallory", fixture.signerSeeds[0]),
                        ownerKeyRotationProof(draft, "bob", fixture.signerSeeds[1]),
                    ),
                )
            }
        } finally {
            fixture.close()
        }
    }

    @Test
    fun rejectsInvalidThresholdSignatureForVersionedRotation() {
        val fixture = createVersionedTestFixture()
        try {
            val draft = fixture.adapter.createVersionedOwnerKeyRotationDraft(fixture.wallet, fixture.ownerName)
            val aliceSignature = ownerKeyRotationProof(draft, "alice", fixture.signerSeeds[0]).signature
            aliceSignature[0] = (aliceSignature[0].toInt() xor 1).toByte()
            val proofs = listOf(
                OwnerKeyRotationProof("alice", aliceSignature),
                ownerKeyRotationProof(draft, "bob", fixture.signerSeeds[1]),
            )

            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                draft.finalizeWithProofs(proofs)
            }
        } finally {
            fixture.close()
        }
    }

    @Test
    fun rejectsDuplicateThresholdSignerProofForVersionedRotation() {
        val fixture = createVersionedTestFixture()
        try {
            val draft = fixture.adapter.createVersionedOwnerKeyRotationDraft(fixture.wallet, fixture.ownerName)
            val aliceProof = ownerKeyRotationProof(draft, "alice", fixture.signerSeeds[0])
            val bobProof = ownerKeyRotationProof(draft, "bob", fixture.signerSeeds[1])

            org.junit.Assert.assertThrows(WalletInvalidIdentityStateException::class.java) {
                draft.finalizeWithProofs(listOf(aliceProof, aliceProof, bobProof))
            }
        } finally {
            fixture.close()
        }
    }

    @Test
    fun staleVersionedHeadIsRejectedBeforeConsent() {
        val fixture = createVersionedTestFixture()
        try {
            val draft = finalizedVersionedDraft(fixture)
            fixture.transport.setCurrent(fixture.genesis, fixture.genesisHash)
            var consentCalls = 0

            org.junit.Assert.assertThrows(WalletIdentityStateChangedException::class.java) {
                prepareVersioned(fixture, draft) {
                    consentCalls += 1
                    true
                }
            }

            assertEquals(0, consentCalls)
            assertEquals(0, fixture.transport.writeCount)
        } finally {
            fixture.close()
        }
    }

    @Test
    fun samePredecessorStateWithDifferentProofEnvelopeRemainsCurrentDuringConsent() {
        val fixture = createVersionedTestFixture()
        val alternateEnvelope = alternateVersionedEnvelope(
            fixture.predecessor,
            listOf("alice" to fixture.signerSeeds[0], "carol" to fixture.signerSeeds[2]),
        )
        try {
            val draft = finalizedVersionedDraft(fixture)
            val publication = prepareVersioned(fixture, draft) {
                fixture.transport.setCurrent(alternateEnvelope, fixture.predecessorHash)
                true
            }

            assertNotNull(publication)
            assertEquals(0, fixture.transport.writeCount)
        } finally {
            alternateEnvelope.fill(0)
            fixture.close()
        }
    }

    @Test
    fun ambiguousVersionedDispatchReopensAndConfirmsWithoutRetry() {
        val fixture = createVersionedTestFixture()
        var reopened: WalletSession? = null
        var candidateEnvelope: ByteArray? = null
        try {
            val draft = finalizedVersionedDraft(fixture)
            candidateEnvelope = draft.envelopeBytes
            fixture.transport.dropWrites = true
            val publication = prepareVersioned(fixture, draft) { true }
            val permit = fixture.wallet.latchOwnerKeyRotationDispatchIntent(publication)
            val result = fixture.adapter.dispatchOwnerKeyRotation(publication, permit)

            assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
            assertEquals(1, fixture.transport.writeCount)
            val intent = checkNotNull(fixture.wallet.ownerKeyRotationDispatchIntent)
            fixture.wallet.close()
            reopened = AndroidWallet.open(fixture.directory.resolve("wallet.dw"), TEST_PASSWORD)
            assertNull(fixture.adapter.confirmOwnerKeyRotation(intent))
            fixture.transport.setRemoteEnvelope(checkNotNull(candidateEnvelope))
            val confirmation = checkNotNull(fixture.adapter.confirmOwnerKeyRotation(intent))
            reopened.finalizeSigningKeyRotation(confirmation)

            assertArrayEquals(fixture.pendingPublic, reopened.ownerPublicKey)
            assertEquals(null, reopened.pendingOwnerPublicKey)
            assertEquals(1, fixture.transport.writeCount)
        } finally {
            candidateEnvelope?.fill(0)
            reopened?.close()
            fixture.close()
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

    private fun finalizedVersionedDraft(fixture: VersionedTestFixture): OwnerKeyRotationDraft {
        val draft = fixture.adapter.createVersionedOwnerKeyRotationDraft(fixture.wallet, fixture.ownerName)
        return draft.finalizeWithProofs(
            listOf(
                ownerKeyRotationProof(draft, "alice", fixture.signerSeeds[0]),
                ownerKeyRotationProof(draft, "bob", fixture.signerSeeds[1]),
            ),
        )
    }

    private fun prepareVersioned(
        fixture: VersionedTestFixture,
        draft: OwnerKeyRotationDraft,
        consent: () -> Boolean,
    ): OwnerKeyRotationPublication = fixture.adapter.prepareOwnerKeyRotationPublication(
        draft = draft,
        consent = { consent() },
        authenticatedOrigin = "https://wallet.example",
        environment = "testnet",
        purpose = "publish owner-key rotation",
        capability = "identity.rotate-owner-key",
        expiresAt = 2_000_000_000L,
        replayNonce = ByteArray(32) { (it + 1).toByte() },
    )

    private fun alternateVersionedEnvelope(
        predecessor: ByteArray,
        signers: List<Pair<String, ByteArray>>,
    ): ByteArray {
        val outer = IdentityCbor.decodeCanonical(predecessor) as? Map<*, *>
            ?: throw WalletInvalidIdentityStateException()
        val update = outer[BigInteger.valueOf(2)] as? ByteArray
            ?: throw WalletInvalidIdentityStateException()
        val digest = AndroidIdentityCrypto.sha256(update)
        val proofValues = ArrayList<Map<BigInteger, Any?>>(signers.size)
        try {
            for ((signerId, signerSeed) in signers.sortedBy(Pair<String, ByteArray>::first)) {
                val signature = AndroidIdentityCrypto.sign(signerSeed, digest)
                proofValues.add(
                    linkedMapOf(
                        BigInteger.ONE to signerId,
                        BigInteger.valueOf(2) to signature,
                    ),
                )
            }
            return IdentityCbor.encodeCanonical(
                linkedMapOf<BigInteger, Any?>(
                    BigInteger.ONE to BigInteger.ONE,
                    BigInteger.valueOf(2) to update,
                    BigInteger.valueOf(3) to proofValues,
                ),
            )
        } finally {
            digest.fill(0)
            update.fill(0)
            proofValues.forEach { (it[BigInteger.valueOf(2)] as? ByteArray)?.fill(0) }
        }
    }

    private fun createVersionedTestFixture(): VersionedTestFixture {
        val directory = Files.createTempDirectory("wallet-android-versioned-proof-")
        val vectorText = String(
            resource("/identity-owner-key-rotation-v1-predecessor-separate-owner.json"),
            Charsets.UTF_8,
        )
        val ownerName = hexField(vectorText, "owner_name_utf8_hex")
        val genesis = hexField(vectorText, "genesis_envelope_cbor_hex")
        val genesisHash = hexField(vectorText, "genesis_state_hash_hex")
        val predecessor = hexField(vectorText, "predecessor_envelope_cbor_hex")
        val predecessorHash = hexField(vectorText, "predecessor_state_hash_hex")
        val ownerSeed = syntheticSeed(200)
        val pendingSeed = syntheticSeed(160)
        val signerSeeds = listOf(syntheticSeed(0), syntheticSeed(32), syntheticSeed(64))
        val ownerPublic = AndroidIdentityCrypto.publicKeyFromSeed(ownerSeed)
        val pendingPublic = AndroidIdentityCrypto.publicKeyFromSeed(pendingSeed)
        val payload = mutableMapOf<String, Any?>(
            "private_seed" to ownerSeed.copyOf(),
            "public_key" to ownerPublic.copyOf(),
            "pending_private_seed" to pendingSeed.copyOf(),
            "pending_public_key" to pendingPublic.copyOf(),
        )
        val wallet = AndroidWallet.create(
            directory.resolve("wallet.dw"),
            TEST_PASSWORD,
            TEST_PASSWORD,
            payload,
        )
        WalletJson.clearByteArrays(payload)
        val transport = VersionedIdentityTransport(
            ownerName,
            predecessor,
            predecessorHash,
            mapOf(genesisHash to genesis, predecessorHash to predecessor),
        )
        return VersionedTestFixture(
            directory = directory,
            ownerName = ownerName,
            genesis = genesis,
            genesisHash = genesisHash,
            predecessor = predecessor,
            predecessorHash = predecessorHash,
            ownerSeed = ownerSeed,
            pendingSeed = pendingSeed,
            signerSeeds = signerSeeds,
            ownerPublic = ownerPublic,
            pendingPublic = pendingPublic,
            wallet = wallet,
            transport = transport,
            adapter = AndroidIdentityAdapter(transport, InMemoryReplayNonceStore()),
            vectorText = vectorText,
        )
    }

    private fun ownerKeyRotationProof(
        draft: VersionedOwnerKeyRotationDraft,
        signerId: String,
        signerSeed: ByteArray,
    ): OwnerKeyRotationProof {
        val update = draft.signedUpdateBytes
        val digest = AndroidIdentityCrypto.sha256(update)
        val signature = AndroidIdentityCrypto.sign(signerSeed, digest)
        return try {
            OwnerKeyRotationProof(signerId, signature)
        } finally {
            update.fill(0)
            digest.fill(0)
            signature.fill(0)
        }
    }

    private class VersionedTestFixture(
        val directory: java.nio.file.Path,
        val ownerName: ByteArray,
        val genesis: ByteArray,
        val genesisHash: ByteArray,
        val predecessor: ByteArray,
        val predecessorHash: ByteArray,
        val ownerSeed: ByteArray,
        val pendingSeed: ByteArray,
        val signerSeeds: List<ByteArray>,
        val ownerPublic: ByteArray,
        val pendingPublic: ByteArray,
        val wallet: WalletSession,
        val transport: VersionedIdentityTransport,
        val adapter: AndroidIdentityAdapter,
        private val vectorText: String,
    ) {
        fun close() {
            wallet.close()
            ownerName.fill(0)
            genesis.fill(0)
            genesisHash.fill(0)
            predecessor.fill(0)
            predecessorHash.fill(0)
            ownerSeed.fill(0)
            pendingSeed.fill(0)
            signerSeeds.forEach { it.fill(0) }
            ownerPublic.fill(0)
            pendingPublic.fill(0)
            vectorText.toByteArray(Charsets.UTF_8).fill(0)
            Files.walk(directory).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private class VersionedIdentityTransport(
        private val ownerName: ByteArray,
        initialEnvelope: ByteArray,
        initialStateHash: ByteArray,
        initialHistory: Map<ByteArray, ByteArray>,
    ) : AndroidIdentityTransport {
        override val registryEnvironment: String = "testnet"
        override val supportsOwnerKeyRotation: Boolean = true
        private var currentEnvelope = initialEnvelope.copyOf()
        private var currentStateHash = initialStateHash.copyOf()
        private var remoteEnvelope: ByteArray? = initialEnvelope.copyOf()
        private val history = HashMap<String, ByteArray>().apply {
            initialHistory.forEach { (stateHash, envelope) ->
                put(stateHashKey(stateHash), envelope.copyOf())
            }
        }
        var writeCount: Int = 0
            private set
        var lastOwnerName: ByteArray? = null
            private set
        var dropWrites: Boolean = false

        fun setCurrent(value: ByteArray, stateHash: ByteArray) {
            currentEnvelope.fill(0)
            currentEnvelope = value.copyOf()
            currentStateHash.fill(0)
            currentStateHash = stateHash.copyOf()
        }

        fun setRemoteEnvelope(value: ByteArray) {
            remoteEnvelope?.fill(0)
            remoteEnvelope = value.copyOf()
        }

        override fun getIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray? {
            require(ownerNameBytes.contentEquals(ownerName))
            return currentEnvelope.copyOf()
        }

        override fun getIdentityEnvelopeByHash(
            ownerNameBytes: ByteArray,
            stateHash: ByteArray,
        ): ByteArray? {
            require(ownerNameBytes.contentEquals(ownerName))
            return history[stateHashKey(stateHash)]?.copyOf()
        }

        override fun getRemoteIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray? {
            require(ownerNameBytes.contentEquals(ownerName))
            return remoteEnvelope?.copyOf()
        }

        override fun putIdentityEnvelopeIfCurrent(
            ownerNameBytes: ByteArray,
            envelopeBytes: ByteArray,
            expectedStateHash: ByteArray,
            expiresAt: Long,
        ) {
            require(ownerNameBytes.contentEquals(ownerName))
            if (!expectedStateHash.contentEquals(currentStateHash)) {
                throw AndroidIdentityPreconditionFailedException()
            }
            if (expiresAt <= System.currentTimeMillis() / 1000) {
                throw AndroidIdentityWriteExpiredException()
            }
            writeCount += 1
            lastOwnerName = ownerNameBytes.copyOf()
            if (dropWrites) throw java.io.IOException()
            history[stateHashKey(currentStateHash)] = currentEnvelope.copyOf()
            val nextHash = stateHashOf(envelopeBytes)
            currentEnvelope.fill(0)
            currentEnvelope = envelopeBytes.copyOf()
            currentStateHash.fill(0)
            currentStateHash = nextHash
            history[stateHashKey(currentStateHash)] = currentEnvelope.copyOf()
            remoteEnvelope?.fill(0)
            remoteEnvelope = envelopeBytes.copyOf()
        }

        private fun stateHashOf(envelopeBytes: ByteArray): ByteArray {
            val outer = IdentityCbor.decodeCanonical(envelopeBytes) as? Map<*, *>
                ?: throw WalletInvalidIdentityStateException()
            val update = outer[BigInteger.valueOf(2)] as? ByteArray
                ?: throw WalletInvalidIdentityStateException()
            return AndroidIdentityCrypto.sha256(update)
        }

        private fun stateHashKey(hash: ByteArray): String =
            hash.joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

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

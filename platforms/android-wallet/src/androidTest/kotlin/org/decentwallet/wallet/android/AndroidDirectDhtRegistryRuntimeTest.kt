package org.decentwallet.wallet.android

import android.app.Instrumentation
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.math.BigInteger
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption.READ
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import java.io.IOException
import java.security.SecureRandom
import java.util.UUID

class AndroidDirectDhtRegistryRuntimeTest {
    @Test
    fun rotatesWalletThroughDirectDhtAndPersistsPromotionOnAndroid() {
        val api = Build.VERSION.SDK_INT
        val abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
        assertTrue(
            "unexpected Android API/ABI: $api/$abi",
            (api == 26 && abi == "x86") || (api == 37 && abi == "x86_64"),
        )

        val arguments = InstrumentationRegistry.getArguments()
        val writerPeer = arguments.getString("decentRegistryTestPeer")
        val readbackPeer = arguments.getString("decentRegistryTestReadbackPeer")
        assumeTrue(
            "configure DECENT_REGISTRY_TEST_PEER and DECENT_REGISTRY_TEST_READBACK_PEER",
            !writerPeer.isNullOrBlank() && !readbackPeer.isNullOrBlank(),
        )
        assertTrue("fixture must use distinct writer and read-back peers", writerPeer != readbackPeer)

        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val walletDirectory = Files.createTempDirectory(
            instrumentation.context.cacheDir.toPath(),
            "android-owner-key-rotation-",
        )
        val walletPath = walletDirectory.resolve("wallet.dw")
        val password = UUID.randomUUID().toString()
        var replayDirectory: java.nio.file.Path? = null
        var ownerName = byteArrayOf()
        var predecessor = byteArrayOf()
        var candidate = byteArrayOf()
        var competingEnvelope = byteArrayOf()
        var competingExpectedHash = byteArrayOf()
        var activeSeed = byteArrayOf()
        var pendingSeed = byteArrayOf()
        var activePublic = byteArrayOf()
        var pendingPublic = byteArrayOf()
        var signerSeeds = emptyList<ByteArray>()
        var signerPublicKeys = emptyList<ByteArray>()
        var replayNonce = byteArrayOf()
        var wallet: WalletSession? = null
        var reopenedWallet: WalletSession? = null
        var transport: AndroidDirectDhtIdentityTransport? = null
        var freshReadbackTransport: AndroidDirectDhtIdentityTransport? = null
        try {
            val fixtureKind = arguments.getString("decentRegistryTestFixture") ?: "legacy"
            check(fixtureKind in setOf("legacy", "versioned", "versioned-promotion-staging-failure", "versioned-lost-acknowledgement", "versioned-conditional-rejection", "versioned-promotion-rollback", "versioned-promotion-unknown", "versioned-competing-write")) {
                "unsupported Android Registry test fixture: $fixtureKind"
            }
            val promotionStagingFailure = fixtureKind == "versioned-promotion-staging-failure"
            val lostAcknowledgement = fixtureKind == "versioned-lost-acknowledgement"
            val conditionalRejection = fixtureKind == "versioned-conditional-rejection"
            val promotionRollback = fixtureKind == "versioned-promotion-rollback"
            val promotionUnknown = fixtureKind == "versioned-promotion-unknown"
            val competingWrite = fixtureKind == "versioned-competing-write"
            val versionedFixture = fixtureKind != "legacy"
            if (promotionStagingFailure || lostAcknowledgement || conditionalRejection || promotionRollback || promotionUnknown || competingWrite) {
                assertEquals(
                    "${this::class.java.name}#rotatesWalletThroughDirectDhtAndPersistsPromotionOnAndroid",
                    arguments.getString("class"),
                )
            }
            val vectorName = if (versionedFixture) {
                "identity-owner-key-rotation-versioned-history.json"
            } else {
                "identity-owner-key-rotation-legacy.json"
            }
            ownerName = fixtureHex(instrumentation, "owner_name_utf8_hex", vectorName)
            if (!versionedFixture) {
                predecessor = fixtureHex(instrumentation, "predecessor_envelope_cbor_hex", vectorName)
                candidate = fixtureHex(instrumentation, "candidate_envelope_cbor_hex", vectorName)
            }
            activeSeed = syntheticSeed(if (versionedFixture) 1 else 0)
            pendingSeed = syntheticSeed(if (versionedFixture) 129 else 32)
            activePublic = AndroidIdentityCrypto.publicKeyFromSeed(activeSeed)
            pendingPublic = AndroidIdentityCrypto.publicKeyFromSeed(pendingSeed)
            signerSeeds = if (versionedFixture) {
                listOf(syntheticSeed(1), syntheticSeed(33), syntheticSeed(65))
            } else {
                listOf(syntheticSeed(32), syntheticSeed(64), syntheticSeed(96))
            }
            signerPublicKeys = signerSeeds.map(AndroidIdentityCrypto::publicKeyFromSeed)
            val payload = mutableMapOf<String, Any?>(
                "private_seed" to activeSeed.copyOf(),
                "public_key" to activePublic.copyOf(),
                "pending_private_seed" to pendingSeed.copyOf(),
                "pending_public_key" to pendingPublic.copyOf(),
            )
            val activeWallet = try {
                AndroidWallet.create(walletPath, password, password, payload).also { wallet = it }
            } finally {
                WalletJson.clearByteArrays(payload)
                payload.clear()
                activeSeed.fill(0)
                pendingSeed.fill(0)
            }

            val config = AndroidRegistryDhtConfig(
                registryEnvironment = "local-two-peer-registry-runtime",
                registryPeers = listOf(writerPeer!!),
                readbackPeer = readbackPeer!!,
                enableOwnerKeyRotation = true,
                requestTimeoutMillis = 30_000,
            )
            var competitorAccepted = false
            val losingWirePeers = mutableListOf<String>()
            val publishingTransport = if (competingWrite) {
                val realRpc = JvmLibp2pKadDhtRpcClient(config.requestTimeoutMillis, config.historyPeers)
                val interleavedRpc = object : AndroidKadDhtRpcClient by realRpc {
                    override fun putValue(peerMultiaddr: String, key: ByteArray, value: ByteArray): Boolean {
                        assertArrayEquals(candidate, value)
                        losingWirePeers.add(peerMultiaddr)
                        if (!competitorAccepted) {
                            // Original transport has finished its verified-current checks.
                            // A separate concrete writer wins this deterministic race window.
                            AndroidDirectDhtIdentityTransport(config).use { competitor ->
                                competitor.putIdentityEnvelopeIfCurrent(
                                    ownerName, competingEnvelope, competingExpectedHash,
                                    System.currentTimeMillis() / 1000 + 3600,
                                )
                                assertEnvelopeEquals(competingEnvelope, competitor.getIdentityEnvelope(ownerName))
                                assertEnvelopeEquals(competingEnvelope, competitor.getRemoteIdentityEnvelope(ownerName))
                            }
                            competitorAccepted = true
                        }
                        // Delegate the losing PUT and its genuine response, even if it fails.
                        return realRpc.putValue(peerMultiaddr, key, value)
                    }
                }
                AndroidDirectDhtIdentityTransport(config, interleavedRpc) { System.currentTimeMillis() / 1000 }
            } else {
                AndroidDirectDhtIdentityTransport(config)
            }
            transport = publishingTransport
            if (versionedFixture) {
                predecessor = publishingTransport.getIdentityEnvelope(ownerName)
                    ?: error("versioned Registry fixture is missing its predecessor")
                assertEnvelopeEquals(
                    predecessor,
                    publishingTransport.getRemoteIdentityEnvelope(ownerName),
                )
                assertArrayEquals(
                    fixtureHex(instrumentation, "predecessor_owner_public_key_hex", vectorName),
                    activePublic,
                )
                assertArrayEquals(
                    fixtureHex(instrumentation, "successor_owner_public_key_hex", vectorName),
                    pendingPublic,
                )
            } else {
                assertEnvelopeEquals(predecessor, publishingTransport.getIdentityEnvelope(ownerName))
                assertEnvelopeEquals(predecessor, publishingTransport.getRemoteIdentityEnvelope(ownerName))
            }

            replayDirectory = Files.createTempDirectory(
                instrumentation.context.filesDir.toPath(),
                "android-owner-key-rotation-replay-",
            )
            var writeAttempts = 0
            var suppressConfirmationReads = false
            var conditionalWriteRejected = false
            val countingTransport = object : AndroidIdentityTransport by publishingTransport {
                override fun putIdentityEnvelopeIfCurrent(
                    ownerNameBytes: ByteArray, envelopeBytes: ByteArray,
                    expectedStateHash: ByteArray, expiresAt: Long,
                ) {
                    writeAttempts++
                    if (competingWrite) {
                        competingExpectedHash.fill(0)
                        competingExpectedHash = expectedStateHash.copyOf()
                    }
                    if (conditionalRejection) {
                        // Reject a mismatched hash after concrete verified remote reads, before wire PUT.
                        val mismatchedHash = ByteArray(32) { 0xff.toByte() }
                        assertTrue(!mismatchedHash.contentEquals(expectedStateHash))
                        try {
                            publishingTransport.putIdentityEnvelopeIfCurrent(
                                ownerNameBytes, envelopeBytes, mismatchedHash, expiresAt,
                            )
                            error("conditional publication unexpectedly accepted mismatched hash")
                        } catch (failure: AndroidIdentityPreconditionFailedException) {
                            conditionalWriteRejected = true
                            throw failure
                        } finally {
                            mismatchedHash.fill(0)
                        }
                    } else {
                        publishingTransport.putIdentityEnvelopeIfCurrent(
                            ownerNameBytes, envelopeBytes, expectedStateHash, expiresAt,
                        )
                    }
                    if (lostAcknowledgement) {
                        suppressConfirmationReads = true
                        // Inject loss after the concrete PUT completed; do not fabricate publication.
                        throw IOException()
                    }
                }
                override fun getRemoteIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray? {
                    if (suppressConfirmationReads) throw IOException()
                    return publishingTransport.getRemoteIdentityEnvelope(ownerNameBytes)
                }
            }
            val adapter = AndroidIdentityAdapter(
                countingTransport,
                FileAndroidIdentityReplayNonceStore(checkNotNull(replayDirectory).toFile()),
            )
            replayNonce = ByteArray(32).also(SecureRandom()::nextBytes)
            val draft = if (versionedFixture) {
                val versionedDraft = adapter.createVersionedOwnerKeyRotationDraft(activeWallet, ownerName)
                assertEquals(BigInteger.valueOf(7), versionedDraft.sequence)
                val draftSuccessor = versionedDraft.successorOwnerPublicKey
                try {
                    assertArrayEquals(pendingPublic, draftSuccessor)
                } finally {
                    draftSuccessor.fill(0)
                }
                val signedUpdate = versionedDraft.signedUpdateBytes
                val digest = AndroidIdentityCrypto.sha256(signedUpdate)
                var aliceSignature = byteArrayOf()
                var bobSignature = byteArrayOf()
                try {
                    aliceSignature = AndroidIdentityCrypto.sign(signerSeeds[0], digest)
                    bobSignature = AndroidIdentityCrypto.sign(signerSeeds[1], digest)
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
            } else {
                val signers = listOf(
                    IdentityRotationSigner("alice-next", signerPublicKeys[0]),
                    IdentityRotationSigner("bob", signerPublicKeys[1]),
                    IdentityRotationSigner("carol", signerPublicKeys[2]),
                )
                activeWallet.createLegacyOwnerKeyRotationDraft(ownerName, predecessor, signers)
            }
            val draftEnvelope = draft.envelopeBytes
            try {
                if (versionedFixture) {
                    candidate = draftEnvelope.copyOf()
                } else {
                    assertArrayEquals(candidate, draftEnvelope)
                }
            } finally {
                draftEnvelope.fill(0)
            }
            signerPublicKeys.forEach { it.fill(0) }
            val publication = adapter.prepareOwnerKeyRotationPublication(
                draft = draft,
                consent = { transcript ->
                    assertEquals(config.registryEnvironment, transcript.environment)
                    val reviewed = transcript.reviewEnvelopeBytes
                    try {
                        assertArrayEquals(candidate, reviewed)
                    } finally {
                        reviewed.fill(0)
                    }
                    true
                },
                authenticatedOrigin = "https://wallet.example",
                environment = config.registryEnvironment,
                purpose = "publish owner-key rotation",
                capability = "identity.rotate-owner-key",
                expiresAt = System.currentTimeMillis() / 1000 + 3600,
                replayNonce = replayNonce,
            )
            assertThrows(WalletIdentityReplayRejectedException::class.java) {
                AndroidIdentityAdapter(
                    publishingTransport,
                    FileAndroidIdentityReplayNonceStore(checkNotNull(replayDirectory).toFile()),
                ).prepareOwnerKeyRotationPublication(
                    draft = draft,
                    consent = { true },
                    authenticatedOrigin = "https://wallet.example",
                    environment = config.registryEnvironment,
                    purpose = "publish owner-key rotation",
                    capability = "identity.rotate-owner-key",
                    expiresAt = System.currentTimeMillis() / 1000 + 3600,
                    replayNonce = replayNonce,
                )
            }
            val publicationEnvelope = publication.envelopeBytes
            try {
                assertArrayEquals(candidate, publicationEnvelope)
            } finally {
                publicationEnvelope.fill(0)
            }

            if (competingWrite) {
                val alternateSeed = syntheticSeed(161)
                val alternatePublic = AndroidIdentityCrypto.publicKeyFromSeed(alternateSeed)
                val competingPayload = mutableMapOf<String, Any?>(
                    "private_seed" to signerSeeds[0].copyOf(),
                    "public_key" to activePublic.copyOf(),
                    "pending_private_seed" to alternateSeed,
                    "pending_public_key" to alternatePublic,
                )
                try {
                    AndroidWallet.create(walletDirectory.resolve("competitor.dw"), password, password, competingPayload).use { rivalWallet ->
                        val rivalDraft = adapter.createVersionedOwnerKeyRotationDraft(rivalWallet, ownerName)
                        assertEquals(BigInteger.valueOf(7), rivalDraft.sequence)
                        val update = rivalDraft.signedUpdateBytes
                        val digest = AndroidIdentityCrypto.sha256(update)
                        val alice = AndroidIdentityCrypto.sign(signerSeeds[0], digest)
                        val bob = AndroidIdentityCrypto.sign(signerSeeds[1], digest)
                        try {
                            competingEnvelope = rivalDraft.finalizeWithProofs(listOf(
                                OwnerKeyRotationProof("alice", alice), OwnerKeyRotationProof("bob", bob),
                            )).envelopeBytes
                            assertTrue(!candidate.contentEquals(competingEnvelope))
                        } finally {
                            update.fill(0)
                            digest.fill(0)
                            alice.fill(0)
                            bob.fill(0)
                        }
                    }
                } finally {
                    WalletJson.clearByteArrays(competingPayload)
                    competingPayload.clear()
                }
            }
            val permit = activeWallet.latchOwnerKeyRotationDispatchIntent(publication)
            val intent = permit.intent
            assertEquals(intent, activeWallet.ownerKeyRotationDispatchIntent)
            activeWallet.close()
            wallet = null

            val dispatchWallet = AndroidWallet.open(walletPath, password)
            wallet = dispatchWallet
            assertEquals(intent, dispatchWallet.ownerKeyRotationDispatchIntent)
            val latchedActivePublic = dispatchWallet.ownerPublicKey
            val latchedPendingPublic = dispatchWallet.pendingOwnerPublicKey
            try {
                assertArrayEquals(activePublic, latchedActivePublic)
                assertArrayEquals(pendingPublic, latchedPendingPublic)
            } finally {
                latchedActivePublic.fill(0)
                latchedPendingPublic?.fill(0)
            }
            assertEnvelopeEquals(predecessor, publishingTransport.getIdentityEnvelope(ownerName))

            val latchedBytes = dispatchWallet.exportContainer()
            val result = adapter.dispatchOwnerKeyRotation(publication, permit)
            if (competingWrite) {
                try {
                    assertTrue(competitorAccepted)
                    assertTrue(losingWirePeers.isNotEmpty())
                    assertEquals(losingWirePeers.size, losingWirePeers.distinct().size)
                    assertTrue(losingWirePeers.all { it in config.historyPeers })
                    assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
                    assertNull(result.confirmation)
                    assertEquals(1, writeAttempts)
                    assertArrayEquals(latchedBytes, dispatchWallet.exportContainer())
                    assertArrayEquals(activePublic, dispatchWallet.ownerPublicKey)
                    assertArrayEquals(pendingPublic, dispatchWallet.pendingOwnerPublicKey)
                    assertEquals(intent, dispatchWallet.ownerKeyRotationDispatchIntent)
                    assertEnvelopeEquals(competingEnvelope, publishingTransport.getIdentityEnvelope(ownerName))
                    assertEnvelopeEquals(competingEnvelope, publishingTransport.getRemoteIdentityEnvelope(ownerName))
                    val putsBeforeReuse = losingWirePeers.toList()
                    assertThrows(WalletInvalidIdentityStateException::class.java) {
                        adapter.dispatchOwnerKeyRotation(publication, permit)
                    }
                    dispatchWallet.close()
                    wallet = null
                    val recovered = AndroidWallet.open(walletPath, password)
                    wallet = recovered
                    assertArrayEquals(latchedBytes, recovered.exportContainer())
                    assertArrayEquals(activePublic, recovered.ownerPublicKey)
                    assertArrayEquals(pendingPublic, recovered.pendingOwnerPublicKey)
                    assertEquals(intent, recovered.ownerKeyRotationDispatchIntent)
                    assertThrows(WalletRotationInProgressException::class.java) { recovered.cancelSigningKeyRotation() }
                    val freshReader = AndroidDirectDhtIdentityTransport(config)
                    freshReadbackTransport = freshReader
                    assertEnvelopeEquals(competingEnvelope, freshReader.getRemoteIdentityEnvelope(ownerName))
                    val recoveredAdapter = AndroidIdentityAdapter(
                        freshReader, FileAndroidIdentityReplayNonceStore(checkNotNull(replayDirectory).toFile()),
                    )
                    assertNull(recoveredAdapter.confirmOwnerKeyRotation(intent))
                    assertArrayEquals(latchedBytes, recovered.exportContainer())
                    assertEquals(intent, recovered.ownerKeyRotationDispatchIntent)
                    assertEquals(1, writeAttempts)
                    assertEquals(putsBeforeReuse, losingWirePeers)
                    return
                } finally {
                    latchedBytes.fill(0)
                }
            }
            if (conditionalRejection) {
                try {
                    assertTrue(conditionalWriteRejected)
                    assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
                    assertNull(result.confirmation)
                    assertEquals(1, writeAttempts)
                    assertArrayEquals(latchedBytes, dispatchWallet.exportContainer())
                    assertArrayEquals(activePublic, dispatchWallet.ownerPublicKey)
                    assertArrayEquals(pendingPublic, dispatchWallet.pendingOwnerPublicKey)
                    assertEquals(intent, dispatchWallet.ownerKeyRotationDispatchIntent)
                    assertEnvelopeEquals(predecessor, publishingTransport.getIdentityEnvelope(ownerName))
                    assertEnvelopeEquals(predecessor, publishingTransport.getRemoteIdentityEnvelope(ownerName))
                    assertThrows(WalletInvalidIdentityStateException::class.java) {
                        adapter.dispatchOwnerKeyRotation(publication, permit)
                    }
                    dispatchWallet.close()
                    wallet = null
                    val recovered = AndroidWallet.open(walletPath, password)
                    wallet = recovered
                    assertArrayEquals(latchedBytes, recovered.exportContainer())
                    assertArrayEquals(activePublic, recovered.ownerPublicKey)
                    assertArrayEquals(pendingPublic, recovered.pendingOwnerPublicKey)
                    assertEquals(intent, recovered.ownerKeyRotationDispatchIntent)
                    assertThrows(WalletRotationInProgressException::class.java) {
                        recovered.cancelSigningKeyRotation()
                    }
                    val freshReader = AndroidDirectDhtIdentityTransport(config)
                    freshReadbackTransport = freshReader
                    assertEnvelopeEquals(predecessor, freshReader.getRemoteIdentityEnvelope(ownerName))
                    val recoveredAdapter = AndroidIdentityAdapter(
                        freshReader,
                        FileAndroidIdentityReplayNonceStore(checkNotNull(replayDirectory).toFile()),
                    )
                    assertNull(recoveredAdapter.confirmOwnerKeyRotation(intent))
                    assertArrayEquals(latchedBytes, recovered.exportContainer())
                    assertEquals(intent, recovered.ownerKeyRotationDispatchIntent)
                    assertEquals(1, writeAttempts)
                    return
                } finally {
                    latchedBytes.fill(0)
                }
            }
            if (lostAcknowledgement) {
                assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
                assertNull(result.confirmation)
                assertEquals(1, writeAttempts)
                assertArrayEquals(latchedBytes, dispatchWallet.exportContainer())
                assertEquals(intent, dispatchWallet.ownerKeyRotationDispatchIntent)
                assertThrows(WalletInvalidIdentityStateException::class.java) {
                    adapter.dispatchOwnerKeyRotation(publication, permit)
                }
                assertEquals(1, writeAttempts)
            } else {
                assertEquals(OwnerKeyRotationDispatchStatus.CONFIRMED, result.status)
            }
            if (!lostAcknowledgement) latchedBytes.fill(0)
            assertEnvelopeEquals(candidate, publishingTransport.getIdentityEnvelope(ownerName))

            val freshReader = AndroidDirectDhtIdentityTransport(config)
            freshReadbackTransport = freshReader
            assertEnvelopeEquals(candidate, freshReader.getRemoteIdentityEnvelope(ownerName))
            val activeBeforePromotion = dispatchWallet.ownerPublicKey
            val pendingBeforePromotion = dispatchWallet.pendingOwnerPublicKey
            try {
                assertArrayEquals(activePublic, activeBeforePromotion)
                assertArrayEquals(pendingPublic, pendingBeforePromotion)
            } finally {
                activeBeforePromotion.fill(0)
                pendingBeforePromotion?.fill(0)
            }

            var promotionWallet = dispatchWallet
            var promotionConfirmation = result.confirmation
            if (lostAcknowledgement) {
                dispatchWallet.close()
                wallet = null
                val recovered = AndroidWallet.open(walletPath, password)
                wallet = recovered
                promotionWallet = recovered
                assertArrayEquals(latchedBytes, recovered.exportContainer())
                latchedBytes.fill(0)
                assertArrayEquals(activePublic, recovered.ownerPublicKey)
                assertArrayEquals(pendingPublic, recovered.pendingOwnerPublicKey)
                assertEquals(intent, recovered.ownerKeyRotationDispatchIntent)
                assertThrows(WalletRotationInProgressException::class.java) {
                    recovered.cancelSigningKeyRotation()
                }
                val recoveredAdapter = AndroidIdentityAdapter(
                    freshReader,
                    FileAndroidIdentityReplayNonceStore(checkNotNull(replayDirectory).toFile()),
                )
                promotionConfirmation = checkNotNull(recoveredAdapter.confirmOwnerKeyRotation(intent))
                assertEquals(1, writeAttempts)
            }
            if (promotionRollback || promotionUnknown) {
                val before = dispatchWallet.exportContainer()
                try {
                    dispatchWallet.close()
                    wallet = null
                    val raw = AtomicWalletFiles.read(walletPath)
                    val opened = ContainerCrypto.open(raw, password)
                    val retainedSeeds = listOf(
                        opened.payload["private_seed"] as ByteArray,
                        opened.payload["pending_private_seed"] as ByteArray,
                    )
                    var replacementCalls = 0
                    var syncCalls = 0
                    // No replacement seam: public finalization uses ordinary atomic storage,
                    // with the PR57 current-thread/normalized-directory sync hook only.
                    val faulted = WalletSession(walletPath, raw, opened.dek, opened.payload)
                    val directorySync: (java.nio.file.Path) -> Unit = { parent ->
                        syncCalls++
                        assertEquals(walletDirectory.toAbsolutePath().normalize(), parent)
                        val visible = Files.readAllBytes(walletPath)
                        try {
                            if (syncCalls == 1) {
                                replacementCalls++
                                assertTrue(!visible.contentEquals(before))
                                AndroidWallet.open(walletPath, password).use { installed ->
                                    assertArrayEquals(pendingPublic, installed.ownerPublicKey)
                                    assertNull(installed.pendingOwnerPublicKey)
                                    assertNull(installed.ownerKeyRotationDispatchIntent)
                                }
                            } else {
                                assertArrayEquals(before, visible)
                            }
                        } finally {
                            visible.fill(0)
                        }
                        if (syncCalls == 1 || promotionUnknown) throw IOException()
                        FileChannel.open(parent, READ).use { it.force(true) }
                    }
                    wallet = faulted
                    val failureType = if (promotionUnknown) {
                        WalletStorageOutcomeUnknownException::class.java
                    } else {
                        WalletStorageException::class.java
                    }
                    val failure = AtomicWalletFiles.withDirectorySyncForTest(walletDirectory, directorySync) {
                        assertThrows(failureType) {
                            faulted.finalizeSigningKeyRotation(checkNotNull(promotionConfirmation))
                        }
                    }
                    assertEquals(failureType, failure.javaClass)
                    assertEquals(
                        if (promotionUnknown) "wallet storage outcome is unknown" else "wallet storage operation failed",
                        failure.message,
                    )
                    assertEquals(1, replacementCalls)
                    assertEquals(2, syncCalls)
                    if (promotionUnknown) {
                        assertTrue(!faulted.isUnlocked)
                        // Before close: prove clearing of the retained buffers, not all JVM copies.
                        assertTrue(raw.all { it == 0.toByte() })
                        assertTrue(opened.dek.all { it == 0.toByte() })
                        assertTrue(retainedSeeds.all { seed -> seed.all { it == 0.toByte() } })
                        assertTrue(opened.payload.isEmpty())
                        assertThrows(WalletLockedException::class.java) { faulted.ownerPublicKey }
                        assertThrows(WalletLockedException::class.java) { faulted.pendingOwnerPublicKey }
                        assertThrows(WalletLockedException::class.java) { faulted.readPayload() }
                        assertThrows(WalletLockedException::class.java) { faulted.exportContainer() }
                        assertThrows(WalletLockedException::class.java) { faulted.cancelSigningKeyRotation() }
                        assertThrows(WalletLockedException::class.java) {
                            faulted.finalizeSigningKeyRotation(checkNotNull(promotionConfirmation))
                        }
                        assertEquals(1, replacementCalls)
                        assertEquals(2, syncCalls)
                        assertEquals(1, writeAttempts)
                        assertEnvelopeEquals(candidate, publishingTransport.getIdentityEnvelope(ownerName))
                        assertEnvelopeEquals(candidate, freshReader.getRemoteIdentityEnvelope(ownerName))
                        Files.list(walletDirectory).use { paths ->
                            assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
                        }
                        // Restored bytes are visible in this fixture, but failed sync means no durability claim.
                        assertArrayEquals(before, Files.readAllBytes(walletPath))
                        return
                    }
                    assertTrue(faulted.isUnlocked)
                    assertArrayEquals(before, Files.readAllBytes(walletPath))
                    assertArrayEquals(before, faulted.exportContainer())
                    assertArrayEquals(activePublic, faulted.ownerPublicKey)
                    assertArrayEquals(pendingPublic, faulted.pendingOwnerPublicKey)
                    assertEquals(intent, faulted.ownerKeyRotationDispatchIntent)
                    assertThrows(WalletRotationInProgressException::class.java) {
                        faulted.cancelSigningKeyRotation()
                    }
                    Files.list(walletDirectory).use { paths ->
                            assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
                        }
                    assertEnvelopeEquals(candidate, freshReader.getRemoteIdentityEnvelope(ownerName))
                    assertEquals(1, writeAttempts)
                    faulted.close()
                    wallet = null
                    val recovered = AndroidWallet.open(walletPath, password)
                    wallet = recovered
                    promotionWallet = recovered
                    assertArrayEquals(before, recovered.exportContainer())
                    assertArrayEquals(activePublic, recovered.ownerPublicKey)
                    assertArrayEquals(pendingPublic, recovered.pendingOwnerPublicKey)
                    assertEquals(intent, recovered.ownerKeyRotationDispatchIntent)
                    assertThrows(WalletRotationInProgressException::class.java) {
                        recovered.cancelSigningKeyRotation()
                    }
                    val recoveredAdapter = AndroidIdentityAdapter(
                        freshReader,
                        FileAndroidIdentityReplayNonceStore(checkNotNull(replayDirectory).toFile()),
                    )
                    promotionConfirmation = checkNotNull(recoveredAdapter.confirmOwnerKeyRotation(intent))
                    assertEquals(1, writeAttempts)
                } finally {
                    before.fill(0)
                }
            }
            if (promotionStagingFailure) {
                val before = dispatchWallet.exportContainer()
                val permissions = Files.getPosixFilePermissions(walletDirectory)
                try {
                    Files.setPosixFilePermissions(walletDirectory, PosixFilePermissions.fromString("r-x------"))
                    assertThrows(IOException::class.java) {
                        Files.createTempFile(walletDirectory, "probe-", ".tmp")
                    }
                    val failure = assertThrows(WalletStorageException::class.java) {
                        dispatchWallet.finalizeSigningKeyRotation(checkNotNull(promotionConfirmation))
                    }
                    assertEquals(WalletStorageException::class.java, failure.javaClass)
                    assertEquals("wallet storage operation failed", failure.message)
                    assertTrue(dispatchWallet.isUnlocked)
                    assertArrayEquals(before, Files.readAllBytes(walletPath))
                    assertEquals(intent, dispatchWallet.ownerKeyRotationDispatchIntent)
                    assertArrayEquals(activePublic, dispatchWallet.ownerPublicKey)
                    assertArrayEquals(pendingPublic, dispatchWallet.pendingOwnerPublicKey)
                    Files.list(walletDirectory).use { paths ->
                            assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
                        }
                } finally {
                    Files.setPosixFilePermissions(walletDirectory, permissions)
                }
                try {
                    dispatchWallet.close()
                    wallet = null
                    val recovered = AndroidWallet.open(walletPath, password)
                    wallet = recovered
                    promotionWallet = recovered
                    assertArrayEquals(before, recovered.exportContainer())
                    assertArrayEquals(activePublic, recovered.ownerPublicKey)
                    assertArrayEquals(pendingPublic, recovered.pendingOwnerPublicKey)
                    assertEquals(intent, recovered.ownerKeyRotationDispatchIntent)
                    assertThrows(WalletRotationInProgressException::class.java) {
                        recovered.cancelSigningKeyRotation()
                    }
                    assertEnvelopeEquals(candidate, freshReader.getRemoteIdentityEnvelope(ownerName))
                    val recoveredAdapter = AndroidIdentityAdapter(
                        freshReader,
                        FileAndroidIdentityReplayNonceStore(checkNotNull(replayDirectory).toFile()),
                    )
                    promotionConfirmation = checkNotNull(recoveredAdapter.confirmOwnerKeyRotation(intent))
                    assertEquals(1, writeAttempts)
                } finally {
                    before.fill(0)
                }
            }
            promotionWallet.finalizeSigningKeyRotation(checkNotNull(promotionConfirmation))
            assertEquals(1, writeAttempts)
            assertEnvelopeEquals(candidate, freshReader.getRemoteIdentityEnvelope(ownerName))
            val promotedPublicKey = promotionWallet.ownerPublicKey
            val pendingAfterPromotion = promotionWallet.pendingOwnerPublicKey
            try {
                assertArrayEquals(pendingPublic, promotedPublicKey)
                assertNull(pendingAfterPromotion)
                assertNull(promotionWallet.ownerKeyRotationDispatchIntent)
            } finally {
                promotedPublicKey.fill(0)
                pendingAfterPromotion?.fill(0)
            }
            promotionWallet.close()
            wallet = null

            val reopened = AndroidWallet.open(walletPath, password)
            reopenedWallet = reopened
            val persistedOwner = reopened.ownerPublicKey
            val persistedPending = reopened.pendingOwnerPublicKey
            try {
                assertArrayEquals(pendingPublic, persistedOwner)
                assertNull(persistedPending)
                assertNull(reopened.ownerKeyRotationDispatchIntent)
            } finally {
                persistedOwner.fill(0)
                persistedPending?.fill(0)
            }
        } finally {
            try {
                freshReadbackTransport?.close()
            } finally {
                try {
                    transport?.close()
                } finally {
                    try {
                        reopenedWallet?.close()
                    } finally {
                        try {
                            wallet?.close()
                        } finally {
                            ownerName.fill(0)
                            predecessor.fill(0)
                            candidate.fill(0)
                            competingEnvelope.fill(0)
                            competingExpectedHash.fill(0)
                            activeSeed.fill(0)
                            pendingSeed.fill(0)
                            activePublic.fill(0)
                            pendingPublic.fill(0)
                            signerSeeds.forEach { it.fill(0) }
                            signerPublicKeys.forEach { it.fill(0) }
                            replayNonce.fill(0)
                            try {
                                Files.walk(walletDirectory).use { paths ->
                                    paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
                                }
                            } finally {
                                replayDirectory?.let { directory ->
                                    Files.walk(directory).use { paths ->
                                        paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    @Test
    fun versionedHistoryAvailabilityFailsClosedBeforeDraftCreation() {
        val api = Build.VERSION.SDK_INT
        val abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
        assertTrue(
            "unexpected Android API/ABI: $api/$abi",
            (api == 26 && abi == "x86") || (api == 37 && abi == "x86_64"),
        )

        val arguments = InstrumentationRegistry.getArguments()
        val writerPeer = arguments.getString("decentRegistryTestPeer")
        val readbackPeer = arguments.getString("decentRegistryTestReadbackPeer")
        assumeTrue(
            "configure DECENT_REGISTRY_TEST_PEER and DECENT_REGISTRY_TEST_READBACK_PEER",
            !writerPeer.isNullOrBlank() && !readbackPeer.isNullOrBlank(),
        )
        assertTrue("fixture must use distinct writer and read-back peers", writerPeer != readbackPeer)

        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val fixtureKind = arguments.getString("decentRegistryTestFixture") ?: "legacy"
        check(
            fixtureKind == "legacy" ||
                fixtureKind == "versioned-missing-history" ||
                fixtureKind == "versioned-corrupt-history",
        ) {
            "unsupported Android Registry test fixture: $fixtureKind"
        }
        val versionedFault = fixtureKind != "legacy"
        val classFilter = arguments.getString("class")
        val expectedFaultFilter =
            "${this::class.java.name}#versionedHistoryAvailabilityFailsClosedBeforeDraftCreation"
        if (versionedFault) {
            check(classFilter == expectedFaultFilter) {
                "history-fault fixtures must run through the filtered history test"
            }
        } else {
            check(classFilter.isNullOrBlank()) {
                "filtered history test requires an explicit missing/corrupt fixture"
            }
        }
        val vectorName = if (versionedFault) {
            "identity-owner-key-rotation-versioned-history.json"
        } else {
            "identity-owner-key-rotation-legacy.json"
        }
        val ownerName = fixtureHex(instrumentation, "owner_name_utf8_hex", vectorName)
        var predecessor = byteArrayOf()
        var activeSeed = byteArrayOf()
        var pendingSeed = byteArrayOf()
        var activePublic = byteArrayOf()
        var pendingPublic = byteArrayOf()
        val walletDirectory = Files.createTempDirectory(
            instrumentation.context.cacheDir.toPath(),
            "android-missing-history-rotation-",
        )
        val walletPath = walletDirectory.resolve("wallet.dw")
        val password = UUID.randomUUID().toString()
        var replayDirectory: java.nio.file.Path? = null
        var wallet: WalletSession? = null
        var transport: AndroidDirectDhtIdentityTransport? = null
        try {
            val config = AndroidRegistryDhtConfig(
                registryEnvironment = "local-two-peer-registry-runtime",
                registryPeers = listOf(writerPeer!!),
                readbackPeer = readbackPeer!!,
                enableOwnerKeyRotation = true,
                requestTimeoutMillis = 30_000,
            )
            transport = AndroidDirectDhtIdentityTransport(config)
            if (!versionedFault) {
                predecessor = fixtureHex(
                    instrumentation,
                    "predecessor_envelope_cbor_hex",
                    vectorName,
                )
                assertEnvelopeEquals(predecessor, transport.getIdentityEnvelope(ownerName))
                return
            }

            activeSeed = syntheticSeed(1)
            pendingSeed = syntheticSeed(129)
            activePublic = AndroidIdentityCrypto.publicKeyFromSeed(activeSeed)
            pendingPublic = AndroidIdentityCrypto.publicKeyFromSeed(pendingSeed)
            assertArrayEquals(
                fixtureHex(instrumentation, "predecessor_owner_public_key_hex", vectorName),
                activePublic,
            )
            assertArrayEquals(
                fixtureHex(instrumentation, "successor_owner_public_key_hex", vectorName),
                pendingPublic,
            )
            val payload = mutableMapOf<String, Any?>(
                "private_seed" to activeSeed.copyOf(),
                "public_key" to activePublic.copyOf(),
                "pending_private_seed" to pendingSeed.copyOf(),
                "pending_public_key" to pendingPublic.copyOf(),
            )
            val activeWallet = try {
                AndroidWallet.create(walletPath, password, password, payload).also { wallet = it }
            } finally {
                WalletJson.clearByteArrays(payload)
                payload.clear()
                activeSeed.fill(0)
                pendingSeed.fill(0)
            }
            replayDirectory = Files.createTempDirectory(
                instrumentation.context.filesDir.toPath(),
                "android-missing-history-replay-",
            )
            val adapter = AndroidIdentityAdapter(
                checkNotNull(transport),
                FileAndroidIdentityReplayNonceStore(checkNotNull(replayDirectory).toFile()),
            )

            assertThrows(WalletIdentityStateChangedException::class.java) {
                adapter.createVersionedOwnerKeyRotationDraft(activeWallet, ownerName)
            }
            assertNull(activeWallet.ownerKeyRotationDispatchIntent)
            val activeAfterFailure = activeWallet.ownerPublicKey
            val pendingAfterFailure = activeWallet.pendingOwnerPublicKey
            try {
                assertArrayEquals(activePublic, activeAfterFailure)
                assertArrayEquals(pendingPublic, pendingAfterFailure)
            } finally {
                activeAfterFailure.fill(0)
                pendingAfterFailure?.fill(0)
            }
        } finally {
            try {
                transport?.close()
            } finally {
                try {
                    wallet?.close()
                } finally {
                    ownerName.fill(0)
                    predecessor.fill(0)
                    activeSeed.fill(0)
                    pendingSeed.fill(0)
                    activePublic.fill(0)
                    pendingPublic.fill(0)
                    try {
                        Files.walk(walletDirectory).use { paths ->
                            paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
                        }
                    } finally {
                        replayDirectory?.let { directory ->
                            Files.walk(directory).use { paths ->
                                paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun assertEnvelopeEquals(expected: ByteArray, actual: ByteArray?) {
        try {
            assertArrayEquals(expected, actual)
        } finally {
            actual?.fill(0)
        }
    }

    private fun syntheticSeed(start: Int): ByteArray = ByteArray(32) { index -> (start + index).toByte() }

    private fun fixtureHex(
        instrumentation: Instrumentation,
        field: String,
        vectorName: String = "identity-owner-key-rotation-legacy.json",
    ): ByteArray {
        val text = instrumentation.context.assets
            .open(vectorName)
            .bufferedReader(StandardCharsets.UTF_8)
            .use { it.readText() }
        val value = Regex("\\\"$field\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
            .find(text)?.groupValues?.get(1) ?: error("missing fixture field $field")
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}

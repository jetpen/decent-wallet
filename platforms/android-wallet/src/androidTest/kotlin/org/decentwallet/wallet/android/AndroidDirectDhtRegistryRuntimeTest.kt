package org.decentwallet.wallet.android

import android.app.Instrumentation
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.nio.file.Files
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
        var ownerName = byteArrayOf()
        var predecessor = byteArrayOf()
        var candidate = byteArrayOf()
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
            ownerName = fixtureHex(instrumentation, "owner_name_utf8_hex")
            predecessor = fixtureHex(instrumentation, "predecessor_envelope_cbor_hex")
            candidate = fixtureHex(instrumentation, "candidate_envelope_cbor_hex")
            activeSeed = syntheticSeed(0)
            pendingSeed = syntheticSeed(32)
            activePublic = AndroidIdentityCrypto.publicKeyFromSeed(activeSeed)
            pendingPublic = AndroidIdentityCrypto.publicKeyFromSeed(pendingSeed)
            signerSeeds = listOf(syntheticSeed(32), syntheticSeed(64), syntheticSeed(96))
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
                signerSeeds.forEach { it.fill(0) }
            }
            val signers = listOf(
                IdentityRotationSigner("alice-next", signerPublicKeys[0]),
                IdentityRotationSigner("bob", signerPublicKeys[1]),
                IdentityRotationSigner("carol", signerPublicKeys[2]),
            )
            signerPublicKeys.forEach { it.fill(0) }
            val draft = activeWallet.createLegacyOwnerKeyRotationDraft(ownerName, predecessor, signers)
            val draftEnvelope = draft.envelopeBytes
            try {
                assertArrayEquals(candidate, draftEnvelope)
            } finally {
                draftEnvelope.fill(0)
            }

            val config = AndroidRegistryDhtConfig(
                registryEnvironment = "local-two-peer-registry-runtime",
                registryPeers = listOf(writerPeer!!),
                readbackPeer = readbackPeer!!,
                enableOwnerKeyRotation = true,
                requestTimeoutMillis = 30_000,
            )
            val publishingTransport = AndroidDirectDhtIdentityTransport(config)
            transport = publishingTransport
            assertEnvelopeEquals(predecessor, publishingTransport.getIdentityEnvelope(ownerName))
            assertEnvelopeEquals(predecessor, publishingTransport.getRemoteIdentityEnvelope(ownerName))

            val consumedDigests = HashSet<List<Byte>>()
            val replayStore = AndroidIdentityReplayNonceStore { digest ->
                try {
                    consumedDigests.add(digest.toList())
                } finally {
                    digest.fill(0)
                }
            }
            val adapter = AndroidIdentityAdapter(publishingTransport, replayStore)
            replayNonce = ByteArray(32).also(SecureRandom()::nextBytes)
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
            assertEquals(1, consumedDigests.size)
            val publicationEnvelope = publication.envelopeBytes
            try {
                assertArrayEquals(candidate, publicationEnvelope)
            } finally {
                publicationEnvelope.fill(0)
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

            val result = adapter.dispatchOwnerKeyRotation(publication, permit)
            assertEquals(OwnerKeyRotationDispatchStatus.CONFIRMED, result.status)
            val confirmation = checkNotNull(result.confirmation)
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

            dispatchWallet.finalizeSigningKeyRotation(confirmation)
            val promotedPublicKey = dispatchWallet.ownerPublicKey
            val pendingAfterPromotion = dispatchWallet.pendingOwnerPublicKey
            try {
                assertArrayEquals(pendingPublic, promotedPublicKey)
                assertNull(pendingAfterPromotion)
                assertNull(dispatchWallet.ownerKeyRotationDispatchIntent)
            } finally {
                promotedPublicKey.fill(0)
                pendingAfterPromotion?.fill(0)
            }
            dispatchWallet.close()
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
                            activeSeed.fill(0)
                            pendingSeed.fill(0)
                            activePublic.fill(0)
                            pendingPublic.fill(0)
                            signerSeeds.forEach { it.fill(0) }
                            signerPublicKeys.forEach { it.fill(0) }
                            replayNonce.fill(0)
                            Files.walk(walletDirectory).use { paths ->
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

    private fun fixtureHex(instrumentation: Instrumentation, field: String): ByteArray {
        val text = instrumentation.context.assets
            .open("identity-owner-key-rotation-legacy.json")
            .bufferedReader(StandardCharsets.UTF_8)
            .use { it.readText() }
        val value = Regex("\\\"$field\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
            .find(text)?.groupValues?.get(1) ?: error("missing fixture field $field")
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}

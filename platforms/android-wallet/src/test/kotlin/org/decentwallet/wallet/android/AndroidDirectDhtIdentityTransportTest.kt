package org.decentwallet.wallet.android

import io.libp2p.core.PeerId
import io.libp2p.core.crypto.KeyType
import io.libp2p.core.crypto.generateKeyPair
import java.io.IOException
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidDirectDhtIdentityTransportTest {
    private val peerOne = peerMultiaddr(4001)
    private val peerTwo = peerMultiaddr(4002)

    @Test
    fun currentAndRemoteReadsIssueFreshDirectRequestsToPinnedPeer() {
        val ownerName = fixtureHex("owner_name_utf8_hex")
        val envelope = fixtureHex("candidate_envelope_cbor_hex")
        val client = FakeKadDhtClient()
        val identityKey = AndroidRegistryDhtKey.identity(ownerName)
        client.records[peerOne to identityKey.toHexForTest()] = envelope.copyOf()
        val transport = transport(client)
        try {
            assertArrayEquals(envelope, transport.getIdentityEnvelope(ownerName))
            assertArrayEquals(envelope, transport.getRemoteIdentityEnvelope(ownerName))
            assertEquals(listOf(peerOne, peerOne), client.getCalls.map { it.first })
            assertEquals(
                listOf(identityKey.toHexForTest(), identityKey.toHexForTest()),
                client.getCalls.map { it.second.toHexForTest() },
            )
            assertTrue(client.putCalls.isEmpty())
        } finally {
            transport.close()
            ownerName.fill(0)
            envelope.fill(0)
            identityKey.fill(0)
        }
    }

    @Test
    fun historyLookupUsesRawOwnerAndStateHashesAndTriesConfiguredPeers() {
        val ownerName = fixtureHex("owner_name_utf8_hex")
        val stateHash = fixtureHex("genesis_state_hash_hex")
        val genesis = fixtureHex("genesis_envelope_cbor_hex")
        val client = FakeKadDhtClient()
        val key = AndroidRegistryDhtKey.history(ownerName, stateHash)
        client.records[peerTwo to key.toHexForTest()] = genesis.copyOf()
        val transport = transport(client)
        try {
            assertArrayEquals(genesis, transport.getIdentityEnvelopeByHash(ownerName, stateHash))
            assertEquals(listOf(peerOne, peerTwo), client.getCalls.map { it.first })
            assertArrayEquals(key, client.getCalls.last().second)
        } finally {
            transport.close()
            ownerName.fill(0)
            stateHash.fill(0)
            genesis.fill(0)
            key.fill(0)
        }
    }

    @Test
    fun mixedMissingAndPeerFailureIsTransportFailure() {
        val ownerName = fixtureHex("owner_name_utf8_hex")
        val stateHash = fixtureHex("genesis_state_hash_hex")
        val client = FakeKadDhtClient().apply {
            failures[peerTwo] = IOException("synthetic peer failure")
        }
        val transport = transport(client)
        try {
            assertThrows(WalletIdentityTransportException::class.java) {
                transport.getIdentityEnvelopeByHash(ownerName, stateHash)
            }
            assertEquals(listOf(peerOne, peerTwo), client.getCalls.map { it.first })
        } finally {
            transport.close()
            ownerName.fill(0)
            stateHash.fill(0)
        }
    }

    @Test
    fun historyLookupReturnsMissingOnlyAfterEveryPeerResponds() {
        val ownerName = fixtureHex("owner_name_utf8_hex")
        val stateHash = fixtureHex("genesis_state_hash_hex")
        val client = FakeKadDhtClient()
        val transport = transport(client)
        try {
            assertEquals(null, transport.getIdentityEnvelopeByHash(ownerName, stateHash))
            assertEquals(listOf(peerOne, peerTwo), client.getCalls.map { it.first })
        } finally {
            transport.close()
            ownerName.fill(0)
            stateHash.fill(0)
        }
    }

    @Test
    fun staleCurrentHeadPreventsAnyPublication() {
        val ownerName = fixtureHex("owner_name_utf8_hex")
        val predecessor = fixtureHex("predecessor_envelope_cbor_hex")
        val candidate = fixtureHex("candidate_envelope_cbor_hex")
        val staleExpectedHash = fixtureHex("genesis_state_hash_hex")
        val client = FakeKadDhtClient()
        client.records[peerOne to AndroidRegistryDhtKey.identity(ownerName).toHexForTest()] = predecessor.copyOf()
        addHistory(client, ownerName)
        val transport = transport(client)
        try {
            assertThrows(AndroidIdentityPreconditionFailedException::class.java) {
                transport.putIdentityEnvelopeIfCurrent(
                    ownerNameBytes = ownerName,
                    envelopeBytes = candidate,
                    expectedStateHash = staleExpectedHash,
                    expiresAt = 2_000,
                )
            }
            assertTrue(client.putCalls.isEmpty())
        } finally {
            transport.close()
            ownerName.fill(0)
            predecessor.fill(0)
            candidate.fill(0)
            staleExpectedHash.fill(0)
        }
    }

    @Test
    fun expiredPublicationIsRejectedBeforeDhtWrite() {
        val ownerName = fixtureHex("owner_name_utf8_hex")
        val predecessor = fixtureHex("predecessor_envelope_cbor_hex")
        val candidate = fixtureHex("candidate_envelope_cbor_hex")
        val expectedHash = fixtureHex("predecessor_state_hash_hex")
        val client = FakeKadDhtClient()
        client.records[peerOne to AndroidRegistryDhtKey.identity(ownerName).toHexForTest()] = predecessor.copyOf()
        addHistory(client, ownerName)
        val transport = transport(client, nowEpochSeconds = 2_000)
        try {
            assertThrows(AndroidIdentityWriteExpiredException::class.java) {
                transport.putIdentityEnvelopeIfCurrent(
                    ownerNameBytes = ownerName,
                    envelopeBytes = candidate,
                    expectedStateHash = expectedHash,
                    expiresAt = 2_000,
                )
            }
            assertTrue(client.putCalls.isEmpty())
        } finally {
            transport.close()
            ownerName.fill(0)
            predecessor.fill(0)
            candidate.fill(0)
            expectedHash.fill(0)
        }
    }

    @Test
    fun validCandidatePublishesExactBytesAndFreshReadSeesPeerValue() {
        val ownerName = fixtureHex("owner_name_utf8_hex")
        val predecessor = fixtureHex("predecessor_envelope_cbor_hex")
        val candidate = fixtureHex("candidate_envelope_cbor_hex")
        val expectedHash = fixtureHex("predecessor_state_hash_hex")
        val client = FakeKadDhtClient()
        client.records[peerOne to AndroidRegistryDhtKey.identity(ownerName).toHexForTest()] = predecessor.copyOf()
        addHistory(client, ownerName)
        val transport = transport(client)
        try {
            transport.putIdentityEnvelopeIfCurrent(
                ownerNameBytes = ownerName,
                envelopeBytes = candidate,
                expectedStateHash = expectedHash,
                expiresAt = 2_000,
            )
            assertEquals(1, client.putCalls.size)
            assertEquals(peerOne, client.putCalls.single().first)
            assertArrayEquals(candidate, client.putCalls.single().third)
            assertArrayEquals(candidate, transport.getRemoteIdentityEnvelope(ownerName))
        } finally {
            transport.close()
            ownerName.fill(0)
            predecessor.fill(0)
            candidate.fill(0)
            expectedHash.fill(0)
        }
    }

    @Test
    fun explicitConfigurationIsRequiredToEnableRotation() {
        val disabled = AndroidDirectDhtIdentityTransport(
            AndroidRegistryDhtConfig("testnet", listOf(peerOne)),
            FakeKadDhtClient(),
            { 1_000 },
        )
        val enabled = AndroidDirectDhtIdentityTransport(
            AndroidRegistryDhtConfig("testnet", listOf(peerOne), enableOwnerKeyRotation = true),
            FakeKadDhtClient(),
            { 1_000 },
        )
        try {
            assertFalse(disabled.supportsOwnerKeyRotation)
            assertTrue(enabled.supportsOwnerKeyRotation)
        } finally {
            disabled.close()
            enabled.close()
        }
    }

    private fun transport(client: FakeKadDhtClient, nowEpochSeconds: Long = 1_000) =
        AndroidDirectDhtIdentityTransport(
            AndroidRegistryDhtConfig(
                registryEnvironment = "testnet",
                registryPeers = listOf(peerOne, peerTwo),
                enableOwnerKeyRotation = true,
            ),
            client,
            { nowEpochSeconds },
        )

    private fun addHistory(client: FakeKadDhtClient, ownerName: ByteArray) {
        val genesisHash = fixtureHex("genesis_state_hash_hex")
        val predecessorHash = fixtureHex("predecessor_state_hash_hex")
        val genesis = fixtureHex("genesis_envelope_cbor_hex")
        val predecessor = fixtureHex("predecessor_envelope_cbor_hex")
        client.records[peerOne to AndroidRegistryDhtKey.history(ownerName, genesisHash).toHexForTest()] = genesis
        client.records[peerOne to AndroidRegistryDhtKey.history(ownerName, predecessorHash).toHexForTest()] = predecessor
        genesisHash.fill(0)
        predecessorHash.fill(0)
    }

    private fun fixtureHex(field: String): ByteArray {
        val text = checkNotNull(javaClass.getResourceAsStream("/identity-owner-key-rotation-versioned-history.json"))
            .bufferedReader(StandardCharsets.UTF_8)
            .use { it.readText() }
        val value = Regex("\\\"$field\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
            .find(text)?.groupValues?.get(1) ?: error("missing fixture field $field")
        return ByteArray(value.length / 2) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private class FakeKadDhtClient : AndroidKadDhtRpcClient {
        val records = mutableMapOf<Pair<String, String>, ByteArray>()
        val failures = mutableMapOf<String, Exception>()
        val getCalls = mutableListOf<Pair<String, ByteArray>>()
        val putCalls = mutableListOf<Triple<String, ByteArray, ByteArray>>()

        override fun getValue(peerMultiaddr: String, key: ByteArray): ByteArray? {
            getCalls += peerMultiaddr to key.copyOf()
            failures[peerMultiaddr]?.let { throw it }
            return records[peerMultiaddr to key.toHexForTest()]?.copyOf()
        }

        override fun putValue(peerMultiaddr: String, key: ByteArray, value: ByteArray): Boolean {
            putCalls += Triple(peerMultiaddr, key.copyOf(), value.copyOf())
            records[peerMultiaddr to key.toHexForTest()] = value.copyOf()
            return true
        }

        override fun close() = Unit
    }
}

private fun peerMultiaddr(port: Int): String {
    val publicKey = generateKeyPair(KeyType.ED25519).second
    return "/ip4/127.0.0.1/tcp/$port/p2p/${PeerId.fromPubKey(publicKey)}"
}

private fun ByteArray.toHexForTest(): String = joinToString("") {
    "%02x".format(it.toInt() and 0xff)
}

package org.decentwallet.wallet.android

import java.io.IOException
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assume.assumeTrue
import org.junit.Test

class AndroidDirectDhtRegistryInteropTest {
    @Test
    fun readsHistoryPublishesAndFreshReadsAgainstPythonRegistryPeer() {
        val peer = System.getProperty("decent.registry.test.peer")?.takeIf { it.isNotBlank() }
            ?: System.getenv("DECENT_REGISTRY_TEST_PEER")?.takeIf { it.isNotBlank() }
        val readbackPeer = System.getProperty("decent.registry.test.readback.peer")?.takeIf { it.isNotBlank() }
            ?: System.getenv("DECENT_REGISTRY_TEST_READBACK_PEER")?.takeIf { it.isNotBlank() }
        assumeTrue(
            "set DECENT_REGISTRY_TEST_PEER and DECENT_REGISTRY_TEST_READBACK_PEER to live local Registry multiaddrs",
            !peer.isNullOrBlank() && !readbackPeer.isNullOrBlank(),
        )

        val ownerName = fixtureHex("owner_name_utf8_hex")
        val predecessor = fixtureHex("predecessor_envelope_cbor_hex")
        val candidate = fixtureHex("candidate_envelope_cbor_hex")
        val predecessorHash = fixtureHex("predecessor_state_hash_hex")
        val transport = AndroidDirectDhtIdentityTransport(
            AndroidRegistryDhtConfig(
                registryEnvironment = "local-python-registry-interop",
                registryPeers = listOf(peer!!),
                readbackPeer = readbackPeer!!,
                enableOwnerKeyRotation = true,
                requestTimeoutMillis = 20_000,
            ),
        )
        try {
            assertArrayEquals(predecessor, transport.getIdentityEnvelope(ownerName))
            assertArrayEquals(predecessor, transport.getIdentityEnvelopeByHash(ownerName, predecessorHash))
            assertArrayEquals(predecessor, transport.getRemoteIdentityEnvelope(ownerName))

            transport.putIdentityEnvelopeIfCurrent(
                ownerNameBytes = ownerName,
                envelopeBytes = candidate,
                expectedStateHash = predecessorHash,
                expiresAt = Long.MAX_VALUE,
            )
            assertArrayEquals(candidate, transport.getRemoteIdentityEnvelope(ownerName))

            val key = AndroidRegistryDhtKey.identity(ownerName)
            val rpcClient = JvmLibp2pKadDhtRpcClient(20_000, listOf(peer))
            try {
                val invalidPutAccepted = try {
                    rpcClient.putValue(peer, key, byteArrayOf(0xa0.toByte()))
                } catch (_: IOException) {
                    false
                }
                assertFalse(invalidPutAccepted)
                assertArrayEquals(candidate, rpcClient.getValue(peer, key))
            } finally {
                rpcClient.close()
                key.fill(0)
            }
        } finally {
            transport.close()
            ownerName.fill(0)
            predecessor.fill(0)
            candidate.fill(0)
            predecessorHash.fill(0)
        }
    }

    private fun fixtureHex(field: String): ByteArray {
        val text = checkNotNull(javaClass.getResourceAsStream("/identity-owner-key-rotation-legacy.json"))
            .bufferedReader(StandardCharsets.UTF_8)
            .use { it.readText() }
        val value = Regex("\\\"$field\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
            .find(text)?.groupValues?.get(1) ?: error("missing fixture field $field")
        return ByteArray(value.length / 2) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
}

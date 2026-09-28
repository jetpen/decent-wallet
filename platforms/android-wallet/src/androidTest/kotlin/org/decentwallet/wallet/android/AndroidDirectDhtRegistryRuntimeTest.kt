package org.decentwallet.wallet.android

import android.app.Instrumentation
import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.nio.charset.StandardCharsets

class AndroidDirectDhtRegistryRuntimeTest {
    @Test
    fun publishesCandidateAndConfirmsItFromIndependentPeerOnAndroid() {
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

        val instrumentation = InstrumentationRegistry.getInstrumentation()
        var ownerName = byteArrayOf()
        var predecessor = byteArrayOf()
        var candidate = byteArrayOf()
        var predecessorHash = byteArrayOf()
        var transport: AndroidDirectDhtIdentityTransport? = null
        var freshReadbackTransport: AndroidDirectDhtIdentityTransport? = null
        try {
            ownerName = fixtureHex(instrumentation, "owner_name_utf8_hex")
            predecessor = fixtureHex(instrumentation, "predecessor_envelope_cbor_hex")
            candidate = fixtureHex(instrumentation, "candidate_envelope_cbor_hex")
            predecessorHash = fixtureHex(instrumentation, "predecessor_state_hash_hex")
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
            assertEnvelopeEquals(
                predecessor,
                publishingTransport.getIdentityEnvelopeByHash(ownerName, predecessorHash),
            )

            publishingTransport.putIdentityEnvelopeIfCurrent(
                ownerNameBytes = ownerName,
                envelopeBytes = candidate,
                expectedStateHash = predecessorHash,
                expiresAt = Long.MAX_VALUE,
            )
            assertEnvelopeEquals(candidate, publishingTransport.getIdentityEnvelope(ownerName))

            val freshReader = AndroidDirectDhtIdentityTransport(config)
            freshReadbackTransport = freshReader
            assertEnvelopeEquals(candidate, freshReader.getRemoteIdentityEnvelope(ownerName))
        } finally {
            try {
                freshReadbackTransport?.close()
            } finally {
                try {
                    transport?.close()
                } finally {
                    ownerName.fill(0)
                    predecessor.fill(0)
                    candidate.fill(0)
                    predecessorHash.fill(0)
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

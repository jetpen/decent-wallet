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
    fun readsVersionedHistoryAndCandidateFromIndependentRegistryPeers() {
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
        val ownerName = fixtureHex(instrumentation, "owner_name_utf8_hex")
        val predecessor = fixtureHex(instrumentation, "predecessor_envelope_cbor_hex")
        val candidate = fixtureHex(instrumentation, "candidate_envelope_cbor_hex")
        val predecessorHash = fixtureHex(instrumentation, "predecessor_state_hash_hex")
        val transport = AndroidDirectDhtIdentityTransport(
            AndroidRegistryDhtConfig(
                registryEnvironment = "local-two-peer-registry-runtime",
                registryPeers = listOf(writerPeer!!),
                readbackPeer = readbackPeer!!,
                enableOwnerKeyRotation = true,
                requestTimeoutMillis = 30_000,
            ),
        )
        try {
            assertArrayEquals(candidate, transport.getIdentityEnvelope(ownerName))
            assertArrayEquals(
                predecessor,
                transport.getIdentityEnvelopeByHash(ownerName, predecessorHash),
            )
            assertArrayEquals(candidate, transport.getRemoteIdentityEnvelope(ownerName))
        } finally {
            transport.close()
            ownerName.fill(0)
            predecessor.fill(0)
            candidate.fill(0)
            predecessorHash.fill(0)
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

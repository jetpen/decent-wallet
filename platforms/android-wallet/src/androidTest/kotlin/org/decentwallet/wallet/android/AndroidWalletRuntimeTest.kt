package org.decentwallet.wallet.android

import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.nio.file.Files
import java.util.Comparator

class AndroidWalletRuntimeTest {
    @Test
    fun runsOnlyOnTheApprovedApiAndAbiTargets() {
        val api = Build.VERSION.SDK_INT
        val abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
        assertTrue("unexpected Android API/ABI: $api/$abi", (api == 26 && abi == "x86") || (api == 37 && abi == "x86_64"))
        assertTrue(Build.FINGERPRINT.isNotBlank())
    }

    @Test
    fun productionLifecycleMatchesVectorAndPreservesEncryptedBytes() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val assets = instrumentation.context.assets
        val vector = assets.open("wallet-container-v2.json").use { it.readBytes() }
        val fixture = assets.open("wallet-v1-pending-rotation.dw").use { it.readBytes() }
        val vectorContainer = vectorContainer(vector)
        val directory = Files.createTempDirectory(instrumentation.targetContext.cacheDir.toPath(), "decent-wallet-")
        try {
            val vectorPath = directory.resolve("vector.dw")
            Files.write(vectorPath, vectorContainer)
            val vectorWallet = AndroidWallet.open(vectorPath, "public-test-only: wallet-v2-vector")
            try {
                val payload = vectorWallet.readPayload()
                assertEquals(BigInteger.valueOf(7), payload["count"])
                assertEquals("wallet-container-v2-interop-café", payload["label"])
                assertArrayEquals(byteArrayOf(0, -1, 16), payload["opaque"] as ByteArray)
                assertArrayEquals(
                    decodeHex("2543b92ff1095511476adc8369db6ddc933665a11978dda1404ee1066ca9559d"),
                    payload["public_key"] as ByteArray,
                )
                assertArrayEquals(vectorContainer, vectorWallet.exportContainer())
                WalletJson.clearByteArrays(payload)
                vectorWallet.background()
                assertFalse(vectorWallet.isUnlocked)
            } finally {
                vectorWallet.close()
            }

            val password = "a sufficiently long device-test password"
            val createdPath = directory.resolve("created.dw")
            val created = AndroidWallet.create(
                createdPath,
                password,
                password,
                mapOf("owner" to "device-test", "opaque" to byteArrayOf(4, 5, 6)),
            )
            val exported = created.exportContainer()
            created.close()
            val importedPath = directory.resolve("imported.dw")
            val imported = AndroidWallet.importContainer(importedPath, exported, password)
            try {
                assertArrayEquals(exported, Files.readAllBytes(importedPath))
                val payload = imported.readPayload()
                assertEquals("device-test", payload["owner"])
                assertArrayEquals(byteArrayOf(4, 5, 6), payload["opaque"] as ByteArray)
                WalletJson.clearByteArrays(payload)
            } finally {
                imported.close()
                exported.fill(0)
            }

            val legacyPath = directory.resolve("legacy.dw")
            Files.write(legacyPath, fixture)
            val migrated = AndroidWallet.migrateContainer(legacyPath, "correct horse battery staple")
            try {
                val current = Files.readAllBytes(legacyPath)
                val envelope = WalletJson.parse(current, ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>
                assertEquals(BigInteger.valueOf(2), envelope["version"])
                current.fill(0)
                assertTrue(migrated.isUnlocked)
            } finally {
                migrated.close()
            }
        } finally {
            vector.fill(0)
            fixture.fill(0)
            vectorContainer.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private fun decodeHex(value: String): ByteArray = ByteArray(value.length / 2) { index ->
        value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
    }

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

package org.decentwallet.wallet.android

import android.os.Build
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException
import java.math.BigInteger
import java.nio.channels.FileChannel
import java.nio.file.StandardOpenOption.READ
import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
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
    fun presentationVerifierNarrowsBigIntegerAtApi26WithoutLongValueExact() {
        assertEquals(Long.MIN_VALUE, WalletAccountPresentationVerifier.exactLong(BigInteger.valueOf(Long.MIN_VALUE)))
        assertEquals(Long.MAX_VALUE, WalletAccountPresentationVerifier.exactLong(BigInteger.valueOf(Long.MAX_VALUE)))
        assertThrows(WalletDisclosureRequestException::class.java) {
            WalletAccountPresentationVerifier.exactLong(BigInteger.valueOf(Long.MIN_VALUE).subtract(BigInteger.ONE))
        }
        assertThrows(WalletDisclosureRequestException::class.java) {
            WalletAccountPresentationVerifier.exactLong(BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE))
        }
    }

    @Test
    fun ownerBindingVerifierUsesSupportedAndroidCryptoProviders() {
        val now = 1_800_000_001L
        val ownerX = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 3 })
        val jti = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(32) { 7 })
        val thumbJson = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"$ownerX\"}"
        val thumbprint = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(
            java.security.MessageDigest.getInstance("SHA-256").digest(thumbJson.toByteArray(Charsets.US_ASCII)),
        )
        val context = WalletAccountDisclosureContext(
            keycloakIssuer = "https://login.example.test/realm",
            rpClientId = "client",
            rpDisplayName = "Example",
            rpOrigin = "https://rp.example.test",
            action = "signup",
            requestId = "request-id",
            transactionId = "transaction-id",
            oidcNonce = "nonce",
            purpose = "Runtime crypto provider test",
            claims = emptyList(),
            expiresAtEpochSeconds = 1_800_000_300L,
        )
        val payload = mapOf(
            "v" to 1,
            "iss" to context.keycloakIssuer,
            "aud" to context.rpClientId,
            "sub" to "subject",
            "identity_id" to "mailto:test@example.test",
            "owner_key" to mapOf("kty" to "OKP", "crv" to "Ed25519", "x" to ownerX),
            "owner_key_thumbprint" to thumbprint,
            "action" to context.action,
            "transaction_id" to context.transactionId,
            "request_id" to context.requestId,
            "oidc_nonce" to context.oidcNonce,
            "iat" to now,
            "exp" to context.expiresAtEpochSeconds,
            "jti" to jti,
        )
        val rsa = java.security.KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
        val rsaPublic = rsa.public as java.security.interfaces.RSAPublicKey
        fun unsigned(value: BigInteger): String {
            val bytes = value.toByteArray().let { if (it.first() == 0.toByte()) it.copyOfRange(1, it.size) else it }
            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }
        val jwks = mapOf(
            "keys" to listOf(
                mapOf(
                    "kid" to "runtime-key",
                    "kty" to "RSA",
                    "use" to "sig",
                    "alg" to "RS256",
                    "n" to unsigned(rsaPublic.modulus),
                    "e" to unsigned(rsaPublic.publicExponent),
                ),
            ),
        )
        val encoder = java.util.Base64.getUrlEncoder().withoutPadding()
        val header = encoder.encodeToString(
            WalletJson.canonicalBytes(mapOf("alg" to "RS256", "kid" to "runtime-key", "typ" to "decent-owner-key-binding+jwt")),
        )
        val body = encoder.encodeToString(WalletJson.canonicalBytes(payload))
        val signingInput = "$header.$body"
        val signer = java.security.Signature.getInstance("SHA256withRSA")
        signer.initSign(rsa.private)
        signer.update(signingInput.toByteArray(Charsets.US_ASCII))
        val compact = "$signingInput.${encoder.encodeToString(signer.sign())}"

        val result = WalletOwnerKeyBindingVerifier.verify(
            compact,
            jwks,
            context,
            "mailto:test@example.test",
            now,
        )

        assertEquals("subject", result.subject)
        assertEquals(ownerX, result.ownerKey.x)
        assertEquals(thumbprint, result.ownerKeyThumbprint)
    }

    @Test
    fun requestObjectVerifierUsesAndroidX509AndEcdsaProviders() {
        val vector = InstrumentationRegistry.getInstrumentation().context.assets
            .open("wallet-account-disclosure-v1/vectors/valid-signup.json").use { it.readBytes() }
        try {
            val root = WalletJson.parse(vector, 64 * 1024) as Map<*, *>
            val now = (root["validation_time"] as BigInteger).toLong()
            val context = WalletAccountDisclosureContextParser.parse(
                WalletJson.canonicalBytes(root["keycloak_context"]),
                root["transaction_handle"] as String,
                "https://login.example.test/realms/site",
                now,
            )
            val ownerBindingJws = root["owner_key_binding_jws"] as String
            val binding = WalletOwnerKeyBindingVerifier.verify(
                ownerBindingJws,
                root["keycloak_jwks"] as Map<*, *>,
                context,
                "mailto:ada@example.test",
                now,
            )
            val certificate = root["rp_certificate"] as Map<*, *>
            val registration = TrustedWalletRelyingPartyRegistration(
                root["oid4vp_client_id"] as String,
                "site.example.test",
                context.rpOrigin,
                "https://site.example.test/oid4vp/response",
                certificate["trust_anchor_sha256"] as String,
                context.rpClientId,
            )
            val verified = WalletOid4vpRequestVerifier.verify(
                root["oid4vp_authorization_parameters"] as Map<*, *>,
                root["oid4vp_request_jws"] as String,
                registration,
                context,
                ownerBindingJws,
                binding,
                now,
            )
            assertEquals("x509_san_dns:site.example.test", verified.clientId)
            assertEquals("signup", verified.action)
            assertEquals(1_800_000_300L, verified.expiresAtEpochSeconds)
        } finally {
            vector.fill(0)
        }
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

    @Test
    fun publicImportSyncFailureRemovesDestinationAndAllowsRecoveryOnAndroid() {
        exercisePublicImportSyncFailure(cleanupSyncFails = false)
    }

    @Test
    fun publicImportUnknownCleanupReturnsNoSessionOnAndroid() {
        exercisePublicImportSyncFailure(cleanupSyncFails = true)
    }

    private fun exercisePublicImportSyncFailure(cleanupSyncFails: Boolean) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val vector = instrumentation.context.assets.open("wallet-container-v2.json").use { it.readBytes() }
        val imported = vectorContainer(vector)
        val password = "public-test-only: wallet-v2-vector"
        val directory = Files.createTempDirectory(instrumentation.targetContext.cacheDir.toPath(), "public-import-sync-")
        val path = directory.resolve("wallet.dw")
        var syncCalls = 0
        var sessionReturned = false
        try {
            assertFalse(Files.exists(path))
            val failureType = if (cleanupSyncFails) WalletStorageOutcomeUnknownException::class.java else WalletStorageException::class.java
            val failure = assertThrows(failureType) {
                AtomicWalletFiles.withDirectorySyncForTest(directory, { parent ->
                    syncCalls++
                    assertEquals(directory.toAbsolutePath().normalize(), parent)
                    if (syncCalls == 1) {
                        val visible = Files.readAllBytes(path)
                        try {
                            assertArrayEquals(imported, visible)
                            val opened = ContainerCrypto.open(visible, password)
                            try {
                                assertEquals(BigInteger.valueOf(7), opened.payload["count"])
                                assertEquals("wallet-container-v2-interop-café", opened.payload["label"])
                            } finally {
                                opened.dek.fill(0)
                                WalletJson.clearByteArrays(opened.payload)
                                opened.payload.clear()
                            }
                        } finally {
                            visible.fill(0)
                        }
                    } else {
                        assertFalse(Files.exists(path))
                    }
                    if (syncCalls == 1 || cleanupSyncFails) throw IOException()
                    FileChannel.open(parent, READ).use { it.force(true) }
                }) {
                    AndroidWallet.importContainer(path, imported, password).use { sessionReturned = true }
                }
            }
            assertEquals(failureType, failure.javaClass)
            assertEquals(if (cleanupSyncFails) "wallet storage outcome is unknown" else "wallet storage operation failed", failure.message)
            assertFalse(sessionReturned)
            assertEquals(2, syncCalls)
            assertFalse(Files.exists(path))
            Files.list(directory).use { paths ->
                assertEquals(0L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
            if (!cleanupSyncFails) {
                AndroidWallet.importContainer(path, imported, password).use { recovered ->
                    assertArrayEquals(imported, recovered.exportContainer())
                }
                AndroidWallet.open(path, password).use { reopened ->
                    assertArrayEquals(imported, reopened.exportContainer())
                }
                Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
            } else {
                // Absent destination is a fixture observation, not durable deletion proof.
                val probe = directory.resolve("scope-probe.dw")
                AndroidWallet.create(probe, password, password, mapOf("purpose" to "scope-check")).use { }
                Files.delete(probe)
                Files.list(directory).use { paths ->
                assertEquals(0L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
                // Do not retry/reopen the unknown-outcome destination.
            }
            assertEquals(2, syncCalls)
        } finally {
            vector.fill(0)
            imported.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
        assertFalse(Files.exists(directory))
    }

    @Test
    fun publicMigrationUnknownRollbackReturnsNoSessionOnAndroid() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val original = instrumentation.context.assets.open("wallet-v1-pending-rotation.dw").use { it.readBytes() }
        val password = "correct horse battery staple"
        val directory = Files.createTempDirectory(instrumentation.targetContext.cacheDir.toPath(), "public-migrate-unknown-")
        val path = directory.resolve("wallet.dw")
        val reference = ContainerCrypto.migrate(password, original)
        val active = (reference.payload["public_key"] as ByteArray).copyOf()
        val pending = (reference.payload["pending_public_key"] as ByteArray).copyOf()
        reference.bytes.fill(0)
        reference.dek.fill(0)
        WalletJson.clearByteArrays(reference.payload)
        reference.payload.clear()
        var syncCalls = 0
        var sessionReturned = false
        try {
            Files.write(path, original)
            val failure = assertThrows(WalletStorageOutcomeUnknownException::class.java) {
                AtomicWalletFiles.withDirectorySyncForTest(directory, { parent ->
                    syncCalls++
                    assertEquals(directory.toAbsolutePath().normalize(), parent)
                    val visible = Files.readAllBytes(path)
                    try {
                        if (syncCalls == 1) {
                            val envelope = WalletJson.parse(visible, ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>
                            assertEquals(BigInteger.valueOf(2), envelope["version"])
                            val opened = ContainerCrypto.open(visible, password)
                            try {
                                assertArrayEquals(active, opened.payload["public_key"] as ByteArray)
                                assertArrayEquals(pending, opened.payload["pending_public_key"] as ByteArray)
                            } finally {
                                opened.dek.fill(0)
                                WalletJson.clearByteArrays(opened.payload)
                                opened.payload.clear()
                            }
                        } else {
                            assertArrayEquals(original, visible)
                        }
                    } finally {
                        visible.fill(0)
                    }
                    throw IOException()
                }) {
                    AndroidWallet.migrateContainer(path, password).use { sessionReturned = true }
                }
            }
            assertEquals(WalletStorageOutcomeUnknownException::class.java, failure.javaClass)
            assertEquals("wallet storage outcome is unknown", failure.message)
            assertFalse(sessionReturned)
            assertEquals(2, syncCalls)
            Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
            // Fixture observation only: failed rollback sync does not establish durable original state.
            assertArrayEquals(original, Files.readAllBytes(path))
            val probe = directory.resolve("scope-probe.dw")
            AndroidWallet.create(probe, password, password, mapOf("purpose" to "scope-check")).use { }
            assertEquals(2, syncCalls)
            Files.delete(probe)
            Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
            // No reopen, retry or promoted-state claim for the unknown-outcome wallet.
        } finally {
            original.fill(0)
            active.fill(0)
            pending.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
        assertFalse(Files.exists(directory))
    }

    @Test
    fun publicMigrationSyncFailureRestoresV1AndAllowsRecoveryOnAndroid() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val original = instrumentation.context.assets.open("wallet-v1-pending-rotation.dw").use { it.readBytes() }
        val password = "correct horse battery staple"
        val directory = Files.createTempDirectory(instrumentation.targetContext.cacheDir.toPath(), "public-migrate-sync-")
        val path = directory.resolve("wallet.dw")
        val reference = ContainerCrypto.migrate(password, original)
        val active = (reference.payload["public_key"] as ByteArray).copyOf()
        val pending = (reference.payload["pending_public_key"] as ByteArray).copyOf()
        reference.bytes.fill(0)
        reference.dek.fill(0)
        WalletJson.clearByteArrays(reference.payload)
        reference.payload.clear()
        var syncCalls = 0
        try {
            Files.write(path, original)
            val failure = assertThrows(WalletStorageException::class.java) {
                AtomicWalletFiles.withDirectorySyncForTest(directory, { parent ->
                    syncCalls++
                    assertEquals(directory.toAbsolutePath().normalize(), parent)
                    val visible = Files.readAllBytes(path)
                    try {
                        if (syncCalls == 1) {
                            val envelope = WalletJson.parse(visible, ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>
                            assertEquals(BigInteger.valueOf(2), envelope["version"])
                            val opened = ContainerCrypto.open(visible, password)
                            try {
                                assertArrayEquals(active, opened.payload["public_key"] as ByteArray)
                                assertArrayEquals(pending, opened.payload["pending_public_key"] as ByteArray)
                            } finally {
                                opened.dek.fill(0)
                                WalletJson.clearByteArrays(opened.payload)
                                opened.payload.clear()
                            }
                        } else {
                            assertArrayEquals(original, visible)
                        }
                    } finally {
                        visible.fill(0)
                    }
                    if (syncCalls == 1) throw IOException()
                    FileChannel.open(parent, READ).use { it.force(true) }
                }) {
                    AndroidWallet.migrateContainer(path, password).use { }
                }
            }
            assertEquals(WalletStorageException::class.java, failure.javaClass)
            assertEquals("wallet storage operation failed", failure.message)
            assertEquals(2, syncCalls)
            assertArrayEquals(original, Files.readAllBytes(path))
            Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
            assertThrows(WalletUnsupportedFormatException::class.java) { AndroidWallet.open(path, password).use { } }
            // Scoped seam must be removed after failure; recover through the unchanged public API.
            AndroidWallet.migrateContainer(path, password).use { recovered ->
                assertArrayEquals(active, recovered.ownerPublicKey)
                assertArrayEquals(pending, recovered.pendingOwnerPublicKey)
            }
            AndroidWallet.open(path, password).use { reopened ->
                assertArrayEquals(active, reopened.ownerPublicKey)
                assertArrayEquals(pending, reopened.pendingOwnerPublicKey)
            }
            assertEquals(2, syncCalls)
            Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
        } finally {
            original.fill(0)
            active.fill(0)
            pending.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
        assertFalse(Files.exists(directory))
    }

    @Test
    fun wrongPasswordMigrationPreservesOriginalV1BytesOnAndroid() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val original = instrumentation.context.assets.open("wallet-v1-pending-rotation.dw")
            .use { it.readBytes() }
        val directory = Files.createTempDirectory(
            instrumentation.targetContext.cacheDir.toPath(), "migration-failure-",
        )
        try {
            val path = directory.resolve("wallet.dw")
            Files.write(path, original)
            assertThrows(WalletUnlockException::class.java) {
                AndroidWallet.migrateContainer(path, "different synthetic device-test password")
            }
            assertArrayEquals(original, Files.readAllBytes(path))
            val envelope = WalletJson.parse(Files.readAllBytes(path), ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>
            assertEquals(BigInteger.ONE, envelope["version"])
            Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
        } finally {
            original.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun importRefusesToOverwriteInitializedWalletOnAndroid() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val vector = instrumentation.context.assets.open("wallet-container-v2.json")
            .use { it.readBytes() }
        val importedBytes = vectorContainer(vector)
        val password = "public-test-only: wallet-v2-vector"
        val directory = Files.createTempDirectory(
            instrumentation.targetContext.cacheDir.toPath(), "import-no-overwrite-",
        )
        var before = byteArrayOf()
        try {
            val destination = directory.resolve("wallet.dw")
            AndroidWallet.create(destination, password, password, mapOf("owner" to "existing-device-wallet"))
                .use { wallet -> before = wallet.exportContainer() }
            assertFalse(before.contentEquals(importedBytes))
            assertThrows(WalletStorageException::class.java) {
                AndroidWallet.importContainer(destination, importedBytes, password)
            }
            assertArrayEquals(before, Files.readAllBytes(destination))
            AndroidWallet.open(destination, password).use { reopened ->
                val payload = reopened.readPayload()
                try {
                    assertEquals("existing-device-wallet", payload["owner"])
                } finally {
                    WalletJson.clearByteArrays(payload)
                }
            }
            Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
        } finally {
            vector.fill(0)
            importedBytes.fill(0)
            before.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun publicImportDoesNotReplaceDestinationCreatedAfterPreflightOnAndroid() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val vector = instrumentation.context.assets.open("wallet-container-v2.json")
            .use { it.readBytes() }
        val importedBytes = vectorContainer(vector)
        val password = "public-test-only: wallet-v2-vector"
        val directory = Files.createTempDirectory(
            instrumentation.targetContext.cacheDir.toPath(), "import-race-no-overwrite-",
        )
        val rivalPath = directory.resolve("rival.dw")
        val rivalWallet = AndroidWallet.create(rivalPath, password, password, mapOf("owner" to "external"))
        val rivalBytes = rivalWallet.exportContainer()
        rivalWallet.close()
        Files.delete(rivalPath)
        try {
            val destination = directory.resolve("wallet.dw")
            assertThrows(WalletStorageException::class.java) {
                AtomicWalletFiles.withBeforeCreateInstallForTest(directory, { target ->
                    Files.write(target, rivalBytes)
                }) {
                    AndroidWallet.importContainer(destination, importedBytes, password).use { }
                }
            }
            assertArrayEquals(rivalBytes, Files.readAllBytes(destination))
            AndroidWallet.open(destination, password).use { rival ->
                val payload = rival.readPayload()
                try {
                    assertEquals("external", payload["owner"])
                } finally {
                    WalletJson.clearByteArrays(payload)
                }
            }
            Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
        } finally {
            vector.fill(0)
            importedBytes.fill(0)
            rivalBytes.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun concurrentPublicImportsInSeparateProcessesDoNotReplaceTheWinnerOnAndroid() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.context
        val password = "public-test-only: cross-process-import-race"
        val directory = Files.createTempDirectory(context.cacheDir.toPath(), "cross-process-import-race-")
        val firstBytes = createRaceWallet(directory.resolve("first-source.dw"), password, "first")
        val secondBytes = createRaceWallet(directory.resolve("second-source.dw"), password, "second")
        val destination = directory.resolve("wallet.dw")
        val requestedServices = mutableSetOf<String>()
        try {
            Files.write(directory.resolve("input-first.dw"), firstBytes)
            Files.write(directory.resolve("input-second.dw"), secondBytes)
            val firstIntent = importRaceIntent(context, ImportRaceWriterOneService::class.java, directory, destination, "first", password)
            val secondIntent = importRaceIntent(context, ImportRaceWriterTwoService::class.java, directory, destination, "second", password)
            if (context.startService(firstIntent) != null) requestedServices.add("first")
            if (context.startService(secondIntent) != null) requestedServices.add("second")

            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(90)
            val firstResult = directory.resolve("result-first.txt")
            val secondResult = directory.resolve("result-second.txt")
            while ((!Files.exists(firstResult) || !Files.exists(secondResult)) && System.nanoTime() < deadline) {
                Thread.sleep(50)
            }
            val observedFiles = Files.list(directory).use { paths ->
                paths.map { it.fileName.toString() }.toArray().joinToString()
            }
            assertTrue(
                "both isolated writer processes must report completion; observed files: $observedFiles",
                Files.exists(firstResult) && Files.exists(secondResult),
            )
            assertTrue(
                "both processes must reach the create-install boundary before either install proceeds",
                Files.exists(directory.resolve("ready-first")) && Files.exists(directory.resolve("ready-second")),
            )
            val firstOutcome = String(Files.readAllBytes(firstResult), Charsets.UTF_8).split(":", limit = 3)
            val secondOutcome = String(Files.readAllBytes(secondResult), Charsets.UTF_8).split(":", limit = 3)
            assertNotEquals("writer processes must be distinct", firstOutcome[0], secondOutcome[0])
            val outcomes = listOf(firstOutcome, secondOutcome)
            assertEquals(listOf("STORAGE_FAILURE", "SUCCESS"), outcomes.map { it[1] }.sorted())
            val loserDetail = outcomes.single { it[1] == "STORAGE_FAILURE" }.getOrNull(2).orEmpty()
            assertTrue(
                "loser must report the destination-exists storage failure, got: $loserDetail",
                loserDetail.startsWith(WalletStorageException::class.java.name),
            )

            val stored = Files.readAllBytes(destination)
            try {
                assertTrue("destination must equal one complete contender", stored.contentEquals(firstBytes) || stored.contentEquals(secondBytes))
                AndroidWallet.open(destination, password).use { winner ->
                    val payload = winner.readPayload()
                    try {
                        assertEquals(if (stored.contentEquals(firstBytes)) "first" else "second", payload["owner"])
                    } finally {
                        WalletJson.clearByteArrays(payload)
                    }
                }
            } finally {
                stored.fill(0)
            }
        } finally {
            val stopped = stopRaceServices(context, directory, destination, password, requestedServices)
            firstBytes.fill(0)
            secondBytes.fill(0)
            assertTrue("race workers must stop before deleting shared state", stopped)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun concurrentApprovedProofRequestsInSeparateProcessesReleaseOnlyOneProofOnAndroid() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = instrumentation.context
        val password = "public-test-only: cross-process-proof-race"
        val challenge = "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ"
        val directory = Files.createTempDirectory(context.cacheDir.toPath(), "cross-process-proof-race-")
        val walletPath = directory.resolve("wallet.dw")
        val vector = context.assets.open("wallet-account-disclosure-v1/vectors/valid-signup.json")
            .use { it.readBytes() }
        val root = WalletJson.parse(vector, 64 * 1024) as Map<*, *>
        val rawRequest = LinkedHashMap(root["keycloak_context"] as Map<*, *>)
        val now = System.currentTimeMillis() / 1000
        rawRequest["expires_at"] = BigInteger.valueOf(now + 299)
        val rawContext = WalletJson.canonicalBytes(rawRequest)
        val handle = root["transaction_handle"] as String
        var pending: PendingAccountApproval? = null
        val requestedServices = mutableSetOf<String>()
        try {
            val wallet = AndroidWallet.createWithGeneratedKey(walletPath, password, password)
            try {
                wallet.setMasterAccountEntity(mapOf("given_name" to "Ada", "email" to "ada@example.test"))
                val review = wallet.reviewAccountDisclosureAt(
                    rawContext,
                    handle,
                    "https://login.example.test/realms/site",
                    "test:android-disclosure-owner",
                    now,
                )
                pending = wallet.approveAccountDisclosureAt(
                    review,
                    review.claims.filter { it.required }.map { it.id }.toSet(),
                    now,
                    currentTimeEpochSeconds = { now },
                ) { true }
            } finally {
                wallet.close()
            }

            val firstIntent = importRaceIntent(
                context, ImportRaceWriterOneService::class.java, directory, walletPath, "first", password,
            ).putExtra(ImportRaceWriterService.EXTRA_OPERATION, "proof")
                .putExtra(ImportRaceWriterService.EXTRA_CHALLENGE, challenge)
            val secondIntent = importRaceIntent(
                context, ImportRaceWriterTwoService::class.java, directory, walletPath, "second", password,
            ).putExtra(ImportRaceWriterService.EXTRA_OPERATION, "proof")
                .putExtra(ImportRaceWriterService.EXTRA_CHALLENGE, challenge)
            if (context.startService(firstIntent) != null) requestedServices.add("first")
            if (context.startService(secondIntent) != null) requestedServices.add("second")

            awaitMarker(directory.resolve("ready-first"))
            awaitMarker(directory.resolve("ready-second"))
            awaitMarker(directory.resolve("attempting-replace-first"))
            awaitMarker(directory.resolve("attempting-replace-second"))
            val comparedDeadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(30)
            while (!Files.exists(directory.resolve("compared-first")) &&
                !Files.exists(directory.resolve("compared-second")) && System.nanoTime() < comparedDeadline
            ) {
                Thread.sleep(10)
            }
            assertTrue(
                "a writer must pause inside the compared revision transaction",
                Files.exists(directory.resolve("compared-first")) || Files.exists(directory.resolve("compared-second")),
            )
            val lockPath = directory.resolve(AtomicWalletFiles.INSTALL_LOCK_FILE_NAME)
            val lockWasHeld = FileChannel.open(
                lockPath,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.WRITE,
            ).use { channel ->
                val probe = channel.tryLock()
                if (probe == null) {
                    false
                } else {
                    probe.release()
                    true
                }
            }
            assertFalse("the OS lock must remain held across revision check and replacement", lockWasHeld)
            Files.write(directory.resolve("release-replace-first"), byteArrayOf(1))
            Files.write(directory.resolve("release-replace-second"), byteArrayOf(1))

            val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(90)
            val firstResult = directory.resolve("result-first.txt")
            val secondResult = directory.resolve("result-second.txt")
            while ((!Files.exists(firstResult) || !Files.exists(secondResult)) && System.nanoTime() < deadline) {
                Thread.sleep(50)
            }
            assertTrue(Files.exists(directory.resolve("ready-first")))
            assertTrue(Files.exists(directory.resolve("ready-second")))
            assertTrue(Files.exists(firstResult) && Files.exists(secondResult))
            val firstOutcome = String(Files.readAllBytes(firstResult), Charsets.UTF_8).split(":", limit = 3)
            val secondOutcome = String(Files.readAllBytes(secondResult), Charsets.UTF_8).split(":", limit = 3)
            assertNotEquals("proof contenders must be separate processes", firstOutcome[0], secondOutcome[0])
            val outcomes = listOf(firstOutcome, secondOutcome)
            assertEquals(listOf("STORAGE_FAILURE", "SUCCESS"), outcomes.map { it[1] }.sorted())
            assertEquals(
                WalletInvalidContainerException::class.java.name,
                outcomes.single { it[1] == "STORAGE_FAILURE" }.getOrNull(2),
            )

            AndroidWallet.open(walletPath, password).use { reopened ->
                val recovered = reopened.recoverPendingAccountApprovalAt(System.currentTimeMillis() / 1000)
                assertEquals(checkNotNull(pending).handle, checkNotNull(recovered).handle)
                val payload = reopened.readPayload()
                try {
                    val approval = payload["pending_account_disclosure_approval"] as Map<*, *>
                    assertEquals(true, approval["proof_issued"])
                    assertEquals(challenge, approval["proof_challenge"])
                } finally {
                    WalletJson.clearByteArrays(payload)
                }
                assertThrows(WalletDisclosureRequestException::class.java) {
                    reopened.createAccountLoginProof(checkNotNull(pending), challenge)
                }
            }
        } finally {
            Files.write(directory.resolve("release-replace-first"), byteArrayOf(1))
            Files.write(directory.resolve("release-replace-second"), byteArrayOf(1))
            val stopped = stopRaceServices(context, directory, walletPath, password, requestedServices)
            vector.fill(0)
            rawContext.fill(0)
            assertTrue("proof workers must stop before deleting shared state", stopped)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private fun createRaceWallet(path: java.nio.file.Path, password: String, owner: String): ByteArray =
        AndroidWallet.create(path, password, password, mapOf("owner" to owner)).use { wallet -> wallet.exportContainer() }

    private fun importRaceIntent(
        context: android.content.Context,
        service: Class<out android.app.Service>,
        directory: java.nio.file.Path,
        destination: java.nio.file.Path,
        contender: String,
        password: String,
    ) = android.content.Intent(context, service).apply {
        putExtra(ImportRaceWriterService.EXTRA_DIRECTORY, directory.toString())
        putExtra(ImportRaceWriterService.EXTRA_DESTINATION, destination.toString())
        putExtra(ImportRaceWriterService.EXTRA_CONTENDER, contender)
        putExtra(ImportRaceWriterService.EXTRA_PASSWORD, password)
    }

    private fun awaitMarker(path: java.nio.file.Path) {
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(30)
        while (!Files.exists(path) && System.nanoTime() < deadline) {
            Thread.sleep(10)
        }
        assertTrue("missing coordination marker: ${path.fileName}", Files.exists(path))
    }

    private fun stopRaceServices(
        context: android.content.Context,
        directory: java.nio.file.Path,
        destination: java.nio.file.Path,
        password: String,
        requestedServices: Set<String>,
    ): Boolean {
        Files.write(directory.resolve("release-replace-first"), byteArrayOf(1))
        Files.write(directory.resolve("release-replace-second"), byteArrayOf(1))
        context.stopService(importRaceIntent(context, ImportRaceWriterOneService::class.java, directory, destination, "first", password))
        context.stopService(importRaceIntent(context, ImportRaceWriterTwoService::class.java, directory, destination, "second", password))
        val stopped = requestedServices.map { directory.resolve("service-stopped-$it") }
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(20)
        while (stopped.any { !Files.exists(it) } && System.nanoTime() < deadline) {
            Thread.sleep(20)
        }
        return stopped.all { Files.exists(it) }
    }

    @Test
    fun recoverableReplacementSyncFailureRestoresV1BytesOnAndroid() {
        exerciseReplacementSyncFailure(rollbackSyncFails = false)
    }

    @Test
    fun failedRollbackSyncReportsUnknownOutcomeOnAndroid() {
        exerciseReplacementSyncFailure(rollbackSyncFails = true)
    }

    private fun exerciseReplacementSyncFailure(rollbackSyncFails: Boolean) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val original = instrumentation.context.assets.open("wallet-v1-pending-rotation.dw")
            .use { it.readBytes() }
        val password = "correct horse battery staple"
        val directory = Files.createTempDirectory(
            instrumentation.targetContext.cacheDir.toPath(), "replacement-sync-failure-",
        )
        var replacement = byteArrayOf()
        try {
            // Build an authenticated migration candidate through the production API.
            // Inject only at its shared atomic-storage boundary, not into migrateContainer itself.
            val candidate = directory.resolve("candidate.dw")
            Files.write(candidate, original)
            AndroidWallet.migrateContainer(candidate, password).use { wallet ->
                replacement = wallet.exportContainer()
            }
            val envelope = WalletJson.parse(replacement, ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>
            assertEquals(BigInteger.valueOf(2), envelope["version"])
            Files.delete(candidate)
            val path = directory.resolve("wallet.dw")
            Files.write(path, original)
            var syncCalls = 0
            val failureType = if (rollbackSyncFails) {
                WalletStorageOutcomeUnknownException::class.java
            } else {
                WalletStorageException::class.java
            }
            val failure = assertThrows(failureType) {
                AtomicWalletFiles.replaceForTest(path, replacement, original) { parent ->
                    syncCalls++
                    assertEquals(directory.toAbsolutePath().normalize(), parent)
                    val visible = Files.readAllBytes(path)
                    try {
                        // Prove replacement preceded the first fault and restoration preceded the second sync.
                        assertArrayEquals(if (syncCalls == 1) replacement else original, visible)
                    } finally {
                        visible.fill(0)
                    }
                    if (syncCalls == 1 || rollbackSyncFails) throw IOException()
                    FileChannel.open(parent, READ).use { channel -> channel.force(true) }
                }
            }
            assertEquals(2, syncCalls)
            assertEquals(failureType, failure.javaClass)
            assertEquals(
                if (rollbackSyncFails) "wallet storage outcome is unknown" else "wallet storage operation failed",
                failure.message,
            )
            // Failed rollback sync can leave restored bytes visible without establishing durability.
            assertArrayEquals(original, Files.readAllBytes(path))
            Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
            assertThrows(WalletUnsupportedFormatException::class.java) {
                AndroidWallet.open(path, password)
            }
            if (!rollbackSyncFails) {
                AndroidWallet.migrateContainer(path, password).use { migrated ->
                    val payload = migrated.readPayload()
                    try {
                        assertArrayEquals(
                            decodeHex("9f8544ce97a2bae6d53c788ca472ca29a58f156ab7cf481f8a6512af86f3c68e"),
                            payload["public_key"] as ByteArray,
                        )
                        assertArrayEquals(
                            decodeHex("abd600e02eec04f20e14c73c8c1744a201f5745fa9b00aa85b1c48119d2e4cd9"),
                            payload["pending_public_key"] as ByteArray,
                        )
                    } finally {
                        WalletJson.clearByteArrays(payload)
                    }
                }
            }
        } finally {
            original.fill(0)
            replacement.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
        assertFalse(Files.exists(directory))
    }

    @Test
    fun recoverableCancellationRollbackKeepsSessionUsableOnAndroid() {
        exerciseSessionCancellationFailure(rollbackSyncFails = false)
    }

    @Test
    fun unknownCancellationRollbackLocksAndClearsSessionOnAndroid() {
        exerciseSessionCancellationFailure(rollbackSyncFails = true)
    }

    private fun exerciseSessionCancellationFailure(rollbackSyncFails: Boolean) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val directory = Files.createTempDirectory(
            instrumentation.targetContext.cacheDir.toPath(), "session-cancel-fault-",
        )
        val path = directory.resolve("wallet.dw")
        val password = "synthetic device cancellation password"
        var before = byteArrayOf()
        var active = byteArrayOf()
        var pending = byteArrayOf()
        try {
            AndroidWallet.createWithGeneratedKey(path, password, password).use { setup ->
                active = setup.ownerPublicKey
                pending = setup.prepareSigningKeyRotation()
                before = setup.exportContainer()
            }
            val raw = AtomicWalletFiles.read(path)
            val opened = ContainerCrypto.open(raw, password)
            val retainedSeeds = listOf(
                opened.payload["private_seed"] as ByteArray,
                opened.payload["pending_private_seed"] as ByteArray,
            )
            var replacements = 0
            var syncCalls = 0
            WalletSession(path, raw, opened.dek, opened.payload) { target, bytes, expected ->
                replacements++
                assertArrayEquals(before, expected)
                AtomicWalletFiles.replaceForTest(target, bytes, expected) { parent ->
                    syncCalls++
                    val visible = Files.readAllBytes(target)
                    try {
                        assertArrayEquals(if (syncCalls == 1) bytes else expected, visible)
                        if (syncCalls == 1) assertFalse(before.contentEquals(visible))
                    } finally {
                        visible.fill(0)
                    }
                    if (syncCalls == 1 || rollbackSyncFails) throw IOException()
                    FileChannel.open(parent, READ).use { channel -> channel.force(true) }
                }
            }.use { wallet ->
                val failureType = if (rollbackSyncFails) {
                    WalletStorageOutcomeUnknownException::class.java
                } else {
                    WalletStorageException::class.java
                }
                val failure = assertThrows(failureType) { wallet.cancelSigningKeyRotation() }
                assertEquals(failureType, failure.javaClass)
                assertEquals(1, replacements)
                assertEquals(2, syncCalls)
                assertArrayEquals(before, Files.readAllBytes(path))
                Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
                if (rollbackSyncFails) {
                    assertFalse(wallet.isUnlocked)
                    assertTrue(raw.all { it == 0.toByte() })
                    assertTrue(opened.dek.all { it == 0.toByte() })
                    assertTrue(retainedSeeds.all { seed -> seed.all { it == 0.toByte() } })
                    assertTrue(opened.payload.isEmpty())
                    assertThrows(WalletLockedException::class.java) { wallet.ownerPublicKey }
                    assertThrows(WalletLockedException::class.java) { wallet.pendingOwnerPublicKey }
                    assertThrows(WalletLockedException::class.java) { wallet.readPayload() }
                    assertThrows(WalletLockedException::class.java) { wallet.exportContainer() }
                    assertThrows(WalletLockedException::class.java) { wallet.cancelSigningKeyRotation() }
                    assertEquals(1, replacements)
                    // Original bytes visible after failed rollback sync are not proof of durability.
                } else {
                    assertTrue(wallet.isUnlocked)
                    assertArrayEquals(active, wallet.ownerPublicKey)
                    assertArrayEquals(pending, checkNotNull(wallet.pendingOwnerPublicKey))
                    assertArrayEquals(before, wallet.exportContainer())
                }
            }
            if (!rollbackSyncFails) {
                AndroidWallet.open(path, password).use { reopened ->
                    assertArrayEquals(active, reopened.ownerPublicKey)
                    assertArrayEquals(pending, checkNotNull(reopened.pendingOwnerPublicKey))
                    reopened.cancelSigningKeyRotation()
                    assertEquals(null, reopened.pendingOwnerPublicKey)
                }
                AndroidWallet.open(path, password).use { reopened ->
                    assertArrayEquals(active, reopened.ownerPublicKey)
                    assertEquals(null, reopened.pendingOwnerPublicKey)
                }
            }
        } finally {
            before.fill(0)
            active.fill(0)
            pending.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
        assertFalse(Files.exists(directory))
    }

    @Test
    fun publicMigrationStagingDenialPreservesV1OnAndroid() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val original = instrumentation.context.assets.open("wallet-v1-pending-rotation.dw")
            .use { it.readBytes() }
        val directory = Files.createTempDirectory(
            instrumentation.targetContext.cacheDir.toPath(), "migration-staging-denial-",
        )
        val permissions = Files.getPosixFilePermissions(directory)
        try {
            val path = directory.resolve("wallet.dw")
            Files.write(path, original)
            Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("r-x------"))
            assertThrows(IOException::class.java) { Files.createTempFile(directory, "probe-", ".tmp") }
            val failure = assertThrows(WalletStorageException::class.java) {
                AndroidWallet.migrateContainer(path, "correct horse battery staple")
            }
            assertEquals(WalletStorageException::class.java, failure.javaClass)
            assertEquals("wallet storage operation failed", failure.message)
            assertArrayEquals(original, Files.readAllBytes(path))
            Files.list(directory).use { paths ->
                assertEquals(1L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
            assertThrows(WalletUnsupportedFormatException::class.java) {
                AndroidWallet.open(path, "correct horse battery staple")
            }
            Files.setPosixFilePermissions(directory, permissions)
            AndroidWallet.migrateContainer(path, "correct horse battery staple").use { migrated ->
                val payload = migrated.readPayload()
                try {
                    assertArrayEquals(
                        decodeHex("9f8544ce97a2bae6d53c788ca472ca29a58f156ab7cf481f8a6512af86f3c68e"),
                        payload["public_key"] as ByteArray,
                    )
                    assertArrayEquals(
                        decodeHex("abd600e02eec04f20e14c73c8c1744a201f5745fa9b00aa85b1c48119d2e4cd9"),
                        payload["pending_public_key"] as ByteArray,
                    )
                } finally {
                    WalletJson.clearByteArrays(payload)
                }
            }
        } finally {
            Files.setPosixFilePermissions(directory, permissions)
            original.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
        assertFalse(Files.exists(directory))
    }

    @Test
    fun publicImportStagingDenialLeavesDestinationAbsentOnAndroid() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val vector = instrumentation.context.assets.open("wallet-container-v2.json").use { it.readBytes() }
        val importedBytes = vectorContainer(vector)
        val password = "public-test-only: wallet-v2-vector"
        val directory = Files.createTempDirectory(
            instrumentation.targetContext.cacheDir.toPath(), "import-staging-denial-",
        )
        val permissions = Files.getPosixFilePermissions(directory)
        try {
            val destination = directory.resolve("wallet.dw")
            Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("r-x------"))
            assertThrows(IOException::class.java) { Files.createTempFile(directory, "probe-", ".tmp") }
            val failure = assertThrows(WalletStorageException::class.java) {
                AndroidWallet.importContainer(destination, importedBytes, password)
            }
            assertEquals(WalletStorageException::class.java, failure.javaClass)
            assertEquals("wallet storage operation failed", failure.message)
            assertFalse(Files.exists(destination))
            Files.list(directory).use { paths ->
                assertEquals(0L, paths.filter { it.fileName.toString() != AtomicWalletFiles.INSTALL_LOCK_FILE_NAME }.count())
            }
            Files.setPosixFilePermissions(directory, permissions)
            AndroidWallet.importContainer(destination, importedBytes, password).use { imported ->
                assertArrayEquals(importedBytes, imported.exportContainer())
            }
            AndroidWallet.open(destination, password).use { reopened ->
                assertArrayEquals(importedBytes, reopened.exportContainer())
            }
        } finally {
            Files.setPosixFilePermissions(directory, permissions)
            vector.fill(0)
            importedBytes.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
        assertFalse(Files.exists(directory))
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

package org.decentwallet.wallet.android

import java.math.BigInteger
import java.nio.file.Files
import org.junit.Assert.*
import org.junit.Test

class PortableLatchTest {
    private val password = "correct horse battery staple"
    private fun payload(): MutableMap<String, Any?> {
        val active = ByteArray(32) { it.toByte() }
        val pending = ByteArray(32) { (it + 32).toByte() }
        return linkedMapOf(
            "private_seed" to active, "public_key" to AndroidIdentityCrypto.publicKeyFromSeed(active),
            "pending_private_seed" to pending, "pending_public_key" to AndroidIdentityCrypto.publicKeyFromSeed(pending),
        )
    }
    private fun intent(payload: Map<String, Any?>): MutableMap<String, Any?> = linkedMapOf(
        "owner_name" to "portable-owner".toByteArray(),
        "predecessor_owner_public_key" to payload["public_key"],
        "successor_owner_public_key" to payload["pending_public_key"],
        "predecessor_state_hash" to ByteArray(32) { 3 }, "sequence" to BigInteger.TWO,
        "envelope_hash" to ByteArray(32) { 4 },
    )
    private inline fun <reified T : Throwable> rejects(action: () -> Unit) {
        try { action(); fail("expected rejection") } catch (failure: Throwable) { assertTrue(failure is T) }
    }

    private fun resourceMap(name: String): Map<*, *> = javaClass.getResourceAsStream("/$name")!!.use {
        WalletJson.parse(it.readBytes(), ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>
    }
    private fun hex(text: Any?): ByteArray = (text as String).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private class VectorTransport(val vector: Map<*, *>, override var registryEnvironment: String = "testnet") : AndroidIdentityTransport {
        var flipAfterLocalRead = false
        var missingLocal = false
        var errorLocal = false
        var flipAfterRemoteRead = false
        var flipAfterHistoryRead = false
        override val supportsOwnerKeyRotation = true
        var remoteReads = 0
        var writes = 0
        var candidate = false
        private fun bytes(name: String) = (vector[name] as String).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        override fun getIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray? {
            if (flipAfterLocalRead) registryEnvironment = "different-testnet"
            if (errorLocal) throw IllegalStateException("synthetic local read failure")
            if (missingLocal) return null
            return bytes("predecessor_envelope_cbor_hex")
        }
        override fun getIdentityEnvelopeByHash(ownerNameBytes: ByteArray, stateHash: ByteArray): ByteArray {
            if (flipAfterHistoryRead) registryEnvironment = "different-testnet"
            return bytes("predecessor_envelope_cbor_hex")
        }
        override fun getRemoteIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray {
            remoteReads++
            if (flipAfterRemoteRead) registryEnvironment = "different-testnet"
            return bytes(if (candidate) "candidate_envelope_cbor_hex" else "predecessor_envelope_cbor_hex")
        }
        override fun putIdentityEnvelopeIfCurrent(ownerNameBytes: ByteArray, envelopeBytes: ByteArray, expectedStateHash: ByteArray, expiresAt: Long) {
            writes++
            fail("portable recovery must never publish")
        }
    }

    @Test fun pythonCiphertextPublicImportExactTransferAndReadonlyPromotion() {
        val fixture = resourceMap("wallet-v2-portable-rotation-latch.json")
        val vector = resourceMap("identity-owner-key-rotation-legacy.json")
        val directory = Files.createTempDirectory("python-latch-")
        try {
            for (legacy in listOf(false, true)) {
                val raw = java.util.Base64.getDecoder().decode(fixture[if (legacy) "legacy_unbound_container_base64" else "python_bound_container_base64"] as String)
                AndroidWallet.importContainer(directory.resolve("$legacy.dw"), raw, password).use { wallet ->
                    assertArrayEquals(raw, wallet.exportContainer())
                    var intent = checkNotNull(wallet.ownerKeyRotationDispatchIntent)
                    assertEquals(if (legacy) null else "testnet", intent.environment)
                    assertArrayEquals(intent.predecessorOwnerPublicKey, wallet.ownerPublicKey)
                    assertArrayEquals(intent.successorOwnerPublicKey, wallet.pendingOwnerPublicKey)
                    rejects<WalletRotationInProgressException> { wallet.prepareSigningKeyRotation() }
                    val wrong = VectorTransport(vector, "other")
                    assertNull(AndroidIdentityAdapter(wrong, AndroidIdentityReplayNonceStore { true }).confirmOwnerKeyRotation(intent))
                    assertEquals(0, wrong.remoteReads)
                    val transport = VectorTransport(vector).also { it.candidate = true }
                    if (legacy) {
                        assertNull(AndroidIdentityAdapter(transport, AndroidIdentityReplayNonceStore { true }).confirmOwnerKeyRotation(intent))
                        assertEquals(0, transport.remoteReads)
                        val siblingBound = OwnerKeyRotationDispatchIntent.fromPayload(intent.toPayload() + ("environment" to "testnet"))
                        val siblingConfirmation = checkNotNull(AndroidIdentityAdapter(transport, AndroidIdentityReplayNonceStore { true }).confirmOwnerKeyRotation(siblingBound))
                        rejects<WalletInvalidIdentityStateException> { wallet.finalizeSigningKeyRotation(siblingConfirmation) }
                        assertArrayEquals(raw, wallet.exportContainer())
                        intent = wallet.bindLegacyRotationDispatchEnvironment("testnet") { _, _ -> true }
                    }
                    val confirmation = checkNotNull(AndroidIdentityAdapter(transport, AndroidIdentityReplayNonceStore { true }).confirmOwnerKeyRotation(intent))
                    wallet.finalizeSigningKeyRotation(confirmation)
                    assertArrayEquals(hex(vector["successor_owner_public_key_hex"]), wallet.ownerPublicKey)
                    assertNull(wallet.pendingOwnerPublicKey)
                    assertEquals(0, transport.writes)
                }
                AndroidWallet.open(directory.resolve("$legacy.dw"), password).use { promoted ->
                    assertArrayEquals(hex(vector["successor_owner_public_key_hex"]), promoted.ownerPublicKey)
                    assertNull(promoted.pendingOwnerPublicKey)
                    assertNull(promoted.ownerKeyRotationDispatchIntent)
                }
            }
        } finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }

    @Test fun actualKotlinPublicAuthoringExportsBoundAndLegacyCiphertext() {
        val vector = resourceMap("identity-owner-key-rotation-legacy.json")
        val directory = Files.createTempDirectory("kotlin-latch-")
        val payload = payload()
        try {
            AndroidWallet.create(directory.resolve("authored.dw"), password, password, payload).use { wallet ->
                val signers = (vector["successor_signers"] as List<*>).map {
                    val signer = it as Map<*, *>
                    IdentityRotationSigner(signer["signer_id"] as String, hex(signer["public_key_hex"]))
                }
                val draft = wallet.createLegacyOwnerKeyRotationDraft(hex(vector["owner_name_utf8_hex"]), hex(vector["predecessor_envelope_cbor_hex"]), signers)
                assertArrayEquals(hex(vector["candidate_envelope_cbor_hex"]), draft.envelopeBytes)
                val transport = VectorTransport(vector)
                val publication = AndroidIdentityAdapter(transport, AndroidIdentityReplayNonceStore { true }).prepareOwnerKeyRotationPublication(
                    draft = draft, consent = { true }, authenticatedOrigin = "https://wallet.example", environment = "testnet",
                    purpose = "publish owner-key rotation", capability = "identity.rotate-owner-key", expiresAt = 2_000_000_000L,
                    replayNonce = ByteArray(32) { it.toByte() },
                )
                wallet.latchOwnerKeyRotationDispatchIntent(publication)
                val raw = wallet.exportContainer()
                val opened = ContainerCrypto.open(raw, password)
                try {
                    val bound = checkNotNull(wallet.ownerKeyRotationDispatchIntent)
                    opened.payload["rotation_dispatch_intent"] = bound.toPayload() - "environment"
                    val legacy = ContainerCrypto.resealPayload(raw, opened.dek, opened.payload)
                    for ((name, bytes) in listOf("kotlin-bound.dw" to raw, "kotlin-legacy.dw" to legacy)) {
                        AndroidWallet.importContainer(directory.resolve(name), bytes, password).use { copy ->
                            assertArrayEquals(bytes, copy.exportContainer())
                            assertArrayEquals(bound.predecessorOwnerPublicKey, copy.ownerPublicKey)
                            assertArrayEquals(bound.successorOwnerPublicKey, copy.pendingOwnerPublicKey)
                        }
                        System.getenv("PORTABLE_LATCH_ARTIFACT_DIR")?.let {
                            val target = java.nio.file.Paths.get(it)
                            Files.createDirectories(target)
                            Files.write(target.resolve(name), bytes)
                        }
                    }
                    assertEquals(0, transport.writes)
                } finally { opened.dek.fill(0); WalletJson.clearByteArrays(opened.payload) }
            }
        } finally {
            WalletJson.clearByteArrays(payload)
            Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    private fun unstablePreparation(change: String) {
        val vector = resourceMap("identity-owner-key-rotation-legacy.json")
        val directory = Files.createTempDirectory("environment-change-")
        val payload = payload()
        try {
            AndroidWallet.create(directory.resolve("wallet.dw"), password, password, payload).use { wallet ->
                val signers = (vector["successor_signers"] as List<*>).map {
                    val signer = it as Map<*, *>
                    IdentityRotationSigner(signer["signer_id"] as String, hex(signer["public_key_hex"]))
                }
                val draft = wallet.createLegacyOwnerKeyRotationDraft(hex(vector["owner_name_utf8_hex"]), hex(vector["predecessor_envelope_cbor_hex"]), signers)
                val transport = VectorTransport(vector)
                val adapter = AndroidIdentityAdapter(transport, AndroidIdentityReplayNonceStore { true })
                transport.flipAfterLocalRead = change == "prepare-read"
                val prepare = {
                    adapter.prepareOwnerKeyRotationPublication(
                        draft = draft, consent = { if (change == "consent") transport.registryEnvironment = "different-testnet"; true },
                        authenticatedOrigin = "https://wallet.example", environment = "testnet", purpose = "publish owner-key rotation",
                        capability = "identity.rotate-owner-key", expiresAt = 2_000_000_000L, replayNonce = ByteArray(32) { it.toByte() },
                    )
                }
                if (!change.startsWith("dispatch-")) {
                    rejects<WalletIdentityEnvironmentMismatchException> { prepare() }
                    assertNull(wallet.ownerKeyRotationDispatchIntent)
                } else {
                    val publication = prepare()
                    val permit = wallet.latchOwnerKeyRotationDispatchIntent(publication)
                    val raw = wallet.exportContainer()
                    val active = wallet.ownerPublicKey
                    val pending = wallet.pendingOwnerPublicKey
                    transport.flipAfterLocalRead = true
                    transport.missingLocal = change == "dispatch-stale"
                    transport.errorLocal = change == "dispatch-error"
                    val result = adapter.dispatchOwnerKeyRotation(publication, permit)
                    assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
                    assertNull(result.rejection)
                    assertNull(result.confirmation)
                    assertEquals(permit.intent, wallet.ownerKeyRotationDispatchIntent)
                    assertArrayEquals(active, wallet.ownerPublicKey)
                    assertArrayEquals(pending, wallet.pendingOwnerPublicKey)
                    assertArrayEquals(raw, wallet.exportContainer())
                    rejects<WalletInvalidIdentityStateException> { adapter.dispatchOwnerKeyRotation(publication, permit) }
                }
                assertEquals(0, transport.writes)
                assertEquals(0, transport.remoteReads)
            }
        } finally {
            WalletJson.clearByteArrays(payload)
            Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test fun environmentChangeDuringConsentCannotPrepare() = unstablePreparation("consent")
    @Test fun environmentChangeDuringPreparationReadCannotPrepare() = unstablePreparation("prepare-read")
    @Test fun environmentChangeDuringDispatchReadCannotPublish() = unstablePreparation("dispatch-read")
    @Test fun environmentChangeDuringStalePreflightMakesNoRemoteCall() = unstablePreparation("dispatch-stale")
    @Test fun environmentChangeDuringErrorPreflightMakesNoRemoteCall() = unstablePreparation("dispatch-error")

    @Test fun expiredDispatchRealmChangeDuringRemoteReadRetainsLatch() {
        val vector = resourceMap("identity-owner-key-rotation-legacy.json")
        val directory = Files.createTempDirectory("expiry-realm-")
        val payload = payload()
        try {
            AndroidWallet.create(directory.resolve("wallet.dw"), password, password, payload).use { wallet ->
                val signers = (vector["successor_signers"] as List<*>).map {
                    val signer = it as Map<*, *>
                    IdentityRotationSigner(signer["signer_id"] as String, hex(signer["public_key_hex"]))
                }
                val draft = wallet.createLegacyOwnerKeyRotationDraft(hex(vector["owner_name_utf8_hex"]), hex(vector["predecessor_envelope_cbor_hex"]), signers)
                val transport = VectorTransport(vector)
                val adapter = AndroidIdentityAdapter(transport, AndroidIdentityReplayNonceStore { true })
                val expiry = System.currentTimeMillis() / 1000 + 3
                val publication = adapter.prepareOwnerKeyRotationPublication(
                    draft = draft, consent = { true }, authenticatedOrigin = "https://wallet.example", environment = "testnet",
                    purpose = "publish owner-key rotation", capability = "identity.rotate-owner-key", expiresAt = expiry,
                    replayNonce = ByteArray(32) { it.toByte() },
                )
                val permit = wallet.latchOwnerKeyRotationDispatchIntent(publication)
                val raw = wallet.exportContainer()
                val active = wallet.ownerPublicKey
                val pending = wallet.pendingOwnerPublicKey
                // Bounded real clock crossing, no fabricated authority or production clock seam.
                val waitMillis = (expiry * 1000 - System.currentTimeMillis()).coerceAtLeast(0) + 20
                assertTrue(waitMillis <= 3020)
                Thread.sleep(waitMillis)
                transport.flipAfterRemoteRead = true
                val result = adapter.dispatchOwnerKeyRotation(publication, permit)
                assertEquals(OwnerKeyRotationDispatchStatus.UNKNOWN, result.status)
                assertNull(result.rejection)
                assertNull(result.confirmation)
                assertArrayEquals(active, wallet.ownerPublicKey)
                assertArrayEquals(pending, wallet.pendingOwnerPublicKey)
                assertEquals(permit.intent, wallet.ownerKeyRotationDispatchIntent)
                assertArrayEquals(raw, wallet.exportContainer())
                assertNull(adapter.confirmOwnerKeyRotation(permit.intent))
                rejects<WalletInvalidIdentityStateException> { adapter.dispatchOwnerKeyRotation(publication, permit) }
                assertEquals(1, transport.remoteReads)
                assertEquals(0, transport.writes)
            }
        } finally {
            WalletJson.clearByteArrays(payload)
            Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test fun environmentChangeDuringConfirmationCannotMintAuthority() {
        val fixture = resourceMap("wallet-v2-portable-rotation-latch.json")
        val vector = resourceMap("identity-owner-key-rotation-legacy.json")
        val raw = java.util.Base64.getDecoder().decode(fixture["python_bound_container_base64"] as String)
        val directory = Files.createTempDirectory("confirmation-environment-")
        try {
            AndroidWallet.importContainer(directory.resolve("wallet.dw"), raw, password).use { wallet ->
                val intent = checkNotNull(wallet.ownerKeyRotationDispatchIntent)
                for (duringHistory in listOf(false, true)) {
                    val transport = VectorTransport(vector).also {
                        it.candidate = true
                        it.flipAfterRemoteRead = !duringHistory
                        it.flipAfterHistoryRead = duringHistory
                    }
                    assertNull(AndroidIdentityAdapter(transport, AndroidIdentityReplayNonceStore { true }).confirmOwnerKeyRotation(intent))
                    assertEquals(0, transport.writes)
                    assertArrayEquals(raw, wallet.exportContainer())
                    rejects<WalletRotationInProgressException> { wallet.cancelSigningKeyRotation() }
                }
            }
        } finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }

    @Test fun legacySixFieldsStayUnboundAcrossExactImport() {
        val directory = Files.createTempDirectory("portable-latch-")
        val payload = payload()
        payload["rotation_dispatch_intent"] = intent(payload)
        payload["synthetic_metadata"] = listOf("preserve", BigInteger.valueOf(42), byteArrayOf(1, 2, 3))
        val created = ContainerCrypto.create(password, password, payload)
        try {
            AndroidWallet.importContainer(directory.resolve("legacy.dw"), created.bytes, password).use { wallet ->
                val legacy = checkNotNull(wallet.ownerKeyRotationDispatchIntent)
                assertNull(legacy.environment)
                assertArrayEquals(created.bytes, wallet.exportContainer())
                rejects<WalletRotationInProgressException> { wallet.cancelSigningKeyRotation() }
                rejects<WalletInvalidIdentityStateException> { wallet.bindLegacyRotationDispatchEnvironment("testnet/é/🌍") { _, _ -> false } }
                assertArrayEquals(created.bytes, wallet.exportContainer())
                rejects<WalletInvalidIdentityStateException> { wallet.bindLegacyRotationDispatchEnvironment("testnet/é/🌍") { _, _ -> throw IllegalStateException("synthetic callback failure") } }
                assertArrayEquals(created.bytes, wallet.exportContainer())
                val bound = wallet.bindLegacyRotationDispatchEnvironment("testnet/é/🌍") { reviewed, realm ->
                    reviewed == legacy && realm == "testnet/é/🌍"
                }
                assertEquals("testnet/é/🌍", bound.environment)
                val opened = ContainerCrypto.open(wallet.exportContainer(), password)
                try {
                    val expected = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
                    expected["rotation_dispatch_intent"] = bound.toPayload()
                    assertArrayEquals(WalletJson.encodePayload(expected), WalletJson.encodePayload(opened.payload))
                    WalletJson.clearByteArrays(expected)
                } finally { opened.dek.fill(0); WalletJson.clearByteArrays(opened.payload) }
                rejects<WalletInvalidIdentityStateException> { wallet.bindLegacyRotationDispatchEnvironment("testnet/é/🌍") { _, _ -> fail("bound repeat must not ask consent"); true } }
                assertArrayEquals(WalletJson.encodePayload(legacy.toPayload()), WalletJson.encodePayload(bound.toPayload() - "environment"))
                assertArrayEquals(legacy.envelopeHash, bound.envelopeHash)
                assertArrayEquals(legacy.predecessorOwnerPublicKey, wallet.ownerPublicKey)
                assertArrayEquals(legacy.successorOwnerPublicKey, wallet.pendingOwnerPublicKey)
                rejects<WalletInvalidIdentityStateException> {
                    wallet.bindLegacyRotationDispatchEnvironment("other") { _, _ -> true }
                }
            }
        } finally {
            created.dek.fill(0); WalletJson.clearByteArrays(created.payload)
            WalletJson.clearByteArrays(payload)
            Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test fun changedSessionDuringLegacyBindingConsentDoesNotWrite() {
        val fixture = resourceMap("wallet-v2-portable-rotation-latch.json")
        val raw = java.util.Base64.getDecoder().decode(fixture["legacy_unbound_container_base64"] as String)
        val directory = Files.createTempDirectory("changed-binding-session-")
        val path = directory.resolve("wallet.dw")
        try {
            AndroidWallet.importContainer(path, raw, password).use { wallet ->
                rejects<WalletLockedException> { wallet.bindLegacyRotationDispatchEnvironment("testnet") { _, _ -> wallet.lock(); true } }
                assertArrayEquals(raw, Files.readAllBytes(path))
            }
            AndroidWallet.open(path, password).use { wallet ->
                assertNull(checkNotNull(wallet.ownerKeyRotationDispatchIntent).environment)
                assertArrayEquals(raw, wallet.exportContainer())
            }
        } finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }

    @Test fun largePositiveIntegerRealEncryptedPublicReadersAndWriter() {
        val fixture = resourceMap("wallet-v2-portable-rotation-latch.json")
        val expected = BigInteger(fixture["large_positive_sequence_decimal"] as String)
        val directory = Files.createTempDirectory("bignum-latch-")
        val pythonRaw = java.util.Base64.getDecoder().decode(fixture["python_bignum_container_base64"] as String)
        val payload = payload()
        payload["rotation_dispatch_intent"] = intent(payload).also { it["environment"] = "testnet"; it["sequence"] = expected }
        val created = ContainerCrypto.create(password, password, payload)
        try {
            for ((name, raw) in listOf("python" to pythonRaw, "kotlin" to created.bytes)) {
                val path = directory.resolve("$name.dw")
                AndroidWallet.importContainer(path, raw, password).use { wallet ->
                    assertEquals(expected, checkNotNull(wallet.ownerKeyRotationDispatchIntent).sequence)
                    assertArrayEquals(raw, wallet.exportContainer())
                    assertArrayEquals(wallet.ownerPublicKey, checkNotNull(wallet.ownerKeyRotationDispatchIntent).predecessorOwnerPublicKey)
                    assertArrayEquals(wallet.pendingOwnerPublicKey, checkNotNull(wallet.ownerKeyRotationDispatchIntent).successorOwnerPublicKey)
                }
                AndroidWallet.open(path, password).use { wallet ->
                    assertEquals(expected, checkNotNull(wallet.ownerKeyRotationDispatchIntent).sequence)
                    assertArrayEquals(raw, wallet.exportContainer())
                }
            }
            System.getenv("PORTABLE_LATCH_ARTIFACT_DIR")?.let {
                val target = java.nio.file.Paths.get(it)
                Files.createDirectories(target)
                Files.write(target.resolve("kotlin-bignum.dw"), created.bytes)
            }
        } finally {
            created.dek.fill(0); WalletJson.clearByteArrays(created.payload); WalletJson.clearByteArrays(payload)
            Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test fun environmentValidationUsesExactUnicodeAndUtf16Contract() {
        for (valid in listOf("é", "testnet/🌍", "🌍".repeat(128), "a ", "a\u0085")) {
            assertTrue(validRegistryEnvironment(valid))
        }
        for (invalid in listOf(null, "", "\u0085\u00a0\u2007\u202f", "🌍".repeat(129), "\ud800")) {
            assertFalse(validRegistryEnvironment(invalid))
            if (invalid != null) rejects<IllegalArgumentException> {
                AndroidRegistryDhtConfig(invalid, listOf("/ip4/127.0.0.1/tcp/1/p2p/synthetic"))
            }
        }
    }

    // Test-only authenticated raw typed JSON for values deliberately refused by the writer.
    private fun sealTypedJson(raw: ByteArray, dek: ByteArray, plaintext: ByteArray): ByteArray {
        val envelope = (WalletJson.parse(raw, ContainerCrypto.MAX_CONTAINER_BYTES) as Map<*, *>).entries.associate { it.key as String to it.value }.toMutableMap()
        val nonce = ByteArray(24).also { java.security.SecureRandom().nextBytes(it) }
        val nonceText = WalletJson.encodeBase64(nonce)
        val info = mapOf("algorithm" to "xchacha20-poly1305", "nonce" to nonceText)
        val aad = WalletJson.canonicalBytes(mapOf("format" to "decent-wallet", "version" to 2, "payload" to info))
        val cipher = org.bouncycastle.crypto.modes.XChaCha20Poly1305()
        cipher.init(true, org.bouncycastle.crypto.params.AEADParameters(org.bouncycastle.crypto.params.KeyParameter(dek), 128, nonce, aad))
        val sealed = ByteArray(cipher.getOutputSize(plaintext.size))
        val count = cipher.processBytes(plaintext, 0, plaintext.size, sealed, 0)
        val size = count + cipher.doFinal(sealed, count)
        envelope["payload"] = info + mapOf("ciphertext" to WalletJson.encodeBase64(sealed.copyOfRange(0, size - 16)), "tag" to WalletJson.encodeBase64(sealed.copyOfRange(size - 16, size)))
        return try { WalletJson.canonicalBytes(envelope) } finally { sealed.fill(0); plaintext.fill(0) }
    }

    @Test fun eagerPublicOpenAndImportRejectBrokenKeyBindings() {
        val directory = Files.createTempDirectory("latch-key-invalid-")
        try {
            val fields = listOf("private_seed", "public_key", "pending_private_seed", "pending_public_key", "predecessor_owner_public_key", "successor_owner_public_key", "predecessor_state_hash", "envelope_hash")
            val faults = listOf("missing-active", "missing-pending", "partial-pending", "seed-mismatch", "equal", "predecessor", "successor", "unknown-field") +
                fields.flatMap { field -> listOf("short", "long", "type").map { "$field:$it" } } +
                listOf("owner:invalid-utf8", "owner:empty", "owner:oversize", "sequence:bool", "sequence:zero", "sequence:negative", "sequence:string", "sequence:float", "environment:scalar")
            for (fault in faults) {
                val payload = payload()
                val intent = intent(payload).also { it["environment"] = "testnet" }
                payload["rotation_dispatch_intent"] = intent
                when (fault) {
                    "missing-active" -> { payload.remove("private_seed"); payload.remove("public_key") }
                    "missing-pending" -> { payload.remove("pending_private_seed"); payload.remove("pending_public_key") }
                    "partial-pending" -> payload.remove("pending_public_key")
                    "seed-mismatch" -> payload["pending_private_seed"] = ByteArray(32) { 7 }
                    "equal" -> { payload["pending_private_seed"] = payload["private_seed"]; payload["pending_public_key"] = payload["public_key"] }
                    "predecessor" -> intent["predecessor_owner_public_key"] = ByteArray(32) { 8 }
                    "successor" -> intent["successor_owner_public_key"] = ByteArray(32) { 9 }
                    "unknown-field" -> intent["unknown"] = true
                    else -> {
                        val (field, kind) = fault.split(":")
                        when (field) {
                            "owner" -> intent["owner_name"] = when (kind) { "invalid-utf8" -> byteArrayOf(0xff.toByte()); "empty" -> ByteArray(0); else -> ByteArray(1_048_577) { 120 } }
                            "sequence" -> intent["sequence"] = when (kind) { "bool" -> true; "zero" -> BigInteger.ZERO; "negative" -> BigInteger.valueOf(-1); "string" -> "2"; else -> BigInteger.TWO }
                            "environment" -> intent["environment"] = "SCALAR_SENTINEL"
                            else -> {
                                val target = if (payload.containsKey(field)) payload else intent
                                target[field] = when (kind) { "short" -> ByteArray(31); "long" -> ByteArray(33); else -> "not-bytes" }
                            }
                        }
                    }
                }
                val created = ContainerCrypto.create(password, password, payload)
                try {
                    val raw = if (fault == "sequence:float" || fault == "environment:scalar") {
                        val typed = WalletJson.encodePayload(payload).toString(Charsets.UTF_8)
                        val malformed = if (fault == "sequence:float") typed.replace("[\"sequence\",{\"t\":\"int\",\"v\":2}]", "[\"sequence\",{\"t\":\"int\",\"v\":2.5}]") else typed.replace("SCALAR_SENTINEL", "\\ud800")
                        assertNotEquals(typed, malformed)
                        sealTypedJson(created.bytes, created.dek, malformed.toByteArray(Charsets.UTF_8))
                    } else created.bytes
                    val original = directory.resolve("original.dw")
                    Files.write(original, raw)
                    rejects<WalletContainerException> { AndroidWallet.open(original, password).close() }
                    assertArrayEquals(raw, Files.readAllBytes(original))
                    val destination = directory.resolve("invalid.dw")
                    rejects<WalletContainerException> { AndroidWallet.importContainer(destination, raw, password).close() }
                    assertFalse(Files.exists(destination))
                } finally { created.dek.fill(0); WalletJson.clearByteArrays(created.payload); WalletJson.clearByteArrays(payload) }
            }
        } finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }

    @Test fun bindingStorageFailuresPreserveOrLockWithoutDispatchAuthority() {
        val directory = Files.createTempDirectory("binding-storage-")
        val fixture = resourceMap("wallet-v2-portable-rotation-latch.json")
        val raw = java.util.Base64.getDecoder().decode(fixture["legacy_unbound_container_base64"] as String)
        try {
            for (unknown in listOf(false, true)) {
                val path = directory.resolve("$unknown.dw")
                Files.write(path, raw)
                val opened = ContainerCrypto.open(raw, password)
                val seeds = listOf(opened.payload["private_seed"] as ByteArray, opened.payload["pending_private_seed"] as ByteArray)
                val sessionRaw = raw.copyOf()
                var replacements = 0
                WalletSession(path, sessionRaw, opened.dek, opened.payload) { _, _, _ ->
                    replacements++
                    if (unknown) throw WalletStorageOutcomeUnknownException() else throw WalletStorageException()
                }.use { wallet ->
                    if (unknown) {
                        rejects<WalletStorageOutcomeUnknownException> { wallet.bindLegacyRotationDispatchEnvironment("testnet") { _, _ -> true } }
                        assertFalse(wallet.isUnlocked)
                        assertTrue(opened.dek.all { it == 0.toByte() })
                        assertTrue(sessionRaw.all { it == 0.toByte() })
                        seeds.forEach { assertTrue(it.all { value -> value == 0.toByte() }) }
                        rejects<WalletLockedException> { wallet.exportContainer() }
                    } else {
                        rejects<WalletStorageException> { wallet.bindLegacyRotationDispatchEnvironment("testnet") { _, _ -> true } }
                        assertTrue(wallet.isUnlocked)
                        assertNull(checkNotNull(wallet.ownerKeyRotationDispatchIntent).environment)
                        assertArrayEquals(raw, wallet.exportContainer())
                    }
                    assertEquals(1, replacements)
                    assertArrayEquals(raw, Files.readAllBytes(path))
                }
            }
        } finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }

    @Test fun publicImportRejectsMalformedLatchBeforeCreatingDestination() {
        val directory = Files.createTempDirectory("portable-invalid-")
        try {
            for (bad in listOf(null, "", " \t\n", "x".repeat(257), 42)) {
                val payload = payload()
                payload["rotation_dispatch_intent"] = intent(payload).also { it["environment"] = bad }
                val created = ContainerCrypto.create(password, password, payload)
                val destination = directory.resolve("invalid.dw")
                try {
                    rejects<WalletContainerException> { AndroidWallet.importContainer(destination, created.bytes, password).close() }
                    assertFalse(Files.exists(destination))
                } finally { created.dek.fill(0); WalletJson.clearByteArrays(created.payload); WalletJson.clearByteArrays(payload) }
            }
        } finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }
}

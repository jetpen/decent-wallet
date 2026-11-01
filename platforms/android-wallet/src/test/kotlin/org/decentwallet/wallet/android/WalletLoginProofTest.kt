package org.decentwallet.wallet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.assertFalse
import org.junit.Assert.fail
import org.junit.Test
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.util.Base64
import java.security.MessageDigest
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class WalletLoginProofTest {
    private val seed = ByteArray(32) { it.toByte() }
    private val challenge = "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ"
    private val expiresAt = System.currentTimeMillis() / 1000 + 60
    private val identity = "mailto:alice@example.org"

    @Test
    fun serializationRejectsProofsExceedingTransportLimit() {
        val validChallengeBytes = ByteArray(32)
        val validSignatureBytes = ByteArray(64)
        val validChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(validChallengeBytes)
        val validSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(validSignatureBytes)
        val longIdentity = "x".repeat(8000)
        val request = try {
            WalletLoginProofRequest("decent-wallet-login-v1", validChallenge, longIdentity, validSignature)
        } finally {
            validChallengeBytes.fill(0)
            validSignatureBytes.fill(0)
        }
        try {
            request.toJsonBytes()
            fail("serialized proof above the protocol body limit must reject")
        } catch (_: WalletLoginProofRejectedException) { }
    }

    @Test
    fun approvedLoginRequestMatchesSharedJcsAndEd25519Vector() {
        val directory = Files.createTempDirectory("wallet-login-vector-")
        val path = directory.resolve("wallet.dw")
        val publicKey = AndroidIdentityCrypto.publicKeyFromSeed(seed)
        val wallet = AndroidWallet.create(path, "a sufficiently long test password", "a sufficiently long test password",
            mapOf("private_seed" to seed.copyOf(), "public_key" to publicKey.copyOf()))
        try {
            var consentCalls = 0
            val request = wallet.createWalletLoginProofRequest(challenge, identity, expiresAt) { profile, id ->
                consentCalls++
                assertEquals("decent-wallet-login-v1", profile)
                assertEquals(identity, id)
                true
            }
            assertEquals(1, consentCalls)
            assertEquals("decent-wallet-login-v1", request.profile)
            assertEquals(challenge, request.challenge)
            assertEquals(identity, request.identityId)
            val vectorBytes = checkNotNull(javaClass.classLoader?.getResourceAsStream("wallet-login-v1/vectors/valid-basic.json")).use { it.readBytes() }
            val vector = WalletJson.parse(vectorBytes, 16 * 1024) as Map<*, *>
            assertExactRequestMatchesVector(request, vector, publicKey)
            val signature = Base64.getUrlDecoder().decode(request.signature)
            assertTrue(AndroidIdentityCrypto.verify(publicKey, (vector["signed_bytes_utf8"] as String).toByteArray(StandardCharsets.UTF_8), signature))
            signature.fill(0)
            vectorBytes.fill(0)
        } finally {
            wallet.close()
            seed.fill(0)
            publicKey.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun publicRequestConstructionRejectsNonCanonicalChallengeSignatureAndIdentity() {
        assertConstructorRejected("decent-wallet-login-v1", challenge + "=", identity, "A".repeat(86))
        assertConstructorRejected("decent-wallet-login-v1", challenge, identity, "A".repeat(86) + "=")
        assertConstructorRejected("decent-wallet-login-v1", challenge, "mailto:alice-${Char(0xD800)}@example.org", "A".repeat(86))
    }

    private fun assertConstructorRejected(profile: String, challenge: String, identityId: String, signature: String) {
        try {
            WalletLoginProofRequest(profile, challenge, identityId, signature)
            fail("invalid public proof request must be rejected")
        } catch (failure: Exception) {
            assertTrue(failure is WalletLoginProofRejectedException || failure is java.nio.charset.CharacterCodingException)
        }
    }

    private fun assertExactRequestMatchesVector(request: WalletLoginProofRequest, vector: Map<*, *>, publicKey: ByteArray) {
        val signedBytes = checkNotNull(vector["signed_bytes_utf8"] as? String).toByteArray(StandardCharsets.UTF_8)
        try {
            assertEquals(vector["signature_b64url"] as String, request.signature)
            assertEquals(vector["profile"] as String, request.profile)
            assertEquals(vector["challenge"] as String, request.challenge)
            assertEquals(vector["identity_id"] as String, request.identityId)
            assertTrue(request.verifyAgainst(publicKey))
            val proofBytes = request.toJsonBytes()
            try {
                val parsed = WalletJson.parse(proofBytes, 16 * 1024) as Map<*, *>
                assertEquals(setOf("profile", "challenge", "identity_id", "signature"), parsed.keys)
                assertEquals(vector["proof"], parsed)
            } finally {
                proofBytes.fill(0)
            }
            assertEquals(String(signedBytes, StandardCharsets.UTF_8),
                String(StrictWalletLoginJson.signingBytes(request.profile, request.challenge, request.identityId), StandardCharsets.UTF_8))
        } finally {
            signedBytes.fill(0)
        }
    }

    private fun assertRejectedBySignature(proof: String, publicKey: ByteArray, expected: String) {
        val request = StrictWalletLoginJson.parse(proof.toByteArray(StandardCharsets.UTF_8))
        val valid = try { request.verifyAgainst(publicKey) } finally { publicKey.fill(0) }
        assertFalse("vector $expected must fail Ed25519 verification", valid)
    }

    private fun assertRejected(proof: String, expected: String) {
        val proofBytes = proof.toByteArray(StandardCharsets.UTF_8)
        try {
            StrictWalletLoginJson.parse(proofBytes)
            fail("vector $expected must be rejected")
        } catch (_: WalletLoginProofRejectedException) {
        } finally {
            proofBytes.fill(0)
        }
    }

    @Test
    fun bundledVectorManifestAndEveryNegativeProofMutationAreEnforced() {
        val manifestBytes = checkNotNull(javaClass.classLoader?.getResourceAsStream("wallet-login-v1/manifest.json")).use { it.readBytes() }
        val manifest = WalletJson.parse(manifestBytes, 16 * 1024) as Map<*, *>
        val hashes = manifest["sha256"] as Map<*, *>
        val positivePath = manifest["positive_vectors"] as List<*>
        val negativePath = manifest["negative_vectors"] as List<*>
        val positiveBytes = checkNotNull(javaClass.classLoader?.getResourceAsStream("wallet-login-v1/${positivePath.single()}")).use { it.readBytes() }
        val negativeBytes = checkNotNull(javaClass.classLoader?.getResourceAsStream("wallet-login-v1/${negativePath.single()}")).use { it.readBytes() }
        val positive = WalletJson.parse(positiveBytes, 16 * 1024) as Map<*, *>
        val proof = positive["proof"] as Map<*, *>
        val publicKey = Base64.getUrlDecoder().decode(positive["public_key_b64url"] as String)
        val base = proofJson(proof)
        try {
            assertEquals(hashes[positivePath.single()] as String,
                MessageDigest.getInstance("SHA-256").digest(positiveBytes).joinToString("") { "%02x".format(it) })
            assertEquals(hashes[negativePath.single()] as String,
                MessageDigest.getInstance("SHA-256").digest(negativeBytes).joinToString("") { "%02x".format(it) })
            val negative = WalletJson.parse(negativeBytes, 16 * 1024) as Map<*, *>
            val cases = negative["vectors"] as List<*>
            assertEquals(10, cases.size)
            val expectedIds = setOf("wrong-profile", "challenge-tampered", "identifier-case-changed",
                "identifier-unicode-normalized", "signature-tampered", "signature-wrong-length",
                "signature-padding", "proof-extra-member", "proof-missing-member", "proof-duplicate-member")
            assertEquals(expectedIds, cases.map { (it as Map<*, *>)["id"] as String }.toSet())
            assertRejected(base.replace("decent-wallet-login-v1", "decent-wallet-login-v0"), "wrong-profile")
            val caseChangedIdentity = "mailto:Alice@example.org"
            assertRejectedBySignature(base.replace(proof["identity_id"] as String, caseChangedIdentity),
                publicKey.copyOf(), "identifier-case-changed")
            val changedChallenge = (proof["challenge"] as String).toCharArray().also {
                it[it.lastIndex] = if (it.last() == 'A') 'B' else 'A'
            }.concatToString()
            assertRejectedBySignature(base.replace(proof["challenge"] as String, changedChallenge), publicKey.copyOf(), "challenge-tampered")
            val composedIdentity = "mailto:alice\u00e9@example.org"
            val decomposedIdentity = "mailto:alicee\u0301@example.org"
            assertRejectedBySignature(base.replace("mailto:alice@example.org", composedIdentity), publicKey.copyOf(), "identifier-unicode-normalized")
            val normalizationBytes = StrictWalletLoginJson.signingBytes("decent-wallet-login-v1", proof["challenge"] as String, composedIdentity)
            val normalizationSignatureBytes = try { AndroidIdentityCrypto.sign(seed, normalizationBytes) }
                finally { normalizationBytes.fill(0) }
            val normalizationSignature = try { Base64.getUrlEncoder().withoutPadding().encodeToString(normalizationSignatureBytes) }
                finally { normalizationSignatureBytes.fill(0) }
            val composedProof = "{\"profile\":\"decent-wallet-login-v1\",\"challenge\":\"${proof["challenge"]}\",\"identity_id\":${quote(composedIdentity)},\"signature\":\"$normalizationSignature\"}"
            val decomposedProof = composedProof.replace(composedIdentity, decomposedIdentity)
            val decomposed = StrictWalletLoginJson.parse(decomposedProof.toByteArray(StandardCharsets.UTF_8))
            assertFalse("canonically equivalent but byte-distinct identity must not reuse a signature",
                decomposed.verifyAgainst(publicKey.copyOf()))
            val signature = Base64.getUrlDecoder().decode(proof["signature"] as String)
            signature[0] = (signature[0].toInt() xor 1).toByte()
            assertRejectedBySignature(base.replace(proof["signature"] as String,
                Base64.getUrlEncoder().withoutPadding().encodeToString(signature)), publicKey.copyOf(), "signature-tampered")
            signature.fill(0)
            assertRejected(base.replace(proof["signature"] as String,
                Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(63))), "signature-wrong-length")
            assertRejected(base.replace(proof["signature"] as String, (proof["signature"] as String) + "="), "signature-padding")
            assertRejected(base.dropLast(1) + ",\"extra\":\"x\"}", "proof-extra-member")
            assertRejected(base.replace(",\"identity_id\":\"mailto:alice@example.org\"", ""), "proof-missing-member")
            assertRejected(base.dropLast(1) + ",\"identity_id\":\"mailto:alice@example.org\"}", "proof-duplicate-member")
        } finally {
            publicKey.fill(0)
            manifestBytes.fill(0)
            positiveBytes.fill(0)
            negativeBytes.fill(0)
        }
    }

    private fun proofJson(proof: Map<*, *>): String =
        "{\"profile\":${quote(proof["profile"] as String)},\"challenge\":${quote(proof["challenge"] as String)}," +
            "\"identity_id\":${quote(proof["identity_id"] as String)},\"signature\":${quote(proof["signature"] as String)}}"

    private fun quote(value: String): String =
        "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    @Test
    fun rejectedConsentAndLockedWalletNeverReturnProof() {
        val directory = Files.createTempDirectory("wallet-login-consent-")
        val path = directory.resolve("wallet.dw")
        val publicKey = AndroidIdentityCrypto.publicKeyFromSeed(seed)
        val wallet = AndroidWallet.create(path, "a sufficiently long test password", "a sufficiently long test password",
            mapOf("private_seed" to seed.copyOf(), "public_key" to publicKey.copyOf()))
        try {
            var calls = 0
            try {
                wallet.createWalletLoginProofRequest(challenge, identity, expiresAt) { _, _ -> calls++; false }
                fail("rejected consent must not create a proof")
            } catch (_: WalletLoginProofRejectedException) { }
            assertEquals(1, calls)
            wallet.close()
            try {
                wallet.createWalletLoginProofRequest(challenge, identity, expiresAt) { _, _ -> fail("locked wallet must not ask consent"); false }
                fail("locked wallet must not sign")
            } catch (_: WalletLockedException) { }
        } finally {
            wallet.close()
            seed.fill(0)
            publicKey.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun walletCanLockWhileLoginConsentIsWaiting() {
        val directory = Files.createTempDirectory("wallet-login-consent-concurrency-")
        val path = directory.resolve("wallet.dw")
        val publicKey = AndroidIdentityCrypto.publicKeyFromSeed(seed)
        val wallet = AndroidWallet.create(path, "a sufficiently long test password", "a sufficiently long test password",
            mapOf("private_seed" to seed.copyOf(), "public_key" to publicKey.copyOf()))
        val signer = Executors.newSingleThreadExecutor()
        val locker = Executors.newSingleThreadExecutor()
        val consentStarted = CountDownLatch(1)
        val allowConsent = CountDownLatch(1)
        var signing: java.util.concurrent.Future<WalletLoginProofRequest>? = null
        var locking: java.util.concurrent.Future<Boolean>? = null
        try {
            signing = signer.submit<WalletLoginProofRequest> {
                wallet.createWalletLoginProofRequest(challenge, identity, expiresAt) { _, _ ->
                    consentStarted.countDown()
                    check(allowConsent.await(4, TimeUnit.SECONDS))
                    true
                }
            }
            assertTrue(consentStarted.await(3, TimeUnit.SECONDS))
            locking = locker.submit<Boolean> { wallet.lock(); true }
            val lockCompletedBeforeConsent = try { locking.get(500, TimeUnit.MILLISECONDS) }
                catch (_: java.util.concurrent.TimeoutException) { false }
            allowConsent.countDown()
            assertTrue("wallet locking must not wait on external consent", lockCompletedBeforeConsent)
            try {
                signing.get(3, TimeUnit.SECONDS)
                fail("a wallet locked during consent must not sign")
            } catch (_: java.util.concurrent.ExecutionException) { }
        } finally {
            allowConsent.countDown()
            signing?.cancel(true)
            locking?.cancel(true)
            signer.shutdownNow()
            locker.shutdownNow()
            wallet.close()
            seed.fill(0)
            publicKey.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun challengeCanProduceOnlyOneConsentBoundProofPerUnlockedSession() {
        val directory = Files.createTempDirectory("wallet-login-one-use-")
        val path = directory.resolve("wallet.dw")
        val publicKey = AndroidIdentityCrypto.publicKeyFromSeed(seed)
        val wallet = AndroidWallet.create(path, "a sufficiently long test password", "a sufficiently long test password",
            mapOf("private_seed" to seed.copyOf(), "public_key" to publicKey.copyOf()))
        try {
            var consentCalls = 0
            wallet.createWalletLoginProofRequest(challenge, identity, expiresAt) { _, _ -> consentCalls++; true }
            try {
                wallet.createWalletLoginProofRequest(challenge, identity, expiresAt) { _, _ -> consentCalls++; true }
                fail("challenge must be one-use per wallet session")
            } catch (_: WalletLoginProofRejectedException) { }
            assertEquals(1, consentCalls)
        } finally {
            wallet.close()
            seed.fill(0)
            publicKey.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun expiredLoginConsentDoesNotCreateProof() {
        val directory = Files.createTempDirectory("wallet-login-expired-")
        val path = directory.resolve("wallet.dw")
        val publicKey = AndroidIdentityCrypto.publicKeyFromSeed(seed)
        val wallet = AndroidWallet.create(path, "a sufficiently long test password", "a sufficiently long test password",
            mapOf("private_seed" to seed.copyOf(), "public_key" to publicKey.copyOf()))
        try {
            var consentCalls = 0
            try {
                wallet.createWalletLoginProofRequest(challenge, identity, System.currentTimeMillis() / 1000) { _, _ ->
                    consentCalls++
                    true
                }
                fail("expired challenge must not sign")
            } catch (_: WalletLoginProofRejectedException) { }
            assertEquals(0, consentCalls)
        } finally {
            wallet.close()
            seed.fill(0)
            publicKey.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun expiryMustBeBoundedToWalletLoginTransactionWindow() {
        val directory = Files.createTempDirectory("wallet-login-expiry-bound-")
        val path = directory.resolve("wallet.dw")
        val publicKey = AndroidIdentityCrypto.publicKeyFromSeed(seed)
        val wallet = AndroidWallet.create(path, "a sufficiently long test password", "a sufficiently long test password",
            mapOf("private_seed" to seed.copyOf(), "public_key" to publicKey.copyOf()))
        try {
            val tooFar = System.currentTimeMillis() / 1000 + 301
            try {
                wallet.createWalletLoginProofRequest(challenge, identity, tooFar) { _, _ ->
                    fail("expiry beyond five minutes must reject before consent")
                    false
                }
                fail("expiry beyond five minutes must reject")
            } catch (_: WalletLoginProofRejectedException) { }
        } finally {
            wallet.close()
            seed.fill(0)
            publicKey.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    @Test
    fun signingBytesPreserveValidNonBmpIdentityUtf8Exactly() {
        val nonBmpIdentity = "mailto:alice-\uD83D\uDE07@example.org"
        val bytes = StrictWalletLoginJson.signingBytes("decent-wallet-login-v1", challenge, nonBmpIdentity)
        assertEquals(
            "{\"challenge\":\"$challenge\",\"identity_id\":\"$nonBmpIdentity\",\"profile\":\"decent-wallet-login-v1\"}",
            String(bytes, StandardCharsets.UTF_8),
        )
        val proof = "{\"profile\":\"decent-wallet-login-v1\",\"challenge\":\"$challenge\",\"identity_id\":\"$nonBmpIdentity\",\"signature\":\"${"A".repeat(86)}\"}"
        assertEquals(nonBmpIdentity, StrictWalletLoginJson.parse(proof.toByteArray(StandardCharsets.UTF_8)).identityId)
        bytes.fill(0)
    }

    @Test
    fun proofParserRejectsMalformedUtf8BytesInIdentity() {
        val prefix = """{"profile":"decent-wallet-login-v1","challenge":"$challenge","identity_id":"mailto:alice"""
        val suffix = """@example.org","signature":"${"A".repeat(86)}"}"""
        val malformedProof = prefix.toByteArray(StandardCharsets.UTF_8) +
            byteArrayOf(0xFF.toByte()) + suffix.toByteArray(StandardCharsets.UTF_8)
        try {
            StrictWalletLoginJson.parse(malformedProof)
            fail("malformed UTF-8 identity bytes must reject")
        } catch (_: WalletLoginProofRejectedException) {
        } finally {
            malformedProof.fill(0)
        }
    }

    @Test
    fun loginProofEncodingRejectsPaddingUnknownFieldsAndDuplicateMembers() {
        val proof = "{\"profile\":\"decent-wallet-login-v1\",\"challenge\":\"$challenge\",\"identity_id\":\"$identity\",\"signature\":\"${"A".repeat(86)}\"}"
        assertEquals(identity, StrictWalletLoginJson.parse(proof.toByteArray()).identityId)
        val padded = proof.replace("${"A".repeat(86)}", "${"A".repeat(86)}=")
        try { StrictWalletLoginJson.parse(padded.toByteArray()); fail("padded signature must reject") }
        catch (_: WalletLoginProofRejectedException) { }
        val extra = proof.dropLast(1) + ",\"extra\":\"x\"}"
        try { StrictWalletLoginJson.parse(extra.toByteArray()); fail("unknown field must reject") }
        catch (_: WalletLoginProofRejectedException) { }
        val duplicate = proof.replace("\"signature\":", "\"identity_id\":\"$identity\",\"signature\":")
        try { StrictWalletLoginJson.parse(duplicate.toByteArray()); fail("duplicate field must reject") }
        catch (_: WalletLoginProofRejectedException) { }
    }
}

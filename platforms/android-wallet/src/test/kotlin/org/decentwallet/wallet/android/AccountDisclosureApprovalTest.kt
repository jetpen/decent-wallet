package org.decentwallet.wallet.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.nio.file.Files
import java.util.Comparator
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class AccountDisclosureApprovalTest {
    @Test
    fun nativeContinuationCapabilityPersistsOnlyAfterProofAndRecoversRedactedAfterReopen() {
        val testFixture = fixture()
        try {
            val pending = approveAtFixtureTime(
                testFixture, testFixture.review, testFixture.review.claims.filter { it.required }.map { it.id }.toSet(),
            ) { true }
            val capability = "Q".repeat(43)
            val beforeProofAttempt = Files.readAllBytes(testFixture.path)
            try {
                assertThrows(WalletDisclosureRequestException::class.java) {
                    testFixture.wallet.installNativeContinuationCapability(
                        pending, capability, pending.approvedAtEpochSeconds + 120,
                    )
                }
                assertContainerUnchanged(testFixture.path, beforeProofAttempt)
            } finally {
                beforeProofAttempt.fill(0)
            }
            testFixture.wallet.createAccountLoginProof(
                pending, "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ",
            )
            testFixture.wallet.installNativeContinuationCapability(
                pending, capability, System.currentTimeMillis() / 1000 + 120,
            )
            testFixture.wallet.lock()
            val reopened = AndroidWallet.open(testFixture.path, testFixture.password)
            try {
                val stored = reopened.nativeContinuationCapability(pending)
                assertNotNull(stored)
                stored!!.use {
                    val copy = it.copyCapabilityBytes()
                    try {
                        assertTrue(copy.contentEquals(java.util.Base64.getUrlDecoder().decode(capability)))
                    } finally {
                        copy.fill(0)
                    }
                    assertTrue(it.expiresAtEpochSeconds <= pending.expiresAtEpochSeconds)
                    assertFalse(it.toString().contains(capability))
                    it.close()
                    assertThrows(IllegalStateException::class.java) { it.copyCapabilityBytes() }
                }
                val fileBytes = Files.readAllBytes(testFixture.path)
                try {
                    assertFalse(String(fileBytes, Charsets.ISO_8859_1).contains(capability))
                    val rawCapability = java.util.Base64.getUrlDecoder().decode(capability)
                    try {
                        assertFalse(containsBytes(fileBytes, rawCapability))
                    } finally {
                        rawCapability.fill(0)
                    }
                    val envelope = WalletJson.parse(fileBytes, fileBytes.size) as Map<*, *>
                    assertEquals(BigInteger.valueOf(2), envelope["version"])
                } finally {
                    fileBytes.fill(0)
                }
            } finally {
                reopened.close()
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun nativeContinuationRejectsMalformedStaleDuplicateAndOutOfWindowWritesWithoutMutation() {
        val testFixture = fixture()
        try {
            val pending = approveAtFixtureTime(
                testFixture, testFixture.review, testFixture.review.claims.filter { it.required }.map { it.id }.toSet(),
            ) { true }
            val secret = "M".repeat(43)
            testFixture.wallet.createAccountLoginProof(
                pending, "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ",
            )
            val baseline = Files.readAllBytes(testFixture.path)
            try {
                val overlongCapability = "Q".repeat(44_000)
                var decoderCalled = false
                assertThrows(WalletDisclosureRequestException::class.java) {
                    decodeNativeContinuationCapability(overlongCapability) {
                        decoderCalled = true
                        java.util.Base64.getUrlDecoder().decode(it)
                    }
                }
                assertFalse("overlong input must be rejected before decoding", decoderCalled)
                assertThrows(WalletDisclosureRequestException::class.java) {
                    testFixture.wallet.installNativeContinuationCapability(
                        pending, overlongCapability, System.currentTimeMillis() / 1000 + 60,
                    )
                }
                assertContainerUnchanged(testFixture.path, baseline)
                val invalid = listOf(
                    "not-base64url",
                    "Q".repeat(43) + "=",
                    java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(ByteArray(31)),
                )
                for (candidate in invalid) {
                    val error = assertThrows(WalletDisclosureRequestException::class.java) {
                        testFixture.wallet.installNativeContinuationCapability(
                            pending, candidate, System.currentTimeMillis() / 1000 + 60,
                        )
                    }
                    assertFalse(error.toString().contains(candidate))
                    assertContainerUnchanged(testFixture.path, baseline)
                }
                val now = System.currentTimeMillis() / 1000
                for (expiry in listOf(now, now + 301, pending.expiresAtEpochSeconds + 1)) {
                    assertThrows(WalletDisclosureRequestException::class.java) {
                        testFixture.wallet.installNativeContinuationCapability(pending, secret, expiry)
                    }
                    assertContainerUnchanged(testFixture.path, baseline)
                }
                val wrongHandle = PendingAccountApproval(
                    "A".repeat(43), pending.expiresAtEpochSeconds, pending.approvedAtEpochSeconds,
                )
                assertThrows(WalletDisclosureRequestException::class.java) {
                    testFixture.wallet.installNativeContinuationCapability(wrongHandle, secret, now + 60)
                }
                val wrongTime = PendingAccountApproval(
                    pending.handle, pending.expiresAtEpochSeconds, pending.approvedAtEpochSeconds + 1,
                )
                assertThrows(WalletDisclosureRequestException::class.java) {
                    testFixture.wallet.installNativeContinuationCapability(wrongTime, secret, now + 60)
                }
                assertContainerUnchanged(testFixture.path, baseline)

                testFixture.wallet.installNativeContinuationCapability(pending, secret, now + 60)
                val installedBytes = Files.readAllBytes(testFixture.path)
                try {
                    assertThrows(WalletDisclosureRequestException::class.java) {
                        testFixture.wallet.installNativeContinuationCapability(pending, secret, now + 90)
                    }
                    assertContainerUnchanged(testFixture.path, installedBytes)
                    testFixture.wallet.lock()
                    assertThrows(WalletLockedException::class.java) {
                        testFixture.wallet.nativeContinuationCapability(pending)
                    }
                } finally {
                    installedBytes.fill(0)
                }
            } finally {
                baseline.fill(0)
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun expiredNativeContinuationIsClearedDurablyBeforeRecoveryReturnsIt() {
        val testFixture = fixture()
        try {
            val absoluteExpiry = System.currentTimeMillis() / 1000 + 1
            val boundaryCapability = NativeContinuationCapability(
                absoluteExpiry,
                System.nanoTime() + TimeUnit.HOURS.toNanos(1),
                byteArrayOf(1, 2, 3, 4),
            )
            while (System.currentTimeMillis() / 1000 < absoluteExpiry) Thread.sleep(25)
            assertThrows(IllegalStateException::class.java) { boundaryCapability.copyCapabilityBytes() }
            assertThrows(IllegalStateException::class.java) { boundaryCapability.copyCapabilityBytes() }
            val ownedBytes = NativeContinuationCapability::class.java.getDeclaredField("ownedBytes")
            ownedBytes.isAccessible = true
            assertNull(ownedBytes.get(boundaryCapability))

            val pending = approveAtFixtureTime(
                testFixture, testFixture.review, testFixture.review.claims.filter { it.required }.map { it.id }.toSet(),
            ) { true }
            testFixture.wallet.createAccountLoginProof(
                pending, "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ",
            )
            val expiry = System.currentTimeMillis() / 1000 + 2
            testFixture.wallet.installNativeContinuationCapability(pending, "Q".repeat(43), expiry)
            val alreadyOpen = testFixture.wallet.nativeContinuationCapability(pending)
            assertNotNull(alreadyOpen)
            val waitUntil = expiry + 1
            while (System.currentTimeMillis() / 1000 < waitUntil) Thread.sleep(100)
            try {
                assertThrows(IllegalStateException::class.java) { alreadyOpen!!.copyCapabilityBytes() }
                assertThrows(IllegalStateException::class.java) { alreadyOpen!!.copyCapabilityBytes() }
            } finally {
                alreadyOpen!!.close()
            }
            testFixture.wallet.lock()

            val reopened = AndroidWallet.open(testFixture.path, testFixture.password)
            try {
                assertNull(reopened.nativeContinuationCapability(pending))
                val payload = reopened.readPayload()
                try {
                    val record = payload["pending_account_disclosure_approval"] as Map<*, *>
                    assertFalse(record.containsKey("native_continuation"))
                } finally {
                    WalletJson.clearByteArrays(payload)
                }
            } finally {
                reopened.close()
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun approvalPersistsExactSelectionAndRecoversAfterLockWithoutReconsent() {
        val testFixture = fixture()
        try {
            var calls = 0
            val selected = testFixture.review.claims.filter { it.required }.map { it.id }.toSet()
            val pending = approveAtFixtureTime(testFixture, testFixture.review, selected) {
                calls++
                assertTrue(it === testFixture.review)
                true
            }
            assertEquals(1, calls)
            assertTrue(pending.expiresAtEpochSeconds <= testFixture.now + 300)
            assertFalse(pending.toString().contains(pending.handle))
            assertFalse(pending.toString().contains("ada@example.test"))
            assertThrows(WalletDisclosureRequestException::class.java) { testFixture.wallet.exportContainer() }

            testFixture.wallet.lock()
            val reopened = AndroidWallet.open(testFixture.path, testFixture.password)
            try {
                val recovered = reopened.recoverPendingAccountApprovalAt(pending.approvedAtEpochSeconds + 1)
                assertNotNull(recovered)
                assertEquals(pending.handle, recovered!!.handle)
                assertEquals(pending.expiresAtEpochSeconds, recovered.expiresAtEpochSeconds)
                assertPersistedSelection(reopened, selected)
                assertEquals(null, reopened.recoverPendingAccountApprovalAt(pending.expiresAtEpochSeconds))
                assertEquals(null, reopened.recoverPendingAccountApprovalAt(pending.expiresAtEpochSeconds + 1))
                val expiredExport = reopened.exportContainer()
                assertTrue(expiredExport.isNotEmpty())
                expiredExport.fill(0)
            } finally {
                reopened.close()
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun recoveryRejectsPersistedApprovalExceedingFiveMinuteLifetime() {
        val testFixture = fixture()
        try {
            val selected = testFixture.review.claims.filter { it.required }.map { it.id }.toSet()
            val pending = approveAtFixtureTime(testFixture, testFixture.review, selected) { true }
            val payload = testFixture.wallet.readPayload()
            try {
                @Suppress("UNCHECKED_CAST")
                val approval = payload["pending_account_disclosure_approval"] as MutableMap<String, Any?>
                @Suppress("UNCHECKED_CAST")
                val review = approval["review"] as MutableMap<String, Any?>
                approval["expires_at"] = pending.approvedAtEpochSeconds + 301
                review["request_expires_at"] = pending.approvedAtEpochSeconds + 600
                val malformedPath = testFixture.directory.resolve("overlong-approval.dw")
                val malformedWallet = AndroidWallet.create(
                    malformedPath,
                    testFixture.password,
                    testFixture.password,
                    payload,
                )
                try {
                    assertThrows(WalletDisclosureRequestException::class.java) {
                        malformedWallet.recoverPendingAccountApprovalAt(pending.approvedAtEpochSeconds + 1)
                    }
                } finally {
                    malformedWallet.close()
                }
            } finally {
                WalletJson.clearByteArrays(payload)
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun approvedAccountDisclosureCanIssueExactlyOneDurableLoginProof() {
        val testFixture = fixture()
        try {
            var consentCalls = 0
            val pending = approveAtFixtureTime(
                testFixture,
                testFixture.review,
                testFixture.review.claims.filter { it.required }.map { it.id }.toSet(),
            ) { consentCalls++; true }
            val wrongHandle = PendingAccountApproval("A".repeat(43), pending.expiresAtEpochSeconds, pending.approvedAtEpochSeconds)
            assertThrows(WalletDisclosureRequestException::class.java) {
                testFixture.wallet.createAccountLoginProofAt(
                    wrongHandle, "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ", testFixture.now,
                )
            }
            assertThrows(WalletDisclosureRequestException::class.java) {
                testFixture.wallet.createAccountLoginProofAt(pending, "not-a-challenge", testFixture.now)
            }
            val request = try {
                testFixture.wallet.createAccountLoginProof(pending, "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ")
            } catch (_: WalletContainerException) {
                null
            }
            assertNotNull("a persisted account approval must authorize the wallet login proof", request)
            val proof = checkNotNull(request)
            assertEquals(1, consentCalls)
            assertEquals("decent-wallet-login-v1", proof.profile)
            assertEquals("ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ", proof.challenge)
            assertEquals(testFixture.identityId, proof.identityId)
            val ownerKey = testFixture.wallet.ownerPublicKey
            try {
                assertTrue(proof.verifyAgainst(ownerKey))
            } finally {
                ownerKey.fill(0)
            }
            val proofBytes = proof.toJsonBytes()
            try {
                val serialized = WalletJson.parse(proofBytes, 16 * 1024) as Map<*, *>
                assertEquals(setOf("profile", "challenge", "identity_id", "signature"), serialized.keys)
                assertFalse(String(proofBytes, Charsets.UTF_8).contains("ada@example.test"))
            } finally {
                proofBytes.fill(0)
            }
            val payload = testFixture.wallet.readPayload()
            try {
                val approval = payload["pending_account_disclosure_approval"] as Map<*, *>
                assertEquals(true, approval["proof_issued"])
                assertEquals("ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ", approval["proof_challenge"])
            } finally {
                WalletJson.clearByteArrays(payload)
            }
            testFixture.wallet.lock()
            val reopened = AndroidWallet.open(testFixture.path, testFixture.password)
            try {
                val recovered = reopened.recoverPendingAccountApprovalAt(testFixture.now)
                assertNotNull(recovered)
                assertThrows(WalletDisclosureRequestException::class.java) {
                    reopened.createAccountLoginProofAt(pending, proof.challenge, testFixture.now)
                }
            } finally {
                reopened.close()
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun staleWalletSessionCannotIssueASecondProofAfterDurableConsumption() {
        val testFixture = fixture()
        try {
            val pending = approveAtFixtureTime(
                testFixture,
                testFixture.review,
                testFixture.review.claims.filter { it.required }.map { it.id }.toSet(),
            ) { true }
            val staleSession = AndroidWallet.open(testFixture.path, testFixture.password)
            try {
                val first = testFixture.wallet.createAccountLoginProof(pending, "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ")
                val firstOwnerKey = testFixture.wallet.ownerPublicKey
                try {
                    assertTrue(first.verifyAgainst(firstOwnerKey))
                } finally {
                    firstOwnerKey.fill(0)
                }
                val duplicate = try {
                    staleSession.createAccountLoginProofAt(
                        pending, "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ", testFixture.now,
                    )
                } catch (_: WalletContainerException) {
                    null
                }
                assertNull("stale disk revision must not release a second proof", duplicate)
            } finally {
                staleSession.close()
            }
            val reopened = AndroidWallet.open(testFixture.path, testFixture.password)
            try {
                assertThrows(WalletDisclosureRequestException::class.java) {
                    reopened.createAccountLoginProofAt(
                        pending, "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ", testFixture.now,
                    )
                }
            } finally {
                reopened.close()
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun proofIsNotReleasedWhenApprovalExpiresWhileSigning() {
        val testFixture = fixture()
        try {
            val pending = approveAtFixtureTime(
                testFixture,
                testFixture.review,
                testFixture.review.claims.filter { it.required }.map { it.id }.toSet(),
            ) { true }
            var timeReads = 0
            val proof = try {
                testFixture.wallet.createAccountLoginProofAt(
                    pending,
                    "ctu3M2x2eAAj-D2kw1Xy7uqFczsT00d2l5F3kMEikIQ",
                    testFixture.now,
                    currentTimeEpochSeconds = {
                        timeReads++
                        if (timeReads == 1) testFixture.now else pending.expiresAtEpochSeconds
                    },
                )
            } catch (_: WalletContainerException) {
                null
            }
            assertNull("expired approval must not release a newly signed proof", proof)
            assertEquals(2, timeReads)
            val payload = testFixture.wallet.readPayload()
            try {
                val approval = payload["pending_account_disclosure_approval"] as Map<*, *>
                assertEquals(false, approval["proof_issued"])
            } finally {
                WalletJson.clearByteArrays(payload)
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun approvalIsRejectedWhenConsentReturnsAfterRequestExpiry() {
        val testFixture = fixture()
        try {
            val selected = testFixture.review.claims.filter { it.required }.map { it.id }.toSet()
            var now = testFixture.now
            assertThrows(WalletDisclosureRequestException::class.java) {
                testFixture.wallet.approveAccountDisclosureAt(
                    testFixture.review, selected, testFixture.now, currentTimeEpochSeconds = { now },
                ) {
                    now = testFixture.review.expiresAtEpochSeconds
                    true
                }
            }
            assertNull(testFixture.wallet.recoverPendingAccountApprovalAt(testFixture.review.expiresAtEpochSeconds))
            val payload = testFixture.wallet.readPayload()
            try {
                assertFalse(payload.containsKey("pending_account_disclosure_approval"))
            } finally {
                WalletJson.clearByteArrays(payload)
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun approvalIsClearedIfItExpiresDuringDurableWrite() {
        val testFixture = fixture()
        try {
            val selected = testFixture.review.claims.filter { it.required }.map { it.id }.toSet()
            var clockReads = 0
            assertThrows(WalletDisclosureRequestException::class.java) {
                testFixture.wallet.approveAccountDisclosureAt(
                    testFixture.review, selected, testFixture.now,
                    currentTimeEpochSeconds = {
                        clockReads++
                        if (clockReads == 1) testFixture.now else testFixture.review.expiresAtEpochSeconds
                    },
                ) { true }
            }
            assertEquals(2, clockReads)
            val payload = testFixture.wallet.readPayload()
            try {
                assertFalse(payload.containsKey("pending_account_disclosure_approval"))
            } finally {
                WalletJson.clearByteArrays(payload)
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun approvalIsClearedWhenWallClockPrecedesPersistedApprovalTime() {
        val testFixture = fixture()
        try {
            val selected = testFixture.review.claims.filter { it.required }.map { it.id }.toSet()
            val pending = approveAtFixtureTime(testFixture, testFixture.review, selected) { true }
            assertNull(testFixture.wallet.recoverPendingAccountApprovalAt(pending.approvedAtEpochSeconds - 1))
            val payload = testFixture.wallet.readPayload()
            try {
                assertFalse(payload.containsKey("pending_account_disclosure_approval"))
            } finally {
                WalletJson.clearByteArrays(payload)
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun denialInvalidSelectionAndCallbackFailurePersistNothing() {
        val testFixture = fixture()
        try {
            val required = testFixture.review.claims.filter { it.required }.map { it.id }.toSet()
            assertThrows(WalletDisclosureRequestException::class.java) {
                approveAtFixtureTime(testFixture, testFixture.review, required - required.first()) { true }
            }
            assertThrows(WalletDisclosureRequestException::class.java) {
                approveAtFixtureTime(testFixture, testFixture.review, required + "urn:decent:account:v1:unknown") { true }
            }
            assertThrows(WalletDisclosureRequestException::class.java) {
                approveAtFixtureTime(testFixture, testFixture.review, required) { false }
            }
            assertThrows(WalletDisclosureRequestException::class.java) {
                approveAtFixtureTime(testFixture, testFixture.review, required) { throw IllegalStateException("synthetic") }
            }
            assertNull(testFixture.wallet.recoverPendingAccountApprovalAt(testFixture.now))
            assertTrue(testFixture.wallet.exportContainer().isNotEmpty())
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun approvalCallbackRunsOutsideWalletMonitorAndRechecksEntityAfterCallback() {
        val testFixture = fixture()
        try {
            var otherThreadObservedWallet = false
            assertThrows(WalletDisclosureRequestException::class.java) {
                approveAtFixtureTime(testFixture, testFixture.review, testFixture.review.claims.map { it.id }.toSet()) {
                    val done = CountDownLatch(1)
                    val worker = Thread {
                        testFixture.wallet.getMasterAccountEntity()
                        otherThreadObservedWallet = true
                        done.countDown()
                    }
                    worker.start()
                    assertTrue("wallet monitor was held during consent", done.await(2, TimeUnit.SECONDS))
                    worker.join(2000)
                    testFixture.wallet.setMasterAccountEntity(mapOf("given_name" to "Changed during consent"))
                    true
                }
            }
            assertTrue(otherThreadObservedWallet)
            assertNull(testFixture.wallet.recoverPendingAccountApprovalAt(testFixture.now))
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun newReviewDuringConsentRejectsStaleApprovalWithoutClearingOwnerKey() {
        val testFixture = fixture()
        try {
            val selected = testFixture.review.claims.map { it.id }.toSet()
            assertThrows(WalletDisclosureRequestException::class.java) {
                approveAtFixtureTime(testFixture, testFixture.review, selected) {
                    testFixture.wallet.reviewAccountDisclosureAt(testFixture.rawContext, testFixture.handle, testFixture.issuer, testFixture.identityId, testFixture.now)
                    true
                }
            }
            val publicKey = testFixture.wallet.ownerPublicKey
            try {
                assertEquals(32, publicKey.size)
            } finally {
                publicKey.fill(0)
            }
            assertNull(testFixture.wallet.recoverPendingAccountApprovalAt(testFixture.now))
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun onlyOneActiveApprovalIsAllowedAndCancellationRestoresExport() {
        val testFixture = fixture()
        try {
            val selected = testFixture.review.claims.map { it.id }.toSet()
            val pending = approveAtFixtureTime(testFixture, testFixture.review, selected) { true }
            assertThrows(WalletDisclosureRequestException::class.java) {
                testFixture.wallet.setMasterAccountEntity(mapOf("given_name" to "Changed after approval"))
            }
            assertThrows(WalletDisclosureRequestException::class.java) {
                val anotherReview = testFixture.wallet.reviewAccountDisclosureAt(testFixture.rawContext, testFixture.handle, testFixture.issuer, testFixture.identityId, testFixture.now)
                approveAtFixtureTime(testFixture, anotherReview, selected) { true }
            }
            assertTrue(testFixture.wallet.cancelAccountDisclosureApproval(pending))
            assertNull(testFixture.wallet.recoverPendingAccountApprovalAt(testFixture.now))
            assertTrue(testFixture.wallet.exportContainer().isNotEmpty())
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun importRejectsAnEncryptedContainerWithAnActiveApproval() {
        val testFixture = fixture()
        try {
            approveAtFixtureTime(testFixture, testFixture.review, testFixture.review.claims.map { it.id }.toSet()) { true }
            val encrypted = Files.readAllBytes(testFixture.path)
            val destination = testFixture.directory.resolve("imported.dw")
            assertThrows(WalletDisclosureRequestException::class.java) {
                AndroidWallet.importContainer(destination, encrypted, testFixture.password)
            }
            assertFalse(Files.exists(destination))
            encrypted.fill(0)
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun expiredApprovalImportsAsExactBytesAndIsClearedBeforeRecovery() {
        val testFixture = fixture()
        try {
            val pending = approveAtFixtureTime(
                testFixture, testFixture.review, testFixture.review.claims.filter { it.required }.map { it.id }.toSet(),
            ) { true }
            val encrypted = Files.readAllBytes(testFixture.path)
            val destination = testFixture.directory.resolve("expired-import.dw")
            val imported = AndroidWallet.importContainerAt(
                destination, encrypted, testFixture.password, pending.expiresAtEpochSeconds + 1,
            )
            try {
                val written = Files.readAllBytes(destination)
                try {
                    assertTrue(encrypted.contentEquals(written))
                } finally {
                    written.fill(0)
                }
                assertNull(imported.recoverPendingAccountApprovalAt(pending.expiresAtEpochSeconds + 1))
            } finally {
                imported.close()
                encrypted.fill(0)
            }
        } finally {
            testFixture.close()
        }
    }

    @Test
    fun privateClaimAndConsentExceptionMarkersAreRedactedWithoutConsumingApproval() {
        val privateMarker = "ANDROID_PRIVATE_CONSENT_EXCEPTION_MARKER_ISSUE62_5f9d7c3a_LONG"
        val testFixture = fixture(email = privateMarker)
        try {
            val review = testFixture.review
            val emailClaim = review.claims.single { it.id.endsWith(":email") }
            assertEquals(privateMarker, emailClaim.value)
            assertFalse(emailClaim.toString().contains(privateMarker))
            assertFalse(review.toString().contains(privateMarker))

            val rejected = assertThrows(WalletDisclosureRequestException::class.java) {
                approveAtFixtureTime(
                    testFixture,
                    review,
                    review.claims.filter { it.required }.map { it.id }.toSet(),
                ) { throw IllegalStateException(privateMarker) }
            }
            val publicFailure = buildString {
                append(rejected.message)
                append(rejected.toString())
                append(rejected.stackTraceToString())
                rejected.cause?.let { append(it.toString()).append(it.stackTraceToString()) }
            }
            assertFalse(publicFailure.contains(privateMarker))
            assertNull(rejected.cause)
            assertNull(testFixture.wallet.recoverPendingAccountApprovalAt(testFixture.now))

            val pending = approveAtFixtureTime(
                testFixture,
                review,
                review.claims.filter { it.required }.map { it.id }.toSet(),
            ) { true }
            assertFalse(pending.toString().contains(privateMarker))
            assertEquals(pending.handle, testFixture.wallet.recoverPendingAccountApprovalAt(testFixture.now)?.handle)
        } finally {
            testFixture.close()
        }
    }

    private fun approveAtFixtureTime(
        fixture: Fixture,
        review: AccountDisclosureReview,
        selectedClaimIds: Set<String>,
        consent: (AccountDisclosureReview) -> Boolean,
    ): PendingAccountApproval = fixture.wallet.approveAccountDisclosureAt(
        review,
        selectedClaimIds,
        fixture.now,
        currentTimeEpochSeconds = { fixture.now },
        consent = consent,
    )

    private fun assertPersistedSelection(wallet: WalletSession, expected: Set<String>) {
        val payload = wallet.readPayload()
        try {
            val approval = payload["pending_account_disclosure_approval"] as Map<*, *>
            val review = approval["review"] as Map<*, *>
            assertEquals(expected, (review["selected_claim_ids"] as List<*>).toSet())
            assertEquals(setOf("given_name", "email"), (review["claims"] as List<*>).map {
                (it as Map<*, *>)["id"] as String
            }.map { it.substringAfterLast(':') }.toSet())
            assertEquals(setOf("given_name"), (review["selected_claims"] as List<*>).map {
                ((it as Map<*, *>)["id"] as String).substringAfterLast(':')
            }.toSet())
            assertFalse((review["selected_claims"] as List<*>).any { it.toString().contains("ada@example.test") })
        } finally {
            WalletJson.clearByteArrays(payload)
        }
    }

    private fun containsBytes(haystack: ByteArray, needle: ByteArray): Boolean {
        if (needle.isEmpty() || needle.size > haystack.size) return false
        for (offset in 0..haystack.size - needle.size) {
            var matches = true
            for (index in needle.indices) {
                if (haystack[offset + index] != needle[index]) {
                    matches = false
                    break
                }
            }
            if (matches) return true
        }
        return false
    }

    private fun assertContainerUnchanged(path: java.nio.file.Path, expected: ByteArray) {
        val actual = Files.readAllBytes(path)
        try {
            assertTrue(expected.contentEquals(actual))
        } finally {
            actual.fill(0)
        }
    }

    private fun fixture(email: String = "ada@example.test"): Fixture {
        val bytes = checkNotNull(javaClass.classLoader?.getResourceAsStream(
            "wallet-account-disclosure-v1/vectors/valid-signup.json",
        )).use { it.readBytes() }
        val root = WalletJson.parse(bytes, 64 * 1024) as Map<*, *>
        val context = LinkedHashMap(root["keycloak_context"] as Map<*, *>)
        val now = System.currentTimeMillis() / 1000
        context["expires_at"] = BigInteger.valueOf(now + 299)
        val rawContext = WalletJson.canonicalBytes(context)
        val handle = root["transaction_handle"] as String
        val directory = Files.createTempDirectory("wallet-android-disclosure-approval-")
        val path = directory.resolve("wallet.dw")
        val password = "a sufficiently long test password"
        val wallet = AndroidWallet.createWithGeneratedKey(path, password, password)
        wallet.setMasterAccountEntity(
            mapOf("given_name" to "Ada", "email" to email),
        )
        val review = wallet.reviewAccountDisclosureAt(
            rawContext, handle, "https://login.example.test/realms/site", "test:android-disclosure-owner", now,
        )
        bytes.fill(0)
        return Fixture(directory, path, password, wallet, review, rawContext, handle, now)
    }

    private class Fixture(
        val directory: java.nio.file.Path,
        val path: java.nio.file.Path,
        val password: String,
        val wallet: WalletSession,
        val review: AccountDisclosureReview,
        val rawContext: ByteArray,
        val handle: String,
        val now: Long,
    ) : AutoCloseable {
        val issuer = "https://login.example.test/realms/site"
        val identityId = "test:android-disclosure-owner"

        override fun close() {
            wallet.close()
            rawContext.fill(0)
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }
}

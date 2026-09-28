package org.decentwallet.wallet.android

import java.math.BigInteger
import java.security.MessageDigest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class IdentityStateHistoryTest {
    @Test
    fun resolvesVersionedOperationFiveAcrossACompleteNonGenesisHistory() {
        val vector = resource("/identity-owner-key-rotation-versioned-history.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = hexField(text, "owner_name_utf8_hex")
        val genesis = hexField(text, "genesis_envelope_cbor_hex")
        val genesisHash = hexField(text, "genesis_state_hash_hex")
        val predecessor = hexField(text, "predecessor_envelope_cbor_hex")
        val predecessorHash = hexField(text, "predecessor_state_hash_hex")
        val candidate = hexField(text, "candidate_envelope_cbor_hex")
        val successorOwner = hexField(text, "successor_owner_public_key_hex")
        val lookups = mutableListOf<ByteArray>()

        try {
            val state = IdentityStateHistoryVerifier.resolve(ownerName, candidate) { requestedHash ->
                lookups += requestedHash.copyOf()
                when {
                    MessageDigest.isEqual(requestedHash, predecessorHash) -> predecessor.copyOf()
                    MessageDigest.isEqual(requestedHash, genesisHash) -> genesis.copyOf()
                    else -> null
                }
            }

            assertArrayEquals(ownerName, state.ownerNameBytes)
            assertArrayEquals(successorOwner, state.ownerPublicKey)
            assertArrayEquals(
                hexField(text, "predecessor_owner_public_key_hex"),
                checkNotNull(state.predecessorOwnerPublicKey),
            )
            assertArrayEquals(predecessorHash, checkNotNull(state.predecessorStateHash))
            assertArrayEquals(hexField(text, "candidate_state_hash_hex"), state.stateHash)
            assertEquals(BigInteger.valueOf(3), state.sequence)
            assertEquals(BigInteger.ONE, state.generation)
            assertEquals(BigInteger.valueOf(2), state.threshold)
            assertEquals(listOf("alice", "bob", "carol"), state.signerSet.map { it.signerId })
            assertEquals(2, state.predecessorEnvelopes.size)
            assertArrayEquals(predecessor, state.predecessorEnvelopes[0])
            assertArrayEquals(genesis, state.predecessorEnvelopes[1])
            assertEquals(2, lookups.size)
            assertArrayEquals(predecessorHash, lookups[0])
            assertArrayEquals(genesisHash, lookups[1])
        } finally {
            vector.fill(0)
            ownerName.fill(0)
            genesis.fill(0)
            genesisHash.fill(0)
            predecessor.fill(0)
            predecessorHash.fill(0)
            candidate.fill(0)
            successorOwner.fill(0)
            lookups.forEach { it.fill(0) }
        }
    }

    @Test
    fun acceptsSkippedOperationThreeGenerationLikePythonCore() {
        val vector = resource("/identity-operation3-generation-skip.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = hexField(text, "owner_name_utf8_hex")
        val genesis = hexField(text, "genesis_envelope_cbor_hex")
        val predecessorHash = hexField(text, "predecessor_state_hash_hex")
        val candidate = hexField(text, "candidate_envelope_cbor_hex")
        try {
            val state = IdentityStateHistoryVerifier.resolve(ownerName, candidate) { requestedHash ->
                if (MessageDigest.isEqual(requestedHash, predecessorHash)) genesis.copyOf() else null
            }
            assertEquals(BigInteger.valueOf(2), state.sequence)
            assertEquals(BigInteger.valueOf(3), state.generation)
            assertArrayEquals(hexField(text, "candidate_state_hash_hex"), state.stateHash)
            assertEquals(listOf("bob", "carol", "dave"), state.signerSet.map { it.signerId })
            assertEquals(1, state.predecessorEnvelopes.size)
            assertArrayEquals(genesis, state.predecessorEnvelopes.single())
        } finally {
            vector.fill(0)
            ownerName.fill(0)
            genesis.fill(0)
            predecessorHash.fill(0)
            candidate.fill(0)
        }
    }

    @Test
    fun rejectsTamperedOperationFiveProofDespiteMatchingHistory() {
        val vector = resource("/identity-owner-key-rotation-versioned-history.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = hexField(text, "owner_name_utf8_hex")
        val genesis = hexField(text, "genesis_envelope_cbor_hex")
        val genesisHash = hexField(text, "genesis_state_hash_hex")
        val predecessor = hexField(text, "predecessor_envelope_cbor_hex")
        val predecessorHash = hexField(text, "predecessor_state_hash_hex")
        val candidate = hexField(text, "candidate_envelope_cbor_hex")
        candidate[candidate.lastIndex] = (candidate.last().toInt() xor 1).toByte()
        try {
            assertThrows(WalletInvalidIdentityStateException::class.java) {
                IdentityStateHistoryVerifier.resolve(ownerName, candidate) { requestedHash ->
                    when {
                        MessageDigest.isEqual(requestedHash, predecessorHash) -> predecessor.copyOf()
                        MessageDigest.isEqual(requestedHash, genesisHash) -> genesis.copyOf()
                        else -> null
                    }
                }
            }
        } finally {
            vector.fill(0)
            ownerName.fill(0)
            genesis.fill(0)
            genesisHash.fill(0)
            predecessor.fill(0)
            predecessorHash.fill(0)
            candidate.fill(0)
        }
    }

    @Test
    fun rejectsTamperedIntermediatePredecessorSignature() {
        val vector = resource("/identity-owner-key-rotation-versioned-history.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = hexField(text, "owner_name_utf8_hex")
        val genesis = hexField(text, "genesis_envelope_cbor_hex")
        val genesisHash = hexField(text, "genesis_state_hash_hex")
        val predecessor = hexField(text, "predecessor_envelope_cbor_hex")
        val predecessorHash = hexField(text, "predecessor_state_hash_hex")
        val candidate = hexField(text, "candidate_envelope_cbor_hex")
        predecessor[predecessor.lastIndex] = (predecessor.last().toInt() xor 1).toByte()
        try {
            assertThrows(WalletInvalidIdentityStateException::class.java) {
                IdentityStateHistoryVerifier.resolve(ownerName, candidate) { requestedHash ->
                    when {
                        MessageDigest.isEqual(requestedHash, predecessorHash) -> predecessor.copyOf()
                        MessageDigest.isEqual(requestedHash, genesisHash) -> genesis.copyOf()
                        else -> null
                    }
                }
            }
        } finally {
            vector.fill(0)
            ownerName.fill(0)
            genesis.fill(0)
            genesisHash.fill(0)
            predecessor.fill(0)
            predecessorHash.fill(0)
            candidate.fill(0)
        }
    }

    @Test
    fun rejectsHistoryReturnedForTheWrongOwnerName() {
        val vector = resource("/identity-owner-key-rotation-versioned-history.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = "another-owner".toByteArray(Charsets.UTF_8)
        val candidate = hexField(text, "candidate_envelope_cbor_hex")
        var lookups = 0
        try {
            assertThrows(WalletInvalidIdentityStateException::class.java) {
                IdentityStateHistoryVerifier.resolve(ownerName, candidate) {
                    lookups++
                    null
                }
            }
            assertEquals(0, lookups)
        } finally {
            vector.fill(0)
            ownerName.fill(0)
            candidate.fill(0)
        }
    }

    @Test
    fun rejectsHistoryBeyondMaximumPredecessorDepth() {
        val ownerName = "depth-test".toByteArray(Charsets.UTF_8)
        val ownerKey = ByteArray(AndroidIdentityCrypto.KEY_BYTES) { 9 }
        val history = HashMap<List<Byte>, ByteArray>()
        var previousHash = ByteArray(AndroidIdentityCrypto.KEY_BYTES)
        var head = ByteArray(0)
        try {
            for (sequence in 1..1025) {
                val (envelope, stateHash) = versionedEnvelope(
                    ownerName,
                    ownerKey,
                    sequence,
                    previousHash,
                )
                history[stateHash.toList()] = envelope
                previousHash.fill(0)
                previousHash = stateHash
            }
            head = versionedEnvelope(ownerName, ownerKey, 1026, previousHash).first
            var lookups = 0
            assertThrows(WalletInvalidIdentityStateException::class.java) {
                IdentityStateHistoryVerifier.resolve(ownerName, head) { requestedHash ->
                    lookups++
                    history[requestedHash.toList()]?.copyOf()
                }
            }
            assertEquals(1024, lookups)
        } finally {
            ownerName.fill(0)
            ownerKey.fill(0)
            previousHash.fill(0)
            head.fill(0)
            history.values.forEach { it.fill(0) }
        }
    }

    @Test
    fun rejectsMoreThanThreeProofsBeforeFetchingHistory() {
        val vector = resource("/identity-owner-key-rotation-versioned-history.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = hexField(text, "owner_name_utf8_hex")
        val candidate = hexField(text, "candidate_envelope_cbor_hex")
        val outer = IdentityCbor.decodeCanonical(candidate) as Map<*, *>
        val update = outer[BigInteger.valueOf(2)] as ByteArray
        val proofs = listOf("alice", "bob", "carol", "dave").map { signerId ->
            linkedMapOf<BigInteger, Any?>(
                BigInteger.ONE to signerId,
                BigInteger.valueOf(2) to ByteArray(AndroidIdentityCrypto.SIGNATURE_BYTES),
            )
        }
        val oversizedProofSet = IdentityCbor.encodeCanonical(
            linkedMapOf<BigInteger, Any?>(
                BigInteger.ONE to BigInteger.ONE,
                BigInteger.valueOf(2) to update,
                BigInteger.valueOf(3) to proofs,
            ),
        )
        var lookups = 0
        try {
            assertThrows(WalletInvalidIdentityStateException::class.java) {
                IdentityStateHistoryVerifier.resolve(ownerName, oversizedProofSet) {
                    lookups++
                    null
                }
            }
            assertEquals(0, lookups)
        } finally {
            vector.fill(0)
            ownerName.fill(0)
            candidate.fill(0)
            update.fill(0)
            oversizedProofSet.fill(0)
            proofs.forEach { (it[BigInteger.valueOf(2)] as ByteArray).fill(0) }
        }
    }

    @Test
    fun rejectsOversizedProofSignerIdBeforeFetchingHistory() {
        val vector = resource("/identity-owner-key-rotation-versioned-history.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = hexField(text, "owner_name_utf8_hex")
        val candidate = hexField(text, "candidate_envelope_cbor_hex")
        val outer = IdentityCbor.decodeCanonical(candidate) as Map<*, *>
        val update = outer[BigInteger.valueOf(2)] as ByteArray
        val signature = ByteArray(AndroidIdentityCrypto.SIGNATURE_BYTES)
        val oversizedProofSet = IdentityCbor.encodeCanonical(
            linkedMapOf<BigInteger, Any?>(
                BigInteger.ONE to BigInteger.ONE,
                BigInteger.valueOf(2) to update,
                BigInteger.valueOf(3) to listOf(
                    linkedMapOf<BigInteger, Any?>(
                        BigInteger.ONE to "s".repeat(257),
                        BigInteger.valueOf(2) to signature,
                    ),
                ),
            ),
        )
        var lookups = 0
        try {
            assertThrows(WalletInvalidIdentityStateException::class.java) {
                IdentityStateHistoryVerifier.resolve(ownerName, oversizedProofSet) {
                    lookups++
                    null
                }
            }
            assertEquals(0, lookups)
        } finally {
            vector.fill(0)
            ownerName.fill(0)
            candidate.fill(0)
            update.fill(0)
            signature.fill(0)
            oversizedProofSet.fill(0)
        }
    }

    @Test
    fun rejectsAggregateHistoryBeyondByteBudgetBeforeFetchingAllPredecessors() {
        val ownerName = ByteArray(400 * 1024) { 'a'.code.toByte() }
        val ownerKey = ByteArray(AndroidIdentityCrypto.KEY_BYTES) { 9 }
        val history = HashMap<List<Byte>, ByteArray>()
        var previousHash = ByteArray(AndroidIdentityCrypto.KEY_BYTES)
        var head = ByteArray(0)
        try {
            for (sequence in 1..12) {
                val (envelope, stateHash) = versionedEnvelope(
                    ownerName,
                    ownerKey,
                    sequence,
                    previousHash,
                )
                history[stateHash.toList()] = envelope
                previousHash.fill(0)
                previousHash = stateHash
            }
            head = versionedEnvelope(ownerName, ownerKey, 13, previousHash).first
            var lookups = 0
            assertThrows(WalletInvalidIdentityStateException::class.java) {
                IdentityStateHistoryVerifier.resolve(ownerName, head) { requestedHash ->
                    lookups++
                    history[requestedHash.toList()]?.copyOf()
                }
            }
            assertTrue("history must fetch predecessors before the byte budget is reached", lookups > 0)
            assertTrue("history must stop before loading all large predecessors", lookups < 12)
        } finally {
            ownerName.fill(0)
            ownerKey.fill(0)
            previousHash.fill(0)
            head.fill(0)
            history.values.forEach { it.fill(0) }
        }
    }

    @Test
    fun rejectsMissingVersionedPredecessorHistory() {
        val vector = resource("/identity-owner-key-rotation-versioned-history.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = hexField(text, "owner_name_utf8_hex")
        val candidate = hexField(text, "candidate_envelope_cbor_hex")
        try {
            assertThrows(WalletInvalidIdentityStateException::class.java) {
                IdentityStateHistoryVerifier.resolve(ownerName, candidate) { null }
            }
        } finally {
            vector.fill(0)
            ownerName.fill(0)
            candidate.fill(0)
        }
    }

    @Test
    fun rejectsHistoryReturnedForTheWrongStateHash() {
        val vector = resource("/identity-owner-key-rotation-versioned-history.json")
        val text = String(vector, Charsets.UTF_8)
        val ownerName = hexField(text, "owner_name_utf8_hex")
        val genesis = hexField(text, "genesis_envelope_cbor_hex")
        val candidate = hexField(text, "candidate_envelope_cbor_hex")
        try {
            assertThrows(WalletInvalidIdentityStateException::class.java) {
                IdentityStateHistoryVerifier.resolve(ownerName, candidate) { genesis.copyOf() }
            }
        } finally {
            vector.fill(0)
            ownerName.fill(0)
            genesis.fill(0)
            candidate.fill(0)
        }
    }

    private fun versionedEnvelope(
        ownerName: ByteArray,
        ownerKey: ByteArray,
        sequence: Int,
        predecessorHash: ByteArray,
    ): Pair<ByteArray, ByteArray> {
        val signers = listOf(
            "alice" to ByteArray(AndroidIdentityCrypto.KEY_BYTES) { 1 },
            "bob" to ByteArray(AndroidIdentityCrypto.KEY_BYTES) { 2 },
            "carol" to ByteArray(AndroidIdentityCrypto.KEY_BYTES) { 3 },
        ).map { (signerId, publicKey) ->
            linkedMapOf<BigInteger, Any?>(BigInteger.ONE to signerId, BigInteger.valueOf(2) to publicKey)
        }
        val sequenceValue = BigInteger.valueOf(sequence.toLong())
        val operation = if (sequence == 1) BigInteger.ONE else BigInteger.valueOf(2)
        val authorization = linkedMapOf<BigInteger, Any?>(
            BigInteger.ONE to BigInteger.ONE,
            BigInteger.valueOf(2) to BigInteger.ONE,
            BigInteger.valueOf(3) to operation,
            BigInteger.valueOf(4) to BigInteger.ONE,
            BigInteger.valueOf(5) to BigInteger.valueOf(2),
            BigInteger.valueOf(6) to signers,
            BigInteger.valueOf(7) to predecessorHash,
        )
        val update = IdentityCbor.encodeCanonical(
            linkedMapOf<BigInteger, Any?>(
                BigInteger.ONE to linkedMapOf<BigInteger, Any?>(
                    BigInteger.ONE to ownerName,
                    BigInteger.valueOf(2) to ownerKey,
                ),
                BigInteger.valueOf(2) to emptyMap<BigInteger, Any?>(),
                BigInteger.valueOf(3) to sequenceValue,
                BigInteger.valueOf(4) to authorization,
            ),
        )
        val envelope = IdentityCbor.encodeCanonical(
            linkedMapOf<BigInteger, Any?>(
                BigInteger.ONE to BigInteger.ONE,
                BigInteger.valueOf(2) to update,
                BigInteger.valueOf(3) to emptyList<Any?>(),
            ),
        )
        val stateHash = MessageDigest.getInstance("SHA-256").digest(update)
        update.fill(0)
        return envelope to stateHash
    }

    private fun resource(name: String): ByteArray =
        checkNotNull(javaClass.getResourceAsStream(name)).use { it.readBytes() }

    private fun hexField(text: String, key: String): ByteArray {
        val regex = Regex("\\\"${Regex.escape(key)}\\\"\\s*:\\s*\\\"([0-9a-f]+)\\\"")
        val value = checkNotNull(regex.find(text)).groupValues[1]
        return ByteArray(value.length / 2) { index ->
            value.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }
}

package org.decentwallet.wallet.android

import java.math.BigInteger

/** A verified signer from an Identity envelope. */
internal class VerifiedIdentitySigner(
    val signerId: String,
    publicKey: ByteArray,
) {
    private val encodedPublicKey = publicKey.copyOf()

    val publicKey: ByteArray
        get() = encodedPublicKey.copyOf()

    internal fun keyCopy(): ByteArray = encodedPublicKey.copyOf()

    internal fun matchesPublicKey(candidate: ByteArray): Boolean =
        encodedPublicKey.contentEquals(candidate)

    internal fun clear() {
        encodedPublicKey.fill(0)
    }
}

/** Public state whose complete predecessor chain has been authenticated. */
internal class VerifiedIdentityState(
    ownerNameBytes: ByteArray,
    ownerPublicKey: ByteArray,
    val sequence: BigInteger,
    stateHash: ByteArray,
    predecessorOwnerPublicKey: ByteArray?,
    predecessorStateHash: ByteArray?,
    val generation: BigInteger?,
    val threshold: BigInteger?,
    signerSet: List<VerifiedIdentitySigner>,
    envelopeBytes: ByteArray,
    predecessorEnvelopes: List<ByteArray>,
) {
    private val ownerName = ownerNameBytes.copyOf()
    private val ownerKey = ownerPublicKey.copyOf()
    private val digest = stateHash.copyOf()
    private val predecessorOwnerKey = predecessorOwnerPublicKey?.copyOf()
    private val predecessorDigest = predecessorStateHash?.copyOf()
    private val envelope = envelopeBytes.copyOf()
    private val signers = signerSet.map { VerifiedIdentitySigner(it.signerId, it.keyCopy()) }
    private val ancestors = predecessorEnvelopes.map(ByteArray::copyOf)

    val ownerNameBytes: ByteArray
        get() = ownerName.copyOf()

    val ownerPublicKey: ByteArray
        get() = ownerKey.copyOf()

    val stateHash: ByteArray
        get() = digest.copyOf()

    val predecessorOwnerPublicKey: ByteArray?
        get() = predecessorOwnerKey?.copyOf()

    val predecessorStateHash: ByteArray?
        get() = predecessorDigest?.copyOf()

    val signerSet: List<VerifiedIdentitySigner>
        get() = signers.map { VerifiedIdentitySigner(it.signerId, it.keyCopy()) }

    val envelopeBytes: ByteArray
        get() = envelope.copyOf()

    /** Immediate predecessor first, then progressively older envelopes. */
    val predecessorEnvelopes: List<ByteArray>
        get() = ancestors.map(ByteArray::copyOf)
}

/**
 * Resolves and validates an Identity envelope and its hash-addressed history.
 * History lookups are always by the signed predecessor state hash; each returned
 * envelope is re-hashed and cryptographically checked before it can authorize a
 * successor state.
 */
internal object IdentityStateHistoryVerifier {
    private val ONE = BigInteger.ONE
    private val TWO = BigInteger.valueOf(2)
    private val K1 = BigInteger.ONE
    private val K2 = BigInteger.valueOf(2)
    private val K3 = BigInteger.valueOf(3)
    private val K4 = BigInteger.valueOf(4)
    private val K5 = BigInteger.valueOf(5)
    private val K6 = BigInteger.valueOf(6)
    private val K7 = BigInteger.valueOf(7)
    private const val MAX_PREDECESSOR_DEPTH = 1024
    private const val MAX_SIGNER_ID_BYTES = 256
    private const val MAX_PROOFS = 3
    // Bound retained CBOR independently of the predecessor-link limit.
    private const val MAX_HISTORY_TOTAL_BYTES = 4 * 1024 * 1024

    fun resolve(
        ownerNameBytes: ByteArray,
        headEnvelopeBytes: ByteArray,
        getEnvelopeByStateHash: (ByteArray) -> ByteArray?,
    ): VerifiedIdentityState {
        if (ownerNameBytes.isEmpty()) invalidState()
        IdentityCbor.requireValidUtf8(ownerNameBytes)

        requireHistoryBudget(headEnvelopeBytes.size, 0)
        val newestFirst = ArrayList<ParsedEnvelope>()
        val visitedHashes = HashSet<String>()
        var totalEnvelopeBytes = headEnvelopeBytes.size
        var currentEnvelope = headEnvelopeBytes.copyOf()
        var predecessorLookups = 0
        try {
            while (true) {
                val parsed = parseEnvelope(ownerNameBytes, currentEnvelope)
                if (!visitedHashes.add(stateHashKey(parsed.stateHash))) invalidState()
                newestFirst.add(parsed)

                val authorization = parsed.authorization ?: break
                if (authorization.operation == ONE) break
                if (predecessorLookups >= MAX_PREDECESSOR_DEPTH) invalidState()
                predecessorLookups++

                val requestedHash = authorization.predecessorHash.copyOf()
                val predecessor = try {
                    getEnvelopeByStateHash(requestedHash)
                } finally {
                    requestedHash.fill(0)
                } ?: invalidState()
                try {
                    requireHistoryBudget(predecessor.size, totalEnvelopeBytes)
                    totalEnvelopeBytes += predecessor.size
                    val nextEnvelope = predecessor.copyOf()
                    currentEnvelope.fill(0)
                    currentEnvelope = nextEnvelope
                } finally {
                    predecessor.fill(0)
                }
            }

            var verified: VerifiedState? = null
            for (parsed in newestFirst.asReversed()) {
                verified = verifyTransition(ownerNameBytes, parsed, verified)
            }
            val predecessorEnvelopes = newestFirst.drop(1).map { it.envelopeBytes }
            return publicState(checkNotNull(verified), predecessorEnvelopes)
        } finally {
            currentEnvelope.fill(0)
            newestFirst.forEach(ParsedEnvelope::clear)
        }
    }

    private fun requireHistoryBudget(envelopeBytes: Int, alreadyFetchedBytes: Int) {
        if (envelopeBytes <= 0 || envelopeBytes > IdentityCbor.MAX_ENCODED_BYTES ||
            envelopeBytes > MAX_HISTORY_TOTAL_BYTES - alreadyFetchedBytes
        ) {
            invalidState()
        }
    }

    private fun stateHashKey(hash: ByteArray): String {
        val digits = "0123456789abcdef"
        val characters = CharArray(hash.size * 2)
        hash.forEachIndexed { index, value ->
            val unsigned = value.toInt() and 0xff
            characters[index * 2] = digits[unsigned ushr 4]
            characters[index * 2 + 1] = digits[unsigned and 0x0f]
        }
        return String(characters)
    }

    private fun parseEnvelope(ownerName: ByteArray, envelopeBytes: ByteArray): ParsedEnvelope {
        val outerValue = try {
            IdentityCbor.decodeCanonical(envelopeBytes)
        } catch (_: Exception) {
            invalidState()
        }
        val outer = map(outerValue)
        return when (integerKeys(outer)) {
            setOf(K1, K2) -> parseLegacy(ownerName, outer, envelopeBytes)
            setOf(K1, K2, K3) -> {
                val version = outer[K1]
                if (version != ONE) {
                    if (version is BigInteger && version > ONE) {
                        throw WalletUnsupportedIdentityStateException()
                    }
                    invalidState()
                }
                parseVersionOne(ownerName, outer, envelopeBytes)
            }
            else -> invalidState()
        }
    }

    private fun parseLegacy(
        ownerName: ByteArray,
        outer: Map<BigInteger, Any?>,
        envelopeBytes: ByteArray,
    ): ParsedEnvelope {
        val updateBytes = bytes(outer[K1])
        val signature = bytes(outer[K2], AndroidIdentityCrypto.SIGNATURE_BYTES)
        val decodedUpdate = exactMap(decode(updateBytes), setOf(K1, K2, K3))
        val record = exactMap(decodedUpdate[K1], setOf(K1, K2))
        val envelopeOwner = bytes(record[K1])
        val ownerKey = bytes(record[K2], AndroidIdentityCrypto.KEY_BYTES)
        if (!envelopeOwner.contentEquals(ownerName)) invalidState()
        IdentityCbor.requireValidUtf8(envelopeOwner)
        if (map(decodedUpdate[K2]).isNotEmpty()) invalidState()
        val sequence = uint(decodedUpdate[K3])
        val stateHash = AndroidIdentityCrypto.sha256(updateBytes)
        val valid = try {
            AndroidIdentityCrypto.verify(ownerKey, stateHash, signature)
        } finally {
            stateHash.fill(0)
        }
        if (!valid) invalidState()
        return ParsedEnvelope(
            envelopeBytes = envelopeBytes.copyOf(),
            updateBytes = updateBytes.copyOf(),
            ownerName = envelopeOwner.copyOf(),
            ownerPublicKey = ownerKey.copyOf(),
            sequence = sequence,
            stateHash = AndroidIdentityCrypto.sha256(updateBytes),
            authorization = null,
            proofs = emptyList(),
        )
    }

    private fun parseVersionOne(
        ownerName: ByteArray,
        outer: Map<BigInteger, Any?>,
        envelopeBytes: ByteArray,
    ): ParsedEnvelope {
        val updateBytes = bytes(outer[K2])
        val decodedUpdate = exactMap(decode(updateBytes), setOf(K1, K2, K3, K4))
        val record = exactMap(decodedUpdate[K1], setOf(K1, K2))
        val envelopeOwner = bytes(record[K1])
        val ownerKey = bytes(record[K2], AndroidIdentityCrypto.KEY_BYTES)
        if (!envelopeOwner.contentEquals(ownerName)) invalidState()
        IdentityCbor.requireValidUtf8(envelopeOwner)
        if (map(decodedUpdate[K2]).isNotEmpty()) invalidState()
        val sequence = uint(decodedUpdate[K3])

        val rawAuthorization = exactMap(
            decodedUpdate[K4],
            setOf(K1, K2, K3, K4, K5, K6, K7),
        )
        if (rawAuthorization[K1] != ONE || rawAuthorization[K2] != ONE) invalidState()
        val operation = uint(rawAuthorization[K3])
        if (operation !in listOf(ONE, TWO, BigInteger.valueOf(3), BigInteger.valueOf(4), BigInteger.valueOf(5))) {
            invalidState()
        }
        val generation = uint(rawAuthorization[K4])
        val threshold = uint(rawAuthorization[K5])
        val predecessorHash = bytes(rawAuthorization[K7], AndroidIdentityCrypto.KEY_BYTES)
        val signers = parseSignerSet(rawAuthorization[K6])
        val proofs = parseProofs(outer[K3])
        return ParsedEnvelope(
            envelopeBytes = envelopeBytes.copyOf(),
            updateBytes = updateBytes.copyOf(),
            ownerName = envelopeOwner.copyOf(),
            ownerPublicKey = ownerKey.copyOf(),
            sequence = sequence,
            stateHash = AndroidIdentityCrypto.sha256(updateBytes),
            authorization = Authorization(
                operation = operation,
                generation = generation,
                threshold = threshold,
                predecessorHash = predecessorHash.copyOf(),
            ),
            signers = signers,
            proofs = proofs,
        )
    }

    private fun parseSignerSet(value: Any?): List<VerifiedIdentitySigner> {
        val raw = value as? List<*> ?: invalidState()
        if (raw.size != 3) invalidState()
        val result = ArrayList<VerifiedIdentitySigner>(raw.size)
        var previousId: ByteArray? = null
        for (item in raw) {
            val entry = exactMap(item, setOf(K1, K2))
            val signerId = entry[K1] as? String ?: invalidState()
            val idBytes = try {
                IdentityCbor.encodeUtf8(signerId)
            } catch (_: Exception) {
                invalidState()
            }
            val publicKey = bytes(entry[K2], AndroidIdentityCrypto.KEY_BYTES)
            if (idBytes.isEmpty() || idBytes.size > MAX_SIGNER_ID_BYTES ||
                result.any { it.signerId == signerId || it.matchesPublicKey(publicKey) } ||
                previousId?.let { compareUnsigned(it, idBytes) >= 0 } == true
            ) {
                invalidState()
            }
            previousId = idBytes
            result.add(VerifiedIdentitySigner(signerId, publicKey))
        }
        return result
    }

    private fun parseProofs(value: Any?): List<Proof> {
        val raw = value as? List<*> ?: invalidState()
        if (raw.size > MAX_PROOFS) invalidState()
        val proofs = ArrayList<Proof>(raw.size)
        var previousId = ByteArray(0)
        var first = true
        val seen = HashSet<String?>()
        try {
            for (item in raw) {
                val entry = exactMap(item, setOf(K1, K2))
                val signerId = when (val id = entry[K1]) {
                    null -> null
                    is String -> id
                    else -> invalidState()
                }
                if (!seen.add(signerId)) invalidState()
                val idBytes = if (signerId == null) ByteArray(0) else IdentityCbor.encodeUtf8(signerId)
                try {
                    if (signerId != null && (idBytes.isEmpty() || idBytes.size > MAX_SIGNER_ID_BYTES)) {
                        invalidState()
                    }
                    if (!first && compareUnsigned(previousId, idBytes) >= 0) invalidState()
                    first = false
                    previousId.fill(0)
                    previousId = idBytes.copyOf()
                    proofs.add(Proof(signerId, bytes(entry[K2], AndroidIdentityCrypto.SIGNATURE_BYTES)))
                } finally {
                    idBytes.fill(0)
                }
            }
            return proofs
        } finally {
            previousId.fill(0)
        }
    }

    private fun verifyTransition(
        expectedOwnerName: ByteArray,
        candidate: ParsedEnvelope,
        previous: VerifiedState?,
    ): VerifiedState {
        if (!candidate.ownerName.contentEquals(expectedOwnerName)) invalidState()
        val authorization = candidate.authorization
        if (authorization == null) {
            if (previous != null) invalidState()
            return VerifiedState.from(candidate, null)
        }

        val operation = authorization.operation
        if (operation == ONE) {
            if (previous != null || candidate.sequence != ONE ||
                authorization.generation != ONE || authorization.threshold != TWO ||
                !authorization.predecessorHash.contentEquals(ByteArray(AndroidIdentityCrypto.KEY_BYTES))
            ) {
                invalidState()
            }
            verifyThresholdProofs(candidate, candidate.signers, TWO)
            return VerifiedState.from(candidate, null)
        }

        val predecessor = previous ?: invalidState()
        if (!predecessor.ownerName.contentEquals(candidate.ownerName) ||
            candidate.sequence != predecessor.sequence.add(ONE) ||
            !authorization.predecessorHash.contentEquals(predecessor.stateHash)
        ) {
            invalidState()
        }

        when (operation) {
            TWO -> {
                if (predecessor.signers.isEmpty() ||
                    !candidate.ownerPublicKey.contentEquals(predecessor.ownerPublicKey) ||
                    authorization.generation != predecessor.generation ||
                    authorization.threshold != predecessor.threshold ||
                    !sameSignerSet(candidate.signers, predecessor.signers)
                ) {
                    invalidState()
                }
                verifyThresholdProofs(candidate, predecessor.signers, checkNotNull(predecessor.threshold))
            }
            BigInteger.valueOf(3) -> {
                // Match the Python core: generations must advance, but may skip unused epochs.
                if (predecessor.signers.isEmpty() ||
                    !candidate.ownerPublicKey.contentEquals(predecessor.ownerPublicKey) ||
                    authorization.generation <= checkNotNull(predecessor.generation) ||
                    authorization.threshold != TWO ||
                    sameSignerSet(candidate.signers, predecessor.signers)
                ) {
                    invalidState()
                }
                verifyThresholdProofs(candidate, predecessor.signers, TWO)
            }
            BigInteger.valueOf(4) -> {
                if (predecessor.signers.isNotEmpty() ||
                    !candidate.ownerPublicKey.contentEquals(predecessor.ownerPublicKey) ||
                    authorization.generation != ONE || authorization.threshold != TWO ||
                    !containsPublicKey(candidate.signers, candidate.ownerPublicKey)
                ) {
                    invalidState()
                }
                if (candidate.proofs.size != 1) invalidState()
                val proof = candidate.proofs.single()
                val signerId = proof.signerId ?: invalidState()
                val signer = candidate.signers.singleOrNull { it.signerId == signerId } ?: invalidState()
                if (!signer.matchesPublicKey(candidate.ownerPublicKey) ||
                    !verify(candidate.ownerPublicKey, candidate.updateBytes, proof.signature)
                ) {
                    invalidState()
                }
            }
            BigInteger.valueOf(5) -> {
                if (candidate.ownerPublicKey.contentEquals(predecessor.ownerPublicKey)) invalidState()
                if (predecessor.signers.isEmpty()) {
                    if (authorization.generation != ONE || authorization.threshold != TWO ||
                        !containsPublicKey(candidate.signers, candidate.ownerPublicKey) ||
                        candidate.proofs.size != 1
                    ) {
                        invalidState()
                    }
                    val proof = candidate.proofs.single()
                    if (proof.signerId != null ||
                        !verify(predecessor.ownerPublicKey, candidate.updateBytes, proof.signature)
                    ) {
                        invalidState()
                    }
                } else {
                    if (authorization.generation != predecessor.generation ||
                        authorization.threshold != predecessor.threshold ||
                        !sameSignerSet(candidate.signers, predecessor.signers)
                    ) {
                        invalidState()
                    }
                    verifyThresholdProofs(candidate, predecessor.signers, checkNotNull(predecessor.threshold))
                }
            }
            else -> invalidState()
        }

        return VerifiedState.from(candidate, predecessor)
    }

    private fun verifyThresholdProofs(
        candidate: ParsedEnvelope,
        authorizedSigners: List<VerifiedIdentitySigner>,
        threshold: BigInteger,
    ) {
        val validSigners = HashSet<String>()
        for (proof in candidate.proofs) {
            val signerId = proof.signerId ?: invalidState()
            val signer = authorizedSigners.singleOrNull { it.signerId == signerId } ?: invalidState()
            val publicKey = signer.keyCopy()
            val isValid = try {
                verify(publicKey, candidate.updateBytes, proof.signature)
            } finally {
                publicKey.fill(0)
            }
            if (!isValid) invalidState()
            validSigners.add(signerId)
        }
        if (BigInteger.valueOf(validSigners.size.toLong()) < threshold) invalidState()
    }

    private fun verify(publicKey: ByteArray, updateBytes: ByteArray, signature: ByteArray): Boolean {
        val digest = AndroidIdentityCrypto.sha256(updateBytes)
        return try {
            AndroidIdentityCrypto.verify(publicKey, digest, signature)
        } finally {
            digest.fill(0)
        }
    }

    private fun containsPublicKey(
        signers: List<VerifiedIdentitySigner>,
        publicKey: ByteArray,
    ): Boolean = signers.any { it.matchesPublicKey(publicKey) }

    private fun sameSignerSet(
        left: List<VerifiedIdentitySigner>,
        right: List<VerifiedIdentitySigner>,
    ): Boolean = left.size == right.size && left.indices.all { index ->
        if (left[index].signerId != right[index].signerId) {
            false
        } else {
            val rightKey = right[index].keyCopy()
            try {
                left[index].matchesPublicKey(rightKey)
            } finally {
                rightKey.fill(0)
            }
        }
    }

    private fun publicState(
        state: VerifiedState,
        predecessorEnvelopes: List<ByteArray>,
    ): VerifiedIdentityState = VerifiedIdentityState(
        ownerNameBytes = state.ownerName,
        ownerPublicKey = state.ownerPublicKey,
        sequence = state.sequence,
        stateHash = state.stateHash,
        predecessorOwnerPublicKey = state.predecessorOwnerPublicKey,
        predecessorStateHash = state.predecessorStateHash,
        generation = state.generation,
        threshold = state.threshold,
        signerSet = state.signers,
        envelopeBytes = state.envelopeBytes,
        predecessorEnvelopes = predecessorEnvelopes,
    )

    private fun decode(bytes: ByteArray): Any? = try {
        IdentityCbor.decodeCanonical(bytes)
    } catch (_: Exception) {
        invalidState()
    }

    private fun map(value: Any?): Map<BigInteger, Any?> {
        val raw = value as? Map<*, *> ?: invalidState()
        if (raw.keys.any { it !is BigInteger }) invalidState()
        @Suppress("UNCHECKED_CAST")
        return raw as Map<BigInteger, Any?>
    }

    private fun integerKeys(value: Map<BigInteger, Any?>): Set<BigInteger> = value.keys.toSet()

    private fun exactMap(value: Any?, expected: Set<BigInteger>): Map<BigInteger, Any?> {
        val raw = map(value)
        if (raw.size != expected.size || raw.keys != expected) invalidState()
        return raw
    }

    private fun bytes(value: Any?, length: Int? = null): ByteArray {
        val result = value as? ByteArray ?: invalidState()
        if (length != null && result.size != length) invalidState()
        return result
    }

    private fun uint(value: Any?): BigInteger {
        val result = value as? BigInteger ?: invalidState()
        if (result.signum() < 0) invalidState()
        return result
    }

    private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
        val commonLength = minOf(left.size, right.size)
        for (index in 0 until commonLength) {
            val comparison = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
            if (comparison != 0) return comparison
        }
        return left.size.compareTo(right.size)
    }

    private fun invalidState(): Nothing = throw WalletInvalidIdentityStateException()

    private data class Authorization(
        val operation: BigInteger,
        val generation: BigInteger,
        val threshold: BigInteger,
        val predecessorHash: ByteArray,
    )

    private data class Proof(val signerId: String?, val signature: ByteArray)

    private class ParsedEnvelope(
        val envelopeBytes: ByteArray,
        val updateBytes: ByteArray,
        val ownerName: ByteArray,
        val ownerPublicKey: ByteArray,
        val sequence: BigInteger,
        val stateHash: ByteArray,
        val authorization: Authorization?,
        val signers: List<VerifiedIdentitySigner> = emptyList(),
        val proofs: List<Proof>,
    ) {
        fun clear() {
            envelopeBytes.fill(0)
            updateBytes.fill(0)
            ownerName.fill(0)
            ownerPublicKey.fill(0)
            stateHash.fill(0)
            authorization?.predecessorHash?.fill(0)
            signers.forEach(VerifiedIdentitySigner::clear)
            proofs.forEach { it.signature.fill(0) }
        }
    }

    private class VerifiedState(
        val envelopeBytes: ByteArray,
        val ownerName: ByteArray,
        val ownerPublicKey: ByteArray,
        val sequence: BigInteger,
        val stateHash: ByteArray,
        val predecessorOwnerPublicKey: ByteArray?,
        val predecessorStateHash: ByteArray?,
        val generation: BigInteger?,
        val threshold: BigInteger?,
        val signers: List<VerifiedIdentitySigner>,
    ) {
        companion object {
            fun from(
                candidate: ParsedEnvelope,
                previous: VerifiedState?,
            ): VerifiedState = VerifiedState(
                envelopeBytes = candidate.envelopeBytes.copyOf(),
                ownerName = candidate.ownerName.copyOf(),
                ownerPublicKey = candidate.ownerPublicKey.copyOf(),
                sequence = candidate.sequence,
                stateHash = candidate.stateHash.copyOf(),
                predecessorOwnerPublicKey = previous?.ownerPublicKey?.copyOf(),
                predecessorStateHash = candidate.authorization?.predecessorHash?.copyOf(),
                generation = candidate.authorization?.generation,
                threshold = candidate.authorization?.threshold,
                signers = candidate.signers.map { VerifiedIdentitySigner(it.signerId, it.keyCopy()) },
            )
        }
    }
}

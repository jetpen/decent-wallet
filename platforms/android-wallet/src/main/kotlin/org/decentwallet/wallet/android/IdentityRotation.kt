package org.decentwallet.wallet.android

import java.math.BigInteger

class IdentityRotationSigner(
    val signerId: String,
    publicKey: ByteArray,
) {
    private val encodedPublicKey = publicKey.copyOf()

    val publicKey: ByteArray
        get() = encodedPublicKey.copyOf()

    internal fun publicKeyCopy(): ByteArray = encodedPublicKey.copyOf()
}

class OwnerKeyRotationDraft internal constructor(
    ownerNameBytes: ByteArray,
    predecessorOwnerPublicKey: ByteArray,
    successorOwnerPublicKey: ByteArray,
    predecessorStateHash: ByteArray,
    val sequence: BigInteger,
    signedUpdateBytes: ByteArray,
    envelopeBytes: ByteArray,
) {
    private val ownerName = ownerNameBytes.copyOf()
    private val predecessorOwner = predecessorOwnerPublicKey.copyOf()
    private val successorOwner = successorOwnerPublicKey.copyOf()
    private val previousHash = predecessorStateHash.copyOf()
    private val update = signedUpdateBytes.copyOf()
    private val envelope = envelopeBytes.copyOf()

    val ownerNameBytes: ByteArray
        get() = ownerName.copyOf()

    val predecessorOwnerPublicKey: ByteArray
        get() = predecessorOwner.copyOf()

    val successorOwnerPublicKey: ByteArray
        get() = successorOwner.copyOf()

    val predecessorStateHash: ByteArray
        get() = previousHash.copyOf()

    val signedUpdateBytes: ByteArray
        get() = update.copyOf()

    val envelopeBytes: ByteArray
        get() = envelope.copyOf()
}

/** Public detached signature supplied by one verified predecessor signer. */
class OwnerKeyRotationProof(
    val signerId: String,
    signature: ByteArray,
) {
    private val encodedSignature = signature.copyOf()

    init {
        val idBytes = try {
            IdentityCbor.encodeUtf8(signerId)
        } catch (_: Exception) {
            throw WalletInvalidIdentityStateException()
        }
        if (idBytes.isEmpty() || idBytes.size > 256 ||
            encodedSignature.size != AndroidIdentityCrypto.SIGNATURE_BYTES
        ) {
            throw WalletInvalidIdentityStateException()
        }
        idBytes.fill(0)
    }

    val signature: ByteArray
        get() = encodedSignature.copyOf()

    internal fun signatureCopy(): ByteArray = encodedSignature.copyOf()
}

/** A version-1 operation-5 update awaiting detached predecessor-signer proofs. */
class VersionedOwnerKeyRotationDraft internal constructor(
    ownerNameBytes: ByteArray,
    predecessorOwnerPublicKey: ByteArray,
    successorOwnerPublicKey: ByteArray,
    predecessorStateHash: ByteArray,
    val sequence: BigInteger,
    signedUpdateBytes: ByteArray,
    authorizedSigners: List<IdentityRotationSigner>,
    val threshold: Int,
) {
    private val ownerName = ownerNameBytes.copyOf()
    private val predecessorOwner = predecessorOwnerPublicKey.copyOf()
    private val successorOwner = successorOwnerPublicKey.copyOf()
    private val previousHash = predecessorStateHash.copyOf()
    private val update = signedUpdateBytes.copyOf()
    private val signers = authorizedSigners.map { signer ->
        val publicKey = signer.publicKeyCopy()
        try {
            IdentityRotationSigner(signer.signerId, publicKey)
        } finally {
            publicKey.fill(0)
        }
    }

    val ownerNameBytes: ByteArray
        get() = ownerName.copyOf()

    val predecessorOwnerPublicKey: ByteArray
        get() = predecessorOwner.copyOf()

    val successorOwnerPublicKey: ByteArray
        get() = successorOwner.copyOf()

    val predecessorStateHash: ByteArray
        get() = previousHash.copyOf()

    val signedUpdateBytes: ByteArray
        get() = update.copyOf()

    val authorizedSigners: List<IdentityRotationSigner>
        get() = signers.map { signer ->
            val publicKey = signer.publicKeyCopy()
            try {
                IdentityRotationSigner(signer.signerId, publicKey)
            } finally {
                publicKey.fill(0)
            }
        }

    fun finalizeWithProofs(proofs: List<OwnerKeyRotationProof>): OwnerKeyRotationDraft {
        if (proofs.isEmpty() || proofs.size > signers.size || threshold !in 1..signers.size) {
            throw WalletInvalidIdentityStateException()
        }
        val signerMap = signers.associateBy(IdentityRotationSigner::signerId)
        val orderedProofs = proofs.sortedWith { left, right ->
            val leftBytes = IdentityCbor.encodeUtf8(left.signerId)
            val rightBytes = IdentityCbor.encodeUtf8(right.signerId)
            try {
                compareUnsigned(leftBytes, rightBytes)
            } finally {
                leftBytes.fill(0)
                rightBytes.fill(0)
            }
        }
        val seen = HashSet<String>()
        val digest = AndroidIdentityCrypto.sha256(update)
        val proofValues = ArrayList<Map<BigInteger, Any?>>(orderedProofs.size)
        try {
            for (proof in orderedProofs) {
                if (!seen.add(proof.signerId)) throw WalletInvalidIdentityStateException()
                val signer = signerMap[proof.signerId] ?: throw WalletInvalidIdentityStateException()
                val publicKey = signer.publicKeyCopy()
                val signature = proof.signatureCopy()
                val valid = try {
                    AndroidIdentityCrypto.verify(publicKey, digest, signature)
                } finally {
                    publicKey.fill(0)
                    signature.fill(0)
                }
                if (!valid) throw WalletInvalidIdentityStateException()
                val encodedSignature = proof.signatureCopy()
                proofValues.add(
                    linkedMapOf(
                        BigInteger.ONE to proof.signerId,
                        BigInteger.valueOf(2) to encodedSignature,
                    ),
                )
            }
            if (seen.size < threshold) throw WalletInvalidIdentityStateException()
            val envelope = IdentityCbor.encodeCanonical(
                linkedMapOf<BigInteger, Any?>(
                    BigInteger.ONE to BigInteger.ONE,
                    BigInteger.valueOf(2) to update,
                    BigInteger.valueOf(3) to proofValues,
                ),
            )
            return try {
                OwnerKeyRotationDraft(
                    ownerNameBytes = ownerName,
                    predecessorOwnerPublicKey = predecessorOwner,
                    successorOwnerPublicKey = successorOwner,
                    predecessorStateHash = previousHash,
                    sequence = sequence,
                    signedUpdateBytes = update,
                    envelopeBytes = envelope,
                )
            } finally {
                envelope.fill(0)
            }
        } finally {
            digest.fill(0)
            proofValues.forEach { value ->
                (value[BigInteger.valueOf(2)] as? ByteArray)?.fill(0)
            }
        }
    }
}

internal object VersionedOwnerKeyRotation {
    private val ONE = BigInteger.ONE
    private val TWO = BigInteger.valueOf(2)
    private val FIVE = BigInteger.valueOf(5)
    private val K1 = BigInteger.ONE
    private val K2 = BigInteger.valueOf(2)
    private val K3 = BigInteger.valueOf(3)
    private val K4 = BigInteger.valueOf(4)
    private val K5 = BigInteger.valueOf(5)
    private val K6 = BigInteger.valueOf(6)
    private val K7 = BigInteger.valueOf(7)

    fun createDraft(
        ownerNameBytes: ByteArray,
        predecessorState: VerifiedIdentityState,
        activeOwnerPublicKey: ByteArray,
        pendingSeed: ByteArray,
        pendingPublicKey: ByteArray,
    ): VersionedOwnerKeyRotationDraft {
        val verifiedOwnerName = predecessorState.ownerNameBytes
        val predecessorOwner = predecessorState.ownerPublicKey
        val predecessorHash = predecessorState.stateHash
        val generation = predecessorState.generation
        val threshold = predecessorState.threshold
        val verifiedSigners = predecessorState.signerSet
        var update: ByteArray? = null
        var digest: ByteArray? = null
        var proofOfPossession: ByteArray? = null
        var signerValues: List<Map<BigInteger, Any?>> = emptyList()
        try {
            if (verifiedSigners.isEmpty() || generation == null || threshold == null ||
                threshold.signum() <= 0 || threshold > BigInteger.valueOf(verifiedSigners.size.toLong()) ||
                !ownerNameBytes.contentEquals(verifiedOwnerName) ||
                !activeOwnerPublicKey.contentEquals(predecessorOwner) ||
                AndroidIdentityCrypto.equalPublicKeys(activeOwnerPublicKey, pendingPublicKey)
            ) {
                throw WalletInvalidIdentityStateException()
            }
            signerValues = verifiedSigners.map { signer ->
                val publicKey = signer.publicKey
                linkedMapOf(K1 to signer.signerId, K2 to publicKey)
            }
            val authorization = linkedMapOf<BigInteger, Any?>(
                K1 to ONE,
                K2 to ONE,
                K3 to FIVE,
                K4 to generation,
                K5 to threshold,
                K6 to signerValues,
                K7 to predecessorHash,
            )
            val sequence = predecessorState.sequence.add(ONE)
            update = IdentityCbor.encodeCanonical(
                linkedMapOf(
                    K1 to linkedMapOf(K1 to ownerNameBytes, K2 to pendingPublicKey),
                    K2 to emptyMap<BigInteger, Any?>(),
                    K3 to sequence,
                    K4 to authorization,
                ),
            )
            digest = AndroidIdentityCrypto.sha256(checkNotNull(update))
            proofOfPossession = AndroidIdentityCrypto.sign(pendingSeed, checkNotNull(digest))
            if (!AndroidIdentityCrypto.verify(pendingPublicKey, checkNotNull(digest), checkNotNull(proofOfPossession))) {
                throw WalletInvalidIdentityStateException()
            }
            val signers = verifiedSigners.map { signer ->
                val publicKey = signer.publicKey
                try {
                    IdentityRotationSigner(signer.signerId, publicKey)
                } finally {
                    publicKey.fill(0)
                }
            }
            return VersionedOwnerKeyRotationDraft(
                ownerNameBytes = ownerNameBytes,
                predecessorOwnerPublicKey = predecessorOwner,
                successorOwnerPublicKey = pendingPublicKey,
                predecessorStateHash = predecessorHash,
                sequence = sequence,
                signedUpdateBytes = checkNotNull(update),
                authorizedSigners = signers,
                threshold = threshold.toInt(),
            )
        } catch (failure: WalletContainerException) {
            throw failure
        } catch (_: Exception) {
            throw WalletInvalidIdentityStateException()
        } finally {
            verifiedOwnerName.fill(0)
            predecessorOwner.fill(0)
            predecessorHash.fill(0)
            update?.fill(0)
            digest?.fill(0)
            proofOfPossession?.fill(0)
            signerValues.forEach { (it[K2] as? ByteArray)?.fill(0) }
            verifiedSigners.forEach(VerifiedIdentitySigner::clear)
        }
    }
}

private fun compareUnsigned(left: ByteArray, right: ByteArray): Int {
    val commonLength = minOf(left.size, right.size)
    for (index in 0 until commonLength) {
        val comparison = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
        if (comparison != 0) return comparison
    }
    return left.size.compareTo(right.size)
}

internal object LegacyOwnerKeyRotation {
    private const val MAX_SIGNER_ID_BYTES = 256
    private val ONE = BigInteger.ONE
    private val TWO = BigInteger.valueOf(2)
    private val FIVE = BigInteger.valueOf(5)
    private val K1 = BigInteger.ONE
    private val K2 = BigInteger.valueOf(2)
    private val K3 = BigInteger.valueOf(3)
    private val K4 = BigInteger.valueOf(4)
    private val K5 = BigInteger.valueOf(5)
    private val K6 = BigInteger.valueOf(6)
    private val K7 = BigInteger.valueOf(7)

    fun createDraft(
        ownerNameBytes: ByteArray,
        predecessorEnvelopeBytes: ByteArray,
        activeSeed: ByteArray,
        activePublicKey: ByteArray,
        pendingSeed: ByteArray,
        pendingPublicKey: ByteArray,
        successorSigners: List<IdentityRotationSigner>,
    ): OwnerKeyRotationDraft {
        if (ownerNameBytes.isEmpty()) invalidIdentityState()
        IdentityCbor.requireValidUtf8(ownerNameBytes)
        val predecessor = parseLegacyPredecessor(predecessorEnvelopeBytes)
        if (!predecessor.ownerName.contentEquals(ownerNameBytes)) invalidIdentityState()
        if (!AndroidIdentityCrypto.equalPublicKeys(predecessor.ownerPublicKey, activePublicKey)) {
            invalidIdentityState()
        }
        if (AndroidIdentityCrypto.equalPublicKeys(activePublicKey, pendingPublicKey)) {
            invalidIdentityState()
        }
        val signerEntries = validateSuccessorSigners(successorSigners, pendingPublicKey)
        val sequence = predecessor.sequence.add(ONE)
        val authorization = linkedMapOf<BigInteger, Any?>(
            K1 to ONE,
            K2 to ONE,
            K3 to FIVE,
            K4 to ONE,
            K5 to TWO,
            K6 to signerEntries.map { signer ->
                linkedMapOf<BigInteger, Any?>(
                    K1 to signer.signerId,
                    K2 to signer.publicKey,
                )
            },
            K7 to predecessor.stateHash,
        )
        val signedUpdate = IdentityCbor.encodeCanonical(
            linkedMapOf(
                K1 to linkedMapOf(K1 to ownerNameBytes, K2 to pendingPublicKey),
                K2 to emptyMap<BigInteger, Any?>(),
                K3 to sequence,
                K4 to authorization,
            ),
        )
        var digest: ByteArray? = null
        var proofOfPossession: ByteArray? = null
        var predecessorProof: ByteArray? = null
        var envelope: ByteArray? = null
        try {
            val updateDigest = AndroidIdentityCrypto.sha256(signedUpdate)
            digest = updateDigest
            proofOfPossession = AndroidIdentityCrypto.sign(pendingSeed, updateDigest)
            if (!AndroidIdentityCrypto.verify(pendingPublicKey, updateDigest, checkNotNull(proofOfPossession))) {
                invalidIdentityState()
            }
            predecessorProof = AndroidIdentityCrypto.sign(activeSeed, updateDigest)
            val proof = linkedMapOf<BigInteger, Any?>(K1 to null, K2 to predecessorProof)
            envelope = IdentityCbor.encodeCanonical(
                linkedMapOf(K1 to ONE, K2 to signedUpdate, K3 to listOf(proof)),
            )
            return OwnerKeyRotationDraft(
                ownerNameBytes = ownerNameBytes,
                predecessorOwnerPublicKey = predecessor.ownerPublicKey,
                successorOwnerPublicKey = pendingPublicKey,
                predecessorStateHash = predecessor.stateHash,
                sequence = sequence,
                signedUpdateBytes = signedUpdate,
                envelopeBytes = checkNotNull(envelope),
            )
        } finally {
            digest?.fill(0)
            proofOfPossession?.fill(0)
            predecessorProof?.fill(0)
            envelope?.fill(0)
            signedUpdate.fill(0)
            predecessor.stateHash.fill(0)
        }
    }

    internal fun parseLegacyPredecessor(envelopeBytes: ByteArray): LegacyPredecessor {
        val outer = IdentityCbor.decodeCanonical(envelopeBytes) as? Map<*, *> ?: invalidIdentityState()
        val keys = integerKeys(outer)
        if (keys == setOf(ONE, K2, K3)) {
            val version = outer[ONE]
            if (version is BigInteger && version.signum() >= 0) {
                throw WalletUnsupportedIdentityStateException()
            }
            invalidIdentityState()
        }
        val envelope = exactMap(outer, setOf(ONE, K2))
        val updateBytes = envelope[ONE] as? ByteArray ?: invalidIdentityState()
        val signature = envelope[K2] as? ByteArray ?: invalidIdentityState()
        if (signature.size != AndroidIdentityCrypto.SIGNATURE_BYTES) invalidIdentityState()
        val update = IdentityCbor.decodeCanonical(updateBytes) as? Map<*, *> ?: invalidIdentityState()
        val decodedUpdate = exactMap(update, setOf(ONE, K2, K3))
        val record = exactMap(decodedUpdate[ONE], setOf(ONE, K2))
        val ownerName = record[ONE] as? ByteArray ?: invalidIdentityState()
        val ownerPublicKey = record[K2] as? ByteArray ?: invalidIdentityState()
        if (ownerPublicKey.size != AndroidIdentityCrypto.KEY_BYTES) invalidIdentityState()
        IdentityCbor.requireValidUtf8(ownerName)
        val payload = decodedUpdate[K2] as? Map<*, *> ?: invalidIdentityState()
        if (payload.isNotEmpty()) invalidIdentityState()
        val sequence = decodedUpdate[K3] as? BigInteger ?: invalidIdentityState()
        if (sequence.signum() < 0) invalidIdentityState()
        val digest = AndroidIdentityCrypto.sha256(updateBytes)
        val valid = try {
            AndroidIdentityCrypto.verify(ownerPublicKey, digest, signature)
        } finally {
            digest.fill(0)
        }
        if (!valid) invalidIdentityState()
        return LegacyPredecessor(
            ownerName = ownerName.copyOf(),
            ownerPublicKey = ownerPublicKey.copyOf(),
            sequence = sequence,
            stateHash = AndroidIdentityCrypto.sha256(updateBytes),
        )
    }

    fun verifyLegacyCandidate(
        predecessorEnvelopeBytes: ByteArray,
        candidateEnvelopeBytes: ByteArray,
        intent: OwnerKeyRotationDispatchIntent,
    ): ByteArray {
        val predecessor = parseLegacyPredecessor(predecessorEnvelopeBytes)
        try {
            val outer = IdentityCbor.decodeCanonical(candidateEnvelopeBytes) as? Map<*, *>
                ?: invalidIdentityState()
            val envelope = exactMap(outer, setOf(ONE, K2, K3))
            if (envelope[ONE] != ONE) invalidIdentityState()
            val updateBytes = envelope[K2] as? ByteArray ?: invalidIdentityState()
            val proofs = envelope[K3] as? List<*> ?: invalidIdentityState()
            if (proofs.size != 1) invalidIdentityState()
            val proof = exactMap(proofs.single(), setOf(ONE, K2))
            if (proof[ONE] != null) invalidIdentityState()
            val signature = proof[K2] as? ByteArray ?: invalidIdentityState()
            if (signature.size != AndroidIdentityCrypto.SIGNATURE_BYTES) invalidIdentityState()

            val update = IdentityCbor.decodeCanonical(updateBytes) as? Map<*, *>
                ?: invalidIdentityState()
            val decoded = exactMap(update, setOf(ONE, K2, K3, K4))
            val record = exactMap(decoded[ONE], setOf(ONE, K2))
            val ownerName = record[ONE] as? ByteArray ?: invalidIdentityState()
            val successorPublicKey = record[K2] as? ByteArray ?: invalidIdentityState()
            if (successorPublicKey.size != AndroidIdentityCrypto.KEY_BYTES) invalidIdentityState()
            IdentityCbor.requireValidUtf8(ownerName)
            val payload = decoded[K2] as? Map<*, *> ?: invalidIdentityState()
            if (payload.isNotEmpty()) invalidIdentityState()
            val sequence = decoded[K3] as? BigInteger ?: invalidIdentityState()
            val authorization = exactMap(decoded[K4], setOf(ONE, K2, K3, K4, K5, K6, K7))
            if (authorization[ONE] != ONE || authorization[K2] != ONE ||
                authorization[K3] != FIVE || authorization[K4] != ONE || authorization[K5] != TWO
            ) {
                invalidIdentityState()
            }
            val predecessorHash = authorization[K7] as? ByteArray ?: invalidIdentityState()
            val signerValues = authorization[K6] as? List<*> ?: invalidIdentityState()
            if (signerValues.size != 3) invalidIdentityState()
            val signerIds = HashSet<String>()
            val signerKeys = ArrayList<ByteArray>(3)
            var previousIdBytes: ByteArray? = null
            for (value in signerValues) {
                val signer = exactMap(value, setOf(ONE, K2))
                val signerId = signer[ONE] as? String ?: invalidIdentityState()
                val signerIdBytes = IdentityCbor.encodeUtf8(signerId)
                if (signerIdBytes.isEmpty() || signerIdBytes.size > MAX_SIGNER_ID_BYTES ||
                    !signerIds.add(signerId)
                ) {
                    invalidIdentityState()
                }
                if (previousIdBytes != null && compareUtf8(previousIdBytes, signerIdBytes) >= 0) {
                    invalidIdentityState()
                }
                previousIdBytes = signerIdBytes
                val signerPublicKey = signer[K2] as? ByteArray ?: invalidIdentityState()
                if (signerPublicKey.size != AndroidIdentityCrypto.KEY_BYTES ||
                    signerKeys.any { AndroidIdentityCrypto.equalPublicKeys(it, signerPublicKey) }
                ) {
                    invalidIdentityState()
                }
                signerKeys.add(signerPublicKey)
            }
            if (signerKeys.none { AndroidIdentityCrypto.equalPublicKeys(it, successorPublicKey) }) {
                invalidIdentityState()
            }

            val envelopeHash = AndroidIdentityCrypto.sha256(candidateEnvelopeBytes)
            val updateDigest = AndroidIdentityCrypto.sha256(updateBytes)
            try {
                if (!ownerName.contentEquals(intent.ownerNameBytes) ||
                    !successorPublicKey.contentEquals(intent.successorOwnerPublicKey) ||
                    !predecessor.ownerName.contentEquals(intent.ownerNameBytes) ||
                    !predecessor.ownerPublicKey.contentEquals(intent.predecessorOwnerPublicKey) ||
                    !predecessor.stateHash.contentEquals(intent.predecessorStateHash) ||
                    !predecessorHash.contentEquals(intent.predecessorStateHash) ||
                    sequence != intent.sequence || sequence != predecessor.sequence.add(ONE) ||
                    !envelopeHash.contentEquals(intent.envelopeHash) ||
                    !AndroidIdentityCrypto.verify(predecessor.ownerPublicKey, updateDigest, signature)
                ) {
                    invalidIdentityState()
                }
                return updateDigest.copyOf()
            } finally {
                envelopeHash.fill(0)
                updateDigest.fill(0)
            }
        } finally {
            predecessor.ownerName.fill(0)
            predecessor.ownerPublicKey.fill(0)
            predecessor.stateHash.fill(0)
        }
    }

    private fun validateSuccessorSigners(
        signers: List<IdentityRotationSigner>,
        successorOwnerPublicKey: ByteArray,
    ): List<SignerEntry> {
        if (signers.size != 3) invalidIdentityState()
        val entries = signers.map { signer ->
            val idBytes = IdentityCbor.encodeUtf8(signer.signerId)
            if (idBytes.isEmpty() || idBytes.size > MAX_SIGNER_ID_BYTES) invalidIdentityState()
            val publicKey = signer.publicKeyCopy()
            if (publicKey.size != AndroidIdentityCrypto.KEY_BYTES) invalidIdentityState()
            SignerEntry(signer.signerId, idBytes, publicKey)
        }
        for (left in entries.indices) {
            for (right in left + 1 until entries.size) {
                if (entries[left].signerId == entries[right].signerId ||
                    AndroidIdentityCrypto.equalPublicKeys(entries[left].publicKey, entries[right].publicKey)
                ) {
                    invalidIdentityState()
                }
            }
        }
        if (entries.none { AndroidIdentityCrypto.equalPublicKeys(it.publicKey, successorOwnerPublicKey) }) {
            invalidIdentityState()
        }
        return entries.sortedWith { left, right -> compareUtf8(left.idBytes, right.idBytes) }
    }

    private fun exactMap(value: Any?, expectedKeys: Set<BigInteger>): Map<BigInteger, Any?> {
        val map = value as? Map<*, *> ?: invalidIdentityState()
        if (integerKeys(map) != expectedKeys) invalidIdentityState()
        @Suppress("UNCHECKED_CAST")
        return map as Map<BigInteger, Any?>
    }

    private fun integerKeys(value: Map<*, *>): Set<BigInteger> {
        val keys = value.keys.map { it as? BigInteger ?: invalidIdentityState() }
        return keys.toSet()
    }

    private fun compareUtf8(left: ByteArray, right: ByteArray): Int {
        val commonLength = minOf(left.size, right.size)
        for (index in 0 until commonLength) {
            val comparison = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
            if (comparison != 0) return comparison
        }
        return left.size.compareTo(right.size)
    }

    private fun invalidIdentityState(): Nothing = throw WalletInvalidIdentityStateException()

    internal data class LegacyPredecessor(
        val ownerName: ByteArray,
        val ownerPublicKey: ByteArray,
        val sequence: BigInteger,
        val stateHash: ByteArray,
    )

    private data class SignerEntry(
        val signerId: String,
        val idBytes: ByteArray,
        val publicKey: ByteArray,
    )
}

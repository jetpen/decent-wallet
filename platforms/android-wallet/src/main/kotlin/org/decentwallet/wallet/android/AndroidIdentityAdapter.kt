package org.decentwallet.wallet.android

import java.math.BigInteger
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Public-only Registry boundary. Implementations must make conditional writes against the exact
 * predecessor state hash and must make getRemoteIdentityEnvelope bypass local caches. Byte-array
 * inputs are defensive copies and must be treated as read-only; returned arrays may be retained by
 * the implementation because the adapter copies them before inspection.
 */
interface AndroidIdentityTransport {
    /** Stable environment identifier, e.g. `mainnet` or `testnet`; empty disables rotation. */
    val registryEnvironment: String
        get() = ""

    /** Opt in only when conditional operation-5 publication and remote readback are supported. */
    val supportsOwnerKeyRotation: Boolean
        get() = false

    fun getIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray?

    fun getIdentityEnvelopeByHash(ownerNameBytes: ByteArray, stateHash: ByteArray): ByteArray?

    /** Return a fresh remote read, not a retained local head or a write-through cache. */
    fun getRemoteIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray?

    /**
     * Publish only if the current accepted state still has expectedStateHash. The transport must
     * throw AndroidIdentityPreconditionFailedException or AndroidIdentityWriteExpiredException
     * only when it can prove this call did not write; all other failures are ambiguous. A
     * precondition failure is not global evidence that another wallet copy did not publish.
     */
    fun putIdentityEnvelopeIfCurrent(
        ownerNameBytes: ByteArray,
        envelopeBytes: ByteArray,
        expectedStateHash: ByteArray,
        expiresAt: Long,
    )
}

class AndroidIdentityPreconditionFailedException : Exception()

class AndroidIdentityWriteExpiredException : Exception()

fun interface AndroidIdentityReplayNonceStore {
    /**
     * Atomically consume a digest once; implementations must not retain the raw consent nonce.
     * Production hosts must persist consumed digests across process restarts.
     */
    fun consume(nonceDigest: ByteArray): Boolean
}

class OwnerKeyRotationConsentTranscript internal constructor(
    ownerNameBytes: ByteArray,
    predecessorStateHash: ByteArray,
    successorOwnerPublicKey: ByteArray,
    envelopeBytes: ByteArray,
    envelopeHash: ByteArray,
    replayNonce: ByteArray,
    val sequence: BigInteger,
    val authenticatedOrigin: String,
    val environment: String,
    val purpose: String,
    val capability: String,
    val expiresAt: Long,
) {
    private val ownerName = ownerNameBytes.copyOf()
    private val predecessorHash = predecessorStateHash.copyOf()
    private val successorPublic = successorOwnerPublicKey.copyOf()
    private val reviewedEnvelope = envelopeBytes.copyOf()
    private val reviewedHash = envelopeHash.copyOf()
    private val nonce = replayNonce.copyOf()

    init {
        val actualHash = AndroidIdentityCrypto.sha256(reviewedEnvelope)
        try {
            if (actualHash.size != reviewedHash.size || !actualHash.contentEquals(reviewedHash) ||
                sequence.signum() <= 0 || expiresAt <= 0
            ) {
                throw WalletInvalidIdentityStateException()
            }
        } finally {
            actualHash.fill(0)
        }
    }

    val operation: String = "owner-key-rotation"
    val generation: BigInteger = BigInteger.ONE
    val payloadHash: ByteArray
        get() = reviewedHash.copyOf()
    val ownerNameBytes: ByteArray
        get() = ownerName.copyOf()
    val predecessorStateHash: ByteArray
        get() = predecessorHash.copyOf()
    val successorOwnerPublicKey: ByteArray
        get() = successorPublic.copyOf()
    val reviewEnvelopeBytes: ByteArray
        get() = reviewedEnvelope.copyOf()
    val envelopeHash: ByteArray
        get() = reviewedHash.copyOf()
    val replayNonce: ByteArray
        get() = nonce.copyOf()

    fun canonicalBytes(): ByteArray = IdentityCbor.encodeCanonical(
        linkedMapOf<BigInteger, Any?>(
            BigInteger.ONE to authenticatedOrigin,
            BigInteger.valueOf(2) to environment,
            BigInteger.valueOf(3) to operation,
            BigInteger.valueOf(4) to reviewedHash,
            BigInteger.valueOf(5) to purpose,
            BigInteger.valueOf(6) to capability,
            BigInteger.valueOf(7) to BigInteger.valueOf(expiresAt),
            BigInteger.valueOf(8) to nonce,
            BigInteger.valueOf(9) to sequence,
            BigInteger.valueOf(10) to generation,
            BigInteger.valueOf(13) to reviewedEnvelope,
        ),
    )

    fun digest(): ByteArray {
        val canonical = canonicalBytes()
        return try {
            AndroidIdentityCrypto.sha256(canonical)
        } finally {
            canonical.fill(0)
        }
    }
}

class OwnerKeyRotationDispatchIntent internal constructor(
    ownerNameBytes: ByteArray,
    predecessorOwnerPublicKey: ByteArray,
    successorOwnerPublicKey: ByteArray,
    predecessorStateHash: ByteArray,
    val sequence: BigInteger,
    val environment: String,
    envelopeHash: ByteArray,
) {
    private val ownerName = ownerNameBytes.copyOf()
    private val predecessorPublic = predecessorOwnerPublicKey.copyOf()
    private val successorPublic = successorOwnerPublicKey.copyOf()
    private val predecessorHash = predecessorStateHash.copyOf()
    private val candidateHash = envelopeHash.copyOf()

    init {
        if (ownerName.isEmpty() || ownerName.size > IdentityCbor.MAX_ENCODED_BYTES ||
            predecessorPublic.size != AndroidIdentityCrypto.KEY_BYTES ||
            successorPublic.size != AndroidIdentityCrypto.KEY_BYTES ||
            predecessorHash.size != AndroidIdentityCrypto.KEY_BYTES ||
            candidateHash.size != AndroidIdentityCrypto.KEY_BYTES || sequence.signum() <= 0 ||
            environment.isBlank() || environment.length > 256
        ) {
            throw WalletInvalidIdentityStateException()
        }
        IdentityCbor.requireValidUtf8(ownerName)
    }

    val ownerNameBytes: ByteArray
        get() = ownerName.copyOf()
    val predecessorOwnerPublicKey: ByteArray
        get() = predecessorPublic.copyOf()
    val successorOwnerPublicKey: ByteArray
        get() = successorPublic.copyOf()
    val predecessorStateHash: ByteArray
        get() = predecessorHash.copyOf()
    val envelopeHash: ByteArray
        get() = candidateHash.copyOf()

    internal fun toPayload(): Map<String, Any?> = linkedMapOf(
        "owner_name" to ownerName.copyOf(),
        "predecessor_owner_public_key" to predecessorPublic.copyOf(),
        "successor_owner_public_key" to successorPublic.copyOf(),
        "predecessor_state_hash" to predecessorHash.copyOf(),
        "sequence" to sequence,
        "environment" to environment,
        "envelope_hash" to candidateHash.copyOf(),
    )

    override fun equals(other: Any?): Boolean = other is OwnerKeyRotationDispatchIntent &&
        ownerName.contentEquals(other.ownerName) &&
        predecessorPublic.contentEquals(other.predecessorPublic) &&
        successorPublic.contentEquals(other.successorPublic) &&
        predecessorHash.contentEquals(other.predecessorHash) &&
        sequence == other.sequence && environment == other.environment &&
        candidateHash.contentEquals(other.candidateHash)

    override fun hashCode(): Int {
        var result = ownerName.contentHashCode()
        result = 31 * result + predecessorPublic.contentHashCode()
        result = 31 * result + successorPublic.contentHashCode()
        result = 31 * result + predecessorHash.contentHashCode()
        result = 31 * result + sequence.hashCode()
        result = 31 * result + environment.hashCode()
        result = 31 * result + candidateHash.contentHashCode()
        return result
    }

    override fun toString(): String = "OwnerKeyRotationDispatchIntent(sequence=$sequence)"

    internal companion object {
        private val EXPECTED_KEYS = setOf(
            "owner_name",
            "predecessor_owner_public_key",
            "successor_owner_public_key",
            "predecessor_state_hash",
            "sequence",
            "environment",
            "envelope_hash",
        )

        fun fromPayload(value: Any?): OwnerKeyRotationDispatchIntent {
            val map = value as? Map<*, *> ?: throw WalletInvalidContainerException()
            if (map.keys != EXPECTED_KEYS) throw WalletInvalidContainerException()
            val sequence = map["sequence"] as? BigInteger ?: throw WalletInvalidContainerException()
            return try {
                OwnerKeyRotationDispatchIntent(
                    ownerNameBytes = map["owner_name"] as? ByteArray ?: throw WalletInvalidContainerException(),
                    predecessorOwnerPublicKey = map["predecessor_owner_public_key"] as? ByteArray
                        ?: throw WalletInvalidContainerException(),
                    successorOwnerPublicKey = map["successor_owner_public_key"] as? ByteArray
                        ?: throw WalletInvalidContainerException(),
                    predecessorStateHash = map["predecessor_state_hash"] as? ByteArray
                        ?: throw WalletInvalidContainerException(),
                    sequence = sequence,
                    environment = map["environment"] as? String ?: throw WalletInvalidContainerException(),
                    envelopeHash = map["envelope_hash"] as? ByteArray ?: throw WalletInvalidContainerException(),
                )
            } catch (failure: WalletContainerException) {
                throw failure
            } catch (_: Exception) {
                throw WalletInvalidContainerException()
            }
        }
    }
}

enum class OwnerKeyRotationDispatchStatus {
    CONFIRMED,
    UNKNOWN,
    STALE,
    EXPIRED,
    FAILED,
}

class OwnerKeyRotationDispatchResult internal constructor(
    val status: OwnerKeyRotationDispatchStatus,
    val confirmation: OwnerKeyRotationConfirmation? = null,
    val rejection: OwnerKeyRotationDispatchRejection? = null,
)

class OwnerKeyRotationPublication internal constructor(
    val intent: OwnerKeyRotationDispatchIntent,
    envelopeBytes: ByteArray,
    predecessorEnvelopeBytes: ByteArray,
    val expiresAt: Long,
    private val seal: Any,
) {
    private val envelope = envelopeBytes.copyOf()
    private val predecessorEnvelope = predecessorEnvelopeBytes.copyOf()
    private val latchClaimed = AtomicBoolean(false)
    private val dispatchStarted = AtomicBoolean(false)
    @Volatile
    private var permit: OwnerKeyRotationDispatchPermit? = null

    val envelopeBytes: ByteArray
        get() = envelope.copyOf()

    internal fun predecessorEnvelopeBytes(): ByteArray = predecessorEnvelope.copyOf()

    internal fun isAuthentic(): Boolean = seal === OwnerKeyRotationTokenAuthority.seal

    internal fun claimLatch(): Boolean = latchClaimed.compareAndSet(false, true)

    internal fun attachPermit(value: OwnerKeyRotationDispatchPermit): Boolean {
        if (!isAuthentic() || value.publication !== this) return false
        synchronized(this) {
            if (permit != null) return false
            permit = value
            return true
        }
    }

    internal fun beginDispatch(value: OwnerKeyRotationDispatchPermit): Boolean =
        isAuthentic() && permit === value && value.isAuthentic() &&
            dispatchStarted.compareAndSet(false, true)
}

class OwnerKeyRotationDispatchPermit internal constructor(
    val intent: OwnerKeyRotationDispatchIntent,
    internal val publication: OwnerKeyRotationPublication,
    private val seal: Any,
) {
    internal fun isAuthentic(): Boolean = seal === OwnerKeyRotationTokenAuthority.seal
}

class OwnerKeyRotationConfirmation internal constructor(
    val intent: OwnerKeyRotationDispatchIntent,
    candidateStateHash: ByteArray,
    private val seal: Any,
) {
    private val confirmedStateHash = candidateStateHash.copyOf()

    val stateHash: ByteArray
        get() = confirmedStateHash.copyOf()

    internal fun isAuthentic(): Boolean = seal === OwnerKeyRotationTokenAuthority.seal
}

class OwnerKeyRotationDispatchRejection internal constructor(
    val intent: OwnerKeyRotationDispatchIntent,
    internal val permit: OwnerKeyRotationDispatchPermit,
    val status: OwnerKeyRotationDispatchStatus,
    private val seal: Any,
) {
    private val consumed = AtomicBoolean(false)

    internal fun isAuthentic(): Boolean = seal === OwnerKeyRotationTokenAuthority.seal
    internal fun canResolve(current: OwnerKeyRotationDispatchPermit?): Boolean =
        isAuthentic() && current === permit && !consumed.get()
    internal fun markResolved() {
        consumed.set(true)
    }
}

internal object OwnerKeyRotationTokenAuthority {
    val seal: Any = Any()

    fun permit(
        publication: OwnerKeyRotationPublication,
        intent: OwnerKeyRotationDispatchIntent,
    ): OwnerKeyRotationDispatchPermit = OwnerKeyRotationDispatchPermit(intent, publication, seal)

    fun confirmation(
        intent: OwnerKeyRotationDispatchIntent,
        stateHash: ByteArray,
    ): OwnerKeyRotationConfirmation = OwnerKeyRotationConfirmation(intent, stateHash, seal)

    fun rejection(
        intent: OwnerKeyRotationDispatchIntent,
        permit: OwnerKeyRotationDispatchPermit,
        status: OwnerKeyRotationDispatchStatus,
    ): OwnerKeyRotationDispatchRejection {
        if (status != OwnerKeyRotationDispatchStatus.EXPIRED) {
            throw WalletInvalidIdentityStateException()
        }
        return OwnerKeyRotationDispatchRejection(intent, permit, status, seal)
    }
}

/**
 * Public-only rotation orchestrator. The host must supply an atomic replay store; production
 * implementations must persist its digests across restarts. `authenticatedOrigin` is a caller
 * assertion and must be derived by the host from a trusted principal.
 */
class AndroidIdentityAdapter(
    private val transport: AndroidIdentityTransport,
    private val replayNonceStore: AndroidIdentityReplayNonceStore,
) {
    /** The authenticated origin and environment are trusted host context, not authenticated here. */
    fun prepareOwnerKeyRotationPublication(
        draft: OwnerKeyRotationDraft,
        consent: (OwnerKeyRotationConsentTranscript) -> Boolean,
        authenticatedOrigin: String,
        environment: String,
        purpose: String,
        capability: String,
        expiresAt: Long,
        replayNonce: ByteArray,
    ): OwnerKeyRotationPublication {
        if (!rotationTransportAvailable()) throw WalletRotationTransportUnavailableException()
        if (!transportMatchesEnvironment(environment)) throw WalletIdentityEnvironmentMismatchException()
        val nonceSnapshot = replayNonce.copyOf()
        var ownerName: ByteArray? = null
        var envelope: ByteArray? = null
        var previous: ByteArray? = null
        var afterConsent: ByteArray? = null
        try {
            validateConsentContext(
                authenticatedOrigin,
                environment,
                purpose,
                capability,
                expiresAt,
                nonceSnapshot,
            )
            ownerName = draft.ownerNameBytes
            envelope = draft.envelopeBytes
            val envelopeHash = AndroidIdentityCrypto.sha256(envelope)
            val intent = try {
                OwnerKeyRotationDispatchIntent(
                    ownerNameBytes = ownerName,
                    predecessorOwnerPublicKey = draft.predecessorOwnerPublicKey,
                    successorOwnerPublicKey = draft.successorOwnerPublicKey,
                    predecessorStateHash = draft.predecessorStateHash,
                    sequence = draft.sequence,
                    environment = environment,
                    envelopeHash = envelopeHash,
                )
            } finally {
                envelopeHash.fill(0)
            }

            previous = readCurrent(ownerName)
                ?: throw WalletIdentityStateChangedException()
            val candidateStateHash = LegacyOwnerKeyRotation.verifyLegacyCandidate(previous, envelope, intent)
            candidateStateHash.fill(0)

            val nonceDigest = replayNonceDigest(ownerName, authenticatedOrigin, environment, nonceSnapshot)
            val nonceAccepted = try {
                replayNonceStore.consume(nonceDigest.copyOf())
            } catch (_: Exception) {
                throw WalletIdentityReplayRejectedException()
            } finally {
                nonceDigest.fill(0)
            }
            if (!nonceAccepted) throw WalletIdentityReplayRejectedException()

            val transcript = OwnerKeyRotationConsentTranscript(
                ownerNameBytes = ownerName,
                predecessorStateHash = intent.predecessorStateHash,
                successorOwnerPublicKey = intent.successorOwnerPublicKey,
                envelopeBytes = envelope,
                envelopeHash = intent.envelopeHash,
                replayNonce = nonceSnapshot,
                sequence = intent.sequence,
                authenticatedOrigin = authenticatedOrigin,
                environment = environment,
                purpose = purpose,
                capability = capability,
                expiresAt = expiresAt,
            )
            val approved = try {
                consent(transcript)
            } catch (_: Exception) {
                false
            }
            if (!approved) throw WalletRotationConsentRejectedException()
            if (expiresAt <= nowSeconds()) throw WalletRotationConsentExpiredException()

            afterConsent = readCurrent(ownerName)
                ?: throw WalletIdentityStateChangedException()
            if (!afterConsent.contentEquals(previous)) throw WalletIdentityStateChangedException()
            val revalidatedStateHash = LegacyOwnerKeyRotation.verifyLegacyCandidate(afterConsent, envelope, intent)
            revalidatedStateHash.fill(0)

            return OwnerKeyRotationPublication(
                intent = intent,
                envelopeBytes = envelope,
                predecessorEnvelopeBytes = previous,
                expiresAt = expiresAt,
                seal = OwnerKeyRotationTokenAuthority.seal,
            )
        } finally {
            nonceSnapshot.fill(0)
            ownerName?.fill(0)
            envelope?.fill(0)
            previous?.fill(0)
            afterConsent?.fill(0)
        }
    }

    fun dispatchOwnerKeyRotation(
        publication: OwnerKeyRotationPublication,
        permit: OwnerKeyRotationDispatchPermit,
    ): OwnerKeyRotationDispatchResult {
        if (!publication.isAuthentic() || permit.publication !== publication ||
            permit.intent != publication.intent || !publication.beginDispatch(permit)
        ) {
            throw WalletInvalidIdentityStateException()
        }
        val intent = publication.intent
        val ownerName = intent.ownerNameBytes
        val predecessor = publication.predecessorEnvelopeBytes()
        val envelope = publication.envelopeBytes
        val expectedHash = intent.predecessorStateHash
        try {
            if (!rotationTransportAvailable() || !transportMatchesEnvironment(intent.environment)) {
                return prewriteFailure(publication, permit, OwnerKeyRotationDispatchStatus.FAILED)
            }
            val current = try {
                readCurrent(ownerName)
            } catch (_: WalletIdentityTransportException) {
                return prewriteFailure(
                    publication,
                    permit,
                    OwnerKeyRotationDispatchStatus.FAILED,
                    clearableRejection = false,
                )
            }
            if (current == null) {
                return prewriteFailure(
                    publication,
                    permit,
                    OwnerKeyRotationDispatchStatus.STALE,
                    clearableRejection = false,
                )
            }
            val candidateObservedLocally = envelopeMatchesIntent(current, intent)
            val verifiedCurrentHash = try {
                if (!current.contentEquals(predecessor)) null
                else LegacyOwnerKeyRotation.verifyLegacyCandidate(current, envelope, intent)
            } catch (_: Exception) {
                null
            } finally {
                current.fill(0)
            }
            val currentMatches = verifiedCurrentHash != null
            verifiedCurrentHash?.fill(0)
            if (!currentMatches) {
                return prewriteFailure(
                    publication,
                    permit,
                    OwnerKeyRotationDispatchStatus.STALE,
                    candidateObservedLocally = candidateObservedLocally,
                    clearableRejection = false,
                )
            }
            if (publication.expiresAt <= nowSeconds()) {
                return prewriteFailure(
                    publication,
                    permit,
                    OwnerKeyRotationDispatchStatus.EXPIRED,
                    clearableRejection = true,
                )
            }

            val writeOwnerName = ownerName.copyOf()
            val writeEnvelope = envelope.copyOf()
            val writeExpectedHash = expectedHash.copyOf()
            try {
                transport.putIdentityEnvelopeIfCurrent(
                    ownerNameBytes = writeOwnerName,
                    envelopeBytes = writeEnvelope,
                    expectedStateHash = writeExpectedHash,
                    expiresAt = publication.expiresAt,
                )
            } catch (_: AndroidIdentityPreconditionFailedException) {
                return prewriteFailure(
                    publication,
                    permit,
                    OwnerKeyRotationDispatchStatus.STALE,
                    clearableRejection = false,
                )
            } catch (_: AndroidIdentityWriteExpiredException) {
                return prewriteFailure(
                    publication,
                    permit,
                    OwnerKeyRotationDispatchStatus.EXPIRED,
                    clearableRejection = true,
                )
            } catch (_: Exception) {
                val recovered = confirmOwnerKeyRotation(intent)
                return if (recovered != null) {
                    OwnerKeyRotationDispatchResult(OwnerKeyRotationDispatchStatus.CONFIRMED, confirmation = recovered)
                } else {
                    OwnerKeyRotationDispatchResult(OwnerKeyRotationDispatchStatus.UNKNOWN)
                }
            }

            val confirmation = confirmOwnerKeyRotation(intent)
            return if (confirmation != null) {
                OwnerKeyRotationDispatchResult(OwnerKeyRotationDispatchStatus.CONFIRMED, confirmation = confirmation)
            } else {
                OwnerKeyRotationDispatchResult(OwnerKeyRotationDispatchStatus.UNKNOWN)
            }
        } finally {
            ownerName.fill(0)
            predecessor.fill(0)
            envelope.fill(0)
            expectedHash.fill(0)
        }
    }

    /** Fresh remote read only; never retries a write. */
    fun confirmOwnerKeyRotation(intent: OwnerKeyRotationDispatchIntent): OwnerKeyRotationConfirmation? {
        if (!rotationTransportAvailable() || !transportMatchesEnvironment(intent.environment)) return null
        val ownerName = intent.ownerNameBytes
        val remote = try {
            readRemote(ownerName)
        } catch (_: Exception) {
            null
        } ?: run {
            ownerName.fill(0)
            return null
        }
        return try {
            confirmObservedCandidate(intent, ownerName, remote)
        } finally {
            ownerName.fill(0)
            remote.fill(0)
        }
    }

    private fun confirmObservedCandidate(
        intent: OwnerKeyRotationDispatchIntent,
        ownerName: ByteArray,
        remote: ByteArray,
    ): OwnerKeyRotationConfirmation? {
        val predecessorHash = intent.predecessorStateHash
        val predecessor = try {
            readByHash(ownerName, predecessorHash)
        } catch (_: Exception) {
            null
        } finally {
            predecessorHash.fill(0)
        } ?: return null
        try {
            if (!envelopeMatchesIntent(remote, intent)) return null
            val stateHash = try {
                LegacyOwnerKeyRotation.verifyLegacyCandidate(predecessor, remote, intent)
            } catch (_: Exception) {
                return null
            }
            return try {
                OwnerKeyRotationTokenAuthority.confirmation(intent, stateHash)
            } finally {
                stateHash.fill(0)
            }
        } finally {
            predecessor.fill(0)
        }
    }

    private fun prewriteFailure(
        publication: OwnerKeyRotationPublication,
        permit: OwnerKeyRotationDispatchPermit,
        status: OwnerKeyRotationDispatchStatus,
        candidateObservedLocally: Boolean = false,
        clearableRejection: Boolean = false,
    ): OwnerKeyRotationDispatchResult {
        val intent = publication.intent
        if (!rotationTransportAvailable() || !transportMatchesEnvironment(intent.environment)) {
            return OwnerKeyRotationDispatchResult(OwnerKeyRotationDispatchStatus.UNKNOWN)
        }
        val ownerName = intent.ownerNameBytes
        val remote = try {
            readRemote(ownerName)
        } catch (_: Exception) {
            null
        } ?: run {
            ownerName.fill(0)
            return OwnerKeyRotationDispatchResult(OwnerKeyRotationDispatchStatus.UNKNOWN)
        }
        try {
            if (candidateObservedLocally || envelopeMatchesIntent(remote, intent)) {
                val confirmation = confirmObservedCandidate(intent, ownerName, remote)
                return if (confirmation != null) {
                    OwnerKeyRotationDispatchResult(
                        OwnerKeyRotationDispatchStatus.CONFIRMED,
                        confirmation = confirmation,
                    )
                } else {
                    OwnerKeyRotationDispatchResult(OwnerKeyRotationDispatchStatus.UNKNOWN)
                }
            }
            if (!clearableRejection) {
                return OwnerKeyRotationDispatchResult(OwnerKeyRotationDispatchStatus.UNKNOWN)
            }
            return OwnerKeyRotationDispatchResult(
                status = status,
                rejection = OwnerKeyRotationTokenAuthority.rejection(intent, permit, status),
            )
        } finally {
            ownerName.fill(0)
            remote.fill(0)
        }
    }

    private fun envelopeMatchesIntent(
        envelope: ByteArray,
        intent: OwnerKeyRotationDispatchIntent,
    ): Boolean {
        val digest = AndroidIdentityCrypto.sha256(envelope)
        val expectedHash = intent.envelopeHash
        return try {
            digest.contentEquals(expectedHash)
        } finally {
            digest.fill(0)
            expectedHash.fill(0)
        }
    }

    private fun readCurrent(ownerName: ByteArray): ByteArray? {
        val transportOwnerName = ownerName.copyOf()
        return try {
            transport.getIdentityEnvelope(transportOwnerName)?.copyOf()
        } catch (_: Exception) {
            throw WalletIdentityTransportException()
        }
    }

    private fun readRemote(ownerName: ByteArray): ByteArray? {
        val transportOwnerName = ownerName.copyOf()
        return transport.getRemoteIdentityEnvelope(transportOwnerName)?.copyOf()
    }

    private fun readByHash(ownerName: ByteArray, stateHash: ByteArray): ByteArray? {
        val transportOwnerName = ownerName.copyOf()
        val transportStateHash = stateHash.copyOf()
        return transport.getIdentityEnvelopeByHash(transportOwnerName, transportStateHash)?.copyOf()
    }

    private fun rotationTransportAvailable(): Boolean = try {
        transport.supportsOwnerKeyRotation
    } catch (_: Exception) {
        false
    }

    private fun transportMatchesEnvironment(environment: String): Boolean = try {
        transport.registryEnvironment == environment
    } catch (_: Exception) {
        false
    }

    private fun validateConsentContext(
        authenticatedOrigin: String,
        environment: String,
        purpose: String,
        capability: String,
        expiresAt: Long,
        replayNonce: ByteArray,
    ) {
        if (authenticatedOrigin.isBlank() || authenticatedOrigin.length > 2048 ||
            environment.isBlank() || environment.length > 256 ||
            purpose.isBlank() || purpose.length > 1024 ||
            capability != "identity.rotate-owner-key" ||
            expiresAt <= nowSeconds() || replayNonce.size !in 16..256
        ) {
            throw WalletInvalidIdentityStateException()
        }
    }

    private fun replayNonceDigest(
        ownerName: ByteArray,
        authenticatedOrigin: String,
        environment: String,
        nonce: ByteArray,
    ): ByteArray {
        val encoded = IdentityCbor.encodeCanonical(
            linkedMapOf<BigInteger, Any?>(
                BigInteger.ONE to ownerName,
                BigInteger.valueOf(2) to authenticatedOrigin,
                BigInteger.valueOf(3) to environment,
                BigInteger.valueOf(4) to nonce,
            ),
        )
        return try {
            AndroidIdentityCrypto.sha256(encoded)
        } finally {
            encoded.fill(0)
        }
    }

    private fun nowSeconds(): Long = System.currentTimeMillis() / 1000
}

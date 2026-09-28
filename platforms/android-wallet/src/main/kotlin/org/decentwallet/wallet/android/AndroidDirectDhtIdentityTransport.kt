package org.decentwallet.wallet.android

import java.security.MessageDigest

/** Stable direct-DHT peer configuration for one Registry environment. */
class AndroidRegistryDhtConfig(
    registryEnvironment: String,
    registryPeers: List<String>,
    val enableOwnerKeyRotation: Boolean = false,
    val requestTimeoutMillis: Long = DEFAULT_REQUEST_TIMEOUT_MILLIS,
) {
    val registryEnvironment: String = registryEnvironment
    val registryPeers: List<String> = registryPeers.toList()

    init {
        require(registryEnvironment.isNotBlank() && registryEnvironment.length <= 256) {
            "Registry environment must be a stable non-empty identifier"
        }
        require(registryPeers.isNotEmpty() && registryPeers.size <= MAX_REGISTRY_PEERS) {
            "configure between one and $MAX_REGISTRY_PEERS Registry peers"
        }
        require(registryPeers.all { it.isNotBlank() && it.startsWith("/") && "/p2p/" in it }) {
            "Registry peers must be complete pinned /p2p/<peer-id> multiaddrs"
        }
        require(registryPeers.distinct().size == registryPeers.size) {
            "Registry peer multiaddrs must be unique"
        }
        require(requestTimeoutMillis in MIN_REQUEST_TIMEOUT_MILLIS..MAX_REQUEST_TIMEOUT_MILLIS) {
            "Registry peer request timeout is outside the supported range"
        }
    }

    internal val primaryPeer: String
        get() = registryPeers.first()

    internal companion object {
        const val DEFAULT_REQUEST_TIMEOUT_MILLIS = 10_000L
        const val MIN_REQUEST_TIMEOUT_MILLIS = 1_000L
        const val MAX_REQUEST_TIMEOUT_MILLIS = 60_000L
        const val MAX_REGISTRY_PEERS = 16
    }
}

/**
 * Direct Kad-DHT transport for Registry-compatible peers. Every read is a new
 * GET_VALUE RPC to a pinned peer; there is no client-side value cache or repair.
 * The Registry peer remains responsible for durable accepted-state/history and
 * validating PUT_VALUE. Confirmation is a separate fresh GET_VALUE call.
 */
class AndroidDirectDhtIdentityTransport internal constructor(
    private val config: AndroidRegistryDhtConfig,
    private val dhtClient: AndroidKadDhtRpcClient,
    private val epochSeconds: () -> Long,
) : AndroidIdentityTransport, AutoCloseable {
    constructor(config: AndroidRegistryDhtConfig) : this(
        config,
        JvmLibp2pKadDhtRpcClient(config.requestTimeoutMillis, config.registryPeers),
        { System.currentTimeMillis() / 1_000 },
    )

    override val registryEnvironment: String
        get() = config.registryEnvironment

    override val supportsOwnerKeyRotation: Boolean
        get() = config.enableOwnerKeyRotation

    override fun getIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray? {
        val ownerName = ownerNameBytes.copyOf()
        val key = AndroidRegistryDhtKey.identity(ownerName)
        return try {
            dhtClient.getValue(config.primaryPeer, key)?.copyOf()
        } catch (failure: Exception) {
            throw WalletIdentityTransportException(failure)
        } finally {
            ownerName.fill(0)
            key.fill(0)
        }
    }

    override fun getIdentityEnvelopeByHash(ownerNameBytes: ByteArray, stateHash: ByteArray): ByteArray? {
        val ownerName = ownerNameBytes.copyOf()
        val hash = stateHash.copyOf()
        val key = AndroidRegistryDhtKey.history(ownerName, hash)
        var lastFailure: Exception? = null
        try {
            for (peer in config.registryPeers) {
                try {
                    val value = dhtClient.getValue(peer, key)
                    if (value != null) return value.copyOf()
                } catch (failure: Exception) {
                    lastFailure = failure
                }
            }
            // A partial set of successful misses cannot prove the hash-addressed record is absent.
            if (lastFailure != null) throw WalletIdentityTransportException(lastFailure)
            return null
        } finally {
            ownerName.fill(0)
            hash.fill(0)
            key.fill(0)
        }
    }

    override fun getRemoteIdentityEnvelope(ownerNameBytes: ByteArray): ByteArray? {
        // This path never consults a local value store or a prior GET/PUT response.
        return getIdentityEnvelope(ownerNameBytes)
    }

    override fun putIdentityEnvelopeIfCurrent(
        ownerNameBytes: ByteArray,
        envelopeBytes: ByteArray,
        expectedStateHash: ByteArray,
        expiresAt: Long,
    ) {
        if (!config.enableOwnerKeyRotation) throw WalletRotationTransportUnavailableException()
        if (ownerNameBytes.isEmpty() || expectedStateHash.size != AndroidIdentityCrypto.KEY_BYTES || envelopeBytes.isEmpty()) {
            throw WalletInvalidIdentityStateException()
        }

        val ownerName = ownerNameBytes.copyOf()
        val candidateEnvelope = envelopeBytes.copyOf()
        val expectedHash = expectedStateHash.copyOf()
        var currentEnvelope: ByteArray? = null
        try {
            val currentState = readVerifiedCurrent(ownerName).also { currentEnvelope = it.envelopeBytes }
            val currentHash = currentState.stateHash
            try {
                if (!MessageDigest.isEqual(currentHash, expectedHash)) {
                    throw AndroidIdentityPreconditionFailedException()
                }
            } finally {
                currentHash.fill(0)
            }

            val candidateState = resolve(ownerName, candidateEnvelope)
            val predecessorHash = candidateState.predecessorStateHash
                ?: throw WalletInvalidIdentityStateException()
            val predecessorOwnerKey = candidateState.predecessorOwnerPublicKey
                ?: throw WalletInvalidIdentityStateException()
            val successorOwnerKey = candidateState.ownerPublicKey
            try {
                if (!MessageDigest.isEqual(predecessorHash, expectedHash) ||
                    MessageDigest.isEqual(predecessorOwnerKey, successorOwnerKey)
                ) {
                    throw AndroidIdentityPreconditionFailedException()
                }
            } finally {
                predecessorHash.fill(0)
                predecessorOwnerKey.fill(0)
                successorOwnerKey.fill(0)
            }

            val freshCurrent = readVerifiedCurrent(ownerName)
            val freshHash = freshCurrent.stateHash
            val freshEnvelope = freshCurrent.envelopeBytes
            try {
                if (!MessageDigest.isEqual(freshHash, expectedHash)) {
                    throw AndroidIdentityPreconditionFailedException()
                }
            } finally {
                freshHash.fill(0)
                freshEnvelope.fill(0)
            }

            if (expiresAt <= epochSeconds()) throw AndroidIdentityWriteExpiredException()
            val key = AndroidRegistryDhtKey.identity(ownerName)
            try {
                // After this call begins, every non-typed failure is ambiguous. Never retry here.
                val acknowledged = try {
                    dhtClient.putValue(config.primaryPeer, key, candidateEnvelope)
                } catch (failure: Exception) {
                    throw WalletIdentityTransportException(failure)
                }
                if (!acknowledged) throw WalletIdentityTransportException()
            } finally {
                key.fill(0)
            }
        } catch (failure: AndroidIdentityPreconditionFailedException) {
            throw failure
        } catch (failure: AndroidIdentityWriteExpiredException) {
            throw failure
        } catch (failure: WalletIdentityTransportException) {
            throw failure
        } catch (failure: Exception) {
            throw WalletIdentityTransportException(failure)
        } finally {
            currentEnvelope?.fill(0)
            ownerName.fill(0)
            candidateEnvelope.fill(0)
            expectedHash.fill(0)
        }
    }

    private fun readVerifiedCurrent(ownerName: ByteArray): VerifiedIdentityState {
        val envelope = getIdentityEnvelope(ownerName) ?: throw WalletIdentityTransportException()
        return try {
            resolve(ownerName, envelope)
        } finally {
            envelope.fill(0)
        }
    }

    private fun resolve(ownerName: ByteArray, envelope: ByteArray): VerifiedIdentityState =
        IdentityStateHistoryVerifier.resolve(ownerName, envelope) { stateHash ->
            getIdentityEnvelopeByHash(ownerName, stateHash)
        }

    override fun close() {
        dhtClient.close()
    }
}

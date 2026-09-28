package org.decentwallet.wallet.android

import java.nio.file.Path
import java.security.SecureRandom

object AndroidWallet {
    fun createWithGeneratedKey(
        path: Path,
        password: String,
        confirmation: String,
    ): WalletSession = createWithGeneratedKey(path, password, confirmation, SecureRandom())

    internal fun createWithGeneratedKeyForTest(
        path: Path,
        password: String,
        confirmation: String,
        random: SecureRandom,
    ): WalletSession = createWithGeneratedKey(path, password, confirmation, random)

    private fun createWithGeneratedKey(
        path: Path,
        password: String,
        confirmation: String,
        random: SecureRandom,
    ): WalletSession {
        val seed = AndroidIdentityCrypto.generateSeed(random)
        var publicKey: ByteArray? = null
        try {
            publicKey = try {
                AndroidIdentityCrypto.publicKeyFromSeed(seed)
            } catch (_: WalletContainerException) {
                throw WalletKeyGenerationException()
            }
            return create(
                path,
                password,
                confirmation,
                mapOf("private_seed" to seed, "public_key" to publicKey),
            )
        } finally {
            seed.fill(0)
            publicKey?.fill(0)
        }
    }

    fun create(
        path: Path,
        password: String,
        confirmation: String,
        payload: Map<String, Any?>,
    ): WalletSession {
        val created = ContainerCrypto.create(password, confirmation, payload)
        return try {
            AtomicWalletFiles.createNew(path, created.bytes)
            WalletSession(path, created.bytes, created.dek, created.payload)
        } catch (failure: WalletContainerException) {
            created.bytes.fill(0)
            created.dek.fill(0)
            WalletJson.clearByteArrays(created.payload)
            throw failure
        } catch (_: Exception) {
            created.bytes.fill(0)
            created.dek.fill(0)
            WalletJson.clearByteArrays(created.payload)
            throw WalletStorageException()
        }
    }

    fun importContainer(path: Path, data: ByteArray, password: String): WalletSession {
        validatePasswordForOpen(password)
        if (data.size > ContainerCrypto.MAX_CONTAINER_BYTES) throw WalletInvalidContainerException()
        val raw = data.copyOf()
        val opened = try {
            ContainerCrypto.open(raw, password)
        } catch (failure: WalletContainerException) {
            raw.fill(0)
            throw failure
        } catch (_: Exception) {
            raw.fill(0)
            throw WalletStorageException()
        }
        try {
            AtomicWalletFiles.createNew(path, raw)
            return WalletSession(path, raw, opened.dek, opened.payload)
        } catch (failure: WalletContainerException) {
            raw.fill(0)
            opened.dek.fill(0)
            WalletJson.clearByteArrays(opened.payload)
            throw failure
        } catch (_: Exception) {
            raw.fill(0)
            opened.dek.fill(0)
            WalletJson.clearByteArrays(opened.payload)
            throw WalletStorageException()
        }
    }

    fun migrateContainer(path: Path, password: String): WalletSession {
        validatePasswordForOpen(password)
        val original = AtomicWalletFiles.read(path)
        try {
            val converted = ContainerCrypto.migrate(password, original)
            try {
                AtomicWalletFiles.replace(path, converted.bytes, original)
                return WalletSession(path, converted.bytes, converted.dek, converted.payload)
            } catch (failure: WalletContainerException) {
                converted.bytes.fill(0)
                converted.dek.fill(0)
                WalletJson.clearByteArrays(converted.payload)
                throw failure
            } catch (_: Exception) {
                converted.bytes.fill(0)
                converted.dek.fill(0)
                WalletJson.clearByteArrays(converted.payload)
                throw WalletStorageException()
            }
        } finally {
            original.fill(0)
        }
    }

    fun open(path: Path, password: String): WalletSession {
        validatePasswordForOpen(password)
        val raw = AtomicWalletFiles.read(path)
        val opened = try {
            ContainerCrypto.open(raw, password)
        } catch (failure: WalletContainerException) {
            raw.fill(0)
            throw failure
        } catch (_: Exception) {
            raw.fill(0)
            throw WalletStorageException()
        }
        return WalletSession(path, raw, opened.dek, opened.payload)
    }

    private fun validatePasswordForOpen(password: String) = ContainerCrypto.validatePassword(password)
}

class WalletSession internal constructor(
    private val path: Path,
    rawBytes: ByteArray,
    dek: ByteArray,
    payload: MutableMap<String, Any?>,
    private val replaceFile: (Path, ByteArray, ByteArray) -> Unit = { target, bytes, expected ->
        AtomicWalletFiles.replace(target, bytes, expected)
    },
) : AutoCloseable {
    private var rawContainer: ByteArray? = rawBytes
    private var dataEncryptionKey: ByteArray? = dek
    private var walletPayload: MutableMap<String, Any?>? = payload
    private var activeOwnerKeyRotationPermit: OwnerKeyRotationDispatchPermit? = null

    val isUnlocked: Boolean
        @Synchronized get() = dataEncryptionKey != null

    val ownerPublicKey: ByteArray
        @Synchronized get() {
            ensureUnlocked()
            return requireActiveKeyPair(checkNotNull(walletPayload)).publicKey.copyOf()
        }

    val pendingOwnerPublicKey: ByteArray?
        @Synchronized get() {
            ensureUnlocked()
            val payload = checkNotNull(walletPayload)
            val active = requireActiveKeyPair(payload)
            val pending = optionalKeyPair(payload, "pending_private_seed", "pending_public_key")
                ?: return null
            if (AndroidIdentityCrypto.equalPublicKeys(active.publicKey, pending.publicKey)) {
                throw WalletInvalidContainerException()
            }
            return pending.publicKey.copyOf()
        }

    val ownerKeyRotationDispatchIntent: OwnerKeyRotationDispatchIntent?
        @Synchronized get() {
            ensureUnlocked()
            val payload = checkNotNull(walletPayload)
            if (!payload.containsKey("rotation_dispatch_intent")) return null
            return OwnerKeyRotationDispatchIntent.fromPayload(payload["rotation_dispatch_intent"])
        }

    @Synchronized
    fun prepareSigningKeyRotation(): ByteArray = prepareSigningKeyRotation(SecureRandom())

    @Synchronized
    internal fun prepareSigningKeyRotation(random: SecureRandom): ByteArray {
        ensureUnlocked()
        val payload = checkNotNull(walletPayload)
        if (payload.containsKey("rotation_dispatch_intent")) {
            throw WalletRotationInProgressException()
        }
        val active = requireActiveKeyPair(payload)
        val currentPending = optionalKeyPair(payload, "pending_private_seed", "pending_public_key")
        if (currentPending != null) {
            if (AndroidIdentityCrypto.equalPublicKeys(active.publicKey, currentPending.publicKey)) {
                throw WalletInvalidContainerException()
            }
            return currentPending.publicKey.copyOf()
        }

        val pendingSeed = AndroidIdentityCrypto.generateSeed(random)
        var pendingPublicKey: ByteArray? = null
        var candidate: MutableMap<String, Any?>? = null
        try {
            pendingPublicKey = try {
                AndroidIdentityCrypto.publicKeyFromSeed(pendingSeed)
            } catch (_: WalletContainerException) {
                throw WalletKeyGenerationException()
            }
            if (AndroidIdentityCrypto.equalPublicKeys(active.publicKey, pendingPublicKey)) {
                throw WalletKeyGenerationException()
            }
            @Suppress("UNCHECKED_CAST")
            candidate = WalletJson.copyPayload(payload) as? MutableMap<String, Any?>
                ?: throw WalletInvalidContainerException()
            candidate["pending_private_seed"] = pendingSeed.copyOf()
            candidate["pending_public_key"] = pendingPublicKey.copyOf()
            persistPayloadCandidate(candidate)
            candidate = null
            return pendingPublicKey.copyOf()
        } finally {
            pendingSeed.fill(0)
            pendingPublicKey?.fill(0)
            candidate?.let {
                WalletJson.clearByteArrays(it)
                it.clear()
            }
        }
    }

    @Synchronized
    fun cancelSigningKeyRotation(): Boolean {
        ensureUnlocked()
        val payload = checkNotNull(walletPayload)
        if (payload.containsKey("rotation_dispatch_intent")) {
            throw WalletRotationInProgressException()
        }
        val active = requireActiveKeyPair(payload)
        val pending = optionalKeyPair(payload, "pending_private_seed", "pending_public_key") ?: return false
        if (AndroidIdentityCrypto.equalPublicKeys(active.publicKey, pending.publicKey)) {
            throw WalletInvalidContainerException()
        }
        @Suppress("UNCHECKED_CAST")
        val candidate = WalletJson.copyPayload(payload) as? MutableMap<String, Any?>
            ?: throw WalletInvalidContainerException()
        var removedSeed: ByteArray? = null
        var removedPublicKey: ByteArray? = null
        var installed = false
        try {
            removedSeed = candidate.remove("pending_private_seed") as? ByteArray
                ?: throw WalletInvalidContainerException()
            removedPublicKey = candidate.remove("pending_public_key") as? ByteArray
                ?: throw WalletInvalidContainerException()
            removedSeed.fill(0)
            removedSeed = null
            removedPublicKey.fill(0)
            removedPublicKey = null
            persistPayloadCandidate(candidate)
            installed = true
            return true
        } finally {
            removedSeed?.fill(0)
            removedPublicKey?.fill(0)
            if (!installed) {
                WalletJson.clearByteArrays(candidate)
                candidate.clear()
            }
        }
    }

    @Synchronized
    fun createLegacyOwnerKeyRotationDraft(
        ownerNameBytes: ByteArray,
        predecessorEnvelopeBytes: ByteArray,
        successorSigners: List<IdentityRotationSigner>,
    ): OwnerKeyRotationDraft {
        ensureUnlocked()
        val payload = checkNotNull(walletPayload)
        if (payload.containsKey("rotation_dispatch_intent")) {
            throw WalletRotationInProgressException()
        }
        val active = requireActiveKeyPair(payload)
        val pending = optionalKeyPair(payload, "pending_private_seed", "pending_public_key")
            ?: throw WalletInvalidIdentityStateException()
        if (AndroidIdentityCrypto.equalPublicKeys(active.publicKey, pending.publicKey)) {
            throw WalletInvalidIdentityStateException()
        }
        if (ownerNameBytes.isEmpty() || ownerNameBytes.size > IdentityCbor.MAX_ENCODED_BYTES ||
            predecessorEnvelopeBytes.size > IdentityCbor.MAX_ENCODED_BYTES || successorSigners.size != 3
        ) {
            throw WalletInvalidIdentityStateException()
        }
        val ownerNameSnapshot = ownerNameBytes.copyOf()
        val predecessorSnapshot = predecessorEnvelopeBytes.copyOf()
        try {
            val signerSnapshot = successorSigners.map { signer ->
                val publicKey = signer.publicKeyCopy()
                try {
                    IdentityRotationSigner(signer.signerId, publicKey)
                } finally {
                    publicKey.fill(0)
                }
            }
            return LegacyOwnerKeyRotation.createDraft(
                ownerNameBytes = ownerNameSnapshot,
                predecessorEnvelopeBytes = predecessorSnapshot,
                activeSeed = active.seed,
                activePublicKey = active.publicKey,
                pendingSeed = pending.seed,
                pendingPublicKey = pending.publicKey,
                successorSigners = signerSnapshot,
            )
        } catch (failure: WalletContainerException) {
            throw failure
        } catch (_: Exception) {
            throw WalletInvalidIdentityStateException()
        } finally {
            ownerNameSnapshot.fill(0)
            predecessorSnapshot.fill(0)
        }
    }

    @Synchronized
    fun latchOwnerKeyRotationDispatchIntent(
        publication: OwnerKeyRotationPublication,
    ): OwnerKeyRotationDispatchPermit {
        ensureUnlocked()
        val payload = checkNotNull(walletPayload)
        if (payload.containsKey("rotation_dispatch_intent") || activeOwnerKeyRotationPermit != null) {
            throw WalletRotationInProgressException()
        }
        if (!publication.isAuthentic()) throw WalletInvalidIdentityStateException()
        if (publication.expiresAt <= System.currentTimeMillis() / 1000) {
            throw WalletRotationConsentExpiredException()
        }
        if (!publication.claimLatch()) throw WalletInvalidIdentityStateException()
        val intent = publication.intent
        val active = requireActiveKeyPair(payload)
        val pending = optionalKeyPair(payload, "pending_private_seed", "pending_public_key")
            ?: throw WalletInvalidIdentityStateException()
        val expectedPredecessor = intent.predecessorOwnerPublicKey
        val expectedSuccessor = intent.successorOwnerPublicKey
        val predecessorEnvelope = publication.predecessorEnvelopeBytes()
        val envelope = publication.envelopeBytes
        var candidate: MutableMap<String, Any?>? = null
        try {
            if (!active.publicKey.contentEquals(expectedPredecessor) ||
                !pending.publicKey.contentEquals(expectedSuccessor)
            ) {
                throw WalletInvalidIdentityStateException()
            }
            val verifiedStateHash = LegacyOwnerKeyRotation.verifyLegacyCandidate(
                predecessorEnvelope,
                envelope,
                intent,
            )
            verifiedStateHash.fill(0)
            @Suppress("UNCHECKED_CAST")
            candidate = WalletJson.copyPayload(payload) as? MutableMap<String, Any?>
                ?: throw WalletInvalidContainerException()
            candidate["rotation_dispatch_intent"] = intent.toPayload()
            val permit = OwnerKeyRotationTokenAuthority.permit(publication, intent)
            if (!publication.attachPermit(permit)) throw WalletInvalidIdentityStateException()
            persistPayloadCandidate(candidate)
            candidate = null
            activeOwnerKeyRotationPermit = permit
            return permit
        } finally {
            expectedPredecessor.fill(0)
            expectedSuccessor.fill(0)
            predecessorEnvelope.fill(0)
            envelope.fill(0)
            candidate?.let {
                WalletJson.clearByteArrays(it)
                it.clear()
            }
        }
    }

    @Synchronized
    fun resolveOwnerKeyRotationDispatchRejection(
        rejection: OwnerKeyRotationDispatchRejection,
    ) {
        ensureUnlocked()
        val payload = checkNotNull(walletPayload)
        if (!payload.containsKey("rotation_dispatch_intent")) throw WalletInvalidIdentityStateException()
        val intent = OwnerKeyRotationDispatchIntent.fromPayload(payload["rotation_dispatch_intent"])
        val permit = activeOwnerKeyRotationPermit
        if (permit == null || intent != rejection.intent || !rejection.canResolve(permit) ||
            rejection.status != OwnerKeyRotationDispatchStatus.EXPIRED
        ) {
            throw WalletInvalidIdentityStateException()
        }
        @Suppress("UNCHECKED_CAST")
        val candidate = WalletJson.copyPayload(payload) as? MutableMap<String, Any?>
            ?: throw WalletInvalidContainerException()
        var installed = false
        try {
            val removed = candidate.remove("rotation_dispatch_intent")
                ?: throw WalletInvalidContainerException()
            WalletJson.clearByteArrays(removed)
            persistPayloadCandidate(candidate)
            installed = true
            activeOwnerKeyRotationPermit = null
            rejection.markResolved()
        } finally {
            if (!installed) {
                WalletJson.clearByteArrays(candidate)
                candidate.clear()
            }
        }
    }

    @Synchronized
    fun finalizeSigningKeyRotation(confirmation: OwnerKeyRotationConfirmation) {
        ensureUnlocked()
        val payload = checkNotNull(walletPayload)
        if (!confirmation.isAuthentic() || !payload.containsKey("rotation_dispatch_intent")) {
            throw WalletInvalidIdentityStateException()
        }
        val intent = OwnerKeyRotationDispatchIntent.fromPayload(payload["rotation_dispatch_intent"])
        val confirmedIntent = confirmation.intent
        val confirmedStateHash = confirmation.stateHash
        val active = requireActiveKeyPair(payload)
        val pending = optionalKeyPair(payload, "pending_private_seed", "pending_public_key")
            ?: throw WalletInvalidIdentityStateException()
        val expectedPredecessor = intent.predecessorOwnerPublicKey
        val expectedSuccessor = intent.successorOwnerPublicKey
        try {
            if (intent != confirmedIntent || confirmedStateHash.size != AndroidIdentityCrypto.KEY_BYTES ||
                !active.publicKey.contentEquals(expectedPredecessor) ||
                !pending.publicKey.contentEquals(expectedSuccessor)
            ) {
                throw WalletInvalidIdentityStateException()
            }
        } finally {
            confirmedStateHash.fill(0)
            expectedPredecessor.fill(0)
            expectedSuccessor.fill(0)
        }

        @Suppress("UNCHECKED_CAST")
        val candidate = WalletJson.copyPayload(payload) as? MutableMap<String, Any?>
            ?: throw WalletInvalidContainerException()
        var installed = false
        try {
            val pendingSeed = candidate.remove("pending_private_seed") as? ByteArray
                ?: throw WalletInvalidContainerException()
            val pendingPublicKey = candidate.remove("pending_public_key") as? ByteArray
                ?: throw WalletInvalidContainerException()
            val activeSeed = candidate["private_seed"] as? ByteArray
                ?: throw WalletInvalidContainerException()
            val activePublicKey = candidate["public_key"] as? ByteArray
                ?: throw WalletInvalidContainerException()
            val promotedSeed = pendingSeed.copyOf()
            val promotedPublicKey = pendingPublicKey.copyOf()
            pendingSeed.fill(0)
            pendingPublicKey.fill(0)
            activeSeed.fill(0)
            activePublicKey.fill(0)
            candidate["private_seed"] = promotedSeed
            candidate["public_key"] = promotedPublicKey
            val removedIntent = candidate.remove("rotation_dispatch_intent")
                ?: throw WalletInvalidContainerException()
            WalletJson.clearByteArrays(removedIntent)
            persistPayloadCandidate(candidate)
            installed = true
            activeOwnerKeyRotationPermit = null
        } finally {
            if (!installed) {
                WalletJson.clearByteArrays(candidate)
                candidate.clear()
            }
        }
    }

    @Synchronized
    internal fun readPayload(): Map<String, Any?> {
        ensureUnlocked()
        @Suppress("UNCHECKED_CAST")
        return WalletJson.copyPayload(walletPayload) as Map<String, Any?>
    }

    @Synchronized
    fun exportContainer(): ByteArray {
        ensureUnlocked()
        val stored = checkNotNull(rawContainer)
        val current = AtomicWalletFiles.read(path)
        if (!current.contentEquals(stored)) {
            current.fill(0)
            throw WalletInvalidContainerException()
        }
        return current
    }

    @Synchronized
    fun lock() {
        activeOwnerKeyRotationPermit = null
        dataEncryptionKey?.fill(0)
        dataEncryptionKey = null
        walletPayload?.let(WalletJson::clearByteArrays)
        walletPayload?.clear()
        walletPayload = null
        rawContainer?.fill(0)
        rawContainer = null
    }

    fun background() = lock()

    override fun close() = lock()

    private fun ensureUnlocked() {
        if (dataEncryptionKey == null || walletPayload == null || rawContainer == null) {
            throw WalletLockedException()
        }
    }

    private fun persistPayloadCandidate(candidate: MutableMap<String, Any?>) {
        ensureUnlocked()
        val expectedOriginal = checkNotNull(rawContainer)
        val dek = checkNotNull(dataEncryptionKey)
        var replacement: ByteArray? = null
        var installed = false
        try {
            replacement = ContainerCrypto.resealPayload(expectedOriginal, dek, candidate)
            try {
                replaceFile(path, replacement, expectedOriginal)
            } catch (failure: WalletStorageOutcomeUnknownException) {
                lock()
                throw failure
            } catch (failure: WalletInvalidContainerException) {
                lock()
                throw failure
            } catch (failure: WalletContainerException) {
                throw failure
            } catch (_: Exception) {
                lock()
                throw WalletStorageOutcomeUnknownException()
            }

            val previousPayload = checkNotNull(walletPayload)
            val previousContainer = checkNotNull(rawContainer)
            walletPayload = candidate
            rawContainer = checkNotNull(replacement)
            replacement = null
            installed = true
            WalletJson.clearByteArrays(previousPayload)
            previousPayload.clear()
            previousContainer.fill(0)
        } finally {
            if (!installed) {
                WalletJson.clearByteArrays(candidate)
                candidate.clear()
                replacement?.fill(0)
            }
        }
    }

    private fun requireActiveKeyPair(payload: Map<String, Any?>): KeyPairBytes =
        requiredKeyPair(payload, "private_seed", "public_key")

    private fun requiredKeyPair(
        payload: Map<String, Any?>,
        seedField: String,
        publicKeyField: String,
    ): KeyPairBytes {
        if (!payload.containsKey(seedField) || !payload.containsKey(publicKeyField)) {
            throw WalletInvalidContainerException()
        }
        val seed = payload[seedField] as? ByteArray ?: throw WalletInvalidContainerException()
        val publicKey = payload[publicKeyField] as? ByteArray ?: throw WalletInvalidContainerException()
        if (seed.size != AndroidIdentityCrypto.KEY_BYTES || publicKey.size != AndroidIdentityCrypto.KEY_BYTES) {
            throw WalletInvalidContainerException()
        }
        val derived = AndroidIdentityCrypto.publicKeyFromSeed(seed)
        val matches = AndroidIdentityCrypto.equalPublicKeys(derived, publicKey)
        derived.fill(0)
        if (!matches) throw WalletInvalidContainerException()
        return KeyPairBytes(seed, publicKey)
    }

    private fun optionalKeyPair(
        payload: Map<String, Any?>,
        seedField: String,
        publicKeyField: String,
    ): KeyPairBytes? {
        val hasSeed = payload.containsKey(seedField)
        val hasPublicKey = payload.containsKey(publicKeyField)
        if (!hasSeed && !hasPublicKey) return null
        if (!hasSeed || !hasPublicKey) throw WalletInvalidContainerException()
        return requiredKeyPair(payload, seedField, publicKeyField)
    }

    private data class KeyPairBytes(val seed: ByteArray, val publicKey: ByteArray)
}

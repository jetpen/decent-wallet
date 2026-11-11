package org.decentwallet.wallet.android

import java.math.BigInteger
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.SecureRandom
import java.util.Base64

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
        val normalizedPayload = payload.toMutableMap()
        if (normalizedPayload.containsKey(MASTER_ACCOUNT_ENTITY_KEY)) {
            val entity = normalizedPayload[MASTER_ACCOUNT_ENTITY_KEY] as? Map<*, *>
                ?: throw WalletInvalidContainerException()
            normalizedPayload[MASTER_ACCOUNT_ENTITY_KEY] = copyMasterAccountEntity(entity)
        }
        val created = ContainerCrypto.create(password, confirmation, normalizedPayload)
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

    fun importContainer(path: Path, data: ByteArray, password: String): WalletSession =
        importContainerAt(path, data, password, System.currentTimeMillis() / 1000)

    internal fun importContainerAt(
        path: Path,
        data: ByteArray,
        password: String,
        nowEpochSeconds: Long,
    ): WalletSession {
        validatePasswordForOpen(password)
        if (data.size > ContainerCrypto.MAX_CONTAINER_BYTES || nowEpochSeconds < 1) {
            throw WalletInvalidContainerException()
        }
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
            val approval = opened.payload[PENDING_ACCOUNT_APPROVAL_KEY]
            if (approval != null) {
                val pending = parsePendingAccountApproval(approval)
                if (pending.approvedAtEpochSeconds <= nowEpochSeconds &&
                    pending.expiresAtEpochSeconds > nowEpochSeconds
                ) throw WalletDisclosureRequestException()
            }
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

private const val MASTER_ACCOUNT_ENTITY_KEY = "master_account_entity"
private const val PENDING_ACCOUNT_APPROVAL_KEY = "pending_account_disclosure_approval"
private const val MASTER_ACCOUNT_ENTITY_MAX_DEPTH = 64

internal fun decodeNativeContinuationCapability(
    encodedCapability: String,
    decoder: (String) -> ByteArray,
): ByteArray {
    if (encodedCapability.length != 43) throw WalletDisclosureRequestException()
    val capabilityBytes = try {
        decoder(encodedCapability)
    } catch (_: Exception) {
        throw WalletDisclosureRequestException()
    }
    try {
        if (capabilityBytes.size != 32 ||
            Base64.getUrlEncoder().withoutPadding().encodeToString(capabilityBytes) != encodedCapability
        ) throw WalletDisclosureRequestException()
        return capabilityBytes
    } catch (failure: Exception) {
        capabilityBytes.fill(0)
        if (failure is WalletDisclosureRequestException) throw failure
        throw WalletDisclosureRequestException()
    }
}

private fun copyMasterAccountEntity(values: Map<*, *>): MutableMap<String, Any?> {
    val active = java.util.Collections.newSetFromMap(java.util.IdentityHashMap<Any, Boolean>())

    fun copyValue(value: Any?, depth: Int): Any? {
        if (depth > MASTER_ACCOUNT_ENTITY_MAX_DEPTH) throw WalletInvalidContainerException()
        return when (value) {
            null, is Boolean, is String, is BigInteger, is Byte, is Short, is Int, is Long -> value
            is List<*> -> {
                if (!active.add(value)) throw WalletInvalidContainerException()
                try {
                    value.map { copyValue(it, depth + 1) }
                } finally {
                    active.remove(value)
                }
            }
            is Map<*, *> -> {
                if (!active.add(value)) throw WalletInvalidContainerException()
                try {
                    val result = LinkedHashMap<String, Any?>()
                    for ((key, child) in value) {
                        val name = key as? String ?: throw WalletInvalidContainerException()
                        result[name] = copyValue(child, depth + 1)
                    }
                    result
                } finally {
                    active.remove(value)
                }
            }
            else -> throw WalletInvalidContainerException()
        }
    }

    @Suppress("UNCHECKED_CAST")
    return copyValue(values, 0) as? MutableMap<String, Any?>
        ?: throw WalletInvalidContainerException()
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
    private var latestDisclosureReview: AccountDisclosureReview? = null
    private val activeWalletLoginChallenges = mutableSetOf<String>()

    private companion object {
        const val MAX_LOGIN_CHALLENGE_LIFETIME_SECONDS = 300L
    }

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

    fun createWalletLoginProofRequest(
        challenge: String,
        identityId: String,
        expiresAtEpochSeconds: Long,
        consent: (String, String) -> Boolean,
    ): WalletLoginProofRequest {
        val challengeKey = reserveLoginProofChallenge(challenge, identityId, expiresAtEpochSeconds)
        try {
            val profile = "decent-wallet-login-v1"
            if (!isApprovedLoginConsent(consent, profile, identityId)) {
                throw WalletLoginProofRejectedException()
            }
            synchronized(this) {
                ensureUnlocked()
                if (walletPayload?.containsKey("rotation_dispatch_intent") == true || activeOwnerKeyRotationPermit != null) {
                    throw WalletRotationInProgressException()
                }
                if (System.currentTimeMillis() / 1000 >= expiresAtEpochSeconds) {
                    throw WalletLoginProofRejectedException()
                }
                return signLoginProof(profile, challenge, identityId)
            }
        } catch (failure: Exception) {
            synchronized(this) { activeWalletLoginChallenges.remove(challengeKey) }
            throw failure
        }
    }

    private fun reserveLoginProofChallenge(
        challenge: String,
        identityId: String,
        expiresAtEpochSeconds: Long,
    ): String {
        val now = System.currentTimeMillis() / 1000
        if (expiresAtEpochSeconds <= now || expiresAtEpochSeconds - now > MAX_LOGIN_CHALLENGE_LIFETIME_SECONDS) {
            throw WalletLoginProofRejectedException()
        }
        val challengeBytes = StrictWalletLoginJson.parseBase64Url(challenge, 32)
        val identityBytes = try {
            encodeExactIdentityId(identityId)
        } catch (_: Exception) {
            challengeBytes.fill(0)
            throw WalletLoginProofRejectedException()
        }
        val challengeKey = Base64.getUrlEncoder().withoutPadding().encodeToString(challengeBytes)
        challengeBytes.fill(0)
        identityBytes.fill(0)
        synchronized(this) {
            ensureUnlocked()
            if (walletPayload?.containsKey("rotation_dispatch_intent") == true || activeOwnerKeyRotationPermit != null) {
                throw WalletRotationInProgressException()
            }
            if (!activeWalletLoginChallenges.add(challengeKey)) throw WalletLoginProofRejectedException()
        }
        return challengeKey
    }

    private fun encodeExactIdentityId(identityId: String): ByteArray =
        StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(java.nio.CharBuffer.wrap(identityId))
            .let { encoded -> ByteArray(encoded.remaining()).also(encoded::get) }

    private fun isApprovedLoginConsent(
        consent: (String, String) -> Boolean,
        profile: String,
        identityId: String,
    ): Boolean = try {
        consent(profile, identityId)
    } catch (_: Exception) {
        false
    }

    private fun signLoginProof(profile: String, challenge: String, identityId: String): WalletLoginProofRequest {
        val active = requireActiveKeyPair(checkNotNull(walletPayload))
        val signingBytes = StrictWalletLoginJson.signingBytes(profile, challenge, identityId)
        var signature: ByteArray? = null
        try {
            signature = AndroidIdentityCrypto.sign(active.seed, signingBytes)
            if (signature.size != AndroidIdentityCrypto.SIGNATURE_BYTES) throw WalletSigningException()
            val encodedSignature = Base64.getUrlEncoder().withoutPadding().encodeToString(signature)
            return WalletLoginProofRequest(profile, challenge, identityId, encodedSignature)
        } finally {
            signingBytes.fill(0)
            signature?.fill(0)
        }
    }

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
    internal fun createVersionedOwnerKeyRotationDraft(
        ownerNameBytes: ByteArray,
        predecessorState: VerifiedIdentityState,
    ): VersionedOwnerKeyRotationDraft {
        ensureUnlocked()
        val payload = checkNotNull(walletPayload)
        if (payload.containsKey("rotation_dispatch_intent")) {
            throw WalletRotationInProgressException()
        }
        val active = requireActiveKeyPair(payload)
        val pending = optionalKeyPair(payload, "pending_private_seed", "pending_public_key")
            ?: throw WalletInvalidIdentityStateException()
        if (ownerNameBytes.isEmpty() || ownerNameBytes.size > IdentityCbor.MAX_ENCODED_BYTES ||
            AndroidIdentityCrypto.equalPublicKeys(active.publicKey, pending.publicKey)
        ) {
            throw WalletInvalidIdentityStateException()
        }
        val ownerNameSnapshot = ownerNameBytes.copyOf()
        return try {
            VersionedOwnerKeyRotation.createDraft(
                ownerNameBytes = ownerNameSnapshot,
                predecessorState = predecessorState,
                activeOwnerPublicKey = active.publicKey,
                pendingSeed = pending.seed,
                pendingPublicKey = pending.publicKey,
            )
        } finally {
            ownerNameSnapshot.fill(0)
        }
    }

    /** Explicit caller-consented local recovery only; no publication or dispatch capability. */
    @Synchronized
    fun bindLegacyRotationDispatchEnvironment(
        environment: String,
        consent: (OwnerKeyRotationDispatchIntent, String) -> Boolean,
    ): OwnerKeyRotationDispatchIntent {
        ensureUnlocked()
        val intent = ownerKeyRotationDispatchIntent ?: throw WalletInvalidIdentityStateException()
        if (intent.environment != null || !validRegistryEnvironment(environment)) {
            throw WalletInvalidIdentityStateException()
        }
        val approved = try { consent(intent, environment) } catch (_: Exception) {
            throw WalletInvalidIdentityStateException()
        }
        ensureUnlocked()
        if (!approved || ownerKeyRotationDispatchIntent != intent) throw WalletInvalidIdentityStateException()
        val bound = OwnerKeyRotationDispatchIntent.fromPayload(intent.toPayload() + ("environment" to environment))
        @Suppress("UNCHECKED_CAST")
        val candidate = WalletJson.copyPayload(checkNotNull(walletPayload)) as MutableMap<String, Any?>
        candidate["rotation_dispatch_intent"] = bound.toPayload()
        persistPayloadCandidate(candidate)
        return bound
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
        val expectedOwnerName = intent.ownerNameBytes
        val expectedPredecessor = intent.predecessorOwnerPublicKey
        val expectedSuccessor = intent.successorOwnerPublicKey
        val expectedPredecessorHash = intent.predecessorStateHash
        val expectedEnvelopeHash = intent.envelopeHash
        val envelope = publication.envelopeBytes
        val verifiedState = publication.verifiedCandidateState
        val verifiedOwnerName = verifiedState.ownerNameBytes
        val verifiedOwner = verifiedState.ownerPublicKey
        val verifiedPredecessorOwner = verifiedState.predecessorOwnerPublicKey
        val verifiedPredecessorHash = verifiedState.predecessorStateHash
        val verifiedEnvelope = verifiedState.envelopeBytes
        val verifiedEnvelopeHash = AndroidIdentityCrypto.sha256(verifiedEnvelope)
        val verifiedStateHash = verifiedState.stateHash
        var candidate: MutableMap<String, Any?>? = null
        try {
            if (!active.publicKey.contentEquals(expectedPredecessor) ||
                !pending.publicKey.contentEquals(expectedSuccessor) ||
                !verifiedOwnerName.contentEquals(expectedOwnerName) ||
                !verifiedOwner.contentEquals(expectedSuccessor) ||
                verifiedPredecessorOwner == null ||
                !verifiedPredecessorOwner.contentEquals(expectedPredecessor) ||
                verifiedPredecessorHash == null ||
                !verifiedPredecessorHash.contentEquals(expectedPredecessorHash) ||
                verifiedState.sequence != intent.sequence ||
                !verifiedEnvelope.contentEquals(envelope) ||
                !verifiedEnvelopeHash.contentEquals(expectedEnvelopeHash) ||
                verifiedStateHash.size != AndroidIdentityCrypto.KEY_BYTES
            ) {
                throw WalletInvalidIdentityStateException()
            }
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
            expectedOwnerName.fill(0)
            expectedPredecessor.fill(0)
            expectedSuccessor.fill(0)
            expectedPredecessorHash.fill(0)
            expectedEnvelopeHash.fill(0)
            verifiedOwnerName.fill(0)
            verifiedOwner.fill(0)
            verifiedPredecessorOwner?.fill(0)
            verifiedPredecessorHash?.fill(0)
            verifiedEnvelope.fill(0)
            verifiedEnvelopeHash.fill(0)
            verifiedStateHash.fill(0)
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
            val removedApproval = candidate.remove(PENDING_ACCOUNT_APPROVAL_KEY)
            WalletJson.clearByteArrays(removedApproval)
            persistPayloadCandidate(candidate)
            installed = true
            activeOwnerKeyRotationPermit = null
            latestDisclosureReview = null
        } finally {
            if (!installed) {
                WalletJson.clearByteArrays(candidate)
                candidate.clear()
            }
        }
    }

    @Synchronized
    fun setMasterAccountEntity(entity: Map<String, Any?>) {
        ensureUnlocked()
        clearExpiredPendingApproval(System.currentTimeMillis() / 1000)
        if (pendingApprovalRecord(checkNotNull(walletPayload)) != null) {
            throw WalletDisclosureRequestException()
        }
        val copiedEntity = copyMasterAccountEntity(entity)
        @Suppress("UNCHECKED_CAST")
        val candidate = WalletJson.copyPayload(checkNotNull(walletPayload)) as? MutableMap<String, Any?>
            ?: throw WalletInvalidContainerException()
        candidate[MASTER_ACCOUNT_ENTITY_KEY] = copiedEntity
        persistPayloadCandidate(candidate)
    }

    @Synchronized
    fun getMasterAccountEntity(): Map<String, Any?> {
        ensureUnlocked()
        val payload = checkNotNull(walletPayload)
        val entity = payload[MASTER_ACCOUNT_ENTITY_KEY] ?: return emptyMap()
        val values = entity as? Map<*, *> ?: throw WalletInvalidContainerException()
        return copyMasterAccountEntity(values)
    }

    fun reviewAccountDisclosure(
        rawContext: ByteArray,
        transactionHandle: String,
        expectedKeycloakIssuer: String,
        identityId: String,
    ): AccountDisclosureReview = reviewAccountDisclosureAt(
        rawContext, transactionHandle, expectedKeycloakIssuer, identityId, System.currentTimeMillis() / 1000,
    )

    internal fun reviewAccountDisclosureAt(
        rawContext: ByteArray,
        transactionHandle: String,
        expectedKeycloakIssuer: String,
        identityId: String,
        nowEpochSeconds: Long,
    ): AccountDisclosureReview {
        if (rawContext.isEmpty() || rawContext.size > WalletAccountDisclosureContextParser.MAX_CONTEXT_BYTES) {
            throw WalletDisclosureRequestException()
        }
        val contextBytes = rawContext.copyOf()
        val context = try {
            WalletAccountDisclosureContextParser.parse(
                contextBytes, transactionHandle, expectedKeycloakIssuer, nowEpochSeconds,
            )
        } finally {
            contextBytes.fill(0)
        }
        try {
            val identityBytes = encodeExactIdentityId(identityId)
            try {
                if (identityBytes.isEmpty()) throw WalletDisclosureRequestException()
            } finally {
                identityBytes.fill(0)
            }
        } catch (_: Exception) {
            throw WalletDisclosureRequestException()
        }
        return synchronized(this) {
            try {
                ensureUnlocked()
                val payload = checkNotNull(walletPayload)
                requireActiveKeyPair(payload)
                val entityValue = payload[MASTER_ACCOUNT_ENTITY_KEY] ?: emptyMap<String, Any?>()
                val entity = entityValue as? Map<*, *> ?: throw WalletDisclosureRequestException()
                val claims = context.claims.map { requested ->
                    val key = requested.id.substringAfterLast(':')
                    val value = entity[key]
                    val stringValue = when (value) {
                        null -> null
                        is String -> {
                            if (value.isEmpty() || strictUtf8ByteLength(value) > 1024) {
                                throw WalletDisclosureRequestException()
                            }
                            value
                        }
                        else -> throw WalletDisclosureRequestException()
                    }
                    if (requested.required && stringValue == null) throw WalletDisclosureRequestException()
                    AccountDisclosureClaimReview(requested.id, requested.required, stringValue)
                }
                AccountDisclosureReview(
                    context.keycloakIssuer, context.rpClientId, context.rpDisplayName,
                    context.rpOrigin, context.action, context.requestId, context.transactionId,
                    context.oidcNonce, context.purpose, claims, identityId, context.expiresAtEpochSeconds,
                ).also { latestDisclosureReview = it }
            } catch (failure: WalletDisclosureRequestException) {
                throw failure
            } catch (failure: WalletLockedException) {
                throw failure
            } catch (_: Exception) {
                throw WalletDisclosureRequestException()
            }
        }
    }

    internal fun approveAccountDisclosureAt(
        review: AccountDisclosureReview,
        approvedClaimIds: Set<String>,
        nowEpochSeconds: Long,
        currentTimeEpochSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
        consent: (AccountDisclosureReview) -> Boolean,
    ): PendingAccountApproval {
        val selected = try {
            approvedClaimIds.toSet()
        } catch (_: Exception) {
            throw WalletDisclosureRequestException()
        }
        val ownerKeySnapshot = synchronized(this) {
            ensureUnlocked()
            clearExpiredPendingApproval(nowEpochSeconds)
            val payload = checkNotNull(walletPayload)
            if (pendingApprovalRecord(payload) != null || !isCurrentDisclosureReview(review, payload) ||
                nowEpochSeconds < 1 || nowEpochSeconds > Long.MAX_VALUE - 300 ||
                review.expiresAtEpochSeconds <= nowEpochSeconds ||
                review.expiresAtEpochSeconds - nowEpochSeconds > 300
            ) {
                throw WalletDisclosureRequestException()
            }
            val ids = review.claims.map { it.id }
            if (ids.toSet().size != ids.size || !selected.all { it in ids } ||
                review.claims.any { it.required && it.id !in selected }
            ) {
                throw WalletDisclosureRequestException()
            }
            requireActiveKeyPair(payload).publicKey.copyOf()
        }
        val consented = try {
            consent(review)
        } catch (_: Exception) {
            ownerKeySnapshot.fill(0)
            throw WalletDisclosureRequestException()
        }
        if (!consented) {
            ownerKeySnapshot.fill(0)
            throw WalletDisclosureRequestException()
        }

        try {
            return synchronized(this) {
                ensureUnlocked()
                val commitTime = try {
                    currentTimeEpochSeconds()
                } catch (_: Exception) {
                    throw WalletDisclosureRequestException()
                }
                if (commitTime < nowEpochSeconds || commitTime < 1 || commitTime > Long.MAX_VALUE - 300 ||
                    review.expiresAtEpochSeconds <= commitTime
                ) {
                    throw WalletDisclosureRequestException()
                }
                clearExpiredPendingApproval(commitTime)
                val payload = checkNotNull(walletPayload)
                val currentKey = requireActiveKeyPair(payload).publicKey.copyOf()
                try {
                    if (pendingApprovalRecord(payload) != null ||
                        !currentKey.contentEquals(ownerKeySnapshot) ||
                        !isCurrentDisclosureReview(review, payload) ||
                        review.expiresAtEpochSeconds <= commitTime
                    ) {
                        throw WalletDisclosureRequestException()
                    }
                    val handleBytes = ByteArray(32).also(SecureRandom()::nextBytes)
                    val handle = try {
                        Base64.getUrlEncoder().withoutPadding().encodeToString(handleBytes)
                    } finally {
                        handleBytes.fill(0)
                    }
                    val expiresAt = minOf(review.expiresAtEpochSeconds, commitTime + 300)
                    @Suppress("UNCHECKED_CAST")
                    val candidate = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
                    candidate[PENDING_ACCOUNT_APPROVAL_KEY] =
                        approvalRecord(review, selected, handle, expiresAt, commitTime, currentKey)
                    persistPayloadCandidate(candidate)
                    val storedAt = try {
                        currentTimeEpochSeconds()
                    } catch (_: Exception) {
                        clearPendingAccountApproval()
                        throw WalletDisclosureRequestException()
                    }
                    if (storedAt < commitTime || storedAt >= expiresAt) {
                        clearPendingAccountApproval()
                        throw WalletDisclosureRequestException()
                    }
                    PendingAccountApproval(handle, expiresAt, commitTime)
                } finally {
                    currentKey.fill(0)
                }
            }
        } catch (failure: WalletContainerException) {
            throw failure
        } catch (_: Exception) {
            throw WalletDisclosureRequestException()
        } finally {
            ownerKeySnapshot.fill(0)
        }
    }

    /** Proposal-only Issue #53 persistence; this is not an adopted protocol-conformance API. */
    fun installNativeContinuationCapability(
        pending: PendingAccountApproval,
        encodedCapability: String,
        expiresAtEpochSeconds: Long,
    ) = synchronized(this) {
        ensureUnlocked()
        val capabilityBytes = decodeNativeContinuationCapability(encodedCapability) {
            Base64.getUrlDecoder().decode(it)
        }
        try {
            val now = System.currentTimeMillis() / 1000
            if (now < 1 || now > Long.MAX_VALUE - 300 || expiresAtEpochSeconds <= now) {
                throw WalletDisclosureRequestException()
            }
            val payload = checkNotNull(walletPayload)
            val record = pendingApprovalRecord(payload) ?: throw WalletDisclosureRequestException()
            val approval = pendingApprovalToDto(record)
            val presentation = record["presentation"] as? Map<*, *>
            if (approval.handle != pending.handle ||
                approval.expiresAtEpochSeconds != pending.expiresAtEpochSeconds ||
                approval.approvedAtEpochSeconds != pending.approvedAtEpochSeconds ||
                approval.expiresAtEpochSeconds <= now || record["proof_issued"] != true ||
                presentation?.get("state") != "approved" || record.containsKey("native_continuation") ||
                expiresAtEpochSeconds > minOf(approval.expiresAtEpochSeconds, now + 300)
            ) throw WalletDisclosureRequestException()
            @Suppress("UNCHECKED_CAST")
            val candidate = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
            try {
                @Suppress("UNCHECKED_CAST")
                val updatedRecord = candidate[PENDING_ACCOUNT_APPROVAL_KEY] as MutableMap<String, Any?>
                updatedRecord["native_continuation"] = linkedMapOf(
                    "capability" to capabilityBytes.copyOf(),
                    "expires_at" to BigInteger.valueOf(expiresAtEpochSeconds),
                )
                persistPayloadCandidate(candidate)
            } catch (failure: Exception) {
                WalletJson.clearByteArrays(candidate)
                candidate.clear()
                throw failure
            }
        } catch (failure: WalletContainerException) {
            throw failure
        } catch (_: Exception) {
            throw WalletDisclosureRequestException()
        } finally {
            capabilityBytes.fill(0)
        }
    }

    fun nativeContinuationCapability(pending: PendingAccountApproval): NativeContinuationCapability? = synchronized(this) {
        ensureUnlocked()
        val current = AtomicWalletFiles.read(path)
        val currentRevisionMatches = try { current.contentEquals(checkNotNull(rawContainer)) }
        finally { current.fill(0) }
        if (!currentRevisionMatches) {
            lock()
            throw WalletInvalidContainerException()
        }
        val now = System.currentTimeMillis() / 1000
        val payload = checkNotNull(walletPayload)
        val record = pendingApprovalRecord(payload) ?: throw WalletDisclosureRequestException()
        val approval = pendingApprovalToDto(record)
        val presentation = record["presentation"] as? Map<*, *>
        if (approval.handle != pending.handle ||
            approval.expiresAtEpochSeconds != pending.expiresAtEpochSeconds ||
            approval.approvedAtEpochSeconds != pending.approvedAtEpochSeconds ||
            approval.expiresAtEpochSeconds <= now || record["proof_issued"] != true ||
            presentation?.get("state") != "approved"
        ) throw WalletDisclosureRequestException()
        val saved = record["native_continuation"] as? Map<*, *> ?: return@synchronized null
        val expiresAt = when (val raw = saved["expires_at"]) {
            is BigInteger -> raw.toLong().also { if (BigInteger.valueOf(it) != raw) throw WalletDisclosureRequestException() }
            is Int -> raw.toLong()
            is Long -> raw
            else -> throw WalletDisclosureRequestException()
        }
        val bytes = saved["capability"] as? ByteArray ?: throw WalletDisclosureRequestException()
        if (expiresAt <= now) {
            @Suppress("UNCHECKED_CAST")
            val candidate = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
            var detachedCapability: ByteArray? = null
            try {
                val updated = candidate[PENDING_ACCOUNT_APPROVAL_KEY] as MutableMap<String, Any?>
                val continuation = updated.remove("native_continuation") as? Map<*, *>
                detachedCapability = continuation?.get("capability") as? ByteArray
                persistPayloadCandidate(candidate)
            } catch (failure: Exception) {
                WalletJson.clearByteArrays(candidate)
                candidate.clear()
                throw failure
            } finally {
                detachedCapability?.fill(0)
            }
            return@synchronized null
        }
        val remainingSeconds = expiresAt - now
        val monotonicNow = System.nanoTime()
        val monotonicExpiry = monotonicNow + remainingSeconds * 1_000_000_000L
        NativeContinuationCapability(expiresAt, monotonicExpiry, bytes)
    }

    fun createAccountLoginProof(
        pending: PendingAccountApproval,
        challenge: String,
    ): WalletLoginProofRequest = createAccountLoginProofAt(
        pending,
        challenge,
        System.currentTimeMillis() / 1000,
        currentTimeEpochSeconds = { System.currentTimeMillis() / 1000 },
    )

    internal fun createAccountLoginProofAt(
        pending: PendingAccountApproval,
        challenge: String,
        nowEpochSeconds: Long,
        currentTimeEpochSeconds: () -> Long = { nowEpochSeconds },
    ): WalletLoginProofRequest = synchronized(this) {
        ensureUnlocked()
        if (nowEpochSeconds < 1) throw WalletDisclosureRequestException()
        val startTime = try {
            currentTimeEpochSeconds()
        } catch (_: Exception) {
            throw WalletDisclosureRequestException()
        }
        if (startTime < nowEpochSeconds || startTime < 1) throw WalletDisclosureRequestException()
        val challengeBytes = try {
            StrictWalletLoginJson.parseBase64Url(challenge, AndroidIdentityCrypto.KEY_BYTES)
        } catch (_: Exception) {
            throw WalletDisclosureRequestException()
        }
        challengeBytes.fill(0)
        clearExpiredPendingApproval(startTime)
        val payload = checkNotNull(walletPayload)
        if (payload.containsKey("rotation_dispatch_intent") || activeOwnerKeyRotationPermit != null) {
            throw WalletRotationInProgressException()
        }
        val record = pendingApprovalRecord(payload) ?: throw WalletDisclosureRequestException()
        val storedApproval = pendingApprovalToDto(record)
        if (storedApproval.handle != pending.handle ||
            storedApproval.expiresAtEpochSeconds != pending.expiresAtEpochSeconds ||
            storedApproval.approvedAtEpochSeconds != pending.approvedAtEpochSeconds ||
            storedApproval.expiresAtEpochSeconds <= startTime || record["proof_issued"] != false
        ) throw WalletDisclosureRequestException()
        val review = record["review"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
        val identityId = review["identity_id"] as? String ?: throw WalletDisclosureRequestException()
        val currentKey = requireActiveKeyPair(payload).publicKey.copyOf()
        try {
            val approvedKey = record["owner_public_key"] as? ByteArray ?: throw WalletDisclosureRequestException()
            if (!currentKey.contentEquals(approvedKey)) {
                clearPendingAccountApproval()
                throw WalletDisclosureRequestException()
            }
            val proof = signLoginProof("decent-wallet-login-v1", challenge, identityId)
            val finishTime = try {
                currentTimeEpochSeconds()
            } catch (_: Exception) {
                throw WalletDisclosureRequestException()
            }
            if (finishTime < startTime || finishTime >= storedApproval.expiresAtEpochSeconds) {
                throw WalletDisclosureRequestException()
            }
            @Suppress("UNCHECKED_CAST")
            val candidate = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
            try {
                @Suppress("UNCHECKED_CAST")
                val updatedRecord = candidate[PENDING_ACCOUNT_APPROVAL_KEY] as? MutableMap<String, Any?>
                    ?: throw WalletDisclosureRequestException()
                updatedRecord["proof_issued"] = true
                updatedRecord["proof_challenge"] = challenge
                persistPayloadCandidate(candidate)
                proof
            } catch (failure: Exception) {
                WalletJson.clearByteArrays(candidate)
                candidate.clear()
                throw failure
            }
        } finally {
            currentKey.fill(0)
        }
    }

    fun prepareAccountPresentation(
        pending: PendingAccountApproval,
        ownerKeyBindingJws: String,
        issuerJwks: Map<*, *>,
        outerAuthorizationParameters: Map<*, *>,
        requestObjectJws: String,
        registration: TrustedWalletRelyingPartyRegistration,
    ): AccountPresentationSubmission = prepareAccountPresentationAt(
        pending,
        ownerKeyBindingJws,
        issuerJwks,
        outerAuthorizationParameters,
        requestObjectJws,
        registration,
        System.currentTimeMillis() / 1000,
        currentTimeEpochSeconds = { System.currentTimeMillis() / 1000 },
    )

    internal fun prepareAccountPresentationAt(
        pending: PendingAccountApproval,
        ownerKeyBindingJws: String,
        issuerJwks: Map<*, *>,
        outerAuthorizationParameters: Map<*, *>,
        requestObjectJws: String,
        registration: TrustedWalletRelyingPartyRegistration,
        nowEpochSeconds: Long,
        currentTimeEpochSeconds: () -> Long = { nowEpochSeconds },
    ): AccountPresentationSubmission {
        var invalidateApproval = false
        try {
            synchronized(this) {
                ensureUnlocked()
                if (nowEpochSeconds < 1 || currentTimeEpochSeconds() < nowEpochSeconds) {
                    throw WalletDisclosureRequestException()
                }
                clearExpiredPendingApproval(nowEpochSeconds)
                val payload = checkNotNull(walletPayload)
                val record = payload["pending_account_disclosure_approval"] as? MutableMap<String, Any?>
                    ?: throw WalletDisclosureRequestException()
                val approval = parsePendingAccountApproval(record)
                if (approval.handle != pending.handle || approval.expiresAtEpochSeconds != pending.expiresAtEpochSeconds ||
                    approval.approvedAtEpochSeconds != pending.approvedAtEpochSeconds || record["proof_issued"] != true
                ) throw WalletDisclosureRequestException()
                val rotation = payload["owner_key_rotation_latch"]
                if (rotation != null) throw WalletDisclosureRequestException()
                val review = record["review"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
                val presentationState = record["presentation"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
                if (presentationState["state"] != "approved" || presentationState["submission"] != null) {
                    throw WalletDisclosureRequestException()
                }
                invalidateApproval = true

                val context = WalletAccountDisclosureContext(
                    keycloakIssuer = review["keycloak_issuer"] as String,
                    rpClientId = review["rp_client_id"] as String,
                    rpDisplayName = review["rp_display_name"] as String,
                    rpOrigin = review["rp_origin"] as String,
                    action = review["action"] as String,
                    requestId = review["request_id"] as String,
                    transactionId = review["transaction_id"] as String,
                    oidcNonce = review["oidc_nonce"] as String,
                    purpose = review["purpose"] as String,
                    claims = (review["claims"] as List<*>).map { item ->
                        val claim = item as Map<*, *>
                        RequestedAccountClaim(claim["id"] as String, claim["required"] as Boolean)
                    },
                    expiresAtEpochSeconds = when (val expiry = review["request_expires_at"]) {
                        is BigInteger -> expiry.toLong()
                        is Long -> expiry
                        is Int -> expiry.toLong()
                        else -> throw WalletDisclosureRequestException()
                    },
                )
                val binding = WalletOwnerKeyBindingVerifier.verify(
                    ownerKeyBindingJws, issuerJwks, context, review["identity_id"] as String, nowEpochSeconds,
                )
                if (record["proof_challenge"] != binding.oidcNonce || binding.oidcNonce != context.oidcNonce) {
                    throw WalletDisclosureRequestException()
                }
                val keyPair = requireActiveKeyPair(payload)
                val ownerSeed = keyPair.seed.copyOf()
                val ownerPublicKey = keyPair.publicKey.copyOf()
                try {
                    if (Base64.getUrlEncoder().withoutPadding().encodeToString(ownerPublicKey) != binding.ownerKey.x ||
                        binding.ownerKeyThumbprint.isEmpty() || binding.identityId != review["identity_id"]
                    ) throw WalletDisclosureRequestException()
                    val request = WalletOid4vpRequestVerifier.verify(
                        outerAuthorizationParameters, requestObjectJws, registration, context,
                        ownerKeyBindingJws, binding, nowEpochSeconds,
                    )
                    if (request.responseUri != registration.responseUri || request.clientId != registration.clientId ||
                        request.action != context.action || request.requestId != context.requestId ||
                        request.transactionId != context.transactionId
                    ) throw WalletDisclosureRequestException()

                    val selectedIds = (review["selected_claim_ids"] as List<*>).map { it as String }
                    val selectedNames = selectedIds.map { it.substringAfterLast(':') }
                    val dcqlCredentials = request.dcqlQuery["credentials"] as List<*>
                    val dcqlCredential = dcqlCredentials.single() as Map<*, *>
                    val claimSets = dcqlCredential["claim_sets"] as List<*>
                    if (claimSets.none { (it as? List<*>)?.toSet() == selectedNames.toSet() }) {
                        throw WalletDisclosureRequestException()
                    }
                    val selectedValues = LinkedHashMap<String, Any?>()
                    val selectedClaims = review["selected_claims"] as List<*>
                    for (item in selectedClaims) {
                        val claim = item as Map<*, *>
                        val id = claim["id"] as String
                        if (id !in selectedIds) throw WalletDisclosureRequestException()
                        val value = claim["value"] as? String ?: throw WalletDisclosureRequestException()
                        if (strictUtf8ByteLength(value) > 1024) throw WalletDisclosureRequestException()
                        selectedValues[id] = value
                    }
                    if (selectedValues.keys != selectedIds.toSet()) throw WalletDisclosureRequestException()

                    val expiry = minOf(
                        approval.expiresAtEpochSeconds,
                        binding.expiresAtEpochSeconds,
                        request.expiresAtEpochSeconds,
                        nowEpochSeconds + 300,
                    )
                    if (expiry <= nowEpochSeconds) throw WalletDisclosureRequestException()
                    val credentialJtiBytes = randomPresentationJti()
                    val vpJtiBytes = randomPresentationJti()
                    try {
                        if (credentialJtiBytes.contentEquals(vpJtiBytes)) throw WalletDisclosureRequestException()
                        val encoder = Base64.getUrlEncoder().withoutPadding()
                        val credential = linkedMapOf<String, Any?>(
                            "profile" to "decent-account-disclosure-v1",
                            "credential_type" to "decent_account_assertion_v1",
                            "iss" to binding.identityId,
                            "sub" to binding.identityId,
                            "iat" to BigInteger.valueOf(nowEpochSeconds),
                            "exp" to BigInteger.valueOf(expiry),
                            "jti" to encoder.encodeToString(credentialJtiBytes),
                            "action" to context.action,
                            "rp_oidc_client_id" to context.rpClientId,
                            "request_id" to context.requestId,
                            "transaction_id" to context.transactionId,
                            "purpose" to context.purpose,
                            "owner_key_thumbprint" to binding.ownerKeyThumbprint,
                            "owner_binding_jti" to binding.jti,
                            "claims" to selectedValues,
                        )
                        val credentialJws = signWalletDisclosureJws(
                            "decent-account-credential+jwt", ownerSeed, ownerPublicKey, binding.ownerKeyThumbprint, credential,
                        )
                        val presentation = linkedMapOf<String, Any?>(
                            "profile" to "decent-account-disclosure-v1",
                            "iss" to binding.identityId,
                            "sub" to binding.identityId,
                            "aud" to request.clientId,
                            "nonce" to request.nonce,
                            "iat" to BigInteger.valueOf(nowEpochSeconds),
                            "exp" to BigInteger.valueOf(expiry),
                            "jti" to encoder.encodeToString(vpJtiBytes),
                            "vp" to mapOf(
                                "type" to listOf("decent_account_presentation_v1"),
                                "verifiableCredential" to listOf(credentialJws),
                            ),
                        )
                        val presentationJws = signWalletDisclosureJws(
                            "decent-account-presentation+jwt", ownerSeed, ownerPublicKey, binding.ownerKeyThumbprint, presentation,
                        )
                        WalletAccountPresentationVerifier.verify(
                            presentationJws, context, request, binding, selectedValues, nowEpochSeconds, expiry,
                        )
                        val bodyMap = mapOf(
                            "state" to request.state,
                            "vp_token" to mapOf("account" to listOf(presentationJws)),
                        )
                        val bodyBytes = walletDisclosureFormBody(bodyMap)
                        try {
                            val finalNow = currentTimeEpochSeconds()
                            if (finalNow < nowEpochSeconds || finalNow >= expiry) throw WalletDisclosureRequestException()
                            @Suppress("UNCHECKED_CAST")
                            val candidate = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
                            val updated = candidate["pending_account_disclosure_approval"] as MutableMap<String, Any?>
                            updated["presentation"] = linkedMapOf(
                                "state" to "prepared",
                                "submission" to linkedMapOf(
                                    "client_id" to request.clientId,
                                    "response_uri" to request.responseUri,
                                    "state" to request.state,
                                    "presentation_jws" to presentationJws,
                                    "body" to bodyBytes.copyOf(),
                                    "expires_at" to BigInteger.valueOf(expiry),
                                ),
                            )
                            persistPayloadCandidate(candidate)
                            val committedNow = currentTimeEpochSeconds()
                            if (committedNow < finalNow || committedNow >= expiry) {
                                clearPendingApprovalAfterExpiry()
                                throw WalletDisclosureRequestException()
                            }
                            invalidateApproval = false
                            return AccountPresentationSubmission(
                                pending, request.responseUri, request.state, presentationJws, bodyBytes,
                            )
                        } finally {
                            bodyBytes.fill(0)
                            WalletJson.clearByteArrays(bodyMap)
                        }
                    } finally {
                        credentialJtiBytes.fill(0)
                        vpJtiBytes.fill(0)
                    }
                } finally {
                    ownerSeed.fill(0)
                    ownerPublicKey.fill(0)
                }
            }
        } catch (failure: WalletContainerException) {
            if (invalidateApproval && failure !is WalletStorageOutcomeUnknownException &&
                failure !is WalletInvalidContainerException
            ) clearPendingApprovalSafely()
            throw failure
        } catch (_: Exception) {
            if (invalidateApproval) clearPendingApprovalSafely()
            throw WalletDisclosureRequestException()
        }
    }


    fun markAccountPresentationAmbiguous(pending: PendingAccountApproval): Boolean =
        markAccountPresentationAmbiguousAt(pending, System.currentTimeMillis() / 1000)

    internal fun markAccountPresentationAmbiguousAt(
        pending: PendingAccountApproval,
        nowEpochSeconds: Long,
    ): Boolean = synchronized(this) {
        ensureUnlocked()
        val now = nowEpochSeconds
        clearExpiredPendingApproval(now)
        val payload = checkNotNull(walletPayload)
        val record = pendingApprovalRecord(payload) ?: return false
        val approval = parsePendingAccountApproval(record)
        if (approval.handle != pending.handle || approval.expiresAtEpochSeconds != pending.expiresAtEpochSeconds ||
            approval.approvedAtEpochSeconds != pending.approvedAtEpochSeconds
        ) return false
        val presentation = record["presentation"] as? Map<*, *> ?: return false
        if (presentation["state"] == "ambiguous") return true
        if (presentation["state"] != "prepared") return false
        @Suppress("UNCHECKED_CAST")
        val candidate = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
        val updated = candidate["pending_account_disclosure_approval"] as MutableMap<String, Any?>
        val updatedPresentation = (updated["presentation"] as Map<*, *>).toMutableMap()
        updatedPresentation["state"] = "ambiguous"
        updated["presentation"] = updatedPresentation
        persistPayloadCandidate(candidate)
        true
    }

    fun getAccountPresentationRetry(
        pending: PendingAccountApproval,
        registration: TrustedWalletRelyingPartyRegistration,
    ): AccountPresentationSubmission = getAccountPresentationRetryAt(
        pending, registration, System.currentTimeMillis() / 1000,
    )

    internal fun getAccountPresentationRetryAt(
        pending: PendingAccountApproval,
        registration: TrustedWalletRelyingPartyRegistration,
        nowEpochSeconds: Long,
    ): AccountPresentationSubmission = synchronized(this) {
        ensureUnlocked()
        val current = AtomicWalletFiles.read(path)
        val currentRevisionMatches = try {
            current.contentEquals(checkNotNull(rawContainer))
        } finally {
            current.fill(0)
        }
        if (!currentRevisionMatches) {
            lock()
            throw WalletInvalidContainerException()
        }
        val now = nowEpochSeconds
        clearExpiredPendingApproval(now)
        val payload = checkNotNull(walletPayload)
        val record = pendingApprovalRecord(payload) ?: throw WalletDisclosureRequestException()
        val approval = parsePendingAccountApproval(record)
        if (approval.handle != pending.handle || approval.expiresAtEpochSeconds != pending.expiresAtEpochSeconds ||
            approval.approvedAtEpochSeconds != pending.approvedAtEpochSeconds || record["proof_issued"] != true
        ) throw WalletDisclosureRequestException()
        val keyPair = requireActiveKeyPair(payload)
        val ownerPublicKey = keyPair.publicKey.copyOf()
        try {
            val storedKey = record["owner_public_key"] as? ByteArray ?: throw WalletDisclosureRequestException()
            if (!AndroidIdentityCrypto.equalPublicKeys(ownerPublicKey, storedKey)) throw WalletDisclosureRequestException()
            val presentation = record["presentation"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
            if (presentation["state"] != "ambiguous") throw WalletDisclosureRequestException()
            val saved = presentation["submission"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
            val responseUri = saved["response_uri"] as? String ?: throw WalletDisclosureRequestException()
            val clientId = saved["client_id"] as? String ?: throw WalletDisclosureRequestException()
            val state = saved["state"] as? String ?: throw WalletDisclosureRequestException()
            val jws = saved["presentation_jws"] as? String ?: throw WalletDisclosureRequestException()
            val body = saved["body"] as? ByteArray ?: throw WalletDisclosureRequestException()
            if (registration.clientId != clientId || registration.responseUri != responseUri ||
                (saved["expires_at"] as? BigInteger)?.let { it.toLong() }?.let { it <= now } != false
            ) throw WalletDisclosureRequestException()
            val expectedBody = walletDisclosureFormBody(mapOf(
                "state" to state,
                "vp_token" to mapOf("account" to listOf(jws)),
            ))
            try {
                if (!expectedBody.contentEquals(body)) throw WalletDisclosureRequestException()
                AccountPresentationSubmission(pending, responseUri, state, jws, body)
            } finally {
                expectedBody.fill(0)
            }
        } finally {
            ownerPublicKey.fill(0)
        }
    }

    fun recoverPendingAccountApproval(): PendingAccountApproval? =
        recoverPendingAccountApprovalAt(System.currentTimeMillis() / 1000)

    fun finishAccountPresentation(
        pending: PendingAccountApproval,
        outcome: PresentationDeliveryOutcome,
        statusCode: Int? = null,
        contentType: String? = null,
        responseBody: ByteArray? = null,
    ) = finishAccountPresentationAt(
        pending, outcome, statusCode, contentType, responseBody, System.currentTimeMillis() / 1000,
    )

    internal fun finishAccountPresentationAt(
        pending: PendingAccountApproval,
        outcome: PresentationDeliveryOutcome,
        statusCode: Int? = null,
        contentType: String? = null,
        responseBody: ByteArray? = null,
        nowEpochSeconds: Long,
    ) = synchronized(this) {
        ensureUnlocked()
        val current = AtomicWalletFiles.read(path)
        val currentRevisionMatches = try { current.contentEquals(checkNotNull(rawContainer)) }
        finally { current.fill(0) }
        if (!currentRevisionMatches) {
            lock()
            throw WalletInvalidContainerException()
        }
        clearExpiredPendingApproval(nowEpochSeconds)
        val payload = checkNotNull(walletPayload)
        val record = pendingApprovalRecord(payload) ?: throw WalletDisclosureRequestException()
        val approval = parsePendingAccountApproval(record)
        if (approval.handle != pending.handle || approval.expiresAtEpochSeconds != pending.expiresAtEpochSeconds ||
            approval.approvedAtEpochSeconds != pending.approvedAtEpochSeconds || approval.expiresAtEpochSeconds <= nowEpochSeconds ||
            record["proof_issued"] != true
        ) throw WalletDisclosureRequestException()
        val presentation = record["presentation"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
        if (presentation["state"] !in setOf("prepared", "ambiguous")) throw WalletDisclosureRequestException()
        val submission = presentation["submission"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
        val submissionExpiry = when (val expiry = submission["expires_at"]) {
            is BigInteger -> expiry.toLong().also {
                if (BigInteger.valueOf(it) != expiry) throw WalletDisclosureRequestException()
            }
            is Int -> expiry.toLong()
            is Long -> expiry
            else -> throw WalletDisclosureRequestException()
        }
        if (submissionExpiry <= nowEpochSeconds) throw WalletDisclosureRequestException()

        if (outcome == PresentationDeliveryOutcome.ACCEPTED) {
            if (statusCode != 200 || !isJsonMediaType(contentType) || responseBody == null ||
                responseBody.isEmpty() || responseBody.size > MAX_DIRECT_POST_RESPONSE_BYTES
            ) throw WalletDisclosureRequestException()
            val responseSnapshot = responseBody.copyOf()
            try { validateDirectPostAcceptance(responseSnapshot, record) }
            finally { responseSnapshot.fill(0) }
        } else if (statusCode != null || contentType != null || responseBody != null) {
            throw WalletDisclosureRequestException()
        }

        when (outcome) {
            PresentationDeliveryOutcome.AMBIGUOUS -> {
                if (presentation["state"] == "ambiguous") return@synchronized
                @Suppress("UNCHECKED_CAST")
                val candidate = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
                val updated = candidate["pending_account_disclosure_approval"] as MutableMap<String, Any?>
                val updatedPresentation = (updated["presentation"] as Map<*, *>).toMutableMap()
                updatedPresentation["state"] = "ambiguous"
                updated["presentation"] = updatedPresentation
                persistPayloadCandidate(candidate)
            }
            PresentationDeliveryOutcome.ACCEPTED,
            PresentationDeliveryOutcome.DEFINITIVE_FAILURE,
            PresentationDeliveryOutcome.CANCELLED -> {
                @Suppress("UNCHECKED_CAST")
                val candidate = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
                candidate.remove(PENDING_ACCOUNT_APPROVAL_KEY)
                persistPayloadCandidate(candidate)
            }
        }
    }

    internal fun recoverPendingAccountApprovalAt(nowEpochSeconds: Long): PendingAccountApproval? = synchronized(this) {
        ensureUnlocked()
        val current = AtomicWalletFiles.read(path)
        val currentRevisionMatches = try { current.contentEquals(checkNotNull(rawContainer)) }
        finally { current.fill(0) }
        if (!currentRevisionMatches) {
            lock()
            throw WalletInvalidContainerException()
        }
        clearExpiredPendingApproval(nowEpochSeconds)
        var record = pendingApprovalRecord(checkNotNull(walletPayload)) ?: return@synchronized null
        val presentation = record["presentation"] as? Map<*, *>
        if (presentation?.get("state") == "prepared") {
            @Suppress("UNCHECKED_CAST")
            val candidate = WalletJson.copyPayload(checkNotNull(walletPayload)) as MutableMap<String, Any?>
            val updated = candidate["pending_account_disclosure_approval"] as MutableMap<String, Any?>
            val updatedPresentation = (updated["presentation"] as Map<*, *>).toMutableMap()
            updatedPresentation["state"] = "ambiguous"
            updated["presentation"] = updatedPresentation
            persistPayloadCandidate(candidate)
            record = pendingApprovalRecord(checkNotNull(walletPayload)) ?: return@synchronized null
        }
        pendingApprovalToDto(record)
    }

    fun cancelAccountDisclosureApproval(pending: PendingAccountApproval): Boolean =
        cancelAccountDisclosureApprovalAt(pending, System.currentTimeMillis() / 1000)

    internal fun cancelAccountDisclosureApprovalAt(
        pending: PendingAccountApproval,
        nowEpochSeconds: Long,
    ): Boolean = synchronized(this) {
        ensureUnlocked()
        val now = nowEpochSeconds
        clearExpiredPendingApproval(now)
        val payload = checkNotNull(walletPayload)
        val record = pendingApprovalRecord(payload) ?: return@synchronized false
        val current = pendingApprovalToDto(record)
        if (current.handle != pending.handle) return@synchronized false
        @Suppress("UNCHECKED_CAST")
        val candidate = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
        candidate.remove(PENDING_ACCOUNT_APPROVAL_KEY)
        persistPayloadCandidate(candidate)
        true
    }

    private fun isCurrentDisclosureReview(review: AccountDisclosureReview, payload: Map<String, Any?>): Boolean {
        if (latestDisclosureReview !== review || payload.containsKey("rotation_dispatch_intent")) return false
        val entity = payload[MASTER_ACCOUNT_ENTITY_KEY] as? Map<*, *> ?: return false
        if (review.claims.isEmpty()) return false
        return review.claims.all { claim ->
            val current = entity[claim.id.substringAfterLast(':')]
            when (current) {
                null -> claim.value == null && !claim.required
                is String -> current.isNotEmpty() && strictUtf8ByteLength(current) <= 1024 && current == claim.value
                else -> false
            }
        } && review.claims.none { it.required && it.value == null }
    }

    private fun approvalRecord(
        review: AccountDisclosureReview,
        selected: Set<String>,
        handle: String,
        expiresAt: Long,
        approvedAt: Long,
        ownerPublicKey: ByteArray,
    ): Map<String, Any?> = linkedMapOf(
        "version" to 1,
        "handle" to handle,
        "approved_at" to approvedAt,
        "expires_at" to expiresAt,
        "owner_public_key" to ownerPublicKey.copyOf(),
        "proof_issued" to false,
        "proof_challenge" to null,
        "presentation" to linkedMapOf("state" to "approved", "submission" to null),
        "review" to linkedMapOf(
            "keycloak_issuer" to review.keycloakIssuer,
            "rp_client_id" to review.rpClientId,
            "rp_display_name" to review.rpDisplayName,
            "rp_origin" to review.rpOrigin,
            "action" to review.action,
            "request_id" to review.requestId,
            "transaction_id" to review.transactionId,
            "oidc_nonce" to review.oidcNonce,
            "purpose" to review.purpose,
            "identity_id" to review.identityId,
            "request_expires_at" to review.expiresAtEpochSeconds,
            "claims" to review.claims.map { mapOf("id" to it.id, "required" to it.required) },
            "selected_claim_ids" to selected.sorted(),
            "selected_claims" to review.claims.filter { it.id in selected }.map {
                mapOf("id" to it.id, "value" to it.value)
            },
        ),
    )

    private fun randomPresentationJti(): ByteArray = ByteArray(32).also { SecureRandom().nextBytes(it) }

    private fun signWalletDisclosureJws(
        type: String,
        seed: ByteArray,
        publicKey: ByteArray,
        ownerKeyThumbprint: String,
        payload: Map<String, Any?>,
    ): String {
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val headerBytes = WalletJson.canonicalBytes(mapOf(
            "alg" to "EdDSA",
            "kid" to ownerKeyThumbprint,
            "typ" to type,
        ))
        val payloadBytes = WalletJson.canonicalBytes(payload)
        val headerSegment = encoder.encodeToString(headerBytes)
        val payloadSegment = encoder.encodeToString(payloadBytes)
        val signingInput = "$headerSegment.$payloadSegment".toByteArray(StandardCharsets.US_ASCII)
        var signature: ByteArray? = null
        try {
            signature = AndroidIdentityCrypto.sign(seed, signingInput)
            return "$headerSegment.$payloadSegment.${encoder.encodeToString(signature)}"
        } finally {
            headerBytes.fill(0)
            payloadBytes.fill(0)
            signingInput.fill(0)
            signature?.fill(0)
        }
    }

    private fun walletDisclosureFormBody(fields: Map<String, Any?>): ByteArray {
        val state = fields["state"] as? String ?: throw WalletDisclosureRequestException()
        val vpToken = fields["vp_token"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
        val vpJsonBytes = WalletJson.canonicalBytes(vpToken)
        try {
            val vpJson = String(vpJsonBytes, StandardCharsets.UTF_8)
            val encoded = "state=${java.net.URLEncoder.encode(state, StandardCharsets.UTF_8)}" +
                "&vp_token=${java.net.URLEncoder.encode(vpJson, StandardCharsets.UTF_8)}"
            return encoded.toByteArray(StandardCharsets.US_ASCII)
        } finally {
            vpJsonBytes.fill(0)
        }
    }

    private fun clearPendingApprovalAfterExpiry() {
        if (dataEncryptionKey != null && walletPayload != null) clearPendingAccountApproval()
    }

    private fun clearPendingApprovalSafely() {
        try {
            synchronized(this) {
                if (dataEncryptionKey != null && walletPayload != null) clearPendingAccountApproval()
            }
        } catch (_: Exception) {
            // Preserve the original validation or signing failure.
        }
    }

    private fun pendingApprovalRecord(payload: Map<String, Any?>): Map<*, *>? {
        if (!payload.containsKey(PENDING_ACCOUNT_APPROVAL_KEY)) return null
        return payload[PENDING_ACCOUNT_APPROVAL_KEY] as? Map<*, *> ?: throw WalletDisclosureRequestException()
    }

    private fun pendingApprovalToDto(record: Map<*, *>): PendingAccountApproval =
        parsePendingAccountApproval(record)

    private fun clearExpiredPendingApproval(nowEpochSeconds: Long) {
        if (nowEpochSeconds < 1) throw WalletDisclosureRequestException()
        val record = pendingApprovalRecord(checkNotNull(walletPayload)) ?: return
        val approval = pendingApprovalToDto(record)
        if (approval.approvedAtEpochSeconds <= nowEpochSeconds &&
            approval.expiresAtEpochSeconds > nowEpochSeconds
        ) return
        clearPendingAccountApproval()
    }

    private fun clearPendingAccountApproval() {
        val payload = checkNotNull(walletPayload)
        if (!payload.containsKey(PENDING_ACCOUNT_APPROVAL_KEY)) return
        @Suppress("UNCHECKED_CAST")
        val candidate = WalletJson.copyPayload(payload) as MutableMap<String, Any?>
        candidate.remove(PENDING_ACCOUNT_APPROVAL_KEY)
        persistPayloadCandidate(candidate)
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
        clearExpiredPendingApproval(System.currentTimeMillis() / 1000)
        if (pendingApprovalRecord(checkNotNull(walletPayload)) != null) {
            throw WalletDisclosureRequestException()
        }
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
        latestDisclosureReview = null
        activeWalletLoginChallenges.clear()
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

private fun parsePendingAccountApproval(value: Any?): PendingAccountApproval {
    val record = value as? Map<*, *> ?: throw WalletDisclosureRequestException()
    val baseKeys = setOf(
        "version", "handle", "approved_at", "expires_at", "owner_public_key", "proof_issued",
        "proof_challenge", "review",
    )
    val keysWithPresentation = baseKeys + "presentation"
    val keysWithContinuation = baseKeys + "native_continuation"
    val keysWithBoth = keysWithPresentation + "native_continuation"
    if ((record.keys != baseKeys && record.keys != keysWithPresentation &&
            record.keys != keysWithContinuation && record.keys != keysWithBoth) ||
        record["version"] != BigInteger.ONE && record["version"] != 1
    ) throw WalletDisclosureRequestException()
    if (record.containsKey("presentation")) {
        val presentation = record["presentation"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
        if (presentation.keys != setOf("state", "submission")) throw WalletDisclosureRequestException()
        when (presentation["state"]) {
            "approved" -> if (presentation["submission"] != null) throw WalletDisclosureRequestException()
            "prepared", "ambiguous" -> {
                val submission = presentation["submission"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
                if (submission.keys != setOf("client_id", "response_uri", "state", "presentation_jws", "body", "expires_at") ||
                    submission["client_id"] !is String || submission["response_uri"] !is String || submission["state"] !is String ||
                    submission["presentation_jws"] !is String || submission["body"] !is ByteArray
                ) throw WalletDisclosureRequestException()
                val body = submission["body"] as ByteArray
                val token = submission["presentation_jws"] as String
                if (body.isEmpty() || body.size > 65_536 || token.isEmpty() || token.length > 16_384) {
                    throw WalletDisclosureRequestException()
                }
            }
            else -> throw WalletDisclosureRequestException()
        }
    }
    val handle = record["handle"] as? String ?: throw WalletDisclosureRequestException()
    val handleBytes = try { Base64.getUrlDecoder().decode(handle) } catch (_: Exception) {
        throw WalletDisclosureRequestException()
    }
    try {
        if (handleBytes.size != 32 || Base64.getUrlEncoder().withoutPadding().encodeToString(handleBytes) != handle) {
            throw WalletDisclosureRequestException()
        }
    } finally {
        handleBytes.fill(0)
    }
    fun exactLong(input: Any?): Long = try {
        when (input) {
            is BigInteger -> input.toLong().also {
                if (BigInteger.valueOf(it) != input) throw ArithmeticException()
            }
            is Int -> input.toLong()
            is Long -> input
            else -> throw WalletDisclosureRequestException()
        }
    } catch (_: ArithmeticException) {
        throw WalletDisclosureRequestException()
    }
    val approvedAt = exactLong(record["approved_at"])
    val expiresAt = exactLong(record["expires_at"])
    val ownerPublicKey = record["owner_public_key"] as? ByteArray ?: throw WalletDisclosureRequestException()
    val proofIssued = record["proof_issued"] as? Boolean ?: throw WalletDisclosureRequestException()
    val proofChallenge = record["proof_challenge"]
    if (ownerPublicKey.size != AndroidIdentityCrypto.KEY_BYTES ||
        if (proofIssued) proofChallenge !is String else proofChallenge != null
    ) throw WalletDisclosureRequestException()
    if (proofIssued) {
        val challengeBytes = try {
            StrictWalletLoginJson.parseBase64Url(proofChallenge as String, AndroidIdentityCrypto.KEY_BYTES)
        } catch (_: Exception) {
            throw WalletDisclosureRequestException()
        }
        challengeBytes.fill(0)
    }
    val review = record["review"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
    val reviewKeys = setOf(
        "keycloak_issuer", "rp_client_id", "rp_display_name", "rp_origin", "action", "request_id",
        "transaction_id", "oidc_nonce", "purpose", "identity_id", "request_expires_at", "claims",
        "selected_claim_ids", "selected_claims",
    )
    val stringFields = reviewKeys - setOf("request_expires_at", "claims", "selected_claim_ids", "selected_claims")
    if (review.keys != reviewKeys || stringFields.any { review[it] !is String } ||
        review["action"] !in setOf("signup", "signup_recovery")
    ) throw WalletDisclosureRequestException()
    val requestExpiry = exactLong(review["request_expires_at"])
    if (approvedAt < 1 || approvedAt > Long.MAX_VALUE - 300 ||
        expiresAt <= approvedAt || expiresAt > approvedAt + 300 || requestExpiry < expiresAt
    ) {
        throw WalletDisclosureRequestException()
    }
    val presentation = record["presentation"] as? Map<*, *>
    if (record.containsKey("native_continuation")) {
        val continuation = record["native_continuation"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
        if (continuation.keys != setOf("capability", "expires_at") || !proofIssued ||
            presentation?.get("state") != "approved"
        ) throw WalletDisclosureRequestException()
        val capability = continuation["capability"] as? ByteArray ?: throw WalletDisclosureRequestException()
        val capabilityExpiry = exactLong(continuation["expires_at"])
        if (capability.size != 32 || capabilityExpiry <= approvedAt ||
            capabilityExpiry > minOf(expiresAt, approvedAt + 300)
        ) throw WalletDisclosureRequestException()
    }
    if (presentation != null && presentation["state"] != "approved") {
        val submission = presentation["submission"] as Map<*, *>
        val presentationExpiry = exactLong(submission["expires_at"])
        val responseUri = submission["response_uri"] as String
        val requestState = submission["state"] as String
        if (presentationExpiry <= approvedAt || presentationExpiry > expiresAt ||
            responseUri.length > 2048 || requestState.isEmpty() || requestState.length > 128
        ) throw WalletDisclosureRequestException()
    }
    val claims = review["claims"] as? List<*> ?: throw WalletDisclosureRequestException()
    if (claims.isEmpty() || claims.size > 16) throw WalletDisclosureRequestException()
    val requested = LinkedHashMap<String, Boolean>()
    for (item in claims) {
        val claim = item as? Map<*, *> ?: throw WalletDisclosureRequestException()
        if (claim.keys != setOf("id", "required")) throw WalletDisclosureRequestException()
        val id = claim["id"] as? String ?: throw WalletDisclosureRequestException()
        val required = claim["required"] as? Boolean ?: throw WalletDisclosureRequestException()
        if (!id.startsWith("urn:decent:account:v1:") || requested.put(id, required) != null) {
            throw WalletDisclosureRequestException()
        }
    }
    val selectedIdsList = review["selected_claim_ids"] as? List<*> ?: throw WalletDisclosureRequestException()
    val selectedIds = selectedIdsList.map { it as? String ?: throw WalletDisclosureRequestException() }
    if (selectedIds.toSet().size != selectedIds.size || !requested.keys.containsAll(selectedIds) ||
        !selectedIds.containsAll(requested.filterValues { it }.keys)
    ) throw WalletDisclosureRequestException()
    val selectedClaims = review["selected_claims"] as? List<*> ?: throw WalletDisclosureRequestException()
    val selectedValues = LinkedHashMap<String, String?>()
    for (item in selectedClaims) {
        val claim = item as? Map<*, *> ?: throw WalletDisclosureRequestException()
        if (claim.keys != setOf("id", "value")) throw WalletDisclosureRequestException()
        val id = claim["id"] as? String ?: throw WalletDisclosureRequestException()
        val raw = claim["value"]
        if (id !in selectedIds) throw WalletDisclosureRequestException()
        val claimValue = when (raw) {
            null -> null
            is String -> raw
            else -> throw WalletDisclosureRequestException()
        }
        if (claimValue != null && (claimValue.isEmpty() || strictUtf8ByteLength(claimValue) > 1024)) {
            throw WalletDisclosureRequestException()
        }
        if (selectedValues.containsKey(id)) throw WalletDisclosureRequestException()
        selectedValues[id] = claimValue
    }
    if (selectedValues.keys != selectedIds.toSet() ||
        selectedIds.any { requested[it] == true && selectedValues[it] == null }
    ) throw WalletDisclosureRequestException()
    return PendingAccountApproval(handle, expiresAt, approvedAt)
}

private const val MAX_DIRECT_POST_RESPONSE_BYTES = 16 * 1024

private fun validateDirectPostAcceptance(responseBody: ByteArray, record: Map<*, *>) {
    val response = try {
        WalletJson.parse(responseBody, MAX_DIRECT_POST_RESPONSE_BYTES) as? Map<*, *>
            ?: throw WalletDisclosureRequestException()
    } catch (_: Exception) { throw WalletDisclosureRequestException() }
    val uriText = response["redirect_uri"] as? String ?: throw WalletDisclosureRequestException()
    if (uriText.isEmpty()) throw WalletDisclosureRequestException()
    val uri = try { java.net.URI(uriText) } catch (_: Exception) { throw WalletDisclosureRequestException() }
    val review = record["review"] as? Map<*, *> ?: throw WalletDisclosureRequestException()
    val rpOrigin = review["rp_origin"] as? String ?: throw WalletDisclosureRequestException()
    val responseOrigin = "${uri.scheme?.lowercase() ?: ""}://${uri.rawAuthority ?: ""}"
    if (!uri.isAbsolute || uri.rawAuthority == null || uri.rawUserInfo != null ||
        uri.rawQuery != null || responseOrigin != rpOrigin
    ) throw WalletDisclosureRequestException()
    val fragment = uri.rawFragment ?: throw WalletDisclosureRequestException()
    val fields = fragment.split('&')
    if (fields.size != 1) throw WalletDisclosureRequestException()
    val separator = fields[0].indexOf('=')
    if (separator <= 0) throw WalletDisclosureRequestException()
    val key = try { java.net.URLDecoder.decode(fields[0].substring(0, separator), "UTF-8") }
    catch (_: Exception) { throw WalletDisclosureRequestException() }
    val code = try { java.net.URLDecoder.decode(fields[0].substring(separator + 1), "UTF-8") }
    catch (_: Exception) { throw WalletDisclosureRequestException() }
    if (key != "response_code" || code.isEmpty() || code.any { it !in 'A'..'Z' && it !in 'a'..'z' && it !in '0'..'9' && it != '_' && it != '-' }) {
        throw WalletDisclosureRequestException()
    }
    val decoded = try { Base64.getUrlDecoder().decode(code) }
    catch (_: Exception) { throw WalletDisclosureRequestException() }
    try {
        if (decoded.size != 32 || Base64.getUrlEncoder().withoutPadding().encodeToString(decoded) != code) {
            throw WalletDisclosureRequestException()
        }
    } finally {
        decoded.fill(0)
    }
}

private fun isJsonMediaType(value: String?): Boolean {
    if (value == null || value.any { it.code > 0x7f }) return false
    var index = 0
    fun skipWhitespace() { while (index < value.length && (value[index] == ' ' || value[index] == '\t')) index++ }
    fun isToken(c: Char): Boolean = c.isLetterOrDigit() && c.code < 128 ||
        c in "!#$%&'*+-.^_`|~"
    fun readToken(): String? {
        val start = index
        while (index < value.length && isToken(value[index])) index++
        return if (index == start) null else value.substring(start, index)
    }
    skipWhitespace()
    if (index + "application/json".length > value.length ||
        !value.regionMatches(index, "application/json", 0, "application/json".length, ignoreCase = true)
    ) return false
    index += "application/json".length
    skipWhitespace()
    while (index < value.length) {
        if (value[index++] != ';') return false
        skipWhitespace()
        if (readToken() == null) return false
        skipWhitespace()
        if (index >= value.length || value[index++] != '=') return false
        skipWhitespace()
        if (index < value.length && value[index] == '"') {
            index++
            var closed = false
            while (index < value.length) {
                val c = value[index++]
                when {
                    c == '"' -> { closed = true; break }
                    c == '\\' -> {
                        if (index >= value.length) return false
                        val escaped = value[index++]
                        if ((escaped.code < 0x20 && escaped != '\t') || escaped.code == 0x7f) return false
                    }
                    (c.code < 0x20 && c != '\t') || c.code == 0x7f -> return false
                }
            }
            if (!closed) return false
        } else if (readToken() == null) return false
        skipWhitespace()
    }
    return true
}

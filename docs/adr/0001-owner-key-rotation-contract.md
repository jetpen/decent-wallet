# ADR-0001: Identity owner-key rotation contract

**Status:** Accepted

**Scope:** Decent Wallet Issue #18 and the required `decent-registry` wire support

## Context

The wallet requires owner-key rotation without changing the Identity's raw owner-name bytes or Registry lookup key. Existing Registry transitions do not permit this:

- Legacy updates verify the signature with the candidate `owner_public_key`; they cannot authenticate a changed key using the predecessor key.
- Version-1 ordinary updates and signer replacement enforce owner-key equality with the current state. Operation 3 changes signer membership, not `owner_public_key`.
- Operation 4 upgrades a legacy Identity to version 1, but requires the owner key to remain unchanged and included in the new 2-of-3 signer set.
- The authorization decoder accepts operations 1–4, and the version-1 envelope decoder accepts version 1 only. Its proof validator requires a non-empty text `signer_id` and sorts proof IDs as UTF-8; a legacy predecessor has no signer-set ID. Older Registry validators reject an unknown operation.
- The Registry's current `MultisignatureState` carries the candidate state but no predecessor chain, and transition validation reconstructs the current version-1 state from one standalone envelope. The DHT write path installs a version-1 candidate in the durable local store before awaiting the remote write; its getter may select that newer local value over the DHT response. A successful local read after a failed/ambiguous write is therefore not independent publication evidence.
- Existing version-1 validators require strictly increasing sequence values, not exactly `predecessor.seq + 1`; operation 5 must add the stricter check rather than reuse that condition unchanged.

The current Registry source checked for this decision is [`659bc42d1b1803e1a0b86ee6188aa8a349009be2`](https://github.com/jetpen/decent-registry/commit/659bc42d1b1803e1a0b86ee6188aa8a349009be2): [`encoding.py`](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/encoding.py#L68-L119), [`signed_envelope.py` proof validation/order](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/signed_envelope.py#L18-L52), [`signed_envelope.py` versioned envelope](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/signed_envelope.py#L109-L168), [`verification.py` legacy decoding and candidate-key verification](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/verification.py#L655-L696), [common v1 owner binding](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/verification.py#L491-L522), [operation 4 validation](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/verification.py#L699-L754), [transition dispatch](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/verification.py#L757-L800), [state type and predecessorless validation](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/verification.py#L36-L52) and [`#L547-L599`](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/verification.py#L547-L599), [record-validator dispatch](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/record_validator.py#L203-L224), and [DHT write-through/read selection](https://github.com/jetpen/decent-registry/blob/659bc42d1b1803e1a0b86ee6188aa8a349009be2/src/decent_registry/dht/libp2p_dht.py#L335-L358).

## Decision

Add authorization **operation 5, `owner-key-rotation`**, inside the existing version-1 `SignedUpdate` authorization map and version-1 `SignedEnvelope`. Keep the outer envelope version and map keys unchanged; the legacy-owner proof uses a null value for field 1 as defined below. The operation changes `Identity Record.owner_public_key` only; it preserves the exact owner-name byte string, derived Registry lookup key, Identity record kind, and state lineage. Signer-set replacement remains operation 3 and is not implied by owner-key rotation.

### Common transition invariants

- The candidate `owner_name_bytes` must equal the predecessor bytes exactly. Matching only `SHA-256(owner_name_bytes)` is insufficient for this operation.
- The candidate sequence is exactly `predecessor.seq + 1`.
- Authorization key 7 is the predecessor state hash: SHA-256 of the exact canonical predecessor `SignedUpdate` bytes.
- The transition is signed over SHA-256 of the exact canonical candidate `SignedUpdate` bytes.
- The predecessor chain must be complete and verified to the signed anchor before the transition is treated as current. Registry acceptance must authenticate that provenance; validating a standalone version-1 envelope against its embedded signer set does not establish that set as current.
- The Registry enforces the exact sequence increment for operation 5, not merely strict monotonicity.
- The Registry rejects owner-key changes for every operation other than operation 5. Wallets do not downgrade or silently fall back to a legacy update or operation 3.

### Legacy predecessor

Operation 5 can rotate directly from a verified legacy Identity. The candidate is a version-1 Identity state with epoch 1, threshold 2, and exactly three distinct successor signers. The new `owner_public_key` must be one of those signers. The two remaining signer public keys are installed as part of the successor signer set; they do not authorize the transition.

The predecessor owner key authorizes the candidate update with one Ed25519 signature. Its single version-1 proof entry uses `signer_id: null`, permitted only for operation 5 when the exact predecessor is a verified legacy Identity. The proof codec must handle null without applying the current text-only sort function; define its canonical sort key as empty bytes. The operation validator rejects null for every other operation or predecessor and requires exactly one proof in this branch. It verifies the signature against the predecessor's `owner_public_key`, not against the successor signer set. The new-key proof-of-possession is performed locally and is not included in the envelope.

### Version-1 predecessor

Operation 5 requires a verified version-1 predecessor and proofs meeting that predecessor's signer threshold. The Identity Record changes only `owner_public_key`; `seq` increments exactly once. The candidate authorization map selects operation 5 and binds the predecessor state hash. The predecessor signer set, threshold, and epoch remain identical. The successor owner key is not required to be in the unchanged signer set.

### Local proof-of-possession

Before dispatch, the wallet signs the exact canonical rotation `SignedUpdate` digest with the pending seed and verifies the result against the candidate owner public key. The signature is discarded locally and is never serialized into the Registry envelope, returned to the host, logged, or transmitted.

## Dispatch and finalization

The wallet retains the predecessor seed as active while the successor seed is pending. After predecessor authorization, local proof-of-possession, complete envelope construction, and fresh publication consent—but before any Registry write—the wallet atomically persists an encrypted dispatch intent containing the exact owner-name bytes, predecessor and successor public keys, predecessor state hash, sequence, and SHA-256 of the exact finalized envelope bytes.

Once this dispatch latch exists:

- the wallet blocks Identity signing and publication, cancellation, and republishing;
- a definitive pre-write rejection may clear the latch, leaving the successor pending for a new explicit attempt and fresh consent;
- any outcome that may have reached the Registry is `unknown`; both keys and the intent remain persisted, and only read-only confirmation is allowed;
- observing the predecessor state alone does not prove non-acceptance;
- no automatic retry, replacement, or rebase occurs.

The public-only `RegistryAdapter` issues an opaque `RotationConfirmation` only after a fresh remote DHT read validates the exact finalized envelope and verified predecessor chain, including the owner-name bytes, successor key, sequence, and predecessor hash. The read must bypass the client's local durable cache and must not rely on the write response or locally installed candidate. If the transport cannot provide this independent remote evidence, no confirmation capability is issued and the result remains `unknown`. `Wallet.finalize_signing_key_rotation(confirmation)` verifies that the capability binds the active predecessor and pending successor, then atomically persists the successor as active and clears the pending key and dispatch intent. It wipes predecessor secret buffers only after the durable write succeeds; a local persistence failure preserves the valid predecessor-plus-pending state. The wallet object and private material never cross into the Registry adapter.

## Rollout and consequences

`decent-registry` must implement and deploy operation 5 before any wallet publishes it. The Registry change must add the operation-specific owner-key transition, exact owner-name byte equality, legacy-predecessor proof validation (including parsing `signer_id: null` while accepting it only in this branch and preserving deterministic envelope validation), version-1 predecessor threshold validation with authenticated provenance to the signed anchor, exact sequence increment, state-hash checks, and rejection of owner-key changes under other operations. Registry read-back used to mint `RotationConfirmation` must perform a fresh remote DHT read that bypasses the local durable cache; a local write-through value or write result is not confirmation. Mixed or old validators fail closed; there is no fallback path.

This reuses the existing canonical SignedUpdate digest, authorization map, and version-1 envelope while requiring a coordinated protocol deployment. The direct legacy path intentionally transitions to the existing 2-of-3 version-1 policy; the version-1 path does not also mutate signer governance.

## Alternatives considered

- **Use operation 3:** rejected because it replaces signer membership while preserving `owner_public_key`; it is a different operation.
- **Use operation 4:** rejected because legacy upgrade requires the old owner key to remain unchanged and present in the new signer set; it cannot perform direct owner-key rotation.
- **Change the outer envelope version:** rejected because operation 5 fits the existing version-1 authorization map and a new wrapper version would add a decoder path without eliminating the need for predecessor-specific validation.
- **Use a legacy envelope signed by the successor:** rejected because legacy verification checks the candidate owner key and therefore does not prove authorization by the predecessor key.

## References

- [Wallet implementation specification, §10.2](../specs/wallet-implementation.md#102-owner-key-rotation)
- [Wallet CSRNG and Identity/Registry boundary research](../research/issue-3-csrng-signing-boundary.md)
- [Registry source commit used for compatibility analysis](https://github.com/jetpen/decent-registry/commit/659bc42d1b1803e1a0b86ee6188aa8a349009be2)

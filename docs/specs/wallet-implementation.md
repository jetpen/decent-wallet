# Decent Wallet Implementation Specification

Status: accepted MVP design with completed wallet storage, signing, Identity adapter, multisignature, and Python-core owner-key rotation publication/confirmation/finalization; format migration, native platform adapters, and cross-platform conformance remain incomplete

This document consolidates the accepted decisions from the wallet implementation wayfinder map, [Wallet implementation specification and security boundary](https://github.com/jetpen/decent-wallet/issues/1). It remains the contract for behavior not yet implemented; the repository now contains code-backed encrypted storage, CSRNG signing, a public-only Identity adapter, the local public-bundle multisignature workflow, and a two-phase owner-key rotation dispatch and promotion API. The Registry operation-5 validator and independent remote read-back support are implemented on `decent-registry` main at commit [`dde0730482076cd00e6f115bdd25f4534ae5e927`](https://github.com/jetpen/decent-registry/commit/dde0730482076cd00e6f115bdd25f4534ae5e927); production deployment and a concrete wallet transport adapter are not verified here. Wallet-container version 2 is current; version 1 is unsupported without migration under [ADR-0002](../adr/0002-wallet-container-v2-dispatch-intent.md).

## 1. Destination and scope

The wallet is the user-controlled custodian for private keys, the local signing component, and the consent agent. It must preserve the following boundaries:

- private keys and wallet secrets remain inside the wallet boundary;
- wallet storage is strongly encrypted and password-initialized;
- signing and disclosure require explicit, purpose-bound user consent;
- Identity/Registry receives only permitted public material and complete signed envelopes;
- multisignature workflows remain independent between signer wallets;
- authentication integration is protocol-neutral and site-specific;
- Registry/DHT storage, account/profile storage, site policy, and site sessions are external responsibilities.

This specification covers the wallet MVP across Android, iPhone, and an optional Podman-hosted laptop/desktop implementation. Platform-specific UI and storage adapters are permitted only when they preserve the contracts below.

## 2. Claim classes and current status

### Proposed MVP design

Format migration, platform-adapter/conformance, and security-acceptance requirements remain proposed implementation requirements derived from the accepted map decisions. The owner-key rotation contract in §10.2 is accepted. Exact encrypted-container export/import, pending-key preparation, wallet-local operation-5 draft/proof/envelope construction, and the wallet-core prepare/dispatch/confirm/promote flow are implemented as partial slices of Issue #18. They do not complete migration, native platform support, or cross-platform conformance.

### Researched but unimplemented

The established Identity/Registry toolchain provides the Ed25519, canonical-CBOR, signed-envelope, sequence, and finalized-publication contracts described in `docs/research/issue-3-csrng-signing-boundary.md`. Interactive consent UI, native platform adapters, a concrete production Registry/DHT transport for this wallet, and format migration remain unimplemented in this repository. The `decent-registry` main branch includes operation-5 validation and independent remote read-back at commit [`dde0730482076cd00e6f115bdd25f4534ae5e927`](https://github.com/jetpen/decent-registry/commit/dde0730482076cd00e6f115bdd25f4534ae5e927); this repository does not establish that support is deployed in any target environment.

### Implemented/code-backed

The repository currently provides:

- Argon2id and XChaCha20-Poly1305 encrypted wallet-container v2 with atomic persistence, authenticated format-version binding, password rewrapping, and lifecycle invalidation; version 1 and other unsupported versions are rejected without migration under ADR-0002;
- exact encrypted-container export/import in the Python core: export returns the existing bytes from an unlocked wallet; import authenticates and atomically writes the unchanged artifact only to an absent destination, without touching Registry state (Issue #18 partial);
- local owner-key rotation in the Python core: one CSRNG-generated successor seed is encrypted with the wallet container before its public key is returned; the active key remains unchanged, preparation is idempotent while a successor is pending, cancellation removes only the pending successor, and pending state survives reopen/export/import. The wallet constructs operation-5 drafts from verified legacy or version-1 predecessors, performs and discards the staged key's proof-of-possession signature, builds predecessor-authorized proofs, and locally finalizes canonical envelopes. `RegistryAdapter.prepare_owner_key_rotation_publication(bundle, ...)` requires an explicit supported-Registry transport flag and fresh remote read method, then obtains consent over the exact finalized envelope and rechecks the predecessor before returning a one-use public capability. `Wallet.latch_signing_key_rotation_dispatch_intent(bundle, publication)` persists the exact transition/hash before dispatch, blocks signing/cancellation/republishing, and returns a sealed process-local permit. `RegistryAdapter.dispatch_owner_key_rotation(publication, permit)` conditionally writes and requires fresh remote envelope read-back plus verified predecessor history; ambiguous outcomes remain latched, while a one-use adapter-issued pre-write rejection may clear the latch. `confirm_owner_key_rotation(intent)` supports read-only resolution after reopen. `Wallet.finalize_signing_key_rotation(confirmation)` promotes the pending seed only after matching adapter-issued confirmation and wipes the predecessor seed only after durable persistence. These are Python-core APIs over an injected transport, not a production Registry integration (Issue #18 partial);
- CSRNG-only Ed25519 generation and protocol-specific, one-operation signer capabilities;
- canonical Identity SignedUpdate validation and a public-only Identity adapter with immutable consent transcripts, atomic replay-nonce consumption, expiry checks, stale-state conditional writes, detached threshold proofs, and exact-envelope read-back confirmation;
- immutable public drafts and local CBOR proof bundles for independent legacy and version-1 signing, strict proof merge/threshold validation, finalization to the established envelope formats, conditional complete-envelope publication, and exact read-back confirmation. Bundle encoding is not a Registry/DHT wire format.

### Long-term vision

Hardware-backed non-exportable signing, multi-device synchronization, remote device revocation or wipe, password recovery, recovery phrases, escrow, cloud transfer, and additional site authentication protocols are outside the MVP.

## 3. Non-negotiable security invariants

1. A password, password-derived key, Ed25519 seed, private-key object, PEM/DER encoding, decrypted wallet payload, recovery secret, or secret-bearing diagnostic never leaves the wallet boundary.
2. No secret appears in a return value, representation, exception, traceback, log, diagnostic, crash artifact, metric, telemetry event, command argument, environment variable, temporary file, clipboard, network request, Registry/DHT value, or subprocess payload.
3. Key generation uses exactly 32 bytes from the approved OS-backed CSRNG. Provider exceptions, replacement, wrong types, and wrong lengths are fatal. There is no PRNG, deterministic, time-based, process-based, or legacy-generator fallback.
4. Every private-key operation is local, explicit, operation-scoped, and invalidated on use, cancellation, lock, backgrounding, timeout, or transcript mismatch.
5. Failed authentication, malformed data, stale state, interrupted writes, ambiguous publication, and insufficient multisignature authorization fail closed without partial accepted state.
6. Public outputs are limited to approved disclosures, public keys, canonical public records/envelopes, detached public proofs, non-secret hashes, stable result categories, and explicitly authorized metadata.
7. Managed-runtime memory clearing is best-effort. The implementation must minimize secret lifetime, use mutable buffers where practical, clear buffers where practical, release operation-scoped references, and document the limits of absolute zeroization.

## 4. Wallet components and authorities

### 4.1 Encrypted storage

Owns container creation, password verification, encryption/decryption, atomic replacement, migration, backup import/export, lock state, and operation-scoped secret lifetime.

### 4.2 Key and signer service

Owns CSRNG-only Ed25519 generation, local public-key derivation, typed private-key construction, one-operation signer capabilities, and protocol-specific signing of exact canonical Identity bytes. It exposes no generic arbitrary-message signer and no private-key export.

### 4.3 Consent and request service

Authenticates request origin metadata, constructs or validates canonical transcripts, presents non-secret request details, obtains per-item user consent, and returns explicit approval, denial, cancellation, expiry, or failure outcomes.

### 4.4 Identity/Registry adapter

Uses public codec and finalized-envelope interfaces. It may receive owner-name bytes, public keys, canonical signed-update bytes, signatures, complete envelopes, and non-secret request metadata. It never receives private-key bytes, private-key objects, passwords, paths to private material, or secret-bearing callbacks.

### 4.5 Local multisignature workflow

Creates drafts, signs exact canonical bytes locally, exchanges public bundles, merges proofs, verifies threshold rules, and finalizes only complete publishable envelopes. Partial bundles remain local artifacts.

### 4.6 Evidence plane

Produces values-free security-test receipts and non-secret result metadata. It is separate from wallet control state and never writes evidence to Registry/DHT or into the encrypted wallet payload unless explicitly defined as non-secret audit metadata.

## 5. Encrypted wallet container

The container is versioned and authenticated. The current wallet-container format is version 2. Outside ciphertext, it contains only the minimum envelope fields required for format recognition and unlock, such as the format version, KDF profile identifier and parameters, salt, wrapped-DEK metadata, encryption nonce, and authentication data required by the selected format. Private material and wallet metadata remain inside authenticated ciphertext. Version 1 is rejected; there is no compatibility or migration path in this implementation.

The MVP cryptographic profile is:

- Argon2id-derived 32-byte KEK;
- 64 MiB memory, `t=3`, `p=4`, and a 16-byte salt in the initial versioned profile;
- a randomly generated wallet DEK wrapped by the KEK;
- XChaCha20-Poly1305 authenticated encryption for the wallet payload;
- a versioned format identifier so parameters can be changed only through explicit migration; v2 authentication binds the format version.

The encrypted payload contains the typed 32-byte Ed25519 private input, public identity metadata, local signer state, pending rotation state and dispatch intent when present, and other wallet-local authorization state. It never contains Registry/DHT state as an authority or a plaintext backup of secrets outside the authenticated payload.

The owner must confirm a password of at least 16 characters. Arbitrary characters and passphrases are allowed without composition rules. There is no password reset or bypass in the MVP.

### 5.1 Unlock and lock

- Wrong passwords and authentication failures return a generic unlock-failed category.
- Unsupported formats and unavailable storage may return distinct stable non-secret categories.
- Lock occurs on explicit request, application backgrounding, or inactivity.
- The inactivity timeout is user-configurable from 1 to 15 minutes and defaults to 5 minutes.
- Backgrounding immediately clears operation-scoped secret material and cancels pending consent or signing with an explicit cancellation result.
- Progressive delay is bounded and must not become destructive lockout.
- Atomic writes preserve the previous valid container when a replacement fails.

## 6. Identity signing boundary

The wallet reuses the established Identity/Registry wire contract:

- Ed25519 with a 32-byte private input and 32-byte raw public key;
- canonical CBOR for signed updates and envelopes;
- the project signing message is `SHA-256(canonical SignedUpdate bytes)`;
- legacy single-owner output is a complete two-field signed envelope;
- version-1 output is a complete explicit-signer envelope;
- the Identity lookup key is derived from the raw owner-name UTF-8 bytes without normalization.

The wallet obtains or verifies the accepted Registry state before drafting. It derives the next sequence and, for version-1 transitions, the predecessor state together. It then obtains consent over immutable canonical bytes and signs only those exact bytes. Stale state, changed bytes, or changed authorization metadata causes rejection; the wallet never auto-rebases or silently re-signs.

The network-facing adapter receives only public material and a complete signed envelope or detached public proof. Registry remains responsible for canonical validation, signature validation, owner binding, sequence monotonicity, transition rules, and publication; the wallet adapter independently verifies the retained version-1 predecessor chain before treating a fetched state as current.

## 7. Consent and authentication-neutral requests

A signing or disclosure request is an immutable canonical transcript. It binds the applicable authenticated origin or domain, network/environment, contract or operation identifier, payload or artifact hash, purpose, requested capability, expiry, replay-protection data, and Identity sequence/generation when applicable. Identity consent callbacks also receive the exact non-secret canonical review payload bytes; the adapter verifies that their hash equals the transcript payload hash so the host UI can render the same bytes that are signed or published.

Consent is:

- explicit and active;
- purpose-bound;
- evaluated separately for each requested disclosure or capability;
- invalidated by lock, backgrounding, timeout, cancellation, transcript mismatch, or request expiry.

The wallet returns distinct `approved`, `denied`, `cancelled`, `expired`, `failed`, `dispatched`, `confirmed`, and `unknown` outcomes as applicable. Authentication proves control of an identity; it does not imply consent or site-resource authorization.

## 8. Signer capabilities

Only the storage/unlock subsystem may construct a signer from decrypted private material. Production APIs accept no seed, PEM/DER, filesystem path, or caller-supplied random provider.

The signer capability is opaque, wallet-owned, non-copyable, non-serializable, and scoped to one authorized protocol operation. It exposes the public key separately and exposes only the protocol-specific signing operation. It has no private-key export, string conversion, representation, callback, generic-message operation, or serialization method.

The signer validates canonical input before private-key use, computes the required digest internally, returns only the signature, and invalidates after use or cancellation and on lock/backgrounding.

## 9. Multisignature workflow

Each signer wallet independently reviews and signs the same exact canonical update. Wallets may create, exchange, merge, and verify public draft material outside Registry/DHT.

The workflow is:

1. create a local draft from immutable canonical bytes;
2. obtain purpose-bound consent;
3. create a detached local proof with one wallet-local signer capability;
4. exchange only public bundle data;
5. merge and validate proofs without importing private material;
6. require the configured threshold and operation-specific rules;
7. finalize one complete publishable envelope;
8. obtain fresh purpose-bound consent for the final publication, with an atomic deadline and replay nonce;
9. submit only the finalized envelope through the Registry adapter.

The public implementation uses `RegistryAdapter.create_draft()` and `sign_draft()`, immutable `IdentityDraft`, `IdentityProof`, and `IdentityBundle` values, `IdentityBundle.merge()` / `finalize()`, and `RegistryAdapter.publish_bundle()` / `confirm_bundle()`. Local draft/bundle CBOR v2 carries predecessor history and is separate from the unchanged legacy and version-1 Registry envelopes; v1 local bundles are accepted only when their history is sufficient to verify the transition. Exchanged proof metadata does not carry or control the final publication deadline. Publication compares the draft's predecessor state, consumes a fresh consent nonce, supplies an expected-state hash and deadline to the transport, and reads back the exact envelope through that injected transport. The current transport interface does not guarantee that the read is fresh or bypasses the Registry client's local durable cache; a transport may return a locally installed candidate after the remote write fails. Therefore, the existing generic confirmation result is not independent proof of remote acceptance unless the transport separately guarantees uncached remote reads. The accepted publication contract requires fresh remote bytes that bypass local durable cache and write-result state; without this evidence the outcome remains `unknown`. Operation-5 `RotationConfirmation` must use this stronger read path and cannot be minted from the generic cached read. Every non-genesis version-1 state requires exact predecessor-envelope lookup by state hash back to its signed anchor; missing or mismatched history is rejected. History walks are capped at 1,024 version-1 transitions and fail closed beyond that bound.

Partial, duplicate, out-of-order, revoked, conflicting, wrong-signer, wrong-bytes, and below-threshold proofs remain non-publishable. A disconnect or timeout after dispatch is `unknown` until independent read-back verifies the exact accepted target. For owner-key rotation, both key states and the encrypted dispatch intent survive restart; while unresolved, the wallet permits only read-only confirmation and blocks Identity signing, cancellation, and republishing. Merely reading the predecessor state does not resolve an ambiguous write.

## 10. Key rotation and format migration

### 10.1 Password rewrap

An ordinary password change preserves the existing wallet DEK and encrypted payload. After successful unlock, the wallet derives the new KEK and atomically replaces only the KDF parameters, salt, and wrapped DEK. It does not regenerate signing keys or write Registry state.

### 10.2 Owner-key rotation

Owner-key rotation replaces `Identity Record.owner_public_key` while preserving the exact raw owner-name bytes, derived DHT lookup key, and state lineage. It is distinct from version-1 signer-set replacement (operation 3). The predecessor owner key authorizes a legacy transition; the predecessor signer threshold authorizes a version-1 transition. New-key proof-of-possession is local-only. See [ADR-0001](../adr/0001-owner-key-rotation-contract.md) for the accepted tradeoff and Registry compatibility rationale.

#### Accepted transition contract

The Registry wire change is authorization operation **5 (owner-key rotation)** within the existing version-1 `SignedUpdate` authorization map and version-1 `SignedEnvelope`; the outer envelope version and map keys do not change. The legacy-owner proof uses a null value for proof field 1 as defined below. The record remains an Identity with an empty payload. The candidate owner-name bytes must equal the predecessor bytes exactly—not merely hash to the same lookup key. `seq` is exactly `predecessor.seq + 1`. Authorization key 7 is the predecessor state hash, defined as SHA-256 of the exact canonical predecessor `SignedUpdate` bytes.

- **Legacy predecessor:** Verify the exact accepted legacy envelope and its owner signature. The new version-1 state has epoch 1, threshold 2, and exactly three distinct successor signers; the new owner key is one of those signers. One proof over the candidate canonical `SignedUpdate` is authorized by the predecessor owner key. Its single v1 proof entry has `signer_id: null`, permitted only for operation 5 with a verified legacy predecessor. The version-1 proof codec must handle null without applying the current text-only sort function; define its canonical sort key as empty bytes. The operation validator rejects null for every other operation or predecessor and requires exactly one proof in this branch. The other two successor public keys are part of the newly installed signer set; they do not replace predecessor authorization.
- **Version-1 predecessor:** Verify the complete predecessor chain and its current signer threshold. The Identity Record changes only `owner_public_key`; `seq` increments exactly once. The candidate authorization map selects operation 5 and binds the predecessor state hash. Preserve the predecessor signer set, threshold, and epoch exactly. The new owner key need not be a member of the unchanged signer set. Proofs use signer IDs from the predecessor set and meet its threshold.
- **New-key possession:** Before dispatch, the wallet signs the exact canonical rotation `SignedUpdate` digest with the pending seed and verifies the signature against the successor public key. This local proof is discarded and never included in the Registry envelope or returned to the host.

The existing version-1 signing message remains SHA-256 of canonical `SignedUpdate` bytes. The Registry validates operation 5, exact owner-name byte equality, predecessor authority, predecessor state hash, exact sequence increment, and rejection of owner-key changes under other operations. For a version-1 predecessor, a standalone envelope whose proofs validate against its embedded signer set is insufficient; Registry acceptance requires authenticated provenance for that signer set back to its signed anchor. The `decent-registry` main branch implements this transition in PR #109 and fresh independent remote read-back in PR #110, at commit [`dde0730482076cd00e6f115bdd25f4534ae5e927`](https://github.com/jetpen/decent-registry/commit/dde0730482076cd00e6f115bdd25f4534ae5e927). This is source status only; target deployment is not verified. Operation 5 never falls back to a legacy update or operation 3. A wallet transport must refuse dispatch unless it is connected to a Registry implementation that enforces this contract.

#### Local dispatch and finalization state machine

`Wallet.prepare_signing_key_rotation()` creates and atomically persists one encrypted pending successor while preserving the active key. `wallet.pending_signing_public_key` exposes only its public key; repeated preparation returns the existing pending public key. Cancellation is available only before a dispatch intent is latched.

`RegistryAdapter.prepare_owner_key_rotation_publication(bundle, ...)` first requires `transport.supports_owner_key_rotation is True` and a fresh remote-read method; unsupported transports fail before consent or wallet latching. The flag is a trusted transport configuration assertion, not a network handshake, and must be true only for a pinned Registry deployment known to validate operation 5. Preparation validates a complete bundle, checks the accepted predecessor, obtains fresh purpose-bound consent over the exact finalized envelope, then re-reads state and expiry. It returns `PublicationResult(status=READY, publication=...)` only when those checks pass; no write occurs during preparation. The application then calls `Wallet.latch_signing_key_rotation_dispatch_intent(bundle, publication)` to persist an encrypted intent binding exact owner-name bytes, predecessor/successor keys, predecessor state hash, sequence, and finalized-envelope hash. After durable persistence this method returns an opaque, process-local `RotationDispatchPermit`; the persisted `RotationDispatchIntent` alone is not dispatch authority. The caller passes the permit to `RegistryAdapter.dispatch_owner_key_rotation(publication, permit)`. The wallet object and private material are never passed to the adapter or transport.

Once latched, the wallet blocks Identity signing, cancellation, and republishing. The adapter's per-owner gate also blocks ordinary signing/submission and `publish_bundle()` while that adapter instance knows the rotation is unresolved; per-owner locking serializes the latch with conditional Identity writes. `dispatch_owner_key_rotation(publication, permit)` requires the ephemeral permit minted only after the encrypted intent has been durably written; a reconstructed intent from disk cannot be used to dispatch. The adapter rechecks the predecessor immediately before a conditional write, which must atomically enforce both the expected state hash and consent deadline. A known pre-write state/expiry/conditional rejection returns a one-use `RotationDispatchRejection`; `Wallet.resolve_signing_key_rotation_rejection(rejection)` may clear only the matching latch while preserving both keys, releasing the adapter gate only after the local write succeeds. Any other outcome that may have reached the Registry returns `unknown`, retains both keys and the intent, and permits only read-only confirmation. After reopening, before any other mutating adapter operation, the application must read the persisted intent and call `confirm_owner_key_rotation`; this installs the per-owner gate even when remote evidence is still unavailable. There is no dispatch permit or automatic retry after reopen. Observing only the predecessor does not prove non-acceptance. No replacement or rebase occurs.

`dispatch_owner_key_rotation` and the read-only `RegistryAdapter.confirm_owner_key_rotation(intent)` call the transport's required `get_remote_identity_envelope(owner_name_hex=...)` method. That method must return bytes from a fresh remote DHT response, bypassing local durable cache, write-through state, and write results. The adapter compares the exact envelope hash with the encrypted intent, validates the full predecessor chain using history-by-state-hash reads, and checks the owner-name bytes, predecessor/successor keys, sequence, and predecessor hash before issuing an opaque `RotationConfirmation`. If remote evidence is unavailable, malformed, stale, or mismatched, no capability is issued and the result remains `unknown`; reading only the predecessor never clears the latch. `Wallet.finalize_signing_key_rotation(confirmation)` accepts only that adapter-issued capability and verifies that it matches the active and pending wallet keys and persisted intent. It atomically persists the successor as active and clears the pending key and intent; predecessor secret buffers are wiped only after the durable write succeeds. A failed local write preserves the valid predecessor-plus-pending container. The wallet is never passed to the Registry adapter, and the adapter never receives private material.

The Python core implements local preparation/cancellation, operation-5 draft/proof-of-possession/predecessor-proof/envelope construction, consent-gated two-phase conditional dispatch, fresh remote confirmation, safe pre-write rejection resolution, and active-key promotion. `publish_bundle()` and `confirm_bundle()` continue to reject operation 5; callers must use the dedicated rotation flow, and a latched intent is never evidence of Registry acceptance. The injected transport is a protocol, not a production Registry/DHT adapter; the Registry main implementation is present at the commit cited above, but deployment is not verified. Migration, native platform adapters, and cross-platform conformance remain open for Issue #18. A suspected compromised device cannot be remotely erased through this workflow; rotation must be explicitly completed from a restored wallet.

### 10.3 Wallet-format migration and compatibility

Wallet-container v2 is the only supported format in this implementation. Version 1 and all other unsupported versions are rejected by open/import; no automatic or explicit v1 migration is provided. The repository owner explicitly accepted this compatibility break to ensure older implementations cannot ignore the dispatch-intent latch. This does not satisfy the broader current-plus-predecessor migration criterion in Issue #18; any future migration requires a separate contract.

## 11. Backup, portability, and platform adapters

Backup and portability use explicit export/import of the exact encrypted container:

- export never decrypts or re-encrypts the payload;
- import is accepted only by a new or uninitialized wallet;
- import requires the owner password and verifies format, version, and integrity; only container v2 is accepted and older versions are unsupported;
- no merge, overwrite, Registry publication, or Identity rollback occurs;
- the artifact is never disclosed to logs or the clipboard, intentionally persisted in general-purpose temporary storage, or placed in automatic synchronization. Atomic persistence uses a restrictive same-directory staging file for encrypted bytes. It is removed on success; failure paths attempt cleanup, though an unrecoverable filesystem unlink failure can leave an encrypted staging artifact.

The Python core exposes `Wallet.export_container() -> bytes` for exact bytes from an unlocked wallet and `Wallet.import_container(path, data, password, *, inactivity_minutes=5)` to authenticate and atomically create an imported wallet only at an absent destination. Import preserves the provided bytes and returns the new wallet unlocked. Pending rotation state and the dispatch intent are encrypted within v2 and preserved by exact export/import. Version-1 containers are rejected without migration. This implements the local portable-container and pending-key-preparation cores only; Registry publication, independent confirmation, key promotion, migration, native platform adapters, and cross-platform conformance remain incomplete under Issue #18.

Android, iPhone, and optional desktop/Podman implementations use the same portable container and cryptographic contract. OS keystores, desktop keyrings, and hardware facilities are optional defense-in-depth adapters and cannot be the only recovery path or alter the portable format. Hardware-backed non-exportable signing is deferred.

Only one active wallet copy is supported. An imported copy is an explicit snapshot, not a synchronized replica. Concurrent copies are not merged or auto-rebased. Device loss causes no automatic Registry mutation, remote wipe, or revocation. Without a valid encrypted backup and password, replacement recovery is impossible in the MVP.

Transfer occurs through an external user-controlled channel. The wallet does not provide cloud synchronization, automatic upload, device discovery, QR, Bluetooth, Wi-Fi Direct, clipboard, or temporary-file transfer in the MVP.

## 12. Security acceptance matrix

The following are mandatory release gates:

- secret leakage tests cover APIs, exceptions, representations, tracebacks, logs, diagnostics, telemetry, crash artifacts, arguments, environment variables, temporary files, and network/subprocess payloads;
- CSRNG exceptions, provider replacement, wrong types, wrong lengths, and malformed construction produce no fallback, output, container, or network request;
- wrong passwords, authentication failures, tampering, malformed containers, storage errors, and interrupted writes fail closed and preserve the last valid container;
- consent tests reject stale, expired, replayed, duplicated, reordered, origin-changed, network-changed, contract-changed, payload-changed, capability-changed, and signer-changed requests;
- signer capabilities invalidate on use, cancellation, lock, backgrounding, timeout, or mismatch;
- stale Registry state is rejected without auto-rebase or retry;
- partial and invalid multisignature material never enters publication;
- owner-key rotation tests cover legacy and version-1 predecessors, exact owner-name byte preservation, operation-5 state binding, predecessor authorization, the legacy-only null signer ID, and unchanged version-1 signer governance;
- the new-owner proof-of-possession is verified locally and never appears in any envelope, API result, log, or transport request;
- a latched rotation intent survives lock, process restart, and export/import; while unresolved, Identity signing, publication, cancellation, and retransmission are rejected;
- only an opaque adapter-issued confirmation of a fresh remote read that bypasses local durable cache/write-through state and validates the exact target envelope plus its verified predecessor chain may promote the successor; a readback showing only the predecessor leaves the result unknown;
- ambiguous dispatch remains `unknown` until independent read-back;
- all supported platforms pass shared semantic and wire-format vectors;
- failed, skipped, quarantined, or nondeterministic mandatory tests block MVP acceptance.

Tests use disposable wallets, ephemeral directories, synthetic test-only secrets, test-only keys, and zero-value/local Registry state. Evidence receipts contain no secret values or decrypted wallet contents. Ciphertext byte equality is not required across platforms because authenticated encryption is randomized; semantic results and canonical public artifacts must agree.

## 13. External responsibilities and handoff

Consuming site integrations define their own authentication protocol details, verifier responsibilities, and site authorization policy. They must call the wallet through the authentication-neutral request and consent boundary and must not obtain private material or bypass wallet consent.

Identity and Registry own public-record validation, sequence/state-transition validation, and DHT publication. `decent-registry` main implements version-1 authorization operation 5, legacy-predecessor verification, `signer_id: null` handling for that exact branch, byte-for-byte owner-name preservation, authenticated predecessor-chain provenance, and an independent remote read path that bypasses local durable cache (commit [`dde0730482076cd00e6f115bdd25f4534ae5e927`](https://github.com/jetpen/decent-registry/commit/dde0730482076cd00e6f115bdd25f4534ae5e927)). This repository provides only the wallet transport protocol; production transport integration and deployment of the Registry changes are not verified. Account/profile storage, site sessions, and a concrete Registry/DHT transport remain outside this wallet implementation.

## 14. Implementation sequencing

Implementation should proceed as vertical slices, each preserving the security invariants:

1. encrypted container creation, unlock, lock, atomic persistence, and tamper rejection (implemented, issue #14);
2. CSRNG-only Ed25519 generation and non-exporting signer capability (implemented, issue #15);
3. canonical Identity request construction, consent, sequence validation, and finalized-envelope adapter (implemented, issue #16);
4. local multisignature draft, proof, merge, finalize, and publication rejection paths (implemented, issue #17);
5. exact encrypted-container export/import, local pending-key preparation, operation-5 draft/proof/envelope construction, two-phase conditional dispatch, independent remote confirmation, latch resolution, and key promotion (implemented in the Python core as partial slices of Issue #18); current-plus-predecessor format migration, native platform adapters, and cross-platform conformance remain;
6. cross-platform conformance and the complete security acceptance matrix.

No slice may introduce a private-key export or a network-facing private-key boundary. The repository issue tracker should carry the implementation slices and their blocking relationships before code work begins.

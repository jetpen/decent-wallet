# Decent Wallet Implementation Specification

Status: implementation-ready MVP design with completed storage, signing, Identity adapter, and multisignature slices

This document consolidates the accepted decisions from the wallet implementation wayfinder map, [Wallet implementation specification and security boundary](https://github.com/jetpen/decent-wallet/issues/1). It remains the contract for behavior that is not yet implemented; the repository now contains code-backed encrypted storage, CSRNG signing, a public-only Identity adapter, and the local public-bundle multisignature workflow for the completed slices.

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

The remaining migration, signing-key rotation, platform-adapter/conformance, and security-acceptance requirements in this document are proposed implementation requirements derived from the accepted map decisions. Exact encrypted-container export/import is implemented in the Python core as a partial slice of Issue #18; it does not complete the broader portability, migration, or rotation scope.

### Researched but unimplemented

The established Identity/Registry toolchain provides the Ed25519, canonical-CBOR, signed-envelope, sequence, and finalized-publication contracts described in `docs/research/issue-3-csrng-signing-boundary.md`. Interactive consent UI, platform adapters, Registry/DHT transport implementations, key rotation, and format migration remain unimplemented in this repository.

### Implemented/code-backed

The repository currently provides:

- Argon2id and XChaCha20-Poly1305 encrypted wallet containers with atomic persistence, password rewrapping, and lifecycle invalidation;
- exact encrypted-container export/import in the Python core: export returns the existing bytes from an unlocked wallet; import authenticates and atomically writes the unchanged artifact only to an absent destination, without touching Registry state (Issue #18 partial);
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

The container is versioned and authenticated. Outside ciphertext, it contains only the minimum envelope fields required for format recognition and unlock, such as the format version, KDF profile identifier and parameters, salt, wrapped-DEK metadata, encryption nonce, and authentication data required by the selected format. Private material and wallet metadata remain inside authenticated ciphertext.

The MVP cryptographic profile is:

- Argon2id-derived 32-byte KEK;
- 64 MiB memory, `t=3`, `p=4`, and a 16-byte salt in the initial versioned profile;
- a randomly generated wallet DEK wrapped by the KEK;
- XChaCha20-Poly1305 authenticated encryption for the wallet payload;
- a versioned format identifier so parameters can be changed only through explicit migration.

The encrypted payload contains the typed 32-byte Ed25519 private input, public identity metadata, local signer state, pending rotation state when present, and other wallet-local authorization state. It never contains Registry/DHT state as an authority or a plaintext backup of secrets outside the authenticated payload.

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

The public implementation uses `RegistryAdapter.create_draft()` and `sign_draft()`, immutable `IdentityDraft`, `IdentityProof`, and `IdentityBundle` values, `IdentityBundle.merge()` / `finalize()`, and `RegistryAdapter.publish_bundle()` / `confirm_bundle()`. Local draft/bundle CBOR v2 carries predecessor history and is separate from the unchanged legacy and version-1 Registry envelopes; v1 local bundles are accepted only when their history is sufficient to verify the transition. Exchanged proof metadata does not carry or control the final publication deadline. Publication compares the draft's predecessor state, consumes a fresh consent nonce, supplies an expected-state hash and deadline to the transport, and confirms the exact finalized envelope by independent read-back. Every non-genesis version-1 state requires exact predecessor-envelope lookup by state hash back to its signed anchor; missing or mismatched history is rejected. History walks are capped at 1,024 version-1 transitions and fail closed beyond that bound.

Partial, duplicate, out-of-order, revoked, conflicting, wrong-signer, wrong-bytes, and below-threshold proofs remain non-publishable. A disconnect or timeout after dispatch is `unknown` until independent read-back verifies the exact accepted target.

## 10. Key rotation and format migration

### 10.1 Password rewrap

An ordinary password change preserves the existing wallet DEK and encrypted payload. After successful unlock, the wallet derives the new KEK and atomically replaces only the KDF parameters, salt, and wrapped DEK. It does not regenerate signing keys or write Registry state.

### 10.2 Signing-key rotation

Signing-key rotation preserves the existing Identity, raw owner-name bytes, DHT lookup key, and state lineage. The current owner key, or the current version-1 signer threshold, authorizes the successor transition. New-key proof-of-possession is local-only.

The local state machine is:

1. generate a successor through the approved CSRNG boundary;
2. persist it encrypted as `pending successor` while the predecessor remains active;
3. build and sign the immutable successor request;
4. dispatch the complete envelope;
5. independently read back and verify canonical data, successor public key, sequence, and predecessor state;
6. atomically promote the successor and remove predecessor private material;
7. retain only non-secret historical public identity data.

Ambiguous dispatch retains both local states and performs no automatic retry or replacement. A suspected compromised device cannot be remotely erased through this workflow; the user must explicitly rotate after restoration.

### 10.3 Wallet-format migration

The wallet supports the current format and one immediately preceding format. Migration is explicit, one-way, authenticated, semantically validated, and preserves key material, local state, and Identity meaning. Unknown newer versions and downgrades are rejected.

Migration writes and validates a new container before atomic replacement. A failure preserves the prior valid container. Migration does not rotate keys, change owner-name bytes, alter Registry state, or silently rewrite an initialized wallet.

## 11. Backup, portability, and platform adapters

Backup and portability use explicit export/import of the exact encrypted container:

- export never decrypts or re-encrypts the payload;
- import is accepted only by a new or uninitialized wallet;
- import requires the owner password and verifies format, version, integrity, and compatibility;
- no merge, overwrite, Registry publication, or Identity rollback occurs;
- the artifact is never placed in logs, the clipboard, temporary files, or automatic synchronization.

The Python core exposes `Wallet.export_container() -> bytes` for exact bytes from an unlocked wallet and `Wallet.import_container(path, data, password, *, inactivity_minutes=5)` to authenticate and atomically create an imported wallet only at an absent destination. Import preserves the provided bytes and returns the new wallet unlocked. This implements the local portable-container core only; format migration, signing-key rotation, native platform adapters, and cross-platform conformance remain unimplemented under Issue #18.

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
- ambiguous dispatch remains `unknown` until independent read-back;
- all supported platforms pass shared semantic and wire-format vectors;
- failed, skipped, quarantined, or nondeterministic mandatory tests block MVP acceptance.

Tests use disposable wallets, ephemeral directories, synthetic test-only secrets, test-only keys, and zero-value/local Registry state. Evidence receipts contain no secret values or decrypted wallet contents. Ciphertext byte equality is not required across platforms because authenticated encryption is randomized; semantic results and canonical public artifacts must agree.

## 13. External responsibilities and handoff

Consuming site integrations define their own authentication protocol details, verifier responsibilities, and site authorization policy. They must call the wallet through the authentication-neutral request and consent boundary and must not obtain private material or bypass wallet consent.

Identity and Registry own public-record validation, sequence/state-transition validation, and DHT publication. Account/profile storage, site sessions, and Registry/DHT operation remain outside this wallet implementation.

## 14. Implementation sequencing

Implementation should proceed as vertical slices, each preserving the security invariants:

1. encrypted container creation, unlock, lock, atomic persistence, and tamper rejection (implemented, issue #14);
2. CSRNG-only Ed25519 generation and non-exporting signer capability (implemented, issue #15);
3. canonical Identity request construction, consent, sequence validation, and finalized-envelope adapter (implemented, issue #16);
4. local multisignature draft, proof, merge, finalize, and publication rejection paths (implemented, issue #17);
5. exact encrypted-container export/import core (implemented as a partial slice of Issue #18); password rewrap (implemented with Issue #14); remaining format migration, signing-key rotation state machines, and platform adapters;
6. cross-platform conformance and the complete security acceptance matrix.

No slice may introduce a private-key export or a network-facing private-key boundary. The repository issue tracker should carry the implementation slices and their blocking relationships before code work begins.

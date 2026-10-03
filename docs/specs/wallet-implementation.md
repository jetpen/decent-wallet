# Decent Wallet Implementation Specification

Status: accepted MVP design with completed Python-core wallet storage, signing, Identity adapter, multisignature, owner-key rotation publication/confirmation/finalization, and v1-to-v2 migration. Android and Linux desktop/Podman container-lifecycle targets are partial; Android also has legacy and versioned operation-5 authoring, bounded versioned Identity-history verification, injected-transport dispatch/promotion orchestration, and a concrete direct Kad-DHT client. A local host-JVM Registry interop test passes; deployed Registry, independent second-peer, and Android-device transport acceptance remain outstanding. Native iOS is explicitly deferred outside the current MVP by [ADR-0004](../adr/0004-current-mvp-platform-scope.md). Production Registry deployment, Android rotation runtime evidence, and full cross-platform conformance for in-scope targets remain incomplete.

This document consolidates the accepted decisions from the wallet implementation wayfinder map, [Wallet implementation specification and security boundary](https://github.com/jetpen/decent-wallet/issues/1). It remains the contract for behavior not yet implemented; the repository now contains code-backed encrypted storage, CSRNG signing, a public-only Identity adapter, the local public-bundle multisignature workflow, and the Python core's two-phase owner-key rotation dispatch and promotion API. Android implements legacy and versioned operation-5 authoring plus a partial dispatch/confirmation/promotion flow through `AndroidIdentityTransport`, with a concrete direct Kad-DHT client. A host-JVM loopback test against the Python Registry verifies direct current/history reads, publication of a legacy-anchored owner-key rotation, and exact fresh read-back from the same peer; this does not establish production or Android-device acceptance. Versioned drafts require a fully verified predecessor chain and detached threshold proofs from the predecessor signer set. Adapter unit tests use a fake transport, while only the direct transport's loopback integration test exercises the concrete client. The Registry operation-5 validator and independent remote read-back support are implemented on `decent-registry` main at commit [`dde0730482076cd00e6f115bdd25f4534ae5e927`](https://github.com/jetpen/decent-registry/commit/dde0730482076cd00e6f115bdd25f4534ae5e927); a production Registry deployment and target-network compatibility are not verified here. Wallet-container version 2 is current; version 1 can be upgraded only through the explicit migration in [ADR-0003](../adr/0003-wallet-container-v1-to-v2-migration.md).

## 1. Destination and scope

The wallet is the user-controlled custodian for private keys, the local signing component, and the consent agent. It must preserve the following boundaries:

- private keys and wallet secrets remain inside the wallet boundary;
- wallet storage is strongly encrypted and password-initialized;
- signing and disclosure require explicit, purpose-bound user consent;
- Identity/Registry receives only permitted public material and complete signed envelopes;
- multisignature workflows remain independent between signer wallets;
- authentication integration is protocol-neutral and site-specific;
- Registry/DHT storage, account/profile storage, site policy, and site sessions are external responsibilities.

This specification covers the current MVP across Android and Linux desktop/Podman implementations. Native iOS is explicitly excluded from the current MVP because the project has no Apple development hardware or macOS/Xcode environment to build and validate it; see [ADR-0004](../adr/0004-current-mvp-platform-scope.md). The Android container library and Linux desktop/Podman CLI are partial lifecycle targets; full parity across these in-scope targets remains incomplete. Platform-specific UI and storage adapters are permitted only when they preserve the contracts below.

## 2. Claim classes and current status

### Proposed MVP design

The explicit v1-to-v2 migration contract, platform-adapter/conformance, and security-acceptance requirements derive from the accepted map decisions. The owner-key rotation contract in §10.2 is accepted. Exact encrypted-container export/import, v1-to-v2 migration, pending-key preparation, wallet-local operation-5 draft/proof/envelope construction, and the wallet-core prepare/dispatch/confirm/promote flow are implemented as Python-core slices of Issue #18. Native platform support and cross-platform conformance remain incomplete.

### Kotlin/JVM v2 vector consumer (Issue #33; accepted and implemented)

The first non-Python conformance slice is implemented as a standalone, test-only Kotlin/JVM Maven module under `interop/kotlin/`. It reads `tests/vectors/wallet-container-v2.json` directly. It does not change the Python package, add a production API or CLI, add CI, or constitute an Android application or production adapter. It does not complete Issues #18 or #19.

The locked build uses Maven Wrapper 3.9.16 with pinned wrapper/distribution checksums, Kotlin Maven Plugin 2.4.20, JDK 17 or newer to run the build, and Java 8 bytecode/API release (`jdkRelease=8`). `io.github.chains-project:maven-lockfile:5.18.3` generates and validates a checked-in lockfile containing SHA-256 checksums for resolved dependencies and Maven plugins. Run `./mvnw -B -ntp verify` from `interop/kotlin/`; the `validate`-phase lock check runs before compilation and tests.

The approved crypto dependency is `org.bouncycastle:bcprov-jdk18on:1.86` under the Bouncy Castle License. Use its lightweight APIs directly without registering a global JCA provider. The accepted Android API 26 evidence is Bouncy Castle's build-time compatibility check only; it is not an Android runtime result and does not establish runtime compatibility for this module. Parse JSON with `com.fasterxml.jackson.core:jackson-core:2.22.2` and strict duplicate-name detection, while implementing the wallet-specific canonical JSON/AAD writer and typed-payload decoder in the module.

The positive vector test derives the KEK from the public fixture password, checks expected KDF/AAD intermediates, unwraps the DEK with the derived KEK, decrypts the payload with that recovered DEK, and verifies decoded semantics and the expected public key. It must not bypass the wrap path by using the fixture DEK directly for payload decryption. Accept legal outer-envelope whitespace and member-order variations while reconstructing canonical AAD. Test Unicode code-point key ordering with a supplementary-plane key and a BMP key; do not normalize strings.

Negative tests separately exercise the wrap and payload AEAD boundaries, including malformed authenticated typed-payload bytes, v2-to-v1 relabeling, and unsupported versions. Diagnostics remain values-free and never print the fixture password, seed, DEK, or derived key. This slice does not add deterministic randomness to production code.

### Researched but unimplemented

The established Identity/Registry toolchain provides the Ed25519, canonical-CBOR, signed-envelope, sequence, and finalized-publication contracts described in `docs/research/issue-3-csrng-signing-boundary.md`. Native iOS implementation is excluded from the current MVP by [ADR-0004](../adr/0004-current-mvp-platform-scope.md). An interactive consent UI and a concrete production Registry/DHT transport for this wallet remain unimplemented. The Android library and desktop/Podman CLI are partial container-lifecycle targets. The `decent-registry` main branch includes operation-5 validation and independent remote read-back at commit [`dde0730482076cd00e6f115bdd25f4534ae5e927`](https://github.com/jetpen/decent-registry/commit/dde0730482076cd00e6f115bdd25f4534ae5e927); this repository does not establish that support is deployed in any target environment.

### Implemented/code-backed

The repository currently provides:

- Argon2id and XChaCha20-Poly1305 encrypted wallet-container v2 with atomic persistence, authenticated format-version binding, password rewrapping, lifecycle invalidation, and explicit authenticated v1-to-v2 migration; direct open/import still reject v1 and other unsupported versions;
- partial platform lifecycle targets: the production Android library under `platforms/android-wallet/` and the Linux desktop/Podman CLI under `platforms/desktop-wallet/` reuse the Python wire contract for create/open, exact encrypted import/export, and explicit migration; the desktop CLI never handles Registry operations or rotation UX;
- a normative v2 container wire-format specification and public synthetic known-answer vector, verified by the Python suite and consumed by the Android production module and desktop/Podman conformance target; native iOS is excluded from the MVP by ADR-0004, and full conformance across the in-scope targets remains incomplete;
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

The container is versioned and authenticated. The current wallet-container format is version 2. Outside ciphertext, it contains only the minimum envelope fields required for format recognition and unlock, such as the format version, KDF profile identifier and parameters, salt, wrapped-DEK metadata, encryption nonce, and authentication data required by the selected format. Private material and wallet metadata remain inside authenticated ciphertext. Version 1 is accepted only by the explicit, authenticated, one-way migration in §10.3; direct open/import reject it. Other older or newer versions fail closed. The exact v2 wire profile is specified in [wallet-container-v2-wire-format.md](wallet-container-v2-wire-format.md), with a public synthetic known-answer vector at `tests/vectors/wallet-container-v2.json`; this does not constitute native-platform conformance.

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
8. obtain fresh purpose-bound consent, consuming a replay nonce atomically in the wallet and binding a client-side expiry timestamp for the Registry transport;
9. submit only the finalized envelope through the Registry adapter.

The public implementation uses `RegistryAdapter.create_draft()` and `sign_draft()`, immutable `IdentityDraft`, `IdentityProof`, and `IdentityBundle` values, `IdentityBundle.merge()` / `finalize()`, and `RegistryAdapter.publish_bundle()` / `confirm_bundle()`. Local draft/bundle CBOR v2 carries predecessor history and is separate from the unchanged legacy and version-1 Registry envelopes; v1 local bundles are accepted only when their history is sufficient to verify the transition. Exchanged proof metadata does not carry or control the final publication deadline. Publication compares the draft's predecessor state, consumes a fresh consent nonce, and supplies an expected-state hash and expiry to the transport. The direct-DHT Registry API requires a non-null 32-byte expected hash for conditional writes; it rejects `None` because KadDHT cannot distinguish confirmed absence from an inconclusive lookup. Initial record creation uses a separate Registry API. For rotation, the Registry compares the expected hash against the value selected by one instance from its DHT read and local durable accepted state, under that instance's lock, then checks expiry immediately before beginning the DHT write. Neither check is a network-wide CAS or remote expiry guarantee; other peers may accept a competing authorized branch, and an in-flight write may arrive after expiry. Confirmation must use fresh remote bytes that bypass the writer's local durable cache and write-through state. For owner-key rotation, `CONFIRMED` means the exact latched envelope was observed and validated in one fresh remote DHT response; it does not establish global commit, replication, or convergence. A generic cached read is not independent evidence. Compatible Registry DHT nodes need the `/decent-registry` namespace validator that permits higher-sequence updates and rejects equal-sequence competing states while applying peer-local transition checks; unupdated/default peers may refuse to replace existing values, so fresh one-peer read-back remains mandatory. Every non-genesis version-1 state requires exact predecessor-envelope lookup by state hash back to its signed anchor; Registry by-hash reads search only that instance's retained accepted history, not the DHT. Missing or mismatched history is rejected. History walks are capped at 1,024 version-1 transitions and fail closed beyond that bound. These revised transport guarantees are recorded in [ADR-0006](../adr/0006-direct-dht-best-effort-rotation.md).

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

Once latched, the wallet blocks Identity signing, cancellation, and republishing. The adapter's per-owner gate also blocks ordinary signing/submission and `publish_bundle()` while that adapter instance knows the rotation is unresolved; per-owner locking serializes the latch with conditional Identity writes. `dispatch_owner_key_rotation(publication, permit)` requires the ephemeral permit minted only after the encrypted intent has been durably written; a reconstructed intent from disk cannot be used to dispatch. The adapter rechecks the predecessor immediately before a conditional write. Registry compares the expected hash with the head selected from its DHT read and local accepted state under that Registry instance's lock, and checks the expiry immediately before beginning the DHT write. These are best-effort, per-instance checks—not a network-wide CAS or remote deadline enforcement. Other instances may accept a competing authorized branch, and a write already in flight may arrive after expiry. A state-change or conditional-precondition rejection never returns a clearable rejection: if the exact candidate is observed locally or by an independent remote read, the adapter verifies it and returns confirmation; otherwise the result remains `unknown` and latched. Only a typed expiry rejection may return a one-use `RotationDispatchRejection`, and only after independent read-back does not show the exact candidate. `Wallet.resolve_signing_key_rotation_rejection(rejection)` clears only that matching expiry latch while preserving both keys, releasing the adapter gate only after the local write succeeds. Any outcome with unavailable read-back or incomplete history remains `unknown`, retains both keys and the intent, and permits only read-only confirmation. After reopening, before any other mutating adapter operation, the application must read the persisted intent and call `confirm_owner_key_rotation`; this installs the per-owner gate even when remote evidence is still unavailable. There is no dispatch permit or automatic retry after reopen. Observing only the predecessor does not prove non-acceptance. No replacement or rebase occurs.

`dispatch_owner_key_rotation` and the read-only `RegistryAdapter.confirm_owner_key_rotation(intent)` call the transport's required `get_remote_identity_envelope(owner_name_hex=...)` method. That method must issue a direct GET_VALUE request to a configured remote peer, bypassing local durable cache, write-through state, and write results. It must not use `KadDHT.get_value()` or another lookup path that caches or propagates values as a repair side effect. It returns raw bytes; the consuming Registry or wallet confirmation layer must verify the exact envelope and full predecessor chain before issuing confirmation. The adapter compares the exact envelope hash with the encrypted intent, validates the full predecessor chain using history-by-state-hash reads, and checks the owner-name bytes, predecessor/successor keys, sequence, and predecessor hash before issuing an opaque, one-peer-observed `RotationConfirmation`. This capability does not certify global commit, replication, or convergence. If remote evidence is unavailable, malformed, stale, or mismatched, no capability is issued and the result remains `unknown`; reading only the predecessor never clears the latch. `Wallet.finalize_signing_key_rotation(confirmation)` accepts only that adapter-issued capability and verifies that it matches the active and pending wallet keys and persisted intent. It atomically persists the successor as active and clears the pending key and intent; predecessor secret buffers are wiped only after the durable write succeeds. A failed local write preserves the valid predecessor-plus-pending container. The wallet is never passed to the Registry adapter, and the adapter never receives private material.

The Python core implements local preparation/cancellation, operation-5 draft/proof-of-possession/predecessor-proof/envelope construction, consent-gated two-phase conditional dispatch, fresh remote confirmation, expiry-only rejection resolution, and active-key promotion; stale-state and conditional-precondition conflicts remain latched unless exact candidate confirmation succeeds. Expiry-rejection capabilities are process-local; if one is lost before durable resolution, the reopened intent remains latched for read-only confirmation because a predecessor-only read cannot rule out a delayed write. `publish_bundle()` and `confirm_bundle()` continue to reject operation 5; callers must use the dedicated rotation flow, and a latched intent is never evidence of Registry acceptance. The injected transport protocol has a concrete optional synchronous `RegistryTransport` implementation over the supported Registry API, exercised against local DHT peers; no production deployment or target-network validation has been established. Explicit Python-core v1-to-v2 migration is implemented under ADR-0003. Android and Linux desktop/Podman container-lifecycle slices are available; iPhone support, native rotation parity, deployed Registry acceptance, target-network validation, and full cross-platform conformance remain open for Issue #18. A suspected compromised device cannot be remotely erased through this workflow; rotation must be explicitly completed from a restored wallet.

The Android library implements legacy and versioned-predecessor variants of the same partial flow. Its versioned history verifier caps traversal at 1,024 predecessor links and 4 MiB aggregate envelope bytes; proof lists are capped at three entries and signer IDs at 256 UTF-8 bytes. `AndroidIdentityAdapter` binds consent to the exact canonical transcript and finalized envelope, checks the predecessor before consent and immediately before a conditional write, and only creates a confirmation after the injected transport returns the exact envelope from its independent remote-read method and the referenced predecessor is verified. The selected environment is persisted in the dispatch intent and must match the transport's stable `registryEnvironment` for preparation, dispatch, and confirmation. `WalletSession` durably latches the dispatch intent before the write and atomically promotes the pending key only after that confirmation. Ambiguous outcomes remain latched and are never retried automatically. A stale-state or conditional-precondition conflict does not create a clearable rejection: the adapter confirms only if the exact candidate and verified predecessor are observed; otherwise the intent remains unknown and latched. Only a typed expiry rejection may be resolved, after independent read-back does not show the candidate. Rejection capabilities are process-local: the host must durably resolve one before locking/exiting; if it is lost, a reopened wallet remains latched and allows only read-only confirmation, because observing only the predecessor cannot prove that a write will never arrive. `IdentityStateHistoryVerifier` resolves complete bounded version-1 predecessor histories through hash-addressed lookups and validates operation-5 candidate transitions. `AndroidIdentityAdapter.createVersionedOwnerKeyRotationDraft()` creates canonical versioned operation-5 updates from verified v1 predecessors; `VersionedOwnerKeyRotationDraft.finalizeWithProofs()` accepts detached threshold signatures from the predecessor signer set, rejects outsiders/duplicates/invalid or insufficient proofs, and emits the shared canonical envelope. Preparation and dispatch revalidate against the exact current state hash rather than requiring byte-identical proof envelopes, so valid proof-set variants of the same update remain the same state. The host must provide an atomic `AndroidIdentityReplayNonceStore` and use durable storage in production. `authenticatedOrigin` is trusted host context, not authenticated by this library. Android rotation-state tests use a fake transport; the direct JVM Kad-DHT client is covered by host-JVM interoperability against a local Python Registry peer only, which does not establish deployed Registry or Android-device acceptance. Approved-AVD instrumentation currently covers container lifecycle only, not Android rotation through a real transport.

### 10.3 Wallet-format migration and compatibility

Wallet-container v2 is current; version 1 is the immediately preceding format. `Wallet.migrate_container(path, password, *, inactivity_minutes=5)` is the only migration entry point. It authenticates a v1 container using the v1 AAD, preserves the same password and wallet content, rewraps the DEK and re-encrypts the payload with v2 version-bound AAD, atomically replaces the same path, and returns the migrated wallet unlocked. Wrong passwords and malformed payloads leave the original v1 bytes untouched. A failed write whose rollback is verified restores those bytes and returns `StorageFailure`; if rollback or its directory sync cannot be verified, the wallet raises the value-free `StorageOutcomeUnknown` and callers must inspect/reopen the container before continuing. Migration does not retain a second plaintext or decrypted backup. The method accepts exactly v1, rejecting older, current-v2, and newer versions rather than downgrading. `Wallet.open()` and `Wallet.import_container()` remain v2-only and never migrate implicitly; callers must invoke migration explicitly before opening or importing a v1 artifact. Version-2 files remain unreadable to older v1 implementations because the format version is authenticated. This contract supersedes only the no-migration decision recorded in ADR-0002; other v2 dispatch-intent requirements remain unchanged.

## 11. Backup, portability, and platform adapters

Backup and portability use explicit export/import of the exact encrypted container:

- export never decrypts or re-encrypts the payload;
- import is accepted only by a new or uninitialized wallet;
- import requires the owner password and verifies format, version, and integrity; only container v2 is accepted directly. A v1 artifact must first be explicitly migrated through `Wallet.migrate_container()`;
- no merge, overwrite, Registry publication, or Identity rollback occurs;
- the artifact is never disclosed to logs or the clipboard, intentionally persisted in general-purpose temporary storage, or placed in automatic synchronization. Atomic persistence uses a restrictive same-directory staging file for encrypted bytes. It is removed on success; failure paths attempt cleanup, though an unrecoverable filesystem unlink failure can leave an encrypted staging artifact.

The Python core exposes `Wallet.export_container() -> bytes` for exact bytes from an unlocked wallet, `Wallet.import_container(path, data, password, *, inactivity_minutes=5)` to authenticate and atomically create an imported wallet only at an absent destination, and `Wallet.migrate_container(path, password, *, inactivity_minutes=5)` for explicit one-way v1-to-v2 migration. Import preserves provided v2 bytes and returns the new wallet unlocked; v1 import remains rejected until the caller explicitly migrates the source. Pending rotation state and the dispatch intent are encrypted within v2 and preserved by exact export/import. Android and desktop container-lifecycle slices now consume this contract; native iOS is excluded from the current MVP by ADR-0004. Desktop owner-key rotation is exposed programmatically through the shared Python API, not a CLI command, as described in [ADR-0005](../adr/0005-desktop-rotation-api-boundary.md). Issue #18 still requires the Android rotation implementation, production Registry transport/deployment, and full cross-platform conformance.

Android and Linux desktop/Podman implementations in the current MVP use the same portable container and cryptographic contract. Native iOS is excluded from current MVP acceptance by ADR-0004. OS keystores, desktop keyrings, and hardware facilities are optional defense-in-depth adapters and cannot be the only recovery path or alter the portable format. Hardware-backed non-exportable signing is deferred.

Only one active wallet copy is supported. An imported copy is an explicit snapshot, not a synchronized replica. Concurrent copies are not merged or auto-rebased. Device loss causes no automatic Registry mutation, remote wipe, or revocation. Without a valid encrypted backup and password, replacement recovery is impossible in the MVP.

Transfer occurs through an external user-controlled channel. The wallet does not provide cloud synchronization, automatic upload, device discovery, QR, Bluetooth, Wi-Fi Direct, clipboard, or temporary-file transfer in the MVP.

### 11.1 Portable rotation-latch compatibility

[ADR-0007](../adr/0007-portable-environment-bound-rotation-latch.md) defines the owner-approved amendment: within authenticated container v2, readers accept exactly legacy six-field unbound latches and current seven-field latches with a valid non-null `environment`. New publication preparation always binds that explicit trusted caller realm; missing or different configuration fails closed before confirmation RPC. Outer v2 and version-bound AAD do not change, and old strict readers are not forward-compatible with the other shape. Both public open/import paths validate the latch against actual seed-derived active and pending keys before returning/installing.

Legacy ciphertext remains exactly inspectable/exportable/importable with both keys and mutation blocks retained. No realm is inferred and no remote confirmation/finalization is permitted while unbound. Explicit caller-consented atomic local six-to-seven binding preserves all original fields/keys/metadata, invokes no Registry operation and creates no dispatch authority. Python exposes `bind_legacy_rotation_dispatch_environment(environment, *, consent)`; Android exposes `bindLegacyRotationDispatchEnvironment(environment, consent)`. The callback reviews the intent and exact requested realm. Already-bound intents reject even same-realm repeats. Typed recoverable storage failures preserve legacy state; unknown outcomes lock/clear the session. Only subsequent matching-realm exact authenticated envelope/history read-back may authorize durable promotion. Exact import/export never performs this binding implicitly. Environment validation and trusted transport/adapter configuration are specified in ADR-0007; labels are not network authentication or public-DHT guarantees.

Prior device and packaged acceptance records predate this production amendment and remain historical; they are not fresh verification of the amended portable latch.

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

`core` runs default Python modules except provider-dependent Registry collection modules, which belong to the locked Registry integration profile. Four named cases with environment-dependent prerequisites are separately allowlisted as optional skips. The single conditional transport-configuration probe is reported separately whether it passes or skips. The Podman Registry deployment test now runs under `core`: absent managed peers are an optional skip; configured peers must make the test pass. All optional outcomes are excluded from mandatory counts. Any unapproved skip, failure, or error blocks. `android-jvm` runs the Android JVM suite and Kotlin-authored container artifacts and records its collected live-peer outcome separately. `full` adds the pinned Registry integration suite, checks exact case inventories for all included Registry modules, and rejects omissions. Each profile produces a values-free receipt. Android device/AVD runtime and global DHT convergence remain separate evidence.

- Tests use disposable wallets, ephemeral directories, synthetic test-only secrets and keys, and local/zero-value Registry state. Receipts contain no secret values or decrypted wallet contents; randomized ciphertext is compared semantically rather than byte-for-byte.
- The gate fails closed on mandatory test failure/error, unexpected skip, receipt schema violation, missing suite/artifact, or altered optional-test inventory.
- Receipts remain local evidence and are never published to wallet or Registry/DHT state.

## 13. External responsibilities and handoff

Consuming site integrations define their own authentication protocol details, verifier responsibilities, and site authorization policy. They must call the wallet through the authentication-neutral request and consent boundary and must not obtain private material or bypass wallet consent.

Identity and Registry own public-record validation, sequence/state-transition validation, and DHT publication. `decent-registry` main implements version-1 authorization operation 5, legacy-predecessor verification, `signer_id: null` handling for that exact branch, byte-for-byte owner-name preservation, authenticated predecessor-chain provenance, and an independent remote read path that bypasses local durable cache (commit [`dde0730482076cd00e6f115bdd25f4534ae5e927`](https://github.com/jetpen/decent-registry/commit/dde0730482076cd00e6f115bdd25f4534ae5e927)). This repository provides only the wallet transport protocol; production transport integration and deployment of the Registry changes are not verified. Account/profile storage, site sessions, and a concrete Registry/DHT transport remain outside this wallet implementation.

## 14. Implementation sequencing

Implementation should proceed as vertical slices, each preserving the security invariants:

1. encrypted container creation, unlock, lock, atomic persistence, and tamper rejection (implemented, issue #14);
2. CSRNG-only Ed25519 generation and non-exporting signer capability (implemented, issue #15);
3. canonical Identity request construction, consent, sequence validation, and finalized-envelope adapter (implemented, issue #16);
4. local multisignature draft, proof, merge, finalize, and publication rejection paths (implemented, issue #17);
5. exact encrypted-container export/import, explicit v1-to-v2 migration, local pending-key preparation, operation-5 draft/proof/envelope construction, two-phase conditional dispatch, independent remote confirmation, latch resolution, and key promotion (implemented in the Python core as partial slices of Issue #18); Android additionally implements local pending-key preparation/cancellation and legacy plus versioned operation-5 authoring/dispatch/confirmation/promotion through an injected transport, with bounded version-1 predecessor verification; a concrete Android transport, production deployment, runtime AVD acceptance, and full in-scope cross-platform conformance remain;
6. cross-platform conformance and the complete security acceptance matrix.

## 15. Issue #18 acceptance map

The live Issue #18 checklist remains authoritative. This map separates code present from end-to-end acceptance evidence; iOS is excluded by ADR-0004, and the desktop rotation interface is API-level per ADR-0005.

| Issue #18 criterion | Current implementation | Remaining acceptance |
|---|---|---|
| Android and desktop share semantic and wire-format vectors | The wallet-container v2 vector is consumed by Python, Android, and desktop/Podman. The legacy operation-5 rotation vector is consumed by the Python core test and Android's production draft API; its canonical consent-transcript vector is consumed by Python and Android adapter tests. The non-genesis versioned-history/operation-5 vector, including an exact versioned candidate envelope generated by Python and authored byte-for-byte by Android, is consumed by the Python core and Android authoring/adapter tests. The operation-3 generation-skip vector is consumed by the Python core and Android history verifier. | Run fresh cross-target evidence for all vectors and the packaged desktop runtime. |
| Exact export/import into an empty wallet; no merge, overwrite, or Registry mutation | Python core, Android container library, and desktop CLI have corresponding operations and tests (`tests/test_container.py`, `platforms/android-wallet/src/test/kotlin/org/decentwallet/wallet/android/AndroidWalletTest.kt`, `tests/test_desktop_cli.py`). | The complete lifecycle/fault matrix must be exercised across both in-scope targets and the packaged desktop runtime. |
| Explicit, authenticated one-way v1-to-v2 migration with safe failure behavior | Python core, Android container library, and desktop CLI implement explicit migration. Python-core tests cover unsupported versions and rollback; Android tests cover one-way migration and recoverable/unverifiable rollback; desktop tests cover v1 migration and preservation after failure. | Run the required fresh in-scope acceptance matrix and verify exact target evidence for all failure cases. |
| Rotation preserves Identity/Owner Name invariants and finalizes only after independent verified read-back | The Python core implements operation-5 draft/proof, dispatch-intent, confirmation, and promotion APIs with tests in `tests/test_multisig.py`. Android builds legacy and versioned operation-5 envelopes; the versioned path requires complete bounded predecessor history, preserves Owner Name/epoch/threshold/signer-set semantics, accepts only valid detached threshold proofs from the predecessor signers, and matches the Python-generated candidate vector byte-for-byte. The adapter binds consent to the canonical transcript, revalidates the predecessor state hash before dispatch, confirms only on exact candidate bytes from the injected remote-read method with verified history, and atomically promotes after confirmation. Android verifies successor proof-of-possession locally and discards that signature instead of including it in the envelope. Desktop/Podman parity is through the shared Python API, not a CLI rotation command. `RegistryTransport` is exported from the package root, and the optional `registry` extra pins the provider implementation. The rootless Podman verifier exercises the installed package and provider against loopback DHT peers from a runtime-derived test stage, covering success, expiry rejection, and ambiguous-write recovery. | The host-JVM loopback integration test exercises the concrete direct-DHT client against one Python Registry peer: it reads current and hash-addressed values, publishes a legacy-anchored rotation candidate, and confirms exact bytes through a fresh direct read from that same peer. This does not prove read-back from an independent second peer, Android-device runtime, a deployed target Registry, or global DHT convergence. Approved-AVD instrumentation currently covers container lifecycle only; complete cross-platform fault acceptance remains outstanding. |
| Retain predecessor material on ambiguity; remove it only after confirmed acceptance; never auto-retry | The Python core and Android persist an encrypted dispatch latch, block conflicting mutation, preserve both keys on ambiguous outcomes, allow only read-only confirmation, and promote only after a matching confirmation. Stale-state and conditional-precondition conflicts cannot clear a latch unless exact candidate confirmation succeeds; only expiry rejection has a one-use resolution path after independent read-back. Android adapter tests cover sibling-copy acceptance, conditional conflicts, lost-write/reopen/read-back, expiry rejection, latch-storage failure, and promotion-storage failure using a fake transport. | The loopback direct-DHT integration test covers the concrete transport's write and fresh-read path; Android-device behavior, deployed Registry acceptance, and the broader cross-platform fault matrix remain outstanding. |
| Cross-platform and lifecycle fault tests cover every criterion | Python-core tests, Android container, local-rotation and dispatch-adapter unit tests, and the rootless Podman verifier cover implemented slices; its runtime-derived stage exercised the installed package against loopback Registry peers under network isolation. Approved-AVD instrumentation currently covers container lifecycle only. This proves the pinned local integration path, not production deployment compatibility or global DHT behavior. | Exercise versioned rotation and the concrete transport on `Medium_Phone` (API 26, Google Play x86) and `Pixel_9` (API 37, Google APIs Play Store x86_64, 16 KB pages), verify independent remote read-back against a supported target deployment, complete the lifecycle/fault matrix, and publish sanitized reports before checking the issue criteria. |

No slice may introduce a private-key export or a network-facing private-key boundary. The repository issue tracker should carry the implementation slices and their blocking relationships before code work begins.

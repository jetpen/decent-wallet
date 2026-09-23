# ADR-0002: Wallet container v2 for rotation dispatch intent

**Status:** Accepted

**Scope:** Owner-key rotation dispatch-intent persistence and wallet-container compatibility.

## Context

The version-1 wallet payload can contain extensible wallet-local fields. Earlier wallet implementations do not recognize a rotation dispatch intent and could ignore it while still creating a signer or cancelling a pending successor. Persisting the latch as an unknown v1 payload field would therefore fail to enforce the accepted rotation state machine across implementation versions.

At decision time, Registry main did not support operation 5. Registry operation-5 validation and independent remote read-back were later merged to `decent-registry` main at commit [`dde0730482076cd00e6f115bdd25f4534ae5e927`](https://github.com/jetpen/decent-registry/commit/dde0730482076cd00e6f115bdd25f4534ae5e927). This ADR still records the local container-v2 persistence decision; it does not establish deployment compatibility.

## Decision

- The current encrypted wallet-container format is version 2. The authenticated data binds version 2 for both DEK wrapping and payload encryption.
- The v2 payload may hold the non-secret rotation dispatch intent: exact owner-name bytes, predecessor and successor owner public keys, predecessor state hash, sequence, and SHA-256 of the exact finalized operation-5 envelope.
- Opening or importing any version other than 2 is rejected. In particular, version-1 containers are unsupported and are not migrated. This compatibility break is explicitly accepted by the repository owner for this implementation; it does not satisfy the broader migration criterion in Issue #18.
- `RegistryAdapter.prepare_owner_key_rotation_publication(...)` returns a ready, one-use publication capability only when its transport explicitly opts in to the supported Registry operation-5 contract and exposes fresh remote read-back. It validates state before and after consent; unsupported transports fail before consent or wallet latching.
- `Wallet.latch_signing_key_rotation_dispatch_intent(bundle, publication)` accepts only a matching prepared capability, verifies and discards the successor proof-of-possession signature, persists the non-secret intent atomically, invalidates outstanding signer capabilities, and returns a sealed process-local `RotationDispatchPermit`. The persisted intent alone is not dispatch authority.
- After latching, the wallet blocks signer creation, successor preparation, proof-of-possession, cancellation, and another latch. The adapter also gates ordinary signing and publication for that owner while its instance knows the latch; per-owner locking serializes this gate with writes. Generic wallet metadata updates preserve the intent. Conditional dispatch requires the ephemeral permit; remote confirmation requires a fresh uncached read. After reopen, the application must call read-only confirmation with the persisted intent before any other mutating adapter operation, installing the new instance's gate. A definitive pre-write rejection or confirmed finalization clears the gate only after the local durable write; an ambiguous outcome remains latched.
- The original decision covered local persistence only. The Python core now implements dispatch, confirmation, safe pre-write rejection resolution, and successor promotion. Concrete production transport integration and target deployment remain unverified.

## Consequences

- Version-1 wallet files remain unchanged on disk but cannot be opened or imported by this implementation. No migration path is provided.
- A caller must not use the local latch alone as evidence of Registry acceptance. The wallet core now provides consent preparation, conditional operation-5 dispatch, uncached remote confirmation, safe pre-write rejection resolution, and key promotion through an injected transport protocol. A concrete production transport and Registry deployment remain unverified.
- Issue #18 remains open; Issue #19 remains blocked by Issue #18.

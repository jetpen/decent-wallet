# ADR-0002: Wallet container v2 for rotation dispatch intent

**Status:** Accepted

**Scope:** Owner-key rotation dispatch-intent persistence and wallet-container compatibility.

## Context

The version-1 wallet payload can contain extensible wallet-local fields. Earlier wallet implementations do not recognize a rotation dispatch intent and could ignore it while still creating a signer or cancelling a pending successor. Persisting the latch as an unknown v1 payload field would therefore fail to enforce the accepted rotation state machine across implementation versions.

The current Registry main does not support operation 5. This decision enables only local intent persistence and fail-closed wallet state; it does not authorize or implement Registry publication, confirmation, or key promotion.

## Decision

- The current encrypted wallet-container format is version 2. The authenticated data binds version 2 for both DEK wrapping and payload encryption.
- The v2 payload may hold the non-secret rotation dispatch intent: exact owner-name bytes, predecessor and successor owner public keys, predecessor state hash, sequence, and SHA-256 of the exact finalized operation-5 envelope.
- Opening or importing any version other than 2 is rejected. In particular, version-1 containers are unsupported and are not migrated. This compatibility break is explicitly accepted by the repository owner for this implementation; it does not satisfy the broader migration criterion in Issue #18.
- `Wallet.latch_signing_key_rotation_dispatch_intent(bundle)` accepts only a complete, locally valid operation-5 bundle bound to the wallet's active and pending keys and verified predecessor history. It verifies and discards the successor proof-of-possession signature, persists the intent atomically, and invalidates outstanding signer capabilities.
- After latching, the wallet blocks signer creation, successor preparation, proof-of-possession, cancellation, and another latch. Generic wallet metadata updates preserve the intent. The caller must obtain fresh publication consent and invoke the latch immediately before any dispatch attempt.
- This slice does not dispatch the envelope, confirm remote acceptance, resolve an ambiguous outcome, or promote the successor key. An unresolved latch remains blocking until a later approved confirmation/finalization slice.

## Consequences

- Version-1 wallet files remain unchanged on disk but cannot be opened or imported by this implementation. No migration path is provided.
- A caller must not use this local latch as evidence of Registry acceptance. The operation-5 Registry rollout, fresh uncached remote confirmation, dispatch resolution, and active-key promotion remain outstanding.
- Issue #18 remains open; Issue #19 remains blocked by Issue #18.

# ADR-0006: Direct-DHT best-effort owner-key rotation

**Status:** Accepted

**Scope:** The publication and confirmation guarantees for Issue #18 owner-key rotation over the existing Registry DHT.

## Context

ADR-0001 defines operation-5 authorization and a safe wallet lifecycle, but its transport wording could be read as requiring a network-wide atomic compare-and-write and deadline enforcement. The Registry is a direct-DHT system: accepted-state validation and history are local to each Registry instance, while DHT publication and reads are best-effort. It offers no global compare-and-swap, consensus, quorum commit, or network-wide expiry enforcement. Registry rejects equal-sequence competing updates at an individual accepted-state validator; it does not choose a single winner across partitions or reconcile every peer's branch.

The wallet will use direct DHT only. No authenticated HTTP coordinator is introduced. The transport contract must describe what one Registry instance and one fresh DHT read can prove without weakening operation-5 authorization or wallet key-retention safeguards.

## Decision

- Use the Registry's public direct-DHT API. Conditional publication requires a non-null 32-byte `expected_state_hash` and compares it with the current value selected by that Registry instance from its DHT read and local durable accepted state, under its local accepted-state lock. The direct-DHT API rejects `None` because KadDHT returns `None` for both an absent key and an inconclusive lookup, so it cannot prove absence for a conditional create. Initial record creation uses a separate Registry API. This is an instance-local precondition, not a network-wide CAS: another instance or partition may accept a different authorized successor.
- Treat `expires_at` as a client-side deadline. After validation, the Registry checks it immediately before beginning the DHT write, then installs the local accepted head after the DHT call. No remote peer enforces the deadline, and an in-flight publication may be received after it. A local-store failure after the DHT call is ambiguous and requires fresh read-back.
- Keep expected-state and expiry checks separate from cryptographic authorization. The candidate must still be the exact latched envelope and pass Registry validation, including operation-5 authorization, exact Owner Name preservation, exact sequence increment, predecessor state hash, and complete authenticated predecessor history.
- `get_identity_envelope` returns the exact current envelope after Registry validation. `get_identity_envelope_by_hash` searches only the Registry instance's locally retained, validated accepted history; it is not a DHT-wide hash lookup. If the predecessor or required history is unavailable, the wallet fails closed and does not dispatch or finalize.
- After dispatch, confirmation requires a fresh direct GET_VALUE response from a configured peer that bypasses the writer's local durable cache and returns the exact latched envelope. It must not use a Kademlia lookup path that caches or repairs peers as a side effect. The Registry confirmation method and wallet then verify the full predecessor chain and transition. `CONFIRMED` means “observed and validated from a fresh remote DHT response”; it does not mean globally committed, replicated to all peers, or guaranteed to remain the network-wide current value.
- Preserve the existing wallet safeguards: persist the exact-envelope dispatch intent before dispatch; do not rebase, replace, or automatically retry; retain both keys and the latch after any ambiguous outcome; promote the successor and wipe the predecessor only after exact peer-observed confirmation and durable local persistence.

## Consequences

- A partition or stale peer can cause separate Registry instances to accept distinct authorized successors. Local equal-sequence conflict rejection does not resolve this network-wide fork risk.
- A fresh remote read is evidence of one peer's response only. A later read may return a different branch, and this workflow does not reconcile branches or guarantee global convergence.
- A client without locally retained predecessor history may be unable to validate a current version-1 state or rotate it. This is an intentional fail-closed availability limitation; it must not be bypassed by trusting a standalone envelope or querying an unvalidated history source.
- An unknown dispatch outcome retains the old and pending keys. A peer-observed exact envelope permits local promotion under the accepted wallet contract, but does not establish what every other peer has accepted.
- End-to-end acceptance still requires a supported Registry implementation, persistent local accepted-state storage, a configured DHT bootstrap peer, and a test that exercises conditional local rejection plus fresh one-peer read-back. Nodes expected to store replacements must run a Registry-compatible DHT namespace validator; unupdated peers may refuse to replace an existing value. No production deployment or network-wide safety guarantee is implied.

## Supersession

This ADR supersedes only the network-wide atomicity, deadline, and confirmation-scope implications in ADR-0001 and the wallet implementation specification. It does not supersede operation-5 cryptographic rules, exact-envelope dispatch latching, complete predecessor-chain validation, fail-closed history handling, ambiguous-outcome retention, no-automatic-retry, or durable-promotion requirements.

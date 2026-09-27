# ADR-0005: Desktop owner-key rotation API boundary

**Status:** Proposed

## Context

ADR-0004 keeps both Android and Linux desktop/Podman in the current MVP and requires rotation parity on those targets. The desktop target packages the shared Python wallet core, while its CLI is intentionally limited to local container create/open/import/export/migrate operations. The Python core already exposes owner-key rotation APIs over an injected `IdentityTransport`; a separate CLI state machine or cryptographic implementation would duplicate security-sensitive behavior without adding parity.

The current Issue #18 requirement is behavior parity, not a requirement for a desktop GUI or a dedicated rotation command. The production Registry transport and deployment remain separate, uncompleted acceptance requirements.

## Decision

- The desktop/Podman rotation surface is the shared public `decent_wallet` Python API, including the existing wallet and Registry-adapter contracts. This API is available to host integrations and from the package installed in the runtime image.
- The desktop CLI remains limited to container lifecycle commands. A dedicated rotation CLI command, GUI, or separate desktop rotation state machine is not required for Issue #18.
- Desktop integrations must use the shared core's consent, transport, dispatch-intent, independent-read-back, and finalization contracts; they must not duplicate cryptography or treat a write response/cache value as confirmation.
- The concrete production transport and a verified Registry deployment are still required before end-to-end Issue #18 acceptance. This ADR does not claim they exist.

## Consequences

- Desktop/Podman rotation parity must be tested through the public Python API in the packaged runtime, not through a new CLI subcommand.
- The Android wallet remains a separate native adapter and must implement the same semantics against shared fixtures.
- Shared rotation fixtures should be added when the Android rotation adapter can consume them; the current Kotlin/JVM verifier only consumes the wallet-container v2 vector and is not a rotation verifier.
- The desktop CLI documentation and Issue #18 acceptance text should distinguish the API-level rotation surface from the CLI's local container operations.

## References

- [ADR-0004: Exclude native iOS from the current MVP](0004-current-mvp-platform-scope.md)
- [Wallet implementation specification, Issue #18 acceptance map](../specs/wallet-implementation.md#15-issue-18-acceptance-map)
- [Desktop wallet-container CLI guide](../../platforms/desktop-wallet/README.md)

# ADR-0004: Exclude native iOS from the current MVP

**Status:** Accepted

**Date:** 2026-09-27

## Context

The device-integration decision in Issue #11 originally included Android, iPhone, and an optional Podman-hosted desktop target. Issue #18 consequently listed Android, iPhone, and desktop/Podman implementations in its cross-platform acceptance criteria.

The current project development and verification environment is Linux-based, and no Apple development hardware is available. Native iOS builds and Simulator acceptance require a supported macOS/Xcode environment; the current project cannot build or validate an iPhone target with its available hardware. Keeping iOS in the current MVP would make the scope dependent on unavailable infrastructure.

This is a feasibility and acceptance-scope decision. It does not change the portable wallet-container format, custody boundary, migration contract, rotation contract, or explicit-transfer model.

## Decision

- The current MVP platform set is the Android wallet target and the Linux desktop/Podman target. Native iPhone/iOS implementation and iOS-specific UI or device testing are excluded from current MVP acceptance, including Issue #18.
- This decision supersedes only the platform list in Issue #11. Its remaining device-boundary requirements continue to apply: one portable encrypted-container contract, explicit exact-container import/export into an empty wallet, one active snapshot at a time, no synchronization or automatic transfer, and optional rather than required platform keystore protection.
- Issue #18 cross-platform vectors, lifecycle tests, migration, and rotation parity apply to the current in-scope Android and desktop/Podman targets. Production Registry transport/deployment and independent remote read-back remain separate acceptance requirements.
- Reconsider iOS as a separate future scope only when the project can provide a supported Mac/Xcode build and Simulator test path. For that future work, set the supported iOS range from the pinned current stable Xcode's device and Simulator support, not from compile-only legacy deployment targets; use a physical iPhone for device-specific validation when available.
- The shared wire format and security contract remain platform-neutral; no algorithm, format, or migration change is authorized by this scope decision.

## Consequences

- iOS availability is not a prerequisite or a completion criterion for the current MVP.
- Do not create iOS-specific implementation or acceptance claims without reopening scope and providing the required Apple build/test environment.
- Update the implementation specification, contributor guidance, README, parent Issue #1 summary, and Issue #18 acceptance text to match this decision. The earlier Issue #11 resolution remains historical and is explicitly superseded for the current MVP.

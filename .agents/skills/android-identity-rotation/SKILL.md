---
name: android-identity-rotation
description: "Use when implementing Android owner-key rotation."
version: 0.1.0
author: User, Hermes Agent
license: MIT
platforms: [linux, macos]
metadata:
  hermes:
    tags: [android, identity, rotation, wire-format, security]
    related_skills: [test-driven-development, requesting-code-review, repository-issue-review]
---

# Android Identity Rotation

Use this workflow for Android wallet owner-key rotation, including version-1 predecessor verification, draft signing, dispatch, and confirmation. In the Identity wire format, the corresponding authorization is named operation 5; use “owner-key rotation” in prose unless discussing the encoded protocol. Keep semantics aligned with the Python core and accepted ADRs; injected-transport tests do not prove production Registry acceptance.

## When to Use

- Implementing or reviewing Android owner-key rotation.
- Changing versioned Identity history verification, detached threshold proofs, dispatch latches, or rotation confirmation.
- Extending cross-language rotation vectors or adapter tests.

Don't use for container-only work, unrelated Identity operations, or implementing a concrete production Registry client; use the relevant transport design and acceptance workflow for that scope.

## Prerequisites

- Read repository `AGENTS.md`, the live Issue #18 plan, `docs/adr/0001-owner-key-rotation-contract.md`, and `docs/adr/0006-direct-dht-best-effort-rotation.md`.
- Inspect the Python core's corresponding Identity and rotation implementation before changing Android semantics.
- Preserve the requested branch and all existing staged, unstaged, and untracked changes. Don't reset, clean, or stage broadly.
- Use `test-driven-development` for each behavior and `requesting-code-review` before committing.

## Procedure

1. Reconcile scope and state. Read the issue's ordered slices and acceptance criteria, inspect `git status` and all relevant diffs, and identify which slice is currently in progress. Keep the slice independently reviewable; do not silently combine it with adjacent uncommitted slices.

2. Add a failing focused test before production edits. Cover one behavior at a time and observe the expected failure. Keep synthetic keys and test credentials confined to fixtures; never copy real credential values into tests, logs, vectors, or reports.

3. Resolve the current predecessor through the bounded hash-addressed history verifier. Fail closed on missing, malformed, tampered, wrong-owner, invalid-signature, or over-depth history. Authenticate each link and validate transitions using the Python core's exact rules. Bound aggregate retained envelope bytes independently of link depth (Android currently caps at 4 MiB), and reject proof lists larger than the predecessor signer set or signer IDs over 256 UTF-8 bytes before fetching more history; a per-envelope CBOR cap does not bound aggregate retention. For multi-peer hash lookups, report missing only if every peer answered successfully with no value; if any peer fails and none returns a value, propagate transport failure rather than treating incomplete history as absent. Treat the canonical signed-update state hash as state identity; do not require complete proof-envelope bytes to remain unchanged when detached proof sets differ but authenticate the same update.

4. Build a versioned owner-key-rotation update from the verified predecessor. Preserve Owner Name bytes exactly, and preserve its generation, threshold, and signer set. Advance the sequence according to the Python core's transition rule. Require the wallet's active owner key to match the predecessor and a valid pending successor key pair. Sign and verify successor proof-of-possession locally, then discard that signature; never include it in the public envelope or export a private key.

5. Collect predecessor-signer proofs outside the wallet. Accept detached signatures over the canonical update digest. Reject unknown signer IDs, duplicate signers, invalid signatures, malformed proof data, and a set below threshold. Canonically order proof entries by the wire-format's UTF-8 byte ordering before encoding. Do not accept an owner-key signature as a substitute for the predecessor threshold proofs.

6. Revalidate at each trust boundary. Verify candidate history against the freshly read current predecessor before consent, read and revalidate again after consent, and check the current state once more before conditional dispatch. Compare verified state hashes and transition fields, not full predecessor envelope bytes. If the semantic predecessor changed, reject as stale before writing.

7. Persist the encrypted dispatch latch before the conditional write. A write response, local cache, or write acknowledgement is not confirmation. Never automatically retry an ambiguous write. Keep both old and pending keys while outcome is unknown; allow read-only confirmation after reopen.

8. Confirm only through the transport's independent fresh remote-read path. Require exact candidate-envelope bytes, verify the candidate and its complete predecessor history, then promote the pending key. If the remote read is absent, inconclusive, stale, or unverifiable, leave the latch and both keys intact. Do not claim production acceptance from fake transport tests.

9. Add cross-language evidence with the first real consumer. Use shared vectors under `tests/vectors/`; test the Python core's acceptance and Android's generated candidate bytes against the same fixture. Include tests for same-state proof-envelope variants, stale state, threshold boundaries, invalid/duplicate/outsider proofs, ambiguous write/reopen, and no-retry behavior as relevant to the slice.

10. Verify the exact changed code. From the repository root, run the focused test first, then the full Python suite and Android unit tests/lint. Review both staged and unstaged diffs and untracked fixtures. Run `git diff --check HEAD` and `git diff --cached --check`. Obtain an independent diff review before claiming the slice ready.

## Quick Reference

From the repository root, on Linux/macOS with Android SDK configured:

```sh
ANDROID_HOME="$HOME/Android/Sdk" ANDROID_SDK_ROOT="$HOME/Android/Sdk" PATH="$HOME/Android/Sdk/platform-tools:$HOME/Android/Sdk/emulator:$PATH" ./gradlew --no-daemon --dependency-verification=strict :platforms/android-wallet:testDebugUnitTest :platforms/android-wallet:lintDebug
./.venv/bin/pytest -q -o addopts=''
git diff --check HEAD
git diff --cached --check
```

Run `python scripts/run_issue18_registry_acceptance.py --serial <emulator-serial>` for the self-managed local acceptance harness. By default it runs desktop Python RegistryTransport integration, Android host-JVM interop, then Android-device wallet rotation. It starts a fresh two-peer Registry fixture for each networked phase, verifies the peers opened distinct LMDB files, parses readiness without echoing arbitrary fixture logs, supplies pinned peer IDs to the clients, installs loopback mappings with atomic `adb reverse --no-rebind`, verifies exact targets before Gradle, forces tests to execute, and verifies the expected cases passed rather than skipped. It then tears down the fixture, temporary stores, and only the matching reverse mappings it created. Use `--desktop-only`, `--jvm-only`, or `--android-only` to select phases; `--android-only` runs JVM and device phases. The process backend is the default and requires no Podman because it launches the actual Registry DHT/LMDB implementation directly. These temporary loopback peers are not deployed Registry acceptance and do not close Issue #18 gate 1.

The optional `--peer-backend podman` mode is currently limited to `--desktop-only` diagnostics; the harness rejects JVM/device phases with this backend. The diagnostic independently seeds both peers, confirms the writer's candidate, and records that the distinct direct-read peer still has the seeded predecessor. This is not independent-candidate confirmation and does not satisfy gate 1. For reliable teardown, resolve the locked Registry interpreter with `uv run --locked --project <decent-registry> --extra dev python -c 'import sys; print(sys.executable)'`, then launch that Python executable directly. Signaling the `uv run` wrapper can let it exit before the fixture finishes removing its containers and private network.

The device phase requires exactly one connected Android target. The harness verifies boot completion, the host AVD name/config, Google Play image, API, and ABI, rejects extra emulators or physical devices, and repeats the target check immediately before Gradle. Do not connect or disconnect other Android devices during the run. Run approved AVDs sequentially, never concurrently, because this test host cannot sustain multiple emulators. Do not run another harness or modify `adb reverse` mappings for the selected serial during a run; ADB has no atomic compare-and-remove. Pixel_9/API 37 targets SDK 37; without the host app declaring and requesting `ACCESS_LOCAL_NETWORK`, Android 17 blocks outgoing TCP to `10.0.2.2` and typically surfaces a timeout. The harness uses `adb reverse --no-rebind` loopback mappings and verifies exact targets. Do not add this runtime permission silently from a library; make LAN access an explicit host-app/privacy decision.

Run focused tests first using Gradle's `--tests '<fully.qualified.TestClass.testName>'` and pytest's `path::test_name` selector.

## Pitfalls

- A proof-envelope byte change is not necessarily a state change. Validate the canonical update/state hash and its authenticated transition.
- A local read or cached DHT value is not a fresh remote read. Keep transport read paths distinct and honor the direct-DHT acceptance boundary.
- A timed-out direct Kad-DHT RPC must close its stream, including a stream that resolves after negotiation timeout; closing must release the controller's pending response future.
- Operation-3 generation gaps are valid when generation strictly increases; sequence linkage is checked separately. Follow the Python core, not a guessed `+1` generation rule.
- Android minSdk is API 26. Check lint for API-level availability; avoid newer JDK methods unless the minimum SDK safely supports them.
- If androidTest packaging reports duplicate Netty resources, exclude only `META-INF/INDEX.LIST`, merge `META-INF/io.netty.versions.properties` to preserve distinct module entries, and use `pickFirst` for license metadata only after verifying duplicate contents are identical.
- A green unit suite using an injected fake transport proves library logic only. It does not prove concrete transport behavior, deployed Registry compatibility, emulator rotation, or global DHT behavior.
- Keep docs precise: state what is implemented and unit-tested separately from what is runtime-tested or remotely accepted.
- Do not commit or open a PR unless requested. If asked, stage explicit intended files and inspect the staged diff; preserve any pre-existing staged work.

## Verification

Before reporting the slice ready, confirm all applicable items:

- The focused RED test failed for the intended reason, then passed after implementation.
- The exact shared candidate vector is accepted by Python and emitted byte-for-byte by Android.
- Android unit tests and `lintDebug` pass; Python tests pass.
- Diff whitespace checks pass and an independent reviewer reports no blocking logic/security findings.
- Report the branch/worktree state and clearly list any remaining transport, emulator, remote-read, or deployment acceptance work.

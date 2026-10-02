# Android wallet-container core

This Android library is a production container-storage slice for Issue #18. It is separate from the Kotlin vector verifier and the Issue #36 conformance harness.

The module targets Android API 26+ and uses the shared v2 wallet-container wire format. Its portable operations are:

- `AndroidWallet.create(path, password, confirmation, payload)` creates a new encrypted v2 container.
- `AndroidWallet.open(path, password)` opens v2 only.
- `AndroidWallet.importContainer(path, bytes, password)` authenticates the encrypted input and creates a new destination without merging or replacing existing state. It preserves the imported bytes exactly.
- `AndroidWallet.migrateContainer(path, password)` explicitly migrates the immediately preceding v1 format in place. Direct open/import do not migrate v1.
- `WalletSession.exportContainer()` returns the original encrypted bytes only while the session is unlocked; `lock()`, `background()`, and `close()` wipe mutable session buffers where feasible.

Example:

```kotlin
val session = AndroidWallet.open(walletPath, password)
try {
    val encryptedBackup = session.exportContainer()
    // Transfer encryptedBackup through the app's separately approved transport.
} finally {
    session.background()
}
```

Call `background()` from the app's lifecycle handling when the wallet should lock. The library does not install lifecycle observers automatically. Store the container in app-private storage; these APIs accept `java.nio.file.Path` and use same-directory staging/installation, process-local path serialization, and provider-backed in-place replacement. The strongest atomic-visibility guarantee depends on the filesystem provider. New-file creation additionally uses a persistent hidden `.decent-wallet-install.lock` in the parent directory to serialize cooperating app processes; it is not wallet data and should not be removed while storage calls may be active. This lock coordinates callers using this library, not arbitrary writers that ignore it.

The v2 profile uses Argon2id v1.3 (65,536 KiB, 3 iterations, 4 lanes) and XChaCha20-Poly1305, strict duplicate-key rejection, canonical UTF-8 JSON, and version-bound associated data. Passwords must contain at least 16 Unicode scalar values. Error messages do not include passwords, keys, payloads, or raw storage errors.

The library supports CSRNG-generated Ed25519 owner keys, encrypted pending-successor preparation/cancellation, legacy-predecessor operation-5 authoring, and versioned-predecessor operation-5 authoring. `AndroidIdentityAdapter.createVersionedOwnerKeyRotationDraft()` resolves and verifies bounded predecessor history by state hash, then builds the canonical operation-5 update while preserving the predecessor epoch, threshold, signer set, Owner Name bytes, and sequence lineage. The host requests detached signatures from those predecessor signers and supplies `OwnerKeyRotationProof` values; the wallet validates the signer identities, signatures, and threshold without receiving signer private keys. It signs/verifies candidate proof-of-possession locally with the pending owner key, then discards that signature rather than including it in the envelope. The adapter revalidates the complete candidate chain before consent and dispatch. History resolution is capped at 1,024 predecessor links and 4 MiB aggregate envelope bytes; each versioned envelope permits at most three proofs and proof signer IDs are capped at 256 UTF-8 bytes.

`AndroidIdentityAdapter` adds the public-only prepare/latch/dispatch/confirm/promote orchestration through an injected `AndroidIdentityTransport`. Consent is bound to the exact canonical transcript and finalized envelope; the encrypted dispatch intent, including its selected environment, is persisted before the conditional write. The transport's stable `registryEnvironment` must match the reviewed environment for preparation, dispatch, and confirmation. Promotion requires a fresh remote read of the exact envelope and verified predecessor history. Ambiguous outcomes remain latched without automatic retry. A stale-state or conditional-precondition conflict is not clearable: if the exact candidate is independently observed and its predecessor verified, the adapter returns confirmation; otherwise the intent remains unknown and latched. Only a typed adapter-issued expiry rejection can clear the latch, and only after readback does not show the candidate. Rejection capabilities are process-local: the host must durably resolve one before locking or exiting. If the capability is lost, a reopened wallet remains latched and permits only read-only confirmation; observing only the predecessor cannot prove that an in-flight write will never arrive. Android unit tests exercise this state machine with a fake transport and shared consent vector. The module includes `FileAndroidIdentityReplayNonceStore` for this host responsibility: construct it with an app-private internal-storage directory (for example, `Context.filesDir`). It persists only 32-byte nonce digests, serializes concurrent processes, and forces each append to storage before returning success; corruption and capacity exhaustion fail closed. Hosts may still provide another atomic `AndroidIdentityReplayNonceStore` implementation. `authenticatedOrigin` is a trusted host assertion, not authenticated by this library, and must come from a trusted principal rather than user-controlled text.

The module has no UI, interactive consent screen, or consumer payload-reading API. It now includes `AndroidDirectDhtIdentityTransport`, using jvm-libp2p TCP/Noise and standard Kad-DHT `GET_VALUE`/`PUT_VALUE` messages to explicitly configured, peer-ID-pinned Registry multiaddrs. Current and history-by-state-hash reads and confirmation use direct peer RPCs rather than a local DHT value store. Hash-addressed reads report absence only when every configured peer returns successfully without a value; if none provides the record and any peer errors, the result remains a transport failure. A matching-key `PUT_VALUE` acknowledgement is necessary but not confirmation: dispatch remains latched until a fresh direct read returns the exact candidate. Expected-state and expiry checks are client-side best-effort preconditions, not a network-wide compare-and-swap or remote deadline.

The optional host-JVM interop test exercises a legacy-anchored owner-key rotation against the Python Registry implementation, including direct current/history reads, publication, and fresh read-back; this is local loopback evidence only. `AndroidDirectDhtRegistryRuntimeTest` exercises the Android wallet, adapter, and concrete direct-DHT transport against a local two-peer fixture that seeds the predecessor, never the tested rotation candidate. Legacy and versioned/non-genesis rotation preserve the encrypted latch across reopen before dispatch, verify exact candidate bytes through the writer and distinct read-back peer, and persist promotion across another reopen. Missing/corrupt intermediate history, injected acknowledgement loss/no retry, concrete client preflight refusal, observed competing publication, and pre/post-replacement promotion faults have separate guarded fixture modes. The runtime suite uses the production file-backed replay-nonce store and checks rejection through a recreated store. Automatic lifecycle hooks, consuming-app permission integration and hardware-backed protection are not supplied by this library; these local tests do not establish production deployment, global DHT convergence or physical-outage durability.

## Build and test

From the repository root, with JDK 17 and Android SDK/build-tools 37 installed:

```sh
./gradlew --no-daemon --dependency-verification=strict \
  :platforms:android-wallet:testDebugUnitTest

./gradlew --no-daemon --dependency-verification=strict \
  :platforms:android-wallet:connectedDebugAndroidTest
```

## Wallet Registry acceptance harness

Use the self-managed runner to test both the desktop `RegistryTransport` and Android device transport against real local Registry peers:

```sh
python scripts/run_wallet_registry_acceptance.py --serial emulator-5554
```

The default run executes the marked Python Registry integration tests first, which own their peer fixtures. It then runs the complete Android host-JVM suite against a fresh two-peer Registry fixture, followed by ten device phases, each with another fresh fixture:

1. Full legacy instrumentation: the 14 container-storage cases plus two Registry cases.
2. Versioned/non-genesis owner-key rotation.
3. Missing intermediate predecessor history.
4. Corrupt intermediate predecessor history.
5. Promotion staging denial before replacement.
6. Injected acknowledgement loss with suppressed confirmation, reopen and read-only recovery.
7. Concrete client-side expected-state refusal before a wire PUT.
8. Recoverable post-replacement promotion rollback and read-only recovery.
9. Unknown promotion-storage outcome with session locking and retained-buffer clearing.
10. Deterministically interleaved competing publication with observed rival-head preservation.

Each filtered phase requires its exact class/method and fixture label. The default sequence executes 25 device cases per target (16 plus nine filtered cases); `--all-device-faults` is a redundant compatibility option, not required to enable these phases. The runner supplies pinned peer addresses, maps `DECENT_REGISTRY_TEST_FIXTURE` into the instrumentation argument, forces tasks to execute and rejects a missing/skipped selected testcase. Cleanup stops each fixture, removes temporary LMDB data and removes/verifies only its owned `adb reverse --no-rebind` mappings, preserving a primary execution failure if cleanup also fails. The default fixture runs two distinct peer identities/listeners and LMDB stores within its owned fixture process; it does not claim separate OS processes for those peers. Podman is not needed.

Options:

```sh
python scripts/run_wallet_registry_acceptance.py --desktop-only
python scripts/run_wallet_registry_acceptance.py --jvm-only
python scripts/run_wallet_registry_acceptance.py --android-only --serial emulator-5554
```

`--android-only` skips the Python tests but still runs host-JVM interop and device instrumentation.

Android mode requires exactly one connected Android target, and it must be an approved, boot-complete emulator. The runner checks the host AVD name/config, Google Play image, API level, and ABI, rejects physical devices or extra connected emulators, and repeats the target check immediately before Gradle. Do not connect or disconnect other Android devices during the run. Run approved AVDs sequentially, never concurrently: shut down one AVD before starting the next, then run the harness again. Approved targets are Medium_Phone (API 26, x86, Google Play) and Pixel_9 (API 37.2, x86_64, 16 KB page-size Google Play image). Do not run another harness or modify `adb reverse` mappings for the selected serial while a run is active; ADB has no atomic compare-and-remove, so the runner rechecks each target immediately before cleanup. The instrumentation creates a temporary wallet from deterministic synthetic keys matching the shared vector, verifies persisted latch state before dispatch, checks the exact candidate on both the writer and fresh read-back peer, then confirms persisted promotion after reopen. The fixture data and file-backed replay-nonce records are isolated synthetic test data; using the production store implementation here is not deployed Registry acceptance or proof of public-network behavior.

Pixel_9/API 37 targets Android 17 and is subject to local-network permission enforcement. The fixture uses `adb reverse` and loopback peer addresses; the library does not request `ACCESS_LOCAL_NETWORK`. Host apps that connect directly to private-LAN Registry peers must declare and request that permission themselves. See https://developer.android.com/privacy-and-security/local-network-permission.

The build maps peer and fixture environment variables to test inputs. The harness uses `--rerun-tasks` and verifies fresh instrumentation XML, so a selected test skipped for absent peer configuration cannot be reported as a pass.

Fresh source-only candidate verification at base `1663a893925153fb04ecbb71ccbc243d7a77beb2` passed all ten phases sequentially on Medium_Phone/API26/x86 and Pixel_9/API37.2/x86_64: **25 device cases per target, zero failures/errors/skips**, plus the full 112-case network-configured JVM suite on each target. Pixel_9 measured 16,384-byte pages; API26 lacked `getconf`, so its page size is not inferred. Strict APK assembly, fresh unit tests and lint passed (JDK27 for build/lint; the checked-in network runner selects JDK17). Focused harness/helper Python checks passed 80; the non-Registry host suite passed 326, with four optional/configuration skips and ten explicit Registry-integration deselections. Evidence, complete source/patch hashes, raw commands/logs and per-phase XML are under `/home/ben/.hermes/cache/scratch/issue18-android-registry-fault-slice-20261001T205852Z/`. This README-only update follows the frozen runtime capture; it does not change tested build inputs. Independent review/publication and Issue #18's final cross-target reconciliation remain separate gates.

Interpretation limits: damaged history can cause Registry to withhold the current envelope, so those cases demonstrate fail-closed draft refusal on unavailable current state, not Android parsing of damaged history. The lost acknowledgement is an injected application exception after completed concrete publication. Conditional refusal is client preflight, not provider CAS. The competing-write test observes genuine losing RPCs leaving rival heads intact, not global arbitration. Counters measure publication-method calls, not wire-write exactly-once. Promotion sync faults use the existing current-thread/normalized-directory hook around ordinary public session finalization; the session is reconstructed to retain buffers for pre-close clearing assertions, without replacing its storage callback. The hook covers files in that directory on that thread, not one file or asynchronous work. Recoverable recovery reopens the wallet and recreates the adapter while reusing a fresh reader's uncached remote-read path; it is not an OS-process restart. In the unknown case, restored bytes are fixture-visible but not proven durable. No physical-outage durability is claimed.

To have the unit test emit one randomized encrypted v2 file for an independent Python-core check, set `ANDROID_WALLET_INTEROP_FILE` to a path under the ignored module `build/` directory while running `createsAndReopensRandomizedV2Container`. Open that file with `decent_wallet.Wallet.open()` using the test password and compare `export_container()` to the original bytes. This optional artifact contains only a public synthetic test wallet.

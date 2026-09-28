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

Call `background()` from the app's lifecycle handling when the wallet should lock. The library does not install lifecycle observers automatically. Store the container in app-private storage; these APIs accept `java.nio.file.Path` and rely on atomic same-directory replacement plus process-local path serialization.

The v2 profile uses Argon2id v1.3 (65,536 KiB, 3 iterations, 4 lanes) and XChaCha20-Poly1305, strict duplicate-key rejection, canonical UTF-8 JSON, and version-bound associated data. Passwords must contain at least 16 Unicode scalar values. Error messages do not include passwords, keys, payloads, or raw storage errors.

The library supports CSRNG-generated Ed25519 owner keys, encrypted pending-successor preparation/cancellation, and a legacy-predecessor operation-5 draft/proof API. It verifies the exact predecessor signature and Owner Name bytes, checks the successor key pair and 2-of-3 signer set, and locally signs/verifies the candidate update digest with the pending key to prove possession; that PoP signature is discarded and is not included in the returned envelope. Version-1 predecessors are rejected until complete history verification is implemented.

`AndroidIdentityAdapter` adds the public-only prepare/latch/dispatch/confirm/promote orchestration through an injected `AndroidIdentityTransport`. Consent is bound to the exact canonical transcript and finalized envelope; the encrypted dispatch intent, including its selected environment, is persisted before the conditional write. The transport's stable `registryEnvironment` must match the reviewed environment for preparation, dispatch, and confirmation. Promotion requires a fresh remote read of the exact envelope and verified predecessor history. Ambiguous outcomes remain latched without automatic retry. A stale-state or conditional-precondition conflict is not clearable: if the exact candidate is independently observed and its predecessor verified, the adapter returns confirmation; otherwise the intent remains unknown and latched. Only a typed adapter-issued expiry rejection can clear the latch, and only after readback does not show the candidate. Rejection capabilities are process-local: the host must durably resolve one before locking or exiting. If the capability is lost, a reopened wallet remains latched and permits only read-only confirmation; observing only the predecessor cannot prove that an in-flight write will never arrive. Android unit tests exercise this state machine with a fake transport and shared consent vector. The host must provide an atomic `AndroidIdentityReplayNonceStore`; production implementations must persist consumed digests across process restarts. `authenticatedOrigin` is a trusted host assertion, not authenticated by this library, and must come from a trusted principal rather than user-controlled text.

The module has no UI, interactive consent screen, consumer payload-reading API, or concrete Registry/DHT transport. The host must provide an `AndroidIdentityTransport` that enforces conditional publication and a genuinely fresh remote read; the module cannot prove that a host transport honors those requirements. No production Registry deployment, Android network adapter, AVD runtime evidence, or full cross-platform acceptance is claimed. Automatic lifecycle hooks and hardware-backed protection are also absent.

## Build and test

From the repository root, with JDK 17 and Android SDK/build-tools 37 installed:

```sh
./gradlew --no-daemon --dependency-verification=strict \
  :platforms:android-wallet:testDebugUnitTest

./gradlew --no-daemon --dependency-verification=strict \
  :platforms:android-wallet:connectedDebugAndroidTest
```

The instrumentation tests are intended for the two approved Issue #36 targets: Medium_Phone (API 26, x86, Google Play) and Pixel_9 (API 37, x86_64, 16 KB page-size Google Play image). Connect both AVDs before running the connected test task.

To have the unit test emit one randomized encrypted v2 file for an independent Python-core check, set `ANDROID_WALLET_INTEROP_FILE` to a path under the ignored module `build/` directory while running `createsAndReopensRandomizedV2Container`. Open that file with `decent_wallet.Wallet.open()` using the test password and compare `export_container()` to the original bytes. This optional artifact contains only a public synthetic test wallet.

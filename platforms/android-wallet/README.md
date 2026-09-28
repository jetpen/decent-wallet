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

The library supports CSRNG-generated Ed25519 owner keys, encrypted pending-successor preparation/cancellation, legacy-predecessor operation-5 authoring, and versioned-predecessor operation-5 authoring. `AndroidIdentityAdapter.createVersionedOwnerKeyRotationDraft()` resolves and verifies bounded predecessor history by state hash, then builds the canonical operation-5 update while preserving the predecessor epoch, threshold, signer set, Owner Name bytes, and sequence lineage. The host requests detached signatures from those predecessor signers and supplies `OwnerKeyRotationProof` values; the wallet validates the signer identities, signatures, and threshold without receiving signer private keys. It signs/verifies candidate proof-of-possession locally with the pending owner key, then discards that signature rather than including it in the envelope. The adapter revalidates the complete candidate chain before consent and dispatch. History resolution is capped at 1,024 predecessor links and 4 MiB aggregate envelope bytes; each versioned envelope permits at most three proofs and proof signer IDs are capped at 256 UTF-8 bytes.

`AndroidIdentityAdapter` adds the public-only prepare/latch/dispatch/confirm/promote orchestration through an injected `AndroidIdentityTransport`. Consent is bound to the exact canonical transcript and finalized envelope; the encrypted dispatch intent, including its selected environment, is persisted before the conditional write. The transport's stable `registryEnvironment` must match the reviewed environment for preparation, dispatch, and confirmation. Promotion requires a fresh remote read of the exact envelope and verified predecessor history. Ambiguous outcomes remain latched without automatic retry. A stale-state or conditional-precondition conflict is not clearable: if the exact candidate is independently observed and its predecessor verified, the adapter returns confirmation; otherwise the intent remains unknown and latched. Only a typed adapter-issued expiry rejection can clear the latch, and only after readback does not show the candidate. Rejection capabilities are process-local: the host must durably resolve one before locking or exiting. If the capability is lost, a reopened wallet remains latched and permits only read-only confirmation; observing only the predecessor cannot prove that an in-flight write will never arrive. Android unit tests exercise this state machine with a fake transport and shared consent vector. The module includes `FileAndroidIdentityReplayNonceStore` for this host responsibility: construct it with an app-private internal-storage directory (for example, `Context.filesDir`). It persists only 32-byte nonce digests, serializes concurrent processes, and forces each append to storage before returning success; corruption and capacity exhaustion fail closed. Hosts may still provide another atomic `AndroidIdentityReplayNonceStore` implementation. `authenticatedOrigin` is a trusted host assertion, not authenticated by this library, and must come from a trusted principal rather than user-controlled text.

The module has no UI, interactive consent screen, or consumer payload-reading API. It now includes `AndroidDirectDhtIdentityTransport`, using jvm-libp2p TCP/Noise and standard Kad-DHT `GET_VALUE`/`PUT_VALUE` messages to explicitly configured, peer-ID-pinned Registry multiaddrs. Current and history-by-state-hash reads and confirmation use direct peer RPCs rather than a local DHT value store. Hash-addressed reads report absence only when every configured peer returns successfully without a value; if none provides the record and any peer errors, the result remains a transport failure. A matching-key `PUT_VALUE` acknowledgement is necessary but not confirmation: dispatch remains latched until a fresh direct read returns the exact candidate. Expected-state and expiry checks are client-side best-effort preconditions, not a network-wide compare-and-swap or remote deadline.

The optional local interop test exercises a legacy-anchored owner-key rotation against the Python Registry implementation: direct current/history reads, publication, and exact fresh read-back. It proves loopback interoperability only. Production deployment, an independent second-peer read, Android-device execution of the new transport, and full cross-platform acceptance remain outstanding. Approved-AVD instrumentation still covers container lifecycle only; rotation/runtime behavior otherwise remains unit-tested. Automatic lifecycle hooks and hardware-backed protection are also absent.

## Build and test

From the repository root, with JDK 17 and Android SDK/build-tools 37 installed:

```sh
./gradlew --no-daemon --dependency-verification=strict \
  :platforms:android-wallet:testDebugUnitTest

./gradlew --no-daemon --dependency-verification=strict \
  :platforms:android-wallet:connectedDebugAndroidTest
```

For optional local Android-to-Registry interoperability, start a peer from a sibling `decent-registry` checkout in one terminal:

```sh
uv run --project /path/to/decent-registry python /path/to/decent-wallet/tests/interop/start_android_registry_peer.py
```

Copy the printed `READY` multiaddr, then run from the wallet repository root in another terminal:

```sh
DECENT_REGISTRY_TEST_PEER='<READY multiaddr>' \
  ./gradlew --no-daemon --dependency-verification=strict \
  :platforms:android-wallet:testDebugUnitTest \
  --tests org.decentwallet.wallet.android.AndroidDirectDhtRegistryInteropTest
```

The build maps the peer environment variable to a test system-property input, so a changed peer address invalidates Gradle's test result. The helper starts a temporary Registry with the shared synthetic legacy-anchor fixture. This is a host-JVM loopback test, not Android-device or production-deployment acceptance.

The instrumentation tests are intended for the two approved Issue #36 targets: Medium_Phone (API 26, x86, Google Play) and Pixel_9 (API 37, x86_64, 16 KB page-size Google Play image). Connect both AVDs before running the connected test task.

To have the unit test emit one randomized encrypted v2 file for an independent Python-core check, set `ANDROID_WALLET_INTEROP_FILE` to a path under the ignored module `build/` directory while running `createsAndReopensRandomizedV2Container`. Open that file with `decent_wallet.Wallet.open()` using the test password and compare `export_container()` to the original bytes. This optional artifact contains only a public synthetic test wallet.

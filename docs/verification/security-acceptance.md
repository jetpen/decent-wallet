# Wallet security acceptance

The acceptance contract is the mandatory security matrix in [the wallet implementation specification](../specs/wallet-implementation.md#12-security-acceptance-matrix). Current MVP targets are the Python/desktop core and Android wallet JVM suite; native iOS is excluded by ADR-0004. These commands use public synthetic vectors and disposable, local state only. Do not provide a real wallet, password, key, production credential, or production Registry endpoint.

## Profiles

**Profile split**

- `core` includes all default Python test files except the three modules that skip during import when the optional Registry provider is absent. Those modules run in `full` with the provider installed; individual test skips inside the core suite are still rejected unless explicitly listed. The five optional Python skip cases plus one optional pass case are all reported separately. The Podman Registry deployment probe is included: when managed peers are absent it is an allowlisted optional skip, otherwise it must run and pass. Optional passes/skips stay out of mandatory counts, and receipt validation enforces each outcome against the reviewed case policy.
- `android-jvm` runs the Android wallet JVM suite; all tests except its one explicitly tracked environment-dependent live-peer test must pass. The live-peer test outcome is separately represented in receipt metadata.
- `full` composes the core, Android JVM, Android Registry peer fixture, and local Registry integration suites, using the same JUnit and receipt validation rules across suites.

```sh
# Full Python suite except provider-dependent Registry module collection; that matrix lives under its own pinned Registry profile. Any unexpected skip or failure blocks.
uv run --locked --extra test python scripts/security_acceptance.py \
  --profile core --receipt "$TMPDIR/wallet-security-core.json"

# Android wallet JVM suite and Kotlin-authored encrypted-container artifacts.
# Requires JDK 17 and the Android SDK platform/build tools for this project.
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
uv run --locked --extra test python scripts/security_acceptance.py \
  --profile android-jvm --receipt "$TMPDIR/wallet-security-android-jvm.json"

# `full` runs core, Android JVM, and Registry integration profiles.
# Requires JDK 17, Android SDK, and the local provider checkout pinned in uv.lock.
export ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_SDK_ROOT="$ANDROID_HOME"
export JAVA_HOME="${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v java)")")")}"
export DECENT_REGISTRY_PATH="${DECENT_REGISTRY_PATH:-../decent-registry}"
uv run --locked --extra test --extra registry \
  --with-editable "$DECENT_REGISTRY_PATH" \
  python scripts/security_acceptance.py \
  --profile full --receipt "$TMPDIR/wallet-security-full.json"

```

## Optional-case reporting

Report digests stay local; do not write a JUnit report digest into the receipt because low-entropy strings in raw reports create an offline guessing oracle. Verify reports locally, discard them after validation, and keep only aggregate counts and bounded, allowlisted evidence categories in receipts.

The `Wallet security acceptance` workflow runs the core and Android JVM profiles as independent required jobs. A Registry integration job runs the full profile against the exact provider revision pinned in `uv.lock`, including fresh Kotlin artifact production. Jobs use separate workspaces; none requires production credentials, production peers, or deployed Registry state. The workflow does not claim Android device/AVD runtime or global DHT acceptance; those remain dedicated gates.

## Receipt privacy

Test receipts exclude raw JUnit reports, raw logs, skip/failure text, and digests of report content: even a one-way report hash can serve as an offline guessing oracle for low-entropy sensitive strings. They may include aggregate mandatory-pass counts, the source revision, coarse runtime metadata, approved hashes of reviewed public/synthetic vectors or generated test ciphertext, and a strict allowlist of evidence categories. Never hash wallet, user, credential, or decrypted data into a receipt; never publish receipts to wallet or Registry/DHT state.

## Before / after

- **Before:** The acceptance runner printed Gradle output after a character filter, which still allowed plain-text secrets and test data to pass through. It included a digest of the complete JUnit report, which could permit offline guessing of low-entropy values. Optional skip accounting and transition validation did not clearly separate non-mandatory outcomes from mandatory counts.
- **After:** Command stdout/stderr is captured but never printed; raw reports and their digests stay local. Mandatory suite counts exclude only exact, reviewed environment-gated cases; receipt transitions are validated against fixed allowlists and cannot add arbitrary strings.


The full acceptance profile checks exact JUnit case inventories for the Android peer fixture and both pinned Registry integration modules. Its CI job timeout is 60 minutes to leave room for Android build/runtime tasks and local multi-peer integration tests. Android device/AVD runtime and global DHT acceptance remain dedicated gates and are not claimed by these profiles.

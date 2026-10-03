# Wallet security acceptance

The acceptance contract is the mandatory security matrix in [the wallet implementation specification](../specs/wallet-implementation.md#12-security-acceptance-matrix). Current MVP targets are the Python/desktop core and Android wallet JVM suite; native iOS is excluded by ADR-0004. These commands use public synthetic vectors and disposable, local state only. Do not provide a real wallet, password, key, production credential, or production Registry endpoint.

## Profiles

**Profile split**

- `core` includes the default Python test files except three provider-dependent modules: `test_android_registry_peer.py` belongs to `full`; `test_podman_registry_deployment.py` requires its separately managed Podman diagnostic; `test_remote_registry_acceptance.py` requires a remote fixture and is outside this local acceptance scope. Excluding these modules avoids collection-time import skips in installs without the optional Registry provider. Four artifact/driver-dependent cases and the optional Registry configuration case are disclosed by their actual passed/skipped outcomes, separately from mandatory counts. An unexpected skip still blocks acceptance.
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

# Required managed local Podman diagnostic (no Android tooling or remote peers).
env -u PYTEST_ADDOPTS uv run --locked --extra test --extra registry \
  python scripts/run_wallet_registry_acceptance.py \
  --desktop-only --peer-backend podman --registry-repo "$DECENT_REGISTRY_PATH"

# Required packaged desktop lifecycle/runtime gate.
CONTAINER_RUNTIME=podman platforms/desktop-wallet/verify-container.sh

```

## Optional-case reporting

Report digests stay local; do not write a JUnit report digest into the receipt because low-entropy strings in raw reports create an offline guessing oracle. Verify reports locally, discard them after validation, and keep only aggregate counts and bounded, allowlisted evidence categories in receipts.

The `Wallet security acceptance` workflow runs core, Android JVM, full pinned-provider acceptance, and a managed rootless `podman-registry-deployment` diagnostic as separate fail-closed jobs. The Podman job provisions disposable peers and requires its exact test to pass rather than skip. It establishes peer-scoped stale/expired/ambiguous publication behavior, not independent candidate confirmation or global propagation. Jobs use separate workspaces; none requires production credentials, production peers, or deployed Registry state. Branch protection must require these job names plus the dedicated desktop runtime gate; workflow success is not itself branch-protection enforcement. Android device/AVD runtime and global DHT acceptance are not claimed by these profiles.

## Receipt privacy

Test receipts exclude raw JUnit reports, raw logs, skip/failure text, and digests of report content: even a one-way report hash can serve as an offline guessing oracle for low-entropy sensitive strings. They may include aggregate mandatory-pass counts, the source revision, coarse runtime metadata, approved hashes of reviewed public/synthetic vectors or generated test ciphertext, and a strict allowlist of evidence categories. Never hash wallet, user, credential, or decrypted data into a receipt; never publish receipts to wallet or Registry/DHT state.

## Before / after

- **Before:** The acceptance runner printed Gradle output after a character filter, which still allowed plain-text secrets and test data to pass through. It included a digest of the complete JUnit report, which could permit offline guessing of low-entropy values. Optional skip accounting and transition validation did not clearly separate non-mandatory outcomes from mandatory counts.
- **After:** Command stdout/stderr is captured but never printed; raw reports and their digests stay local. Mandatory suite counts exclude only exact, reviewed environment-gated cases; receipt transitions are validated against fixed allowlists and cannot add arbitrary strings.


The full acceptance profile checks exact JUnit case inventories for the Android peer fixture and both pinned Registry integration modules. The rootless desktop/Podman lifecycle and runtime conformance gate remains the existing `Desktop rotation runtime` workflow, including image builds and CLI smoke tests. Its workflow and `platforms/desktop-wallet/**` paths trigger this gate separately; desktop/Podman runtime is therefore covered by a separate CI release gate, not as a receipt-producing suite of `security_acceptance.py`. The Registry acceptance job has a 60-minute limit for Android build tasks and local multi-peer integration.

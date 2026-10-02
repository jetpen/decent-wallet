# Android container-storage fault acceptance (Issue #18 partial slice)

This slice exercises Android container lifecycle failures without Registry peers.
It does not close Issue #18. Network rotation faults, consuming-host LAN
permission integration, and desktop packaging changes are separate slices.

## Contract and coverage

`AndroidWalletRuntimeTest` contains 14 cases:

- Approved API/ABI validation and the shared-vector encrypted-container lifecycle.
- Wrong-password migration preserves exact v1 bytes.
- Import refuses to overwrite an initialized destination.
- Effective directory-permission denial propagates through public migration and
  import before staging; recovery succeeds after permissions are restored.
- Direct atomic replacement has recoverable and unknown rollback outcomes.
- Public cancellation through the existing internal session replacement callback
  preserves keys/session usability after recoverable rollback; unknown rollback
  locks the session, clears retained raw-container, Wallet DEK and private-seed
  buffers, and rejects subsequent operations without another replacement.
- Public migration post-install sync failure restores exact v1 bytes and supports
  explicit recovery after verified rollback; unknown rollback returns no session.
- Public import post-install sync failure removes the installed destination and
  supports explicit recovery after verified cleanup; unknown cleanup returns no
  session and is not retried.

The internal `AtomicWalletFiles.withDirectorySyncForTest` callback applies to all
wallet files in one normalized directory on the current thread. It does not
propagate to other threads. Nested scopes restore the previous callback, including
on exceptions; leaving the outer scope removes it. JVM tests exercise directory,
thread, nested-scope, and exception-unwinding isolation. Kotlin `internal` visibility
is a trusted test convention, not JVM access control. Public storage APIs are
unchanged; ordinary production calls still force the directory through FileChannel.

Injected sync exceptions establish synchronous error propagation over real file
operations, not physical power-loss durability. Visible bytes after unknown
rollback are fixture observations only. The direct-storage unknown case's
unsupported-format open attempt observes the visible format; it is not recovery.
Unknown public migration/import cases do not reopen or retry the ambiguous target.
Clearing retained arrays does not claim exhaustive JVM heap erasure. Registry state
is not involved in these tests.

## Verified extracted composition

- Strict JVM suite: 112 cases, 111 passed and one optional Registry interop skip;
  zero failures/errors. Lint and instrumentation APK assembly passed. Lint reports
  two dependency-version warnings and a trust-manager warning inside the existing
  Bouncy Castle dependency; no dependency or TLS implementation changed here.
- Medium_Phone API 26/x86: 14 passed, zero failures/errors/skips.
- Pixel_9 API 37/x86_64: 14 passed, zero failures/errors/skips; measured page size
  16384 bytes. API 26's `getconf` probe was unavailable.
- Tracked Python non-Registry suite: 301 passed, four optional/configuration skips,
  ten Registry integration cases explicitly deselected. Untracked LAN-host tests
  in the preparation worktree were not selected.
- Independent implementation review: no blocking logic/security findings.
- The four-file implementation patch replays cleanly onto the recorded base, and
  the replay matches all 142 tracked-source hashes.

Machine XML is retained verbatim. Committed logs and image-properties text have
only trailing whitespace/extra final blank lines normalized. The original raw
bundle remains in the local scratch evidence directory. Reconstruct the recorded
implementation patch with `git diff --binary 4d8ef4647de3b8c780e396a4cc1669caeec452a0
<PR-head> -- platforms/android-wallet`; documentation/evidence are outside that
patch hash. These are acceptance tests for already-existing fail-closed behavior,
not a claim of a newly corrected lifecycle bug.

## Reproduce

Use JDK 27 and the repository-pinned Android SDK/toolchain. Lint's existing
JDK-17 compatibility issue is not fixed by this PR.

```sh
ANDROID_HOME="$HOME/Android/Sdk" ANDROID_SDK_ROOT="$HOME/Android/Sdk" \
  ./gradlew --no-daemon --dependency-verification=strict \
  :platforms:android-wallet:testDebugUnitTest \
  :platforms:android-wallet:lintDebug \
  :platforms:android-wallet:assembleDebugAndroidTest --rerun-tasks

ANDROID_HOME="$HOME/Android/Sdk" ANDROID_SDK_ROOT="$HOME/Android/Sdk" \
  ./gradlew --no-daemon --dependency-verification=strict \
  -PwalletAndroidTestClass=org.decentwallet.wallet.android.AndroidWalletRuntimeTest \
  :platforms:android-wallet:connectedDebugAndroidTest --rerun-tasks
```

Run exactly one approved emulator at a time: Medium_Phone API 26 Google Play x86,
then Pixel_9 API 37 Google Play x86_64. Verify the AVD name with `adb emu avd name`
and cross-check its config/image revision, API, and ABI. Archive each fresh XML
before running the next target. The class selector is explicit; running it does
not refresh the full networked suite. No Registry configuration or ADB reverse
mapping is needed.

The adjacent `issue18-android-storage/` evidence bundle is deliberately retained
under its historical path. It is an immutable record of the Issue #18 verification
run: captured commands, logs, source manifests and hashes use the original names.
Renaming or rewriting the bundle would make its provenance harder to audit. The
maintained runner, selector, and reproduction command above use purpose-based
names; this archive path is historical evidence, not an executable interface.
The bundle records the tested base, implementation patch hash, tracked source hashes,
fresh machine reports, exact device commands, runtime/AVD/image identities, and
independent review. Hashes refer to the extracted implementation before this
documentation/evidence was added; older broad-worktree matrix results are not
relabeled as this PR's verification.

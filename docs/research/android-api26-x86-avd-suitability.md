# API 26 x86 AVD runtime-test target

**Finding:** The only API 26 target in Issue #36's acceptance matrix is `Medium_Phone`, the Google Play x86 AVD. Android's emulator documentation permits x86 images on an x86_64 host for API 10 and later, and this host's KVM check passes. The Issue #36 suite has now passed on this target and on `Pixel_9` (Android 37.2/API 37 x86_64); evidence is under [`docs/reports/issue-36/20260927T025037Z/`](../reports/issue-36/20260927T025037Z/). No physical-device or alternate-image substitution is in scope.

## Target evidence

- Issue #36 and [`CONTRIBUTING.md`](../../CONTRIBUTING.md) select the API 26 x86 `Medium_Phone` AVD and the API 37.2 x86_64 `Pixel_9` AVD only. These are the complete accepted matrix; other images do not count toward acceptance.
- Android's [hardware-acceleration requirements](https://developer.android.com/studio/run/emulator-acceleration) permit the selected API 26 x86 image on this x86_64 host. Linux uses KVM, and the same document describes `emulator -accel-check` as the hypervisor check. The observed check reports `KVM (version 12) is installed and usable`.
- An AVD selects both an Android version and virtual-device characteristics; the [Emulator guide](https://developer.android.com/studio/run/emulator) describes using it to test Android API levels. The API 26 x86 run exercises the Android runtime and verifier path on the sole API 26 image selected for this issue.
- The selected API 26 image uses the x86 guest ABI; the separate API 37 `Pixel_9` image uses x86_64.
- The verifier source is compiled directly into the separate test-only Android module at Java 8 bytecode/API level. Its dependencies are pinned in the Android Gradle module and locked; the Android instrumentation run exercises the canonical vector and tampering/rejection cases on each accepted image. The independent Kotlin/JVM Maven module remains unchanged and outside the Android workflow.

## Local inventory (inspection only)

- `Medium_Phone`: `target=android-26`, `abi.type=x86`, Google Play x86 image.
- `Pixel_9`: Android 37.2, `abi.type=x86_64`.
- `emulator -accel-check`: KVM reports usable. `adb devices -l`: no attached/running device.

## Recommendation

Use `Medium_Phone` as the sole accepted API 26 x86 target and `Pixel_9` as the accepted API 37.2 x86_64 target. Record the ABI and image fingerprint for each result. No physical-device or alternate-image fallback counts toward acceptance. If either selected AVD cannot run, block the test and seek approval before changing the matrix.

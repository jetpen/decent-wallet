# API 26 x86 AVD suitability for verifier runtime tests

**Finding:** The selected API 26 target for Issue #36 is the available `Medium_Phone` Google Play x86 AVD. Android's emulator documentation permits x86 images on an x86_64 host for API 10 and later, and this host's KVM check passes. The Issue #36 suite has now passed on this 32-bit x86 guest and on `Pixel_9` (Android 37.2/API 37 x86_64); evidence is under [`docs/reports/issue-36/20260927T025037Z/`](../reports/issue-36/20260927T025037Z/). The API 26 result provides runtime evidence only for that x86 guest, not x86_64 native-ABI coverage. No physical-device or alternate-image substitution is in scope.

## Evidence and coverage boundaries

- Issue #36 and [`CONTRIBUTING.md`](../../CONTRIBUTING.md) now select the locally available API 26 x86 AVD and the API 37.2 x86_64 AVD only. This supersedes the earlier x86_64 API 26 proposal and physical-device fallback; other images do not count toward acceptance.
- Android's [hardware-acceleration requirements](https://developer.android.com/studio/run/emulator-acceleration) explicitly allow **x86 or x86_64 system images on an x86_64 host** for Android API 10 and later. Linux uses KVM, and the same document describes `emulator -accel-check` as the hypervisor check. Thus API 26 x86 is eligible for KVM acceleration; host/guest ABI mismatch does not itself prevent acceleration. The observed check reports `KVM (version 12) is installed and usable`.
- An AVD selects both an Android version and virtual-device characteristics; the [Emulator guide](https://developer.android.com/studio/run/emulator) describes using it to test Android API levels. An API 26 x86 run can therefore exercise the API-26 Android runtime and the verifier's Java/Kotlin path on that image. It is evidence for that specific 32-bit guest, not proof that every API-26 ABI behaves identically.
- ABI is a separate dimension: Android's [ABI reference](https://developer.android.com/ndk/guides/abis) defines `x86` as IA-32 and `x86_64` as a distinct 64-bit ABI with different instruction-set and binary conventions. An x86 AVD does not test loading/execution of x86_64 native libraries or other 64-bit-specific paths.
- The verifier source is compiled directly into the separate test-only Android module at Java 8 bytecode/API level. Its dependencies are pinned in the Android Gradle module and locked; the Android instrumentation run exercises the canonical vector and tampering/rejection cases on each accepted image. The independent Kotlin/JVM Maven module remains unchanged and outside the Android workflow. The ABI limit still applies: API 26 x86 does not test x86_64 native libraries.

## Local inventory (inspection only)

- `Medium_Phone`: `target=android-26`, `abi.type=x86`, Google Play x86 image.
- `Pixel_9`: Android 37.2, `abi.type=x86_64`.
- `emulator -accel-check`: KVM reports usable. `adb devices -l`: no attached/running device.

## Recommendation

Use `Medium_Phone` as the accepted API 26 x86 target and `Pixel_9` as the accepted API 37.2 x86_64 target. Record the ABI and image fingerprint for each result. The API 26 result does not establish x86_64 native-ABI coverage; no physical-device or alternate-image fallback counts toward acceptance. If either selected AVD cannot run, block the test and seek approval before changing the matrix.

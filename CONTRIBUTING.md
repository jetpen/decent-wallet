# Contributing

## Scope and Android status

The current product is a Python wallet library. The repository has no production Android application or adapter. The accepted Android-related implementation is a standalone, test-only Kotlin/JVM consumer of the wallet-container v2 vector; it uses Maven and is not an Android app. See the [wallet implementation specification](docs/specs/wallet-implementation.md#kotlinjvm-v2-vector-consumer-issue-33-accepted-and-implemented).

Issue [#36](https://github.com/jetpen/decent-wallet/issues/36) tracks a separate test-only Android runtime-conformance harness for that verifier. The Gradle-only Android library and instrumentation harness is implemented. Its latest locked run passed all nine cases on both approved AVDs; see the evidence manifest and XML reports under `docs/reports/issue-36/20260927T025037Z/`. Bouncy Castle's build-time Android API 26 compatibility check remains static evidence only; runtime compatibility claims are limited to the named tested images and cases.

For the Python and Kotlin/JVM checks, Android Studio, the Android SDK, and an emulator are not needed. The existing Kotlin/JVM verifier remains a separate Maven-based module. Issue #36's test-only Android harness uses the Gradle Wrapper exclusively; do not invoke Maven for its build/test workflow or use Maven-produced artifacts.

## Prerequisite tools

Install these tools:

- **Git**, to check out the source. Install from [git-scm.com](https://git-scm.com/downloads) or your operating system's package manager.
- **Python 3.12 or newer**, to install and test the current wallet library. Use the [official Python downloads](https://www.python.org/downloads/) or a supported operating-system package manager. Keep the operating system's default Python intact; use a virtual environment for this project.
- **JDK 17 or newer**, to run the test-only Kotlin/JVM vector verifier. Install a JDK (not only a JRE), for example [Eclipse Temurin](https://adoptium.net/temurin/releases/?version=17). The module emits Java 8 bytecode and targets the Java 8 API; JDK 8 is not sufficient to run its build.

### Install by operating system

- **Debian/Ubuntu:** install Git and Python tooling with `sudo apt update && sudo apt install git python3 python3-venv`. Check that `python3 --version` is at least 3.12; some supported OS releases provide an older Python, so install Python 3.12+ from [python.org](https://www.python.org/downloads/) or an approved package source rather than replacing the system interpreter. Install a JDK 17+ package if available, or use the [Temurin JDK installer](https://adoptium.net/temurin/releases/?version=17).
- **macOS:** install Git with `xcode-select --install`, then install Python 3.12+ from [python.org](https://www.python.org/downloads/) and a JDK 17+ `.pkg` installer from [Temurin](https://adoptium.net/temurin/releases/?version=17).
- **Windows:** install [Git for Windows](https://git-scm.com/download/win), Python 3.12+ from [python.org](https://www.python.org/downloads/) (enable the Python launcher), and the Temurin JDK 17+ `.msi` installer. Ensure the JDK `bin` directory is on `PATH`; set `JAVA_HOME` if more than one JDK is installed.

Verify the tools (use the Python 3.12 interpreter you installed):

```bash
git --version
python3.12 --version
java -version
javac -version
```

On Windows, `py -3.12 --version` can select Python 3.12, and the `java` and `javac` commands should report JDK 17 or newer. If multiple JDKs are installed, set `JAVA_HOME` and `PATH` so the intended JDK is used.

A system-wide Maven installation is not required. The existing Kotlin/JVM module includes Maven Wrapper configured for Apache Maven 3.9.16; the wrapper JAR and Maven distribution each have a pinned SHA-256 checksum. Its lockfile applies only to that JVM module. The independent Issue #36 Android workflow uses Gradle Wrapper and does not invoke Maven or rely on Maven-produced artifacts.

## Test the Kotlin/JVM v2 vector verifier

From `interop/kotlin/`, run the single locked build-and-test command:

```bash
./mvnw -B -ntp verify
```

It runs Maven Lockfile validation in the `validate` phase before compilation and tests. The checked-in `lockfile.json` records SHA-256 checksums for the module's resolved dependencies and Maven plugins. The module reads the canonical shared vector at `tests/vectors/wallet-container-v2.json`; do not copy the fixture into a separate Kotlin tree. All Kotlin dependencies are test-scoped, and the module has no production Kotlin API, Android application, or APK target. Android Studio, the Android SDK, and an emulator are not needed.

## Set up and test the current Python library

Run these commands from the repository root. On Linux or macOS (use the versioned command to avoid an older system Python):

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
python -m pytest -q
python -m compileall -q src tests
python -m pip check
```

On Windows PowerShell, create the environment and invoke its Python directly:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[test]"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m pip check
```

The test dependencies are declared by `pyproject.toml`. Do not put passwords, seeds, private keys, or production wallet data in test commands, environment variables, logs, or temporary files. The checked-in interoperability vector is public synthetic test data; it must never be used to create a real wallet.

## Android runtime-conformance harness (Issue #36)

Issue #36's runtime matrix is limited to the two approved emulator configurations: API 26 `Medium_Phone` using the Google Play x86 system image, and API 37 `Pixel_9` using the Android 37.2 Google APIs Play Store x86_64 image with 16 KB pages. Both are required; physical devices and alternate images do not substitute. `Medium_Phone` with its Google Play x86 image is the sole API 26 target in this matrix. The harness is test-only: it adds no Android wallet app, UI, keystore integration, production adapter, or Registry transport.

Run the complete matrix from the repository root with the single Gradle Wrapper command below. It uses Gradle 9.5.0, AGP 9.3.1, KGP 2.4.20, JDK 17, compileSdk 37, minSdk 26, Java/Kotlin bytecode target 8, AndroidX Test Runner 1.7.0/JUnit 4, Bouncy Castle 1.86, and Jackson Core 2.22.2. Dependency locking and strict SHA-256 verification are enabled; the wrapper distribution checksum is pinned. Maven is not part of this Android workflow.

```bash
./gradlew --no-daemon --dependency-verification=strict :interop:android-runtime:connectedDebugAndroidTest
```

For the reproducible acceptance run, use the repository runner, which validates exact AVD configuration/image revisions, boots both approved AVDs, invokes that Gradle task once, and writes machine-readable JSON/XML results plus logs under `docs/reports/issue-36/<UTC timestamp>/`:

```bash
python3 scripts/run-android-runtime-conformance.py
```

The latest passing evidence is `docs/reports/issue-36/20260927T025037Z/results.json`. It records both AVDs, image/package revisions, API, ABI, build fingerprints, SDK/build-tools/emulator revisions, locked command, and each test report. Each target passed 9 tests with zero failures, errors, or skips. Runtime claims remain bounded to those exact images and cases; no universal Android compatibility or full Issue #18 completion is claimed.

### Required tools

- **JDK 17 or newer.** Install as described above. A JRE alone is insufficient. JDK 17 is also the selected baseline for the Android Gradle Plugin toolchain.
- **Android Studio and Android SDK tools.** Install the current stable [Android Studio](https://developer.android.com/studio). Android Studio is used here to install/manage SDK packages and virtual devices; the Android test harness itself is built only with Gradle Wrapper, not Maven. Google's [Android 17 SDK setup guide](https://developer.android.com/about/versions/17/setup-sdk) recommends Android Studio Meerkat 2024.3.1 or newer for that preview SDK.
- **SDK packages** in Android Studio's **Tools > SDK Manager**:
  - In **SDK Platforms**, install **Android 8.0 (Oreo), API 26** and **Android 17 (Cinnamon Bun Preview), API 37**. API 37 is a preview target and may change before release.
  - In **SDK Tools**, install **Android SDK Command-line Tools (latest)**, **Android SDK Platform-Tools** (`adb`), **Android Emulator**, and **Android SDK Build-Tools 37.x**. Google's [Android 17 SDK setup guide](https://developer.android.com/about/versions/17/setup-sdk) instructs selecting the latest 37.x Build-Tools. The Gradle build must pin and verify the exact SDK package revisions before the setup can be called reproducible.
  - Accept the Android SDK license agreements presented by the SDK Manager before downloading packages.
- **System images and virtual devices.** Issue #36 accepts only two emulator images: `Medium_Phone`, the sole API 26 target, using Google Play x86; and `Pixel_9`, Android 37.2/API 37, using Google APIs Play Store x86_64 with 16 KB page size. The API 26 x86 image is supported for accelerated emulation on an x86_64 host; see Google's [emulator acceleration requirements](https://developer.android.com/studio/run/emulator-acceleration). Record each image revision and ABI. No physical-device fallback or alternate emulator image is in the acceptance matrix; if either target cannot be run, stop and request approval to change the matrix. Follow Google's [AVD guide](https://developer.android.com/studio/run/managing-avds) to manage the devices.
- **Hardware virtualization for accelerated emulation.** Linux uses KVM, Windows can use Windows Hypervisor Platform, and macOS uses Hypervisor.Framework. Acceleration requires processor virtualization support; without it, emulator performance may be poor. Check Google's [emulator acceleration requirements](https://developer.android.com/studio/run/emulator-acceleration). If an accepted AVD cannot use the host hypervisor or boot, the matrix is blocked; do not substitute a physical device or a different image without approval.

### SDK location and environment

Use the SDK location shown in **Tools > SDK Manager**. Set `ANDROID_HOME` to that directory and add its `platform-tools` and `emulator` subdirectories to `PATH`. Android's [environment-variable guide](https://developer.android.com/tools/variables) documents `ANDROID_HOME` as the SDK path variable and marks `ANDROID_SDK_ROOT` as deprecated. Common defaults are `$HOME/Android/Sdk` on Linux, `$HOME/Library/Android/sdk` on macOS, and `%LOCALAPPDATA%\Android\Sdk` on Windows; use the actual location shown by the SDK Manager.

On Linux, for the common SDK location (adjust it for your installation):

```bash
export ANDROID_HOME="$HOME/Android/Sdk"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
```

On macOS, for the common SDK location (adjust it for your installation):

```bash
export ANDROID_HOME="$HOME/Library/Android/sdk"
export PATH="$ANDROID_HOME/platform-tools:$ANDROID_HOME/emulator:$PATH"
```

On Windows PowerShell, for the common SDK location:

```powershell
$env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
$env:Path = "$env:ANDROID_HOME\platform-tools;$env:ANDROID_HOME\emulator;$env:Path"
```

Persist these variables through the shell profile or operating-system environment settings if needed. Keep `JAVA_HOME` and `PATH` pointed at the JDK 17+ installation used for the Android Gradle Plugin build.

### Verify installation

From the repository root on Linux or macOS, run:

```bash
java -version
javac -version
./interop/kotlin/mvnw -v
adb version
emulator -version
emulator -accel-check
emulator -list-avds
adb devices -l
```

On Windows PowerShell, use the wrapper batch file:

```powershell
java -version
javac -version
.\interop\kotlin\mvnw.cmd -v
adb version
emulator -version
emulator -accel-check
emulator -list-avds
adb devices -l
```

The Maven wrapper command above verifies only the separate Kotlin/JVM module; it is not part of the Android workflow. `emulator -list-avds` should show the approved `Medium_Phone` and `Pixel_9` AVDs. For Android conformance, use the single Gradle command above or the runner that supplies the same command and captures evidence. Do not use Maven, a physical device, or another emulator image as a substitute. API 26 evidence is limited to the selected x86 guest.
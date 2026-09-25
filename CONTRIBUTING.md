# Contributing

## Scope and Android status

The current product is a Python wallet library. The repository has no production Android application or adapter. The accepted Android-related implementation is a standalone, test-only Kotlin/JVM consumer of the wallet-container v2 vector; it uses Maven and is not an Android app. See the [wallet implementation specification](docs/specs/wallet-implementation.md#kotlinjvm-v2-vector-consumer-issue-33-accepted-and-implemented).

Issue [#36](https://github.com/jetpen/decent-wallet/issues/36) tracks a separate test-only Android runtime-conformance harness for that verifier. The Maven-only APK packaging and instrumentation path is still under feasibility review; no Android test APK or runtime suite exists yet. Bouncy Castle's build-time Android API 26 compatibility check is static evidence only, not an Android runtime test.

For the currently implemented Python and Kotlin/JVM checks, Android Studio, the Android SDK, and an emulator are not needed. Install Android prerequisites below only to prepare for Issue #36's planned API 26/API 37 runtime tests. The project uses Maven; do not install or invoke Gradle for this work.

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

A system-wide Maven installation is not required. The Kotlin/JVM module includes Maven Wrapper configured for Apache Maven 3.9.16; the wrapper JAR and Maven distribution each have a pinned SHA-256 checksum. The module's lockfile pins resolved dependency and Maven-plugin checksums, and the build validates it during Maven's `validate` phase before running tests.

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

## Android runtime-test prerequisites (Issue #36; planned)

Issue #36 proposes running the existing verifier on real Android runtimes at API 26 and API 37. This setup installs the devices and SDK tools needed for that work; it does **not** mean the Maven-only APK packaging or instrumentation runner has passed its feasibility check. No Android APK or runtime-test command exists yet. Do not use Gradle for this project. The Maven implementation and exact Android SDK package pins must be validated and recorded in Issue #36 before runtime tests are considered reproducible.

### Required tools

- **JDK 17 or newer.** Install as described above. A JRE alone is insufficient. The existing Kotlin/JVM module provides Maven Wrapper, so a separate system-wide Maven installation is not required.
- **Android Studio and Android SDK tools.** Install the current stable [Android Studio](https://developer.android.com/studio). Android Studio is used here only to install/manage SDK packages and virtual devices; do not create a Gradle project or invoke Gradle. Google's [Android 17 SDK setup guide](https://developer.android.com/about/versions/17/setup-sdk) recommends Android Studio Meerkat 2024.3.1 or newer for that preview SDK.
- **SDK packages** in Android Studio's **Tools > SDK Manager**:
  - In **SDK Platforms**, install **Android 8.0 (Oreo), API 26** and **Android 17 (Cinnamon Bun Preview), API 37**. API 37 is a preview target and may change before release.
  - In **SDK Tools**, install **Android SDK Command-line Tools (latest)**, **Android SDK Platform-Tools** (`adb`), **Android Emulator**, and **Android SDK Build-Tools 37.x**. Google's [Android 17 SDK setup guide](https://developer.android.com/about/versions/17/setup-sdk) instructs selecting the latest 37.x Build-Tools. Issue #36's Maven proof of concept must pin the exact package revisions before the setup can be called reproducible.
  - Accept the Android SDK license agreements presented by the SDK Manager before downloading packages.
- **System images and virtual devices.** In **Tools > Device Manager**, create an API 26 AVD and an API 37 AVD with system images matching the host CPU architecture (x86_64 on x86_64 hosts; arm64-v8a on Apple silicon). The issue-approved fallback is a physical API 26 device only if a suitable API 26 emulator image is unavailable; API 37 remains part of the emulator matrix. Follow Google's [AVD guide](https://developer.android.com/studio/run/managing-avds) to download images and create devices.
- **Hardware virtualization for accelerated emulation.** Linux uses KVM, Windows can use Windows Hypervisor Platform, and macOS uses Hypervisor.Framework. Acceleration requires processor virtualization support; without it, emulator performance may be poor. Check Google's [emulator acceleration requirements](https://developer.android.com/studio/run/emulator-acceleration). If using a physical API 26 fallback, enable Developer options and USB debugging on that device and authorize the host when prompted.

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

Persist these variables through the shell profile or operating-system environment settings if needed. Keep `JAVA_HOME` and `PATH` pointed at the JDK 17+ installation used for Maven.

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

The Maven wrapper command confirms the existing Maven/JDK setup. If using emulators for both targets, `emulator -list-avds` should show API 26 and API 37 AVDs; if using the approved physical API 26 fallback, it should show the API 37 AVD. `adb devices -l` should show running emulators or the authorized API 26 device. These checks verify installation only. Issue #36 must still establish and document a Maven-only way to package and run the instrumented tests before an Android runtime test can be run.
# Contributing

## Scope and Android status

The current product is a Python wallet library. This repository does not yet contain a native Android application, APK target, Android SDK configuration, or Android runtime test suite. The accepted Android-related slice is a standalone, test-only Kotlin/JVM consumer of the wallet-container v2 vector; it is not an Android app or production adapter. See the [wallet implementation specification](docs/specs/wallet-implementation.md#kotlinjvm-v2-vector-consumer-issue-33-accepted-and-implemented).

Consequently, Android Studio, the Android SDK, an emulator, and Gradle are not prerequisites for building or testing the code currently in this repository. The Kotlin/JVM consumer uses Maven, not Gradle. Bouncy Castle's build-time Android API 26 compatibility check is the only API-26 evidence; it is not an Android runtime test and does not establish runtime support for this module.

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

## Future native Android development

When a native Android application module is added, its maintainers must document the required Android Studio/Android Gradle Plugin, Gradle wrapper, SDK platform and Build Tools versions, minimum and target API levels, and emulator/device test setup. Those versions are not defined by the current Kotlin/JVM vector-consumer specification, so contributors should not install or assume an arbitrary Android SDK target.
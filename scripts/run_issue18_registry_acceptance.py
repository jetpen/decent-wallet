#!/usr/bin/env python3
"""Run desktop Registry integration and Android runtime tests with managed peers.

The Android phase owns the two-peer Registry fixture lifecycle and adb reverse
mappings. It intentionally runs against local loopback peers; it is not deployed
Registry acceptance.
"""

from __future__ import annotations

import argparse
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_REPO_DEFAULT = ROOT.parent / "decent-registry"
FIXTURE_SCRIPT = ROOT / "tests" / "interop" / "start_android_registry_peer.py"
PODMAN_FIXTURE_SCRIPT = ROOT / "tests" / "interop" / "start_podman_registry_peers.py"
PODMAN_DESKTOP_TEST = ROOT / "tests" / "test_issue18_podman_registry_deployment.py"
PODMAN_DESKTOP_TEST_NAME = "test_podman_writer_publication_remains_peer_scoped"
PODMAN_DESKTOP_TEST_CLASS = "tests.test_issue18_podman_registry_deployment"
ROTATION_TEST_NAME = "rotatesWalletThroughDirectDhtAndPersistsPromotionOnAndroid"
HISTORY_AVAILABILITY_TEST_NAME = (
    "versionedHistoryAvailabilityFailsClosedBeforeDraftCreation"
)
ROTATION_TEST_CLASS = (
    "org.decentwallet.wallet.android.AndroidDirectDhtRegistryRuntimeTest"
)
JVM_INTEROP_TEST_NAME = "readsHistoryPublishesAndFreshReadsAgainstPythonRegistryPeer"
JVM_INTEROP_TEST_CLASS = (
    "org.decentwallet.wallet.android.AndroidDirectDhtRegistryInteropTest"
)
JVM_RESULTS = (
    ROOT
    / "platforms"
    / "android-wallet"
    / "build"
    / "test-results"
    / "testDebugUnitTest"
)
ANDROID_RESULTS = (
    ROOT
    / "platforms"
    / "android-wallet"
    / "build"
    / "outputs"
    / "androidTest-results"
    / "connected"
    / "debug"
)
APPROVED_ANDROID_TARGETS = {
    "Medium_Phone": {
        "AvdId": "Medium_Phone",
        "api": 26,
        "abi": "x86",
        "abi.type": "x86",
        "image.sysdir.1": "system-images/android-26/google_apis_playstore/x86/",
        "target": "android-26",
        "PlayStore.enabled": "true",
        "tag.ids": "google_apis_playstore",
    },
    "Pixel_9": {
        "AvdId": "Pixel_9",
        "api": 37,
        "abi": "x86_64",
        "abi.type": "x86_64",
        "image.sysdir.1": "system-images/android-37.2/google_apis_playstore_ps16k/x86_64/",
        "target": "android-37.2",
        "PlayStore.enabled": "true",
        "tag.ids": "google_apis_playstore,page_size_16kb",
    },
}
ANDROID_QUEUE_MAXSIZE = 4
FIXTURE_STARTUP_TIMEOUT_SECONDS = 90.0
PODMAN_FIXTURE_STARTUP_TIMEOUT_SECONDS = 540.0
FIXTURE_ERROR_PREFIX = "FIXTURE_ERROR\t"
SAFE_FIXTURE_ERRORS = {
    "Podman executable was not found",
    "the Registry fixture requires rootless Podman",
    "data directory must be a real, empty directory",
    "data directory must be empty",
    "could not prepare the empty data directory",
    "Registry peer did not report a valid peer address",
    "Registry peer container exited during startup",
    "Registry peer did not become ready before the startup deadline",
    "could not determine the writer peer's internal address",
    "could not load the synthetic legacy Registry vector",
    "could not seed or confirm the synthetic Registry record",
    "Registry peer bootstrap failed",
    "Registry peer publication failed",
    "Registry peer readback bootstrap failed",
    "Registry peer readback failed",
    "Registry peer did not confirm the synthetic legacy record",
    "Registry peer did not return the synthetic record",
    "Registry peer did not have the expected synthetic record",
    "synthetic Registry Owner Name must be valid hex",
    "Registry peer seed timed out",
    "Registry peers did not receive distinct peer identities",
    "Podman command exceeded its time limit",
    "Podman command could not be started",
    "Podman could not prepare the Registry peer fixture",
    "could not fully tear down Podman Registry resources",
}
READINESS_DIAGNOSTIC = re.compile(
    r"Registry peer readiness failed \(bootstrap_records=[0-9]{1,2}, "
    r"address_error=(?:bootstrap_count|bootstrap_prefix|bootstrap_format|bootstrap_suffix|address_value|container_port|peer_id|logs_unavailable|none), "
    r"tcp_ready=(?:true|false)\)"
)
SEED_ERROR_DIAGNOSTIC = re.compile(
    r"(?:Registry peer (?:bootstrap|publication|readback bootstrap|readback) failed|"
    r"Registry (?:peer seed|readback confirmation) failed|"
    r"could not seed or confirm the synthetic Registry record) "
    r"\(error=[A-Za-z][A-Za-z0-9]{0,39}"
    r"(?:; detail=[A-Za-z0-9 _\[\]().,:;?-]{1,200})?\)"
)


class HarnessError(RuntimeError):
    """An actionable prerequisite or acceptance-harness failure."""


@dataclass(frozen=True)
class RegistryPeerAddress:
    multiaddr: str
    port: int
    peer_id: str


def safe_fixture_error_message(message: str) -> str:
    if (
        message in SAFE_FIXTURE_ERRORS
        or READINESS_DIAGNOSTIC.fullmatch(message)
        or SEED_ERROR_DIAGNOSTIC.fullmatch(message)
    ):
        return message
    return "Registry peer fixture failed"


def parse_peer_multiaddr(value: str) -> RegistryPeerAddress:
    match = re.fullmatch(r"/ip4/127\.0\.0\.1/tcp/([0-9]+)/p2p/([^/]+)", value.strip())
    if match is None:
        raise HarnessError("fixture emitted an unsupported loopback peer multiaddr")
    port = int(match.group(1))
    peer_id = match.group(2)
    if not 1 <= port <= 65535 or not re.fullmatch(
        r"[1-9A-HJ-NP-Za-km-z]{20,}", peer_id
    ):
        raise HarnessError("fixture emitted an invalid Registry peer address")
    return RegistryPeerAddress(multiaddr=value.strip(), port=port, peer_id=peer_id)


def parse_ready_lines(
    lines: list[str],
) -> tuple[RegistryPeerAddress, RegistryPeerAddress]:
    ready: dict[str, RegistryPeerAddress] = {}
    for line in lines:
        parts = line.strip().split("\t", 1)
        if len(parts) != 2 or parts[0] not in {"READY_WRITE", "READY_READBACK"}:
            continue
        tag, multiaddr = parts
        if tag in ready:
            raise HarnessError(
                f"Registry fixture emitted duplicate {tag} readiness lines"
            )
        ready[tag] = parse_peer_multiaddr(multiaddr)
    if set(ready) != {"READY_WRITE", "READY_READBACK"}:
        raise HarnessError(
            "Registry fixture did not announce both writer and read-back peers"
        )
    writer = ready["READY_WRITE"]
    readback = ready["READY_READBACK"]
    if writer.peer_id == readback.peer_id or writer.port == readback.port:
        raise HarnessError(
            "fixture must expose distinct Registry peers and listener ports"
        )
    return writer, readback


def select_single_emulator(
    devices_output: str, requested_serial: str | None = None
) -> str:
    emulators: list[tuple[str, str]] = []
    connected: list[str] = []
    for line in devices_output.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        if parts[1] == "device":
            connected.append(parts[0])
        if parts[0].startswith("emulator-"):
            emulators.append((parts[0], parts[1]))
    if len(connected) != 1:
        raise HarnessError(
            "only one connected Android target is allowed, and it must be exactly one booted "
            "Android emulator; run approved AVDs sequentially and stop the previous emulator first"
        )
    if len(emulators) != 1 or emulators[0][1] != "device":
        raise HarnessError(
            "exactly one booted Android emulator must be attached; run approved AVDs "
            "sequentially and stop the previous emulator first"
        )
    serial = emulators[0][0]
    if requested_serial is not None and serial != requested_serial:
        raise HarnessError(
            f"requested serial {requested_serial!r}, but the sole emulator is {serial!r}"
        )
    return serial


def android_avd_config_root(env: dict[str, str]) -> Path:
    if env.get("ANDROID_AVD_HOME"):
        return Path(env["ANDROID_AVD_HOME"]).expanduser()
    if env.get("ANDROID_USER_HOME"):
        return Path(env["ANDROID_USER_HOME"]).expanduser() / "avd"
    return Path.home() / ".android" / "avd"


def read_avd_config(avd_name: str, env: dict[str, str]) -> dict[str, str]:
    config_path = android_avd_config_root(env) / f"{avd_name}.avd" / "config.ini"
    try:
        lines = config_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise HarnessError(
            f"could not read host AVD configuration for {avd_name}"
        ) from exc
    config: dict[str, str] = {}
    for line in lines:
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            config[key.strip()] = value.strip()
    return config


def verify_android_target(adb: Path, serial: str) -> tuple[str, int, str]:
    avd_name_output = adb_output(adb, serial, "emu", "avd", "name")
    avd_names = [
        line.strip()
        for line in avd_name_output.splitlines()
        if line.strip() and line.strip().upper() != "OK"
    ]
    if len(avd_names) != 1:
        raise HarnessError(
            "could not determine the connected emulator's host-side AVD name"
        )
    avd_name = avd_names[0]
    expected = APPROVED_ANDROID_TARGETS.get(avd_name)
    if expected is None:
        raise HarnessError(
            f"{avd_name} is not an approved AVD for Issue #18 runtime tests"
        )
    if adb_output(adb, serial, "shell", "getprop", "sys.boot_completed").strip() != "1":
        raise HarnessError(f"approved AVD {avd_name} has not completed boot")
    config = read_avd_config(avd_name, os.environ.copy())
    for key in (
        "AvdId",
        "abi.type",
        "image.sysdir.1",
        "target",
        "PlayStore.enabled",
        "tag.ids",
    ):
        if config.get(key) != expected[key]:
            raise HarnessError(
                f"approved AVD {avd_name} has an unexpected {key} image configuration"
            )
    api_text = adb_output(
        adb, serial, "shell", "getprop", "ro.build.version.sdk"
    ).strip()
    abi = adb_output(adb, serial, "shell", "getprop", "ro.product.cpu.abi").strip()
    try:
        api = int(api_text)
    except ValueError as exc:
        raise HarnessError(
            f"approved AVD {avd_name} reported an invalid Android API level"
        ) from exc
    if api != expected["api"] or abi != expected["abi"]:
        raise HarnessError(
            f"approved AVD {avd_name} API/ABI does not match the acceptance matrix"
        )
    play_store = adb_output(adb, serial, "shell", "pm", "path", "com.android.vending")
    if not any(line.strip().startswith("package:") for line in play_store.splitlines()):
        raise HarnessError(
            f"approved AVD {avd_name} is missing the Google Play Store package"
        )
    return avd_name, api, abi


def revalidate_android_target(
    adb: Path, serial: str, expected_target: tuple[str, int, str]
) -> tuple[str, int, str]:
    try:
        devices = subprocess.run(
            [str(adb), "devices", "-l"],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise HarnessError(
            f"could not recheck Android targets before Gradle: {exc}"
        ) from exc
    if devices.returncode:
        raise HarnessError(
            f"adb devices failed before Gradle: {devices.stdout.strip()}"
        )
    current_serial = select_single_emulator(devices.stdout, requested_serial=serial)
    current_target = verify_android_target(adb, current_serial)
    if current_target != expected_target:
        raise HarnessError("approved Android target identity changed before Gradle")
    return current_target


def verify_junit_test_result(
    report_paths: list[Path], expected_class: str, expected_test_name: str
) -> dict[str, int]:
    matches: list[ET.Element] = []
    for path in report_paths:
        try:
            root = ET.parse(path).getroot()
        except (ET.ParseError, OSError) as exc:
            raise HarnessError(f"cannot parse JUnit report {path}: {exc}") from exc
        matches.extend(
            case
            for case in root.iter("testcase")
            if case.attrib.get("name") == expected_test_name
            and case.attrib.get("classname") == expected_class
        )
    if len(matches) != 1:
        raise HarnessError(
            f"expected exactly one result for {expected_class}.{expected_test_name}; "
            f"found {len(matches)}"
        )
    testcase = matches[0]
    if testcase.find("skipped") is not None:
        raise HarnessError(f"{expected_class}.{expected_test_name} must pass, not skip")
    if testcase.find("failure") is not None or testcase.find("error") is not None:
        raise HarnessError(
            f"{expected_class}.{expected_test_name} reported a failure or error"
        )
    return {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}


def verify_android_test_result(
    report_paths: list[Path], expected_test_name: str = ROTATION_TEST_NAME
) -> dict[str, int]:
    return verify_junit_test_result(
        report_paths, ROTATION_TEST_CLASS, expected_test_name
    )


def report_snapshot(report_root: Path) -> dict[Path, tuple[int, int]]:
    if not report_root.exists():
        return {}
    return {
        path: (path.stat().st_mtime_ns, path.stat().st_size)
        for path in report_root.rglob("TEST-*.xml")
        if path.is_file()
    }


def changed_reports(
    report_root: Path, before: dict[Path, tuple[int, int]]
) -> list[Path]:
    if not report_root.exists():
        return []
    return [
        path
        for path in report_root.rglob("TEST-*.xml")
        if path.is_file()
        and before.get(path) != (path.stat().st_mtime_ns, path.stat().st_size)
    ]


def select_reverse_ports(reverse_output: str) -> tuple[int, int]:
    used = {int(value) for value in re.findall(r"tcp:([0-9]+)", reverse_output)}
    available: list[int] = []
    for port in range(31457, 40000):
        if port not in used:
            available.append(port)
            if len(available) == 2:
                return available[0], available[1]
    raise HarnessError(
        "could not find two unused Android reverse-forward ports in 31457..39999"
    )


def parse_reverse_mappings(reverse_output: str) -> dict[int, int]:
    mappings: dict[int, int] = {}
    for line in reverse_output.splitlines():
        ports = re.findall(r"(?:^|\s)tcp:([0-9]+)(?=\s|$)", line)
        if len(ports) < 2:
            continue
        remote_port, local_port = int(ports[-2]), int(ports[-1])
        if remote_port in mappings:
            raise HarnessError(
                f"adb reported duplicate reverse mappings for tcp:{remote_port}"
            )
        mappings[remote_port] = local_port
    return mappings


def verify_reverse_mappings(
    reverse_output: str, expected: list[tuple[int, int]]
) -> None:
    mappings = parse_reverse_mappings(reverse_output)
    for remote_port, local_port in expected:
        observed = mappings.get(remote_port)
        if observed != local_port:
            observed_text = "none" if observed is None else f"tcp:{observed}"
            raise HarnessError(
                f"adb reverse target mismatch for tcp:{remote_port}: expected tcp:{local_port}, "
                f"observed {observed_text}"
            )


def add_reverse_mapping(
    adb: Path, serial: str, remote_port: int, local_port: int
) -> None:
    adb_output(
        adb,
        serial,
        "reverse",
        "--no-rebind",
        f"tcp:{remote_port}",
        f"tcp:{local_port}",
    )


def cleanup_reverse_mappings(
    adb: Path,
    serial: str,
    owned: dict[int, int],
    pending: dict[int, int],
) -> list[str]:
    candidates = {**pending, **owned}
    if not candidates:
        return []
    for remote_port, local_port in sorted(candidates.items()):
        try:
            current = parse_reverse_mappings(
                adb_output(adb, serial, "reverse", "--list")
            )
        except (HarnessError, OSError, subprocess.TimeoutExpired) as exc:
            return [
                f"could not inspect adb reverse tcp:{remote_port} before cleanup: {exc}"
            ]
        if current.get(remote_port) != local_port:
            continue
        # adb has no compare-and-remove; avoid touching a mapping whose target changed.
        try:
            subprocess.run(
                [str(adb), "-s", serial, "reverse", "--remove", f"tcp:{remote_port}"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=20,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
    try:
        remaining = parse_reverse_mappings(adb_output(adb, serial, "reverse", "--list"))
    except (HarnessError, OSError, subprocess.TimeoutExpired) as exc:
        return [f"could not verify adb reverse cleanup: {exc}"]
    leftovers = [
        f"tcp:{remote_port}->tcp:{local_port}"
        for remote_port, local_port in candidates.items()
        if remaining.get(remote_port) == local_port
    ]
    return [f"adb reverse mappings remain: {leftovers}"] if leftovers else []


def handle_android_cleanup_errors(
    cleanup_errors: list[str],
    *,
    operation: str,
    primary_exception: BaseException | None,
    exit_code: int | None,
) -> None:
    if primary_exception is not None and exit_code not in (None, 0):
        primary_exception.add_note(f"{operation} exited with status {exit_code}")
    if not cleanup_errors:
        return
    cleanup_message = (
        f"Android reverse-mapping cleanup failed: {'; '.join(cleanup_errors)}"
    )
    if primary_exception is not None:
        primary_exception.add_note(cleanup_message)
        return
    if exit_code not in (None, 0):
        raise HarnessError(
            f"{operation} exited with status {exit_code}; {cleanup_message}"
        )
    raise HarnessError(cleanup_message)


def ensure_distinct_lmdb_stores(writer_path: Path, readback_path: Path) -> None:
    if not writer_path.is_file() or not readback_path.is_file():
        raise HarnessError("Registry peers did not create separate LMDB files")
    if writer_path.resolve() == readback_path.resolve() or os.path.samefile(
        writer_path, readback_path
    ):
        raise HarnessError("Registry peers must use separate LMDB files")


def fixture_startup_timeout(peer_backend: str, override: float | None) -> float:
    if override is not None:
        return override
    if peer_backend == "process":
        return FIXTURE_STARTUP_TIMEOUT_SECONDS
    if peer_backend == "podman":
        return PODMAN_FIXTURE_STARTUP_TIMEOUT_SECONDS
    raise HarnessError(f"unsupported Registry peer backend: {peer_backend}")


def registry_python_executable(uv: str, registry_repo: Path) -> str:
    project = registry_repo.expanduser().resolve()
    try:
        result = subprocess.run(
            [
                uv,
                "run",
                "--locked",
                "--project",
                str(project),
                "--extra",
                "dev",
                "python",
                "-c",
                "import sys; print(sys.executable)",
            ],
            cwd=project,
            text=True,
            capture_output=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise HarnessError(
            "could not resolve the locked Registry Python environment"
        ) from None
    executable = result.stdout.strip()
    if result.returncode != 0 or not executable or "\n" in executable:
        raise HarnessError("could not resolve the locked Registry Python environment")
    path = Path(executable)
    if not path.is_absolute() or not path.is_file():
        raise HarnessError(
            "locked Registry project returned an invalid Python executable"
        )
    return str(path)


def registry_store_paths(data_root: Path, peer_backend: str) -> tuple[Path, Path]:
    if peer_backend == "process":
        return data_root / "writer.lmdb", data_root / "readback.lmdb"
    if peer_backend == "podman":
        return (
            data_root / "writer" / "writer.lmdb",
            data_root / "readback" / "readback.lmdb",
        )
    raise HarnessError(f"unsupported Registry peer backend: {peer_backend}")


def validate_peer_backend_mode(*, peer_backend: str, desktop_only: bool) -> None:
    if peer_backend == "podman" and not desktop_only:
        raise HarnessError(
            "Podman is currently a desktop-only diagnostic; JVM/device acceptance "
            "requires a deployment that delivers the candidate to a distinct read-back peer"
        )


class RegistryPeerFixture:
    """Start a managed two-peer Registry fixture and always tear it down."""

    def __init__(
        self,
        registry_repo: Path,
        timeout_seconds: float | None = None,
        *,
        peer_backend: str = "process",
        predecessor_format: str = "legacy",
        history_fault: str = "none",
    ):
        if peer_backend not in {"process", "podman"}:
            raise HarnessError(f"unsupported Registry peer backend: {peer_backend}")
        if predecessor_format not in {"legacy", "versioned"}:
            raise HarnessError(
                f"unsupported Registry predecessor format: {predecessor_format}"
            )
        if history_fault not in {"none", "missing", "corrupt"}:
            raise HarnessError(f"unsupported Registry history fault: {history_fault}")
        if predecessor_format == "versioned" and peer_backend != "process":
            raise HarnessError(
                "versioned Registry history fixtures require the process backend"
            )
        if history_fault != "none" and predecessor_format != "versioned":
            raise HarnessError(
                "Registry history faults require versioned predecessor history"
            )
        self.registry_repo = registry_repo.resolve()
        self.timeout_seconds = fixture_startup_timeout(peer_backend, timeout_seconds)
        self.peer_backend = peer_backend
        self.predecessor_format = predecessor_format
        self.history_fault = history_fault
        self.fixture_script = (
            FIXTURE_SCRIPT if peer_backend == "process" else PODMAN_FIXTURE_SCRIPT
        )
        self.process: subprocess.Popen[str] | None = None
        self._lines: list[str] = []
        self._messages: queue.Queue[str | None] = queue.Queue(
            maxsize=ANDROID_QUEUE_MAXSIZE
        )
        self._reader: threading.Thread | None = None
        self._scratch: tempfile.TemporaryDirectory[str] | None = None
        self._data_root: Path | None = None
        self._ready = threading.Event()
        self._stop_signal_sent = False
        self.writer: RegistryPeerAddress | None = None
        self.readback: RegistryPeerAddress | None = None
        self.writer_store: Path | None = None
        self.readback_store: Path | None = None

    def build_command(self, fixture_python: str, data_root: Path) -> list[str]:
        command = [fixture_python, str(self.fixture_script)]
        if self.peer_backend == "process":
            command.extend(
                ["--advertise-host", "127.0.0.1", "--data-dir", str(data_root)]
            )
            if self.predecessor_format != "legacy":
                command.extend(["--predecessor-format", self.predecessor_format])
            if self.history_fault != "none":
                command.extend(["--history-fault", self.history_fault])
        else:
            command.extend(["--data-dir", str(data_root), "--wallet-repo", str(ROOT)])
        return command

    def __enter__(self) -> RegistryPeerFixture:
        if not self.registry_repo.is_dir():
            raise HarnessError(
                f"decent-registry checkout not found: {self.registry_repo}"
            )
        if not self.fixture_script.is_file():
            raise HarnessError(
                f"Registry fixture script not found: {self.fixture_script}"
            )
        uv = shutil.which("uv")
        if uv is None:
            raise HarnessError(
                "uv is required to start the locked decent-registry fixture"
            )
        fixture_python = registry_python_executable(uv, self.registry_repo)

        scratch_root = Path(
            os.environ.get("TMPDIR", Path.home() / ".cache" / "decent-wallet")
        )
        scratch_root.mkdir(parents=True, exist_ok=True)
        self._scratch = tempfile.TemporaryDirectory(
            prefix="issue18-registry-harness-", dir=scratch_root
        )
        self._data_root = Path(self._scratch.name) / "peer-data"
        self._data_root.mkdir()
        env = os.environ.copy()
        env["TMPDIR"] = self._scratch.name
        command = self.build_command(fixture_python, self._data_root)
        print(f"Starting temporary Registry peers: {' '.join(command)}", flush=True)
        try:
            self.process = subprocess.Popen(
                command,
                cwd=self.registry_repo,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            self._reader = threading.Thread(target=self._pump_stdout, daemon=True)
            self._reader.start()
            deadline = time.monotonic() + self.timeout_seconds
            while time.monotonic() < deadline:
                remaining = max(0.01, deadline - time.monotonic())
                try:
                    line = self._messages.get(timeout=min(0.25, remaining))
                except queue.Empty:
                    if self.process.poll() is not None:
                        raise HarnessError(self._fixture_exited_message())
                    continue
                if line is None:
                    raise HarnessError(self._fixture_exited_message())
                if line.startswith(FIXTURE_ERROR_PREFIX):
                    self._lines.append("FIXTURE_ERROR")
                    detail = safe_fixture_error_message(line.split("\t", 1)[1].strip())
                    raise HarnessError(f"Registry fixture failed: {detail}")
                if not line.startswith(("READY_WRITE\t", "READY_READBACK\t")):
                    continue
                self._lines.append(line)
                tag = line.split("\t", 1)[0]
                print(f"Registry fixture announced {tag}.", flush=True)
                if (
                    sum(
                        entry.startswith("READY_WRITE\t")
                        or entry.startswith("READY_READBACK\t")
                        for entry in self._lines
                    )
                    == 2
                ):
                    self.writer, self.readback = parse_ready_lines(self._lines)
                    self.writer_store, self.readback_store = registry_store_paths(
                        self._data_root, self.peer_backend
                    )
                    ensure_distinct_lmdb_stores(self.writer_store, self.readback_store)
                    self._ready.set()
                    print(
                        "Managed writer/read-back peers ready; separate LMDB files verified.",
                        flush=True,
                    )
                    return self
            tags = [line.split("\t", 1)[0] for line in self._lines]
            raise HarnessError(
                f"Registry fixture did not become ready within {self.timeout_seconds:g}s; "
                f"readiness records received: {tags}"
            )
        except BaseException:
            self.stop()
            raise

    def _pump_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        try:
            for line in self.process.stdout:
                if self._ready.is_set() or not line.startswith(
                    ("READY_WRITE\t", "READY_READBACK\t", FIXTURE_ERROR_PREFIX)
                ):
                    continue
                try:
                    self._messages.put_nowait(line)
                except queue.Full:
                    continue
        finally:
            try:
                self._messages.put_nowait(None)
            except queue.Full:
                pass

    def _fixture_exited_message(self) -> str:
        code = self.process.poll() if self.process is not None else None
        tags = [line.split("\t", 1)[0] for line in self._lines]
        return f"Registry fixture exited before readiness (exit={code}); records received: {tags}"

    def stop(self) -> None:
        process = self.process
        if process is not None and process.poll() is None:
            self._stop_signal_sent = True
            try:
                os.killpg(process.pid, signal.SIGINT)
            except (ProcessLookupError, PermissionError):
                process.send_signal(signal.SIGINT)
            stop_timeout = 45 if self.peer_backend == "podman" else 15
            try:
                process.wait(timeout=stop_timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except (ProcessLookupError, PermissionError):
                        process.kill()
                    process.wait(timeout=5)
        if process is not None and process.stdout is not None:
            process.stdout.close()
        if self._reader is not None:
            self._reader.join(timeout=2)
        if self._scratch is not None:
            self._scratch.cleanup()
            self._scratch = None

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
        if self.process is not None:
            exit_code = self.process.poll()
            expected_signal_exits = {-signal.SIGINT, 128 + signal.SIGINT}
            if exit_code != 0 and not (
                self._stop_signal_sent and exit_code in expected_signal_exits
            ):
                raise HarnessError(
                    f"Registry fixture teardown failed (exit={exit_code})"
                )
            print(
                "Temporary Registry peers stopped and scratch LMDB data removed.",
                flush=True,
            )


def fail(message: str) -> NoReturn:
    raise SystemExit(f"Issue #18 Registry acceptance harness: {message}")


def run_command(
    command: list[str], *, cwd: Path, env: dict[str, str], timeout: int
) -> int:
    print(f"\n$ {' '.join(command)}", flush=True)
    try:
        result = subprocess.run(command, cwd=cwd, env=env, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        print(f"command timed out after {timeout}s", file=sys.stderr, flush=True)
        return 124
    return result.returncode


def run_desktop_integration() -> int:
    uv = shutil.which("uv")
    if uv is None:
        fail("uv is required for the desktop RegistryTransport integration suite")
    command = [
        uv,
        "run",
        "--locked",
        "--project",
        str(ROOT),
        "--extra",
        "test",
        "--extra",
        "registry",
        "python",
        "-m",
        "pytest",
        "-q",
        "-o",
        "addopts=",
        "-m",
        "registry_integration",
        "tests/test_registry_transport_integration.py",
    ]
    print(
        "Running desktop RegistryTransport integration tests; pytest owns their peer fixtures.",
        flush=True,
    )
    return run_command(command, cwd=ROOT, env=os.environ.copy(), timeout=1800)


def run_podman_desktop_registry_diagnostic(
    registry_repo: Path, fixture_timeout: float
) -> int:
    uv = shutil.which("uv")
    if uv is None:
        raise HarnessError("uv is required for the Podman Registry diagnostic")
    if not PODMAN_DESKTOP_TEST.is_file():
        raise HarnessError("Podman Registry desktop diagnostic test is missing")
    with RegistryPeerFixture(
        registry_repo, timeout_seconds=fixture_timeout, peer_backend="podman"
    ) as fixture:
        assert fixture.writer is not None and fixture.readback is not None
        assert fixture._scratch is not None
        report = Path(fixture._scratch.name) / "desktop-podman-diagnostic.xml"
        env = os.environ.copy()
        env["DECENT_REGISTRY_ACCEPTANCE_WRITER_PEER"] = fixture.writer.multiaddr
        env["DECENT_REGISTRY_ACCEPTANCE_READBACK_PEER"] = fixture.readback.multiaddr
        command = [
            uv,
            "run",
            "--locked",
            "--project",
            str(ROOT),
            "--extra",
            "test",
            "--extra",
            "registry",
            "python",
            "-m",
            "pytest",
            "-q",
            "-o",
            "addopts=",
            f"--junitxml={report}",
            f"{PODMAN_DESKTOP_TEST}::{PODMAN_DESKTOP_TEST_NAME}",
        ]
        code = run_command(command, cwd=ROOT, env=env, timeout=600)
        if code:
            return code
        verify_junit_test_result(
            [report], PODMAN_DESKTOP_TEST_CLASS, PODMAN_DESKTOP_TEST_NAME
        )
        print(
            "Podman Registry diagnostic passed: writer returned the candidate and the "
            "distinct read-back peer retained the seeded predecessor. Independent-candidate "
            "confirmation remains blocked pending a deployment that delivers the candidate "
            "to a distinct peer.",
            flush=True,
        )
    return 0


def android_sdk_path(env: dict[str, str], sdk_default: Path | None = None) -> Path:
    configured = env.get("ANDROID_HOME") or env.get("ANDROID_SDK_ROOT")
    sdk = (
        Path(configured).expanduser()
        if configured
        else (sdk_default or Path.home() / "Android" / "Sdk")
    )
    if not sdk.is_dir():
        raise HarnessError(
            f"Android SDK not found at {sdk}; set ANDROID_HOME or ANDROID_SDK_ROOT"
        )
    return sdk.resolve()


def is_jdk17_version(version_output: str) -> bool:
    return re.search(r'\bversion\s+"17(?:[.+-][^"]*)?"', version_output) is not None


def jdk17_home(env: dict[str, str]) -> Path:
    candidates: list[Path] = []
    if env.get("JAVA_HOME"):
        candidates.append(Path(env["JAVA_HOME"]).expanduser())
    candidates.extend(
        (
            Path.home() / ".local" / "share" / "mise" / "installs" / "java" / "17.0.2",
            Path("/usr/lib/jvm/java-17-openjdk"),
            Path("/usr/lib/jvm/java-17-openjdk-amd64"),
        )
    )
    jvm_root = Path("/usr/lib/jvm")
    if jvm_root.is_dir():
        candidates.extend(sorted(jvm_root.glob("*17*")))
    seen: set[Path] = set()
    for home in candidates:
        home = home.expanduser()
        if home in seen:
            continue
        seen.add(home)
        java = home / "bin" / "java"
        javac = home / "bin" / "javac"
        if not java.is_file() or not javac.is_file():
            continue
        try:
            version = subprocess.run(
                [str(java), "-version"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=10,
                check=False,
            ).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        if is_jdk17_version(version):
            return home.resolve()
    raise HarnessError("JDK 17 is required; set JAVA_HOME to an installed JDK 17")


def gradle_environment(
    source_env: dict[str, str] | None = None, *, sdk_default: Path | None = None
) -> dict[str, str]:
    env = os.environ.copy() if source_env is None else dict(source_env)
    sdk = str(android_sdk_path(env, sdk_default=sdk_default))
    jdk = str(jdk17_home(env))
    env["ANDROID_HOME"] = sdk
    env["ANDROID_SDK_ROOT"] = sdk
    env["JAVA_HOME"] = jdk
    env["PATH"] = f"{Path(jdk) / 'bin'}:{env.get('PATH', '')}"
    return env


def run_jvm_registry_interop(
    registry_repo: Path, fixture_timeout: float, peer_backend: str = "process"
) -> int:
    before_reports = report_snapshot(JVM_RESULTS)
    gradle_code: int | None = None
    with RegistryPeerFixture(
        registry_repo, timeout_seconds=fixture_timeout, peer_backend=peer_backend
    ) as fixture:
        assert fixture.writer is not None and fixture.readback is not None
        env = gradle_environment()
        env["DECENT_REGISTRY_TEST_PEER"] = fixture.writer.multiaddr
        env["DECENT_REGISTRY_TEST_READBACK_PEER"] = fixture.readback.multiaddr
        command = [
            "./gradlew",
            "--no-daemon",
            "--dependency-verification=strict",
            ":platforms:android-wallet:testDebugUnitTest",
            "--rerun-tasks",
        ]
        gradle_code = run_command(command, cwd=ROOT, env=env, timeout=1800)
    if gradle_code != 0:
        return gradle_code if gradle_code is not None else 1
    reports = changed_reports(JVM_RESULTS, before_reports)
    result = verify_junit_test_result(
        reports, JVM_INTEROP_TEST_CLASS, JVM_INTEROP_TEST_NAME
    )
    print(
        "Android host-JVM Registry interop passed: "
        f"{result['tests']} test, {result['failures']} failures, "
        f"{result['errors']} errors, {result['skipped']} skipped.",
        flush=True,
    )
    return 0


def adb_path() -> Path:
    sdk = android_sdk_path(os.environ.copy())
    candidate = sdk / "platform-tools" / "adb"
    if candidate.is_file():
        return candidate
    located = shutil.which("adb")
    if located is not None:
        return Path(located)
    raise HarnessError(
        f"adb not found under {sdk}; set ANDROID_HOME or install platform-tools"
    )


def adb_output(adb: Path, serial: str, *args: str) -> str:
    result = subprocess.run(
        [str(adb), "-s", serial, *args],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    if result.returncode:
        raise HarnessError(
            f"adb {' '.join(args)} failed ({result.returncode}): {result.stdout.strip()}"
        )
    return result.stdout


def android_report_snapshot() -> dict[Path, tuple[int, int]]:
    return report_snapshot(ANDROID_RESULTS)


def run_versioned_android_runtime(
    registry_repo: Path,
    fixture_timeout: float,
    *,
    adb: Path,
    serial: str,
    expected_target: tuple[str, int, str],
    peer_backend: str,
    history_fault: str = "none",
    promotion_staging_failure: bool = False,
    lost_acknowledgement: bool = False,
    conditional_rejection: bool = False,
    promotion_rollback: bool = False,
    promotion_unknown: bool = False,
    competing_write: bool = False,
) -> tuple[int, list[Path]]:
    if history_fault not in {"none", "missing", "corrupt"}:
        raise HarnessError(
            f"unsupported Android versioned-history fault: {history_fault}"
        )
    fixture_kind = (
        "versioned" if history_fault == "none" else f"versioned-{history_fault}-history"
    )
    if promotion_staging_failure:
        if history_fault != "none":
            raise HarnessError(
                "promotion staging failure cannot use a history-fault fixture"
            )
        fixture_kind = "versioned-promotion-staging-failure"
    if lost_acknowledgement:
        if history_fault != "none" or promotion_staging_failure:
            raise HarnessError("lost acknowledgement cannot combine with another fault")
        fixture_kind = "versioned-lost-acknowledgement"
    if conditional_rejection:
        if history_fault != "none" or promotion_staging_failure or lost_acknowledgement:
            raise HarnessError(
                "conditional rejection cannot combine with another fault"
            )
        fixture_kind = "versioned-conditional-rejection"
    if promotion_rollback:
        if (
            history_fault != "none"
            or promotion_staging_failure
            or lost_acknowledgement
            or conditional_rejection
        ):
            raise HarnessError("promotion rollback cannot combine with another fault")
        fixture_kind = "versioned-promotion-rollback"
    if promotion_unknown:
        if (
            history_fault != "none"
            or promotion_staging_failure
            or lost_acknowledgement
            or conditional_rejection
            or promotion_rollback
        ):
            raise HarnessError("promotion unknown cannot combine with another fault")
        fixture_kind = "versioned-promotion-unknown"
    if competing_write:
        if (
            history_fault != "none"
            or promotion_staging_failure
            or lost_acknowledgement
            or conditional_rejection
            or promotion_rollback
            or promotion_unknown
        ):
            raise HarnessError("competing write cannot combine with another fault")
        fixture_kind = "versioned-competing-write"
    test_name = (
        ROTATION_TEST_NAME
        if history_fault == "none"
        else HISTORY_AVAILABILITY_TEST_NAME
    )
    phase_name = {
        "none": "versioned owner-key rotation",
        "missing": "missing versioned predecessor history",
        "corrupt": "corrupt versioned predecessor history",
    }[history_fault]
    if promotion_staging_failure:
        phase_name = "promotion staging failure"
    env = gradle_environment()
    if lost_acknowledgement:
        phase_name = "lost acknowledgement"
    if conditional_rejection:
        phase_name = "conditional rejection"
    if promotion_rollback:
        phase_name = "promotion rollback"
    if promotion_unknown:
        phase_name = "promotion unknown"
    if competing_write:
        phase_name = "competing write"
    env["DECENT_REGISTRY_TEST_FIXTURE"] = fixture_kind
    owned_mappings: dict[int, int] = {}
    pending_mappings: dict[int, int] = {}
    before_reports = android_report_snapshot()
    gradle_code: int | None = None
    primary_exception: BaseException | None = None
    try:
        with RegistryPeerFixture(
            registry_repo,
            timeout_seconds=fixture_timeout,
            peer_backend=peer_backend,
            predecessor_format="versioned",
            history_fault=history_fault,
        ) as fixture:
            assert fixture.writer is not None and fixture.readback is not None
            writer_device_port, readback_device_port = select_reverse_ports(
                adb_output(adb, serial, "reverse", "--list")
            )
            expected_mappings = [
                (writer_device_port, fixture.writer.port),
                (readback_device_port, fixture.readback.port),
            ]
            for device_port, host_port in expected_mappings:
                pending_mappings[device_port] = host_port
                try:
                    add_reverse_mapping(adb, serial, device_port, host_port)
                except HarnessError:
                    pending_mappings.pop(device_port, None)
                    raise
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise HarnessError(
                        f"adb reverse tcp:{device_port} setup outcome is uncertain: {exc}"
                    ) from exc
                else:
                    pending_mappings.pop(device_port, None)
                    owned_mappings[device_port] = host_port
            verify_reverse_mappings(
                adb_output(adb, serial, "reverse", "--list"), expected_mappings
            )
            env["DECENT_REGISTRY_TEST_PEER"] = (
                f"/ip4/127.0.0.1/tcp/{writer_device_port}/p2p/{fixture.writer.peer_id}"
            )
            env["DECENT_REGISTRY_TEST_READBACK_PEER"] = (
                f"/ip4/127.0.0.1/tcp/{readback_device_port}/p2p/{fixture.readback.peer_id}"
            )
            revalidated_target = revalidate_android_target(adb, serial, expected_target)
            print(
                f"Revalidated sole target immediately before {phase_name} Android Gradle run: "
                f"{revalidated_target[0]} API {revalidated_target[1]}, {revalidated_target[2]}",
                flush=True,
            )
            command = [
                "./gradlew",
                "--no-daemon",
                "--dependency-verification=strict",
                f"-Pissue18AndroidTestClass={ROTATION_TEST_CLASS}#{test_name}",
                ":platforms:android-wallet:connectedDebugAndroidTest",
                "--rerun-tasks",
            ]
            gradle_code = run_command(command, cwd=ROOT, env=env, timeout=2400)
    except BaseException as exc:
        primary_exception = exc
        raise
    finally:
        cleanup_errors = cleanup_reverse_mappings(
            adb, serial, owned_mappings, pending_mappings
        )
        handle_android_cleanup_errors(
            cleanup_errors,
            operation=f"{phase_name} Android Gradle run",
            primary_exception=primary_exception,
            exit_code=gradle_code,
        )

    if gradle_code != 0:
        return gradle_code if gradle_code is not None else 1, []
    return 0, changed_reports(ANDROID_RESULTS, before_reports)


def run_android_runtime(
    registry_repo: Path,
    requested_serial: str | None,
    fixture_timeout: float,
    peer_backend: str = "process",
    *,
    all_device_faults: bool = True,
) -> int:
    adb = adb_path()
    subprocess.run([str(adb), "start-server"], cwd=ROOT, timeout=30, check=True)
    devices = subprocess.run(
        [str(adb), "devices", "-l"],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=30,
        check=False,
    )
    if devices.returncode:
        raise HarnessError(f"adb devices failed: {devices.stdout.strip()}")
    serial = select_single_emulator(devices.stdout, requested_serial)
    avd_name, api, abi = verify_android_target(adb, serial)
    print(
        f"Verified the sole connected target: {avd_name} API {api}, {abi}, serial {serial}",
        flush=True,
    )

    env = gradle_environment()
    env["DECENT_REGISTRY_TEST_FIXTURE"] = "legacy"
    owned_mappings: dict[int, int] = {}
    pending_mappings: dict[int, int] = {}
    before_reports = android_report_snapshot()
    gradle_code: int | None = None
    result_summary: dict[str, int] | None = None
    primary_exception: BaseException | None = None
    try:
        with RegistryPeerFixture(
            registry_repo, timeout_seconds=fixture_timeout, peer_backend=peer_backend
        ) as fixture:
            assert fixture.writer is not None and fixture.readback is not None
            writer_device_port, readback_device_port = select_reverse_ports(
                adb_output(adb, serial, "reverse", "--list")
            )
            expected_mappings = [
                (writer_device_port, fixture.writer.port),
                (readback_device_port, fixture.readback.port),
            ]
            for device_port, host_port in expected_mappings:
                pending_mappings[device_port] = host_port
                try:
                    add_reverse_mapping(adb, serial, device_port, host_port)
                except HarnessError:
                    pending_mappings.pop(device_port, None)
                    raise
                except (OSError, subprocess.TimeoutExpired) as exc:
                    raise HarnessError(
                        f"adb reverse tcp:{device_port} setup outcome is uncertain: {exc}"
                    ) from exc
                else:
                    pending_mappings.pop(device_port, None)
                    owned_mappings[device_port] = host_port
            verify_reverse_mappings(
                adb_output(adb, serial, "reverse", "--list"), expected_mappings
            )
            env["DECENT_REGISTRY_TEST_PEER"] = (
                f"/ip4/127.0.0.1/tcp/{writer_device_port}/p2p/{fixture.writer.peer_id}"
            )
            env["DECENT_REGISTRY_TEST_READBACK_PEER"] = (
                f"/ip4/127.0.0.1/tcp/{readback_device_port}/p2p/{fixture.readback.peer_id}"
            )
            print(
                f"Verified adb reverse writer/read-back targets on device ports "
                f"{writer_device_port}/{readback_device_port}",
                flush=True,
            )
            verify_reverse_mappings(
                adb_output(adb, serial, "reverse", "--list"), expected_mappings
            )
            revalidated_target = revalidate_android_target(
                adb, serial, (avd_name, api, abi)
            )
            print(
                f"Revalidated sole target immediately before Gradle: "
                f"{revalidated_target[0]} API {revalidated_target[1]}, {revalidated_target[2]}",
                flush=True,
            )
            command = [
                "./gradlew",
                "--no-daemon",
                "--dependency-verification=strict",
                ":platforms:android-wallet:connectedDebugAndroidTest",
                "--rerun-tasks",
            ]
            gradle_code = run_command(command, cwd=ROOT, env=env, timeout=2400)
    except BaseException as exc:
        primary_exception = exc
        raise
    finally:
        cleanup_errors = cleanup_reverse_mappings(
            adb, serial, owned_mappings, pending_mappings
        )
        handle_android_cleanup_errors(
            cleanup_errors,
            operation="Legacy Android Gradle run",
            primary_exception=primary_exception,
            exit_code=gradle_code,
        )

    if gradle_code != 0:
        return gradle_code if gradle_code is not None else 1
    new_reports = changed_reports(ANDROID_RESULTS, before_reports)
    result_summary = verify_android_test_result(new_reports)
    print(
        "Android wallet legacy Registry runtime acceptance passed: "
        f"{result_summary['tests']} target rotation test, {result_summary['failures']} failures, "
        f"{result_summary['errors']} errors, {result_summary['skipped']} skipped.",
        flush=True,
    )
    versioned_code, versioned_reports = run_versioned_android_runtime(
        registry_repo,
        fixture_timeout,
        adb=adb,
        serial=serial,
        expected_target=(avd_name, api, abi),
        peer_backend=peer_backend,
    )
    if versioned_code != 0:
        return versioned_code
    versioned_summary = verify_android_test_result(versioned_reports)
    print(
        "Android wallet versioned non-genesis Registry runtime acceptance passed: "
        f"{versioned_summary['tests']} test, {versioned_summary['failures']} failures, "
        f"{versioned_summary['errors']} errors, {versioned_summary['skipped']} skipped.",
        flush=True,
    )
    missing_history_code, missing_history_reports = run_versioned_android_runtime(
        registry_repo,
        fixture_timeout,
        adb=adb,
        serial=serial,
        expected_target=(avd_name, api, abi),
        peer_backend=peer_backend,
        history_fault="missing",
    )
    if missing_history_code != 0:
        return missing_history_code
    missing_history_summary = verify_android_test_result(
        missing_history_reports,
        expected_test_name=HISTORY_AVAILABILITY_TEST_NAME,
    )
    print(
        "Android wallet missing-versioned-history fault acceptance passed: "
        f"{missing_history_summary['tests']} test, "
        f"{missing_history_summary['failures']} failures, "
        f"{missing_history_summary['errors']} errors, "
        f"{missing_history_summary['skipped']} skipped.",
        flush=True,
    )
    corrupt_history_code, corrupt_history_reports = run_versioned_android_runtime(
        registry_repo,
        fixture_timeout,
        adb=adb,
        serial=serial,
        expected_target=(avd_name, api, abi),
        peer_backend=peer_backend,
        history_fault="corrupt",
    )
    if corrupt_history_code != 0:
        return corrupt_history_code
    corrupt_history_summary = verify_android_test_result(
        corrupt_history_reports,
        expected_test_name=HISTORY_AVAILABILITY_TEST_NAME,
    )
    print(
        "Android wallet corrupt-versioned-history fault acceptance passed: "
        f"{corrupt_history_summary['tests']} test, "
        f"{corrupt_history_summary['failures']} failures, "
        f"{corrupt_history_summary['errors']} errors, "
        f"{corrupt_history_summary['skipped']} skipped.",
        flush=True,
    )
    promotion_code, promotion_reports = run_versioned_android_runtime(
        registry_repo,
        fixture_timeout,
        adb=adb,
        serial=serial,
        expected_target=(avd_name, api, abi),
        peer_backend=peer_backend,
        promotion_staging_failure=True,
    )
    if promotion_code != 0:
        return promotion_code
    promotion_summary = verify_android_test_result(promotion_reports)
    print(
        "Android wallet promotion-staging fault acceptance passed: "
        f"{promotion_summary['tests']} test, {promotion_summary['failures']} failures, "
        f"{promotion_summary['errors']} errors, {promotion_summary['skipped']} skipped.",
        flush=True,
    )
    lost_ack_code, lost_ack_reports = run_versioned_android_runtime(
        registry_repo,
        fixture_timeout,
        adb=adb,
        serial=serial,
        expected_target=(avd_name, api, abi),
        peer_backend=peer_backend,
        lost_acknowledgement=True,
    )
    if lost_ack_code != 0:
        return lost_ack_code
    lost_ack_summary = verify_android_test_result(lost_ack_reports)
    print(
        "Android wallet lost-acknowledgement acceptance passed: "
        f"{lost_ack_summary['tests']} test, {lost_ack_summary['failures']} failures, "
        f"{lost_ack_summary['errors']} errors, {lost_ack_summary['skipped']} skipped.",
        flush=True,
    )
    if all_device_faults:
        for fault in (
            "conditional_rejection",
            "promotion_rollback",
            "promotion_unknown",
            "competing_write",
        ):
            code, reports = run_versioned_android_runtime(
                registry_repo,
                fixture_timeout,
                adb=adb,
                serial=serial,
                expected_target=(avd_name, api, abi),
                peer_backend=peer_backend,
                **{fault: True},
            )
            if code != 0:
                return code
            summary = verify_android_test_result(reports)
            print(
                f"Android wallet {fault} acceptance passed: "
                f"{summary['tests']} test, {summary['failures']} failures, "
                f"{summary['errors']} errors, {summary['skipped']} skipped.",
                flush=True,
            )
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run desktop RegistryTransport integration and/or Android runtime acceptance. "
            "The process fixture is the default; --peer-backend podman is currently a "
            "desktop-only diagnostic on a private local network. Peers, scratch data, and "
            "adb reverse mappings are managed and cleaned up."
        )
    )
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--desktop-only",
        action="store_true",
        help="run Python RegistryTransport tests (plus the Podman diagnostic if selected)",
    )
    selection.add_argument(
        "--jvm-only", action="store_true", help="run Android host-JVM interop only"
    )
    selection.add_argument(
        "--android-only",
        action="store_true",
        help="run host-JVM interop and Android device instrumentation, skipping Python tests",
    )
    parser.add_argument(
        "--all-device-faults",
        action="store_true",
        help="compatibility option: all ten device phases run by default",
    )
    parser.add_argument(
        "--peer-backend",
        choices=("process", "podman"),
        default="process",
        help="local Registry peer backend (podman currently supports --desktop-only diagnostics)",
    )
    parser.add_argument(
        "--serial",
        help="the sole connected emulator serial (for example emulator-5554)",
    )
    parser.add_argument(
        "--registry-repo",
        type=Path,
        default=REGISTRY_REPO_DEFAULT,
        help=f"decent-registry checkout (default: {REGISTRY_REPO_DEFAULT})",
    )
    parser.add_argument(
        "--fixture-timeout",
        type=float,
        default=None,
        help="seconds to wait for Registry peers (defaults: 90 for process, 540 for Podman)",
    )
    args = parser.parse_args()
    if args.all_device_faults and (args.desktop_only or args.jvm_only):
        parser.error("--all-device-faults requires Android device phases")
    return args


def format_harness_error(exc: HarnessError) -> str:
    notes = getattr(exc, "__notes__", ())
    if not notes:
        return str(exc)
    return "\n".join((str(exc), *(f"  note: {note}" for note in notes)))


def main() -> int:
    args = parse_args()
    try:
        validate_peer_backend_mode(
            peer_backend=args.peer_backend,
            desktop_only=args.desktop_only,
        )
    except HarnessError as exc:
        print(
            f"Issue #18 Registry acceptance harness: {format_harness_error(exc)}",
            file=sys.stderr,
            flush=True,
        )
        return 1
    if args.fixture_timeout is not None and args.fixture_timeout <= 0:
        fail("--fixture-timeout must be positive")
    fixture_timeout = fixture_startup_timeout(args.peer_backend, args.fixture_timeout)
    try:
        if args.desktop_only:
            code = run_desktop_integration()
            if code or args.peer_backend != "podman":
                return code
            return run_podman_desktop_registry_diagnostic(
                args.registry_repo, fixture_timeout
            )
        if not args.android_only and not args.jvm_only:
            code = run_desktop_integration()
            if code:
                return code
            if args.peer_backend == "podman":
                code = run_podman_desktop_registry_diagnostic(
                    args.registry_repo, fixture_timeout
                )
                if code:
                    return code
        code = run_jvm_registry_interop(
            args.registry_repo, fixture_timeout, peer_backend=args.peer_backend
        )
        if code:
            return code
        if args.jvm_only:
            return 0
        return run_android_runtime(
            args.registry_repo,
            args.serial,
            fixture_timeout,
            peer_backend=args.peer_backend,
            all_device_faults=True,
        )
    except HarnessError as exc:
        print(
            f"Issue #18 Registry acceptance harness: {format_harness_error(exc)}",
            file=sys.stderr,
            flush=True,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

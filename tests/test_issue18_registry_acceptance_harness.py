from __future__ import annotations

import io
import importlib.util
from pathlib import Path
import sys

import pytest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_issue18_registry_acceptance.py"
SPEC = importlib.util.spec_from_file_location("issue18_registry_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


WRITER = "/ip4/127.0.0.1/tcp/39101/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"
READBACK = "/ip4/127.0.0.1/tcp/39102/p2p/12D3KooWR54dTmSuXSKDGdNrnjWxLRykPgcukgbiEJP69h1VJr6V"


def test_parse_ready_lines_accepts_distinct_loopback_peers() -> None:
    writer, readback = HARNESS.parse_ready_lines(
        [f"starting fixture\n", f"READY_READBACK\t{READBACK}\n", f"READY_WRITE\t{WRITER}\n"]
    )

    assert writer.multiaddr == WRITER
    assert readback.multiaddr == READBACK
    assert writer.port == 39101
    assert readback.port == 39102
    assert writer.peer_id != readback.peer_id


def test_parse_ready_lines_rejects_same_peer_id() -> None:
    address = "/ip4/127.0.0.1/tcp/39102/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"

    with pytest.raises(HARNESS.HarnessError, match="distinct Registry peers"):
        HARNESS.parse_ready_lines([f"READY_WRITE\t{WRITER}\n", f"READY_READBACK\t{address}\n"])


def test_select_single_emulator_accepts_only_one_connected_avd() -> None:
    devices = """List of devices attached
emulator-5554 device product:sdk_gphone_x86 model:Medium_Phone
"""

    assert HARNESS.select_single_emulator(devices, requested_serial="emulator-5554") == "emulator-5554"


def test_select_single_emulator_rejects_concurrent_avds() -> None:
    devices = """List of devices attached
emulator-5554 device product:sdk_gphone_x86 model:Medium_Phone
emulator-5556 device product:sdk_gphone64_x86_64 model:Pixel_9
"""

    with pytest.raises(HARNESS.HarnessError, match="exactly one booted Android emulator"):
        HARNESS.select_single_emulator(devices)


def test_select_single_emulator_rejects_other_connected_devices() -> None:
    devices = """List of devices attached
emulator-5554 device product:sdk_gphone_x86 model:Medium_Phone
R58M123456A device product:foo model:Physical_Device
"""

    with pytest.raises(HARNESS.HarnessError, match="only one connected Android target"):
        HARNESS.select_single_emulator(devices)


def test_verify_android_target_accepts_only_a_booted_approved_avd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = tmp_path / "Pixel_9.avd" / "config.ini"
    config.parent.mkdir()
    config.write_text(
        "AvdId=Pixel_9\n"
        "PlayStore.enabled=true\n"
        "abi.type=x86_64\n"
        "image.sysdir.1=system-images/android-37.2/google_apis_playstore_ps16k/x86_64/\n"
        "target=android-37.2\n"
        "tag.ids=google_apis_playstore,page_size_16kb\n",
        encoding="utf-8",
    )
    outputs = iter(
        [
            "Pixel_9\nOK\n",
            "1\n",
            "37\n",
            "x86_64\n",
            "package:/system/priv-app/Phonesky/Phonesky.apk\n",
        ]
    )
    monkeypatch.setenv("ANDROID_AVD_HOME", str(tmp_path))
    monkeypatch.setattr(HARNESS, "adb_output", lambda *_args: next(outputs))

    assert HARNESS.verify_android_target(Path("/sdk/platform-tools/adb"), "emulator-5556") == (
        "Pixel_9",
        37,
        "x86_64",
    )


def test_revalidate_android_target_confirms_the_same_approved_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    devices = """List of devices attached
emulator-5554 device product:sdk_gphone_x86 model:Medium_Phone
"""
    expected = ("Medium_Phone", 26, "x86")
    calls: list[str] = []
    result = type("Result", (), {"returncode": 0, "stdout": devices})()
    monkeypatch.setattr(HARNESS.subprocess, "run", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(
        HARNESS,
        "verify_android_target",
        lambda _adb, serial: calls.append(serial) or expected,
    )

    assert HARNESS.revalidate_android_target(
        Path("/sdk/platform-tools/adb"), "emulator-5554", expected
    ) == expected
    assert calls == ["emulator-5554"]


def test_revalidate_android_target_rejects_a_new_connected_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    devices = """List of devices attached
emulator-5554 device product:sdk_gphone_x86 model:Medium_Phone
R58M123456A device product:foo model:Physical_Device
"""
    result = type("Result", (), {"returncode": 0, "stdout": devices})()
    monkeypatch.setattr(HARNESS.subprocess, "run", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(
        HARNESS,
        "verify_android_target",
        lambda *_args: pytest.fail("must reject additional devices before AVD verification"),
    )

    with pytest.raises(HARNESS.HarnessError, match="only one connected Android target"):
        HARNESS.revalidate_android_target(
            Path("/sdk/platform-tools/adb"), "emulator-5554", ("Medium_Phone", 26, "x86")
        )


def test_revalidate_android_target_rejects_changed_avd_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    devices = """List of devices attached
emulator-5554 device product:sdk_gphone_x86 model:Medium_Phone
"""
    result = type("Result", (), {"returncode": 0, "stdout": devices})()
    monkeypatch.setattr(HARNESS.subprocess, "run", lambda *_args, **_kwargs: result)
    monkeypatch.setattr(
        HARNESS,
        "verify_android_target",
        lambda *_args: ("Pixel_9", 37, "x86_64"),
    )

    with pytest.raises(HARNESS.HarnessError, match="identity changed"):
        HARNESS.revalidate_android_target(
            Path("/sdk/platform-tools/adb"), "emulator-5554", ("Medium_Phone", 26, "x86")
        )


def test_verify_android_target_rejects_unapproved_avd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(["Generic_AVD\nOK\n"])
    monkeypatch.setattr(HARNESS, "adb_output", lambda *_args: next(outputs))

    with pytest.raises(HARNESS.HarnessError, match="not an approved AVD"):
        HARNESS.verify_android_target(Path("/sdk/platform-tools/adb"), "emulator-5554")


def test_select_reverse_ports_avoids_existing_adb_mappings() -> None:
    assert HARNESS.select_reverse_ports("emulator-5554 tcp:31457 tcp:39000\n") == (31458, 31459)


def test_verify_reverse_mappings_checks_device_to_host_targets() -> None:
    output = "emulator-5554 tcp:31457 tcp:39101\nemulator-5554 tcp:31458 tcp:39102\n"

    assert HARNESS.parse_reverse_mappings(output) == {31457: 39101, 31458: 39102}
    HARNESS.verify_reverse_mappings(output, [(31457, 39101), (31458, 39102)])
    with pytest.raises(HARNESS.HarnessError, match="expected tcp:39103"):
        HARNESS.verify_reverse_mappings(output, [(31457, 39103)])


def test_add_reverse_mapping_uses_atomic_no_rebind(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> object:
        calls.append(command)
        return type("Result", (), {"returncode": 0, "stdout": ""})()

    monkeypatch.setattr(HARNESS.subprocess, "run", fake_run)
    HARNESS.add_reverse_mapping(Path("/sdk/platform-tools/adb"), "emulator-5554", 31457, 39101)

    assert calls[0][-4:] == ["reverse", "--no-rebind", "tcp:31457", "tcp:39101"]


def test_cleanup_reverse_mappings_removes_only_matching_targets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    list_outputs = iter(
        [
            "emulator-5554 tcp:31457 tcp:39101\nemulator-5554 tcp:31458 tcp:49000\n",
            "emulator-5554 tcp:31457 tcp:39101\nemulator-5554 tcp:31458 tcp:49000\n",
            "emulator-5554 tcp:31458 tcp:49000\n",
        ]
    )
    adb_calls: list[tuple[str, ...]] = []
    removals: list[list[str]] = []

    def fake_adb_output(_adb: Path, _serial: str, *args: str) -> str:
        adb_calls.append(args)
        return next(list_outputs)

    def fake_run(command: list[str], **_kwargs: object) -> object:
        removals.append(command)
        return type("Result", (), {"returncode": 0, "stdout": ""})()

    monkeypatch.setattr(HARNESS, "adb_output", fake_adb_output)
    monkeypatch.setattr(HARNESS.subprocess, "run", fake_run)

    errors = HARNESS.cleanup_reverse_mappings(
        Path("/sdk/platform-tools/adb"),
        "emulator-5554",
        owned={31457: 39101},
        pending={31458: 39102},
    )

    assert errors == []
    assert len(adb_calls) == 3
    assert len(removals) == 1
    assert removals[0][-2:] == ["--remove", "tcp:31457"]


def test_cleanup_removes_exact_pending_mapping_after_ambiguous_add(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    list_outputs = iter(["emulator-5554 tcp:31457 tcp:39101" + chr(10), ""])
    removals: list[list[str]] = []

    monkeypatch.setattr(HARNESS, "adb_output", lambda *_args: next(list_outputs))
    monkeypatch.setattr(
        HARNESS.subprocess,
        "run",
        lambda command, **_kwargs: (
            removals.append(command) or type("Result", (), {"returncode": 0, "stdout": ""})()
        ),
    )

    errors = HARNESS.cleanup_reverse_mappings(
        Path("/sdk/platform-tools/adb"),
        "emulator-5554",
        owned={},
        pending={31457: 39101},
    )

    assert errors == []
    assert len(removals) == 1
    assert removals[0][-2:] == ["--remove", "tcp:31457"]


def test_lmdb_stores_must_be_separate_files(tmp_path: Path) -> None:
    writer = tmp_path / "writer.lmdb"
    readback = tmp_path / "readback.lmdb"
    writer.write_bytes(b"writer")
    readback.write_bytes(b"readback")

    HARNESS.ensure_distinct_lmdb_stores(writer, readback)
    with pytest.raises(HARNESS.HarnessError, match="separate LMDB files"):
        HARNESS.ensure_distinct_lmdb_stores(writer, writer)


def test_registry_fixture_stops_on_keyboard_interrupt_during_startup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeProcess:
        pid = 987654321

        def __init__(self) -> None:
            self.stdout = io.StringIO(f"READY_WRITE\t{WRITER}\nREADY_READBACK\t{READBACK}\n")
            self.returncode: int | None = None

        def poll(self) -> int | None:
            return self.returncode

        def send_signal(self, _signal: int) -> None:
            self.returncode = 0

        def wait(self, timeout: float | None = None) -> int:
            self.returncode = 0
            return 0

    process = FakeProcess()
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr(HARNESS.shutil, "which", lambda _name: "/usr/bin/uv")
    monkeypatch.setattr(HARNESS, "registry_python_executable", lambda *_args: "/usr/bin/python3")
    monkeypatch.setattr(HARNESS.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(HARNESS.os, "killpg", lambda *_args: (_ for _ in ()).throw(ProcessLookupError()))
    monkeypatch.setattr(
        HARNESS,
        "parse_ready_lines",
        lambda _lines: (_ for _ in ()).throw(KeyboardInterrupt()),
    )

    fixture = HARNESS.RegistryPeerFixture(tmp_path)
    with pytest.raises(KeyboardInterrupt):
        fixture.__enter__()

    assert process.returncode == 0
    assert list(tmp_path.glob("issue18-registry-harness-*")) == []


def test_fixture_reader_queues_only_readiness_records() -> None:
    fixture = HARNESS.RegistryPeerFixture(Path("."))

    class FakeProcess:
        stdout = io.StringIO(
            "unrelated diagnostic\n"
            f"READY_WRITE\t{WRITER}\n"
            "private-looking diagnostic\n"
            f"READY_READBACK\t{READBACK}\n"
        )

    fixture.process = FakeProcess()
    fixture._pump_stdout()
    queued: list[str | None] = []
    while not fixture._messages.empty():
        queued.append(fixture._messages.get_nowait())

    assert queued == [f"READY_WRITE\t{WRITER}\n", f"READY_READBACK\t{READBACK}\n", None]


def test_parse_ready_lines_rejects_duplicate_readiness_record() -> None:
    with pytest.raises(HARNESS.HarnessError, match="duplicate READY_WRITE"):
        HARNESS.parse_ready_lines(
            [f"READY_WRITE\t{WRITER}\n", f"READY_WRITE\t{WRITER}\n", f"READY_READBACK\t{READBACK}\n"]
        )


def test_verify_android_test_result_requires_exact_rotation_test_to_pass(tmp_path: Path) -> None:
    report = tmp_path / "TEST-runtime.xml"
    report.write_text(
        """<testsuite tests="1" failures="0" errors="0" skipped="0">
  <testcase classname="org.decentwallet.wallet.android.AndroidDirectDhtRegistryRuntimeTest"
            name="rotatesWalletThroughDirectDhtAndPersistsPromotionOnAndroid" />
</testsuite>
""",
        encoding="utf-8",
    )

    result = HARNESS.verify_android_test_result(
        [report], "rotatesWalletThroughDirectDhtAndPersistsPromotionOnAndroid"
    )

    assert result == {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}


def test_verify_android_test_result_rejects_skipped_rotation_test(tmp_path: Path) -> None:
    report = tmp_path / "TEST-runtime.xml"
    report.write_text(
        """<testsuite tests="1" failures="0" errors="0" skipped="1">
  <testcase classname="org.decentwallet.wallet.android.AndroidDirectDhtRegistryRuntimeTest"
            name="rotatesWalletThroughDirectDhtAndPersistsPromotionOnAndroid">
    <skipped message="peer configuration missing" />
  </testcase>
</testsuite>
""",
        encoding="utf-8",
    )

    with pytest.raises(HARNESS.HarnessError, match="must pass, not skip"):
        HARNESS.verify_android_test_result(
            [report], "rotatesWalletThroughDirectDhtAndPersistsPromotionOnAndroid"
        )


@pytest.mark.parametrize(
    "version_output",
    [
        'openjdk version "17"',
        'openjdk version "17.0.2"',
        'openjdk version "17-ea"',
        'openjdk version "17+35"',
    ],
)
def test_is_jdk17_version_accepts_jdk17_version_forms(version_output: str) -> None:
    assert HARNESS.is_jdk17_version(version_output)


@pytest.mark.parametrize(
    "version_output",
    ['openjdk version "170"', 'openjdk version "21"', 'openjdk version "17preview"'],
)
def test_is_jdk17_version_rejects_other_versions(version_output: str) -> None:
    assert not HARNESS.is_jdk17_version(version_output)


def test_gradle_environment_sets_both_android_sdk_variables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    jdk_home = tmp_path / "jdk17"
    monkeypatch.setattr(HARNESS, "jdk17_home", lambda _env: jdk_home)
    env = HARNESS.gradle_environment({"ANDROID_HOME": str(tmp_path)})

    assert env["ANDROID_HOME"] == str(tmp_path)
    assert env["ANDROID_SDK_ROOT"] == str(tmp_path)
    assert env["JAVA_HOME"] == str(jdk_home)
    assert env["PATH"].startswith(f"{jdk_home / 'bin'}:")


def test_gradle_environment_finds_standard_sdk_path_when_unset(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    jdk_home = tmp_path / "jdk17"
    monkeypatch.setattr(HARNESS, "jdk17_home", lambda _env: jdk_home)
    env = HARNESS.gradle_environment({}, sdk_default=tmp_path)

    assert env["ANDROID_HOME"] == str(tmp_path)
    assert env["ANDROID_SDK_ROOT"] == str(tmp_path)
    assert env["JAVA_HOME"] == str(jdk_home)


def test_registry_peer_fixture_defaults_to_process_backend() -> None:
    fixture = HARNESS.RegistryPeerFixture(Path("."))

    assert fixture.peer_backend == "process"
    assert fixture.fixture_script == HARNESS.FIXTURE_SCRIPT


def test_registry_peer_fixture_selects_podman_backend(tmp_path: Path) -> None:
    fixture = HARNESS.RegistryPeerFixture(tmp_path, peer_backend="podman")

    assert fixture.peer_backend == "podman"
    assert fixture.fixture_script == HARNESS.PODMAN_FIXTURE_SCRIPT


def test_registry_peer_fixture_rejects_unsupported_backend(tmp_path: Path) -> None:
    with pytest.raises(HARNESS.HarnessError, match="peer backend"):
        HARNESS.RegistryPeerFixture(tmp_path, peer_backend="compose")


def test_registry_store_paths_are_separate_for_each_backend(tmp_path: Path) -> None:
    process_paths = HARNESS.registry_store_paths(tmp_path, "process")
    podman_paths = HARNESS.registry_store_paths(tmp_path, "podman")

    assert process_paths == (tmp_path / "writer.lmdb", tmp_path / "readback.lmdb")
    assert podman_paths == (
        tmp_path / "writer" / "writer.lmdb",
        tmp_path / "readback" / "readback.lmdb",
    )


def test_podman_peer_backend_is_limited_to_desktop_diagnostic() -> None:
    with pytest.raises(HARNESS.HarnessError, match="desktop-only diagnostic"):
        HARNESS.validate_peer_backend_mode(peer_backend="podman", desktop_only=False)

    HARNESS.validate_peer_backend_mode(peer_backend="podman", desktop_only=True)
    HARNESS.validate_peer_backend_mode(peer_backend="process", desktop_only=False)


def test_parse_args_accepts_podman_peer_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        HARNESS.sys,
        "argv",
        ["run_issue18_registry_acceptance.py", "--jvm-only", "--peer-backend", "podman"],
    )

    args = HARNESS.parse_args()

    assert args.peer_backend == "podman"


def test_fixture_error_message_redacts_unrecognized_details() -> None:
    assert HARNESS.safe_fixture_error_message(
        "Registry peer did not become ready before the startup deadline"
    ) == "Registry peer did not become ready before the startup deadline"
    assert HARNESS.safe_fixture_error_message(
        "Registry peer readiness failed (bootstrap_records=0, address_error=bootstrap_count, tcp_ready=true)"
    ) == "Registry peer readiness failed (bootstrap_records=0, address_error=bootstrap_count, tcp_ready=true)"
    assert HARNESS.safe_fixture_error_message(
        "Registry peer publication failed (error=ValueError)"
    ) == "Registry peer publication failed (error=ValueError)"
    assert HARNESS.safe_fixture_error_message(
        "could not seed or confirm the synthetic Registry record (error=ValueError)"
    ) == "could not seed or confirm the synthetic Registry record (error=ValueError)"
    assert HARNESS.safe_fixture_error_message(
        "could not seed or confirm the synthetic Registry record "
        "(error=RuntimeError; detail=no tcp addr)"
    ) == (
        "could not seed or confirm the synthetic Registry record "
        "(error=RuntimeError; detail=no tcp addr)"
    )
    assert HARNESS.safe_fixture_error_message(
        "Registry peer seed failed (error=RuntimeError; detail=no tcp addr)"
    ) == "Registry peer seed failed (error=RuntimeError; detail=no tcp addr)"
    assert HARNESS.safe_fixture_error_message(
        "/home/ben/.hermes/cache/scratch/node_privkey.bin"
    ) == "Registry peer fixture failed"


def test_fixture_stdout_pump_keeps_only_readiness_and_safe_error_records() -> None:
    fixture = HARNESS.RegistryPeerFixture(Path("."), peer_backend="podman")

    class FixtureProcess:
        stdout = io.StringIO(
            "arbitrary fixture log with peer data\n"
            "FIXTURE_ERROR\tRegistry peer did not become ready before the startup deadline\n"
        )

    fixture.process = FixtureProcess()
    fixture._pump_stdout()

    assert fixture._messages.get_nowait() == (
        "FIXTURE_ERROR\tRegistry peer did not become ready before the startup deadline\n"
    )
    assert fixture._messages.get_nowait() is None


def test_fixture_startup_timeout_is_backend_aware_and_overridable() -> None:
    assert HARNESS.fixture_startup_timeout("process", None) == 90
    assert HARNESS.fixture_startup_timeout("podman", None) >= 300 + 2 * 60 + 90
    assert HARNESS.fixture_startup_timeout("podman", 123) == 123


def test_registry_peer_fixture_uses_podman_setup_budget() -> None:
    process_fixture = HARNESS.RegistryPeerFixture(Path("."))
    podman_fixture = HARNESS.RegistryPeerFixture(Path("."), peer_backend="podman")

    assert process_fixture.timeout_seconds == 90
    assert podman_fixture.timeout_seconds >= 300 + 2 * 60 + 90


def test_registry_fixture_does_not_allocate_scratch_before_environment_resolution(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    monkeypatch.setattr(HARNESS.shutil, "which", lambda _name: "uv")

    def fail(_uv: str, _registry_repo: Path) -> str:
        raise HARNESS.HarnessError("missing test interpreter")

    monkeypatch.setattr(HARNESS, "registry_python_executable", fail)
    fixture = HARNESS.RegistryPeerFixture(tmp_path)

    with pytest.raises(HARNESS.HarnessError, match="test interpreter"):
        fixture.__enter__()

    assert fixture._scratch is None
    assert list(tmp_path.glob("issue18-registry-harness-*")) == []


def test_registry_python_executable_comes_from_locked_project(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / ".venv" / "bin" / "python"
    executable.parent.mkdir(parents=True)
    executable.touch()
    calls: list[tuple[list[str], dict[str, object]]] = []

    class Result:
        returncode = 0
        stdout = f"{executable}\n"

    def run(command: list[str], **kwargs: object) -> Result:
        calls.append((command, kwargs))
        return Result()

    monkeypatch.setattr(HARNESS.subprocess, "run", run)

    resolved = HARNESS.registry_python_executable("uv", tmp_path)

    assert resolved == str(executable)
    assert calls[0][0][:6] == [
        "uv",
        "run",
        "--locked",
        "--project",
        str(tmp_path.resolve()),
        "--extra",
    ]
    assert calls[0][0][-4:] == [
        "dev",
        "python",
        "-c",
        "import sys; print(sys.executable)",
    ]
    assert calls[0][1]["cwd"] == tmp_path.resolve()
    assert calls[0][1]["timeout"] > 0


def test_registry_peer_fixture_reports_failed_teardown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailedProcess:
        returncode = 1

        def poll(self) -> int:
            return self.returncode

    fixture = HARNESS.RegistryPeerFixture(Path("."), peer_backend="podman")
    fixture.process = FailedProcess()
    monkeypatch.setattr(fixture, "stop", lambda: None)

    with pytest.raises(HARNESS.HarnessError, match="teardown failed"):
        fixture.__exit__(None, None, None)


def test_registry_peer_fixture_accepts_sigint_exit_after_requested_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SignalExitProcess:
        pid = 123
        stdout = None
        returncode = None

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            self.returncode = 130
            return self.returncode

    fixture = HARNESS.RegistryPeerFixture(Path("."))
    fixture.process = SignalExitProcess()
    monkeypatch.setattr(HARNESS.os, "killpg", lambda *_args: None)

    fixture.__exit__(None, None, None)

    assert fixture._stop_signal_sent is True

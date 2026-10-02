from __future__ import annotations

import importlib.util
import io
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "run_issue18_registry_acceptance.py"
SPEC = importlib.util.spec_from_file_location("issue18_registry_acceptance", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
HARNESS = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = HARNESS
SPEC.loader.exec_module(HARNESS)


WRITER = (
    "/ip4/127.0.0.1/tcp/39101/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"
)
READBACK = (
    "/ip4/127.0.0.1/tcp/39102/p2p/12D3KooWR54dTmSuXSKDGdNrnjWxLRykPgcukgbiEJP69h1VJr6V"
)


def test_parse_ready_lines_accepts_distinct_loopback_peers() -> None:
    writer, readback = HARNESS.parse_ready_lines(
        [
            f"starting fixture\n",
            f"READY_READBACK\t{READBACK}\n",
            f"READY_WRITE\t{WRITER}\n",
        ]
    )

    assert writer.multiaddr == WRITER
    assert readback.multiaddr == READBACK
    assert writer.port == 39101
    assert readback.port == 39102
    assert writer.peer_id != readback.peer_id


def test_parse_ready_lines_rejects_same_peer_id() -> None:
    address = "/ip4/127.0.0.1/tcp/39102/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"

    with pytest.raises(HARNESS.HarnessError, match="distinct Registry peers"):
        HARNESS.parse_ready_lines(
            [f"READY_WRITE\t{WRITER}\n", f"READY_READBACK\t{address}\n"]
        )


def test_select_single_emulator_accepts_only_one_connected_avd() -> None:
    devices = """List of devices attached
emulator-5554 device product:sdk_gphone_x86 model:Medium_Phone
"""

    assert (
        HARNESS.select_single_emulator(devices, requested_serial="emulator-5554")
        == "emulator-5554"
    )


def test_select_single_emulator_rejects_concurrent_avds() -> None:
    devices = """List of devices attached
emulator-5554 device product:sdk_gphone_x86 model:Medium_Phone
emulator-5556 device product:sdk_gphone64_x86_64 model:Pixel_9
"""

    with pytest.raises(
        HARNESS.HarnessError, match="exactly one booted Android emulator"
    ):
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

    assert HARNESS.verify_android_target(
        Path("/sdk/platform-tools/adb"), "emulator-5556"
    ) == (
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

    assert (
        HARNESS.revalidate_android_target(
            Path("/sdk/platform-tools/adb"), "emulator-5554", expected
        )
        == expected
    )
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
        lambda *_args: pytest.fail(
            "must reject additional devices before AVD verification"
        ),
    )

    with pytest.raises(HARNESS.HarnessError, match="only one connected Android target"):
        HARNESS.revalidate_android_target(
            Path("/sdk/platform-tools/adb"),
            "emulator-5554",
            ("Medium_Phone", 26, "x86"),
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
            Path("/sdk/platform-tools/adb"),
            "emulator-5554",
            ("Medium_Phone", 26, "x86"),
        )


def test_verify_android_target_rejects_unapproved_avd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(["Generic_AVD\nOK\n"])
    monkeypatch.setattr(HARNESS, "adb_output", lambda *_args: next(outputs))

    with pytest.raises(HARNESS.HarnessError, match="not an approved AVD"):
        HARNESS.verify_android_target(Path("/sdk/platform-tools/adb"), "emulator-5554")


def test_select_reverse_ports_avoids_existing_adb_mappings() -> None:
    assert HARNESS.select_reverse_ports("emulator-5554 tcp:31457 tcp:39000\n") == (
        31458,
        31459,
    )


def test_verify_reverse_mappings_checks_device_to_host_targets() -> None:
    output = "emulator-5554 tcp:31457 tcp:39101\nemulator-5554 tcp:31458 tcp:39102\n"

    assert HARNESS.parse_reverse_mappings(output) == {31457: 39101, 31458: 39102}
    HARNESS.verify_reverse_mappings(output, [(31457, 39101), (31458, 39102)])
    with pytest.raises(HARNESS.HarnessError, match="expected tcp:39103"):
        HARNESS.verify_reverse_mappings(output, [(31457, 39103)])


def test_add_reverse_mapping_uses_atomic_no_rebind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> object:
        calls.append(command)
        return type("Result", (), {"returncode": 0, "stdout": ""})()

    monkeypatch.setattr(HARNESS.subprocess, "run", fake_run)
    HARNESS.add_reverse_mapping(
        Path("/sdk/platform-tools/adb"), "emulator-5554", 31457, 39101
    )

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
            removals.append(command)
            or type("Result", (), {"returncode": 0, "stdout": ""})()
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
            self.stdout = io.StringIO(
                f"READY_WRITE\t{WRITER}\nREADY_READBACK\t{READBACK}\n"
            )
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
    monkeypatch.setattr(
        HARNESS, "registry_python_executable", lambda *_args: "/usr/bin/python3"
    )
    monkeypatch.setattr(HARNESS.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        HARNESS.os, "killpg", lambda *_args: (_ for _ in ()).throw(ProcessLookupError())
    )
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
            [
                f"READY_WRITE\t{WRITER}\n",
                f"READY_WRITE\t{WRITER}\n",
                f"READY_READBACK\t{READBACK}\n",
            ]
        )


def test_verify_android_test_result_requires_exact_rotation_test_to_pass(
    tmp_path: Path,
) -> None:
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


def test_verify_android_test_result_rejects_skipped_rotation_test(
    tmp_path: Path,
) -> None:
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


def test_registry_peer_fixture_command_selects_versioned_history(
    tmp_path: Path,
) -> None:
    fixture = HARNESS.RegistryPeerFixture(tmp_path, predecessor_format="versioned")

    command = fixture.build_command("/usr/bin/python3", tmp_path / "peer-data")

    assert command[:2] == ["/usr/bin/python3", str(HARNESS.FIXTURE_SCRIPT)]
    assert command[command.index("--predecessor-format") + 1] == "versioned"


def test_registry_peer_fixture_command_selects_missing_history_fault(
    tmp_path: Path,
) -> None:
    fixture = HARNESS.RegistryPeerFixture(
        tmp_path,
        predecessor_format="versioned",
        history_fault="missing",
    )

    command = fixture.build_command("/usr/bin/python3", tmp_path / "peer-data")

    assert command[command.index("--history-fault") + 1] == "missing"


def patch_versioned_android_runtime(
    monkeypatch: pytest.MonkeyPatch,
    *,
    report: Path,
    gradle_error: Exception | None = None,
    gradle_result: int = 0,
    fixture_error: Exception | None = None,
    cleanup_errors: list[str] | None = None,
) -> dict[str, object]:
    captured: dict[str, object] = {}

    class FakeFixture:
        def __init__(self, *_args: object, **kwargs: object) -> None:
            captured["fixture_args"] = kwargs
            self.writer = SimpleNamespace(port=39101, peer_id="writer-peer")
            self.readback = SimpleNamespace(port=39102, peer_id="readback-peer")

        def __enter__(self) -> FakeFixture:
            if fixture_error is not None:
                raise fixture_error
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    def fake_run_command(
        command: list[str], *, cwd: Path, env: dict[str, str], timeout: int
    ) -> int:
        captured["command"] = command
        captured["cwd"] = cwd
        captured["env"] = env.copy()
        captured["timeout"] = timeout
        if gradle_error is not None:
            raise gradle_error
        return gradle_result

    def fake_cleanup(
        adb: Path, serial: str, owned: dict[int, int], pending: dict[int, int]
    ) -> list[str]:
        captured["cleanup"] = (adb, serial, owned.copy(), pending.copy())
        return list(cleanup_errors or [])

    monkeypatch.setattr(HARNESS, "RegistryPeerFixture", FakeFixture)
    monkeypatch.setattr(HARNESS, "gradle_environment", dict)
    monkeypatch.setattr(HARNESS, "android_report_snapshot", dict)
    monkeypatch.setattr(HARNESS, "select_reverse_ports", lambda _output: (31457, 31458))
    monkeypatch.setattr(HARNESS, "adb_output", lambda *_args: "")
    monkeypatch.setattr(HARNESS, "add_reverse_mapping", lambda *_args: None)
    monkeypatch.setattr(HARNESS, "verify_reverse_mappings", lambda *_args: None)
    monkeypatch.setattr(
        HARNESS,
        "revalidate_android_target",
        lambda _adb, _serial, target: target,
    )
    monkeypatch.setattr(HARNESS, "run_command", fake_run_command)
    monkeypatch.setattr(HARNESS, "cleanup_reverse_mappings", fake_cleanup)
    monkeypatch.setattr(HARNESS, "changed_reports", lambda _root, _before: [report])
    return captured


def test_versioned_android_runtime_wires_fixture_filter_and_verified_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "TEST-versioned.xml"
    report.write_text(
        '<testsuites tests="1"><testsuite name="runtime" tests="1">'
        f'<testcase name="{HARNESS.ROTATION_TEST_NAME}" '
        f'classname="{HARNESS.ROTATION_TEST_CLASS}" />'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    captured = patch_versioned_android_runtime(monkeypatch, report=report)

    code, reports = HARNESS.run_versioned_android_runtime(
        tmp_path,
        60.0,
        adb=Path("/sdk/platform-tools/adb"),
        serial="emulator-5554",
        expected_target=("Medium_Phone", 26, "x86"),
        peer_backend="process",
    )

    assert code == 0
    assert reports == [report]
    assert HARNESS.verify_android_test_result(reports) == {
        "tests": 1,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
    }
    assert captured["fixture_args"] == {
        "timeout_seconds": 60.0,
        "peer_backend": "process",
        "predecessor_format": "versioned",
        "history_fault": "none",
    }
    command = captured["command"]
    assert isinstance(command, list)
    assert (
        f"-Pissue18AndroidTestClass={HARNESS.ROTATION_TEST_CLASS}#{HARNESS.ROTATION_TEST_NAME}"
        in command
    )
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["DECENT_REGISTRY_TEST_FIXTURE"] == "versioned"
    assert "/tcp/31457/p2p/writer-peer" in env["DECENT_REGISTRY_TEST_PEER"]
    assert "/tcp/31458/p2p/readback-peer" in env["DECENT_REGISTRY_TEST_READBACK_PEER"]
    cleanup = captured["cleanup"]
    assert cleanup == (
        Path("/sdk/platform-tools/adb"),
        "emulator-5554",
        {31457: 39101, 31458: 39102},
        {},
    )


@pytest.mark.parametrize("history_fault", ["missing", "corrupt"])
def test_versioned_history_fault_android_runtime_wires_fixture_filter_and_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, history_fault: str
) -> None:
    report = tmp_path / "TEST-missing-history.xml"
    report.write_text(
        '<testsuites tests="1"><testsuite name="runtime" tests="1">'
        '<testcase name="versionedHistoryAvailabilityFailsClosedBeforeDraftCreation" '
        'classname="org.decentwallet.wallet.android.AndroidDirectDhtRegistryRuntimeTest" />'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    captured = patch_versioned_android_runtime(monkeypatch, report=report)

    code, reports = HARNESS.run_versioned_android_runtime(
        tmp_path,
        60.0,
        adb=Path("/sdk/platform-tools/adb"),
        serial="emulator-5554",
        expected_target=("Medium_Phone", 26, "x86"),
        peer_backend="process",
        history_fault=history_fault,
    )

    assert code == 0
    assert reports == [report]
    assert HARNESS.verify_android_test_result(
        reports,
        expected_test_name="versionedHistoryAvailabilityFailsClosedBeforeDraftCreation",
    ) == {"tests": 1, "failures": 0, "errors": 0, "skipped": 0}
    assert captured["fixture_args"] == {
        "timeout_seconds": 60.0,
        "peer_backend": "process",
        "predecessor_format": "versioned",
        "history_fault": history_fault,
    }
    command = captured["command"]
    assert isinstance(command, list)
    assert (
        "-Pissue18AndroidTestClass="
        "org.decentwallet.wallet.android.AndroidDirectDhtRegistryRuntimeTest#"
        "versionedHistoryAvailabilityFailsClosedBeforeDraftCreation"
    ) in command
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["DECENT_REGISTRY_TEST_FIXTURE"] == f"versioned-{history_fault}-history"


def test_competing_write_runtime_selects_guarded_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "TEST-competing-write.xml"
    captured = patch_versioned_android_runtime(monkeypatch, report=report)
    code, reports = HARNESS.run_versioned_android_runtime(
        tmp_path,
        60.0,
        adb=Path("/sdk/platform-tools/adb"),
        serial="emulator-5554",
        expected_target=("Medium_Phone", 26, "x86"),
        peer_backend="process",
        competing_write=True,
    )
    assert code == 0 and reports == [report]
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["DECENT_REGISTRY_TEST_FIXTURE"] == "versioned-competing-write"


def test_promotion_unknown_runtime_selects_guarded_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "TEST-promotion-unknown.xml"
    captured = patch_versioned_android_runtime(monkeypatch, report=report)
    code, reports = HARNESS.run_versioned_android_runtime(
        tmp_path,
        60.0,
        adb=Path("/sdk/platform-tools/adb"),
        serial="emulator-5554",
        expected_target=("Medium_Phone", 26, "x86"),
        peer_backend="process",
        promotion_unknown=True,
    )
    assert code == 0 and reports == [report]
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["DECENT_REGISTRY_TEST_FIXTURE"] == "versioned-promotion-unknown"


def test_promotion_rollback_runtime_selects_guarded_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "TEST-promotion-rollback.xml"
    captured = patch_versioned_android_runtime(monkeypatch, report=report)
    code, reports = HARNESS.run_versioned_android_runtime(
        tmp_path,
        60.0,
        adb=Path("/sdk/platform-tools/adb"),
        serial="emulator-5554",
        expected_target=("Medium_Phone", 26, "x86"),
        peer_backend="process",
        promotion_rollback=True,
    )
    assert code == 0 and reports == [report]
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["DECENT_REGISTRY_TEST_FIXTURE"] == "versioned-promotion-rollback"


def test_conditional_rejection_runtime_selects_guarded_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "TEST-conditional.xml"
    captured = patch_versioned_android_runtime(monkeypatch, report=report)
    code, reports = HARNESS.run_versioned_android_runtime(
        tmp_path,
        60.0,
        adb=Path("/sdk/platform-tools/adb"),
        serial="emulator-5554",
        expected_target=("Medium_Phone", 26, "x86"),
        peer_backend="process",
        conditional_rejection=True,
    )
    assert code == 0 and reports == [report]
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["DECENT_REGISTRY_TEST_FIXTURE"] == "versioned-conditional-rejection"


def test_lost_ack_runtime_selects_guarded_label(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "TEST-lost-ack.xml"
    captured = patch_versioned_android_runtime(monkeypatch, report=report)
    code, reports = HARNESS.run_versioned_android_runtime(
        tmp_path,
        60.0,
        adb=Path("/sdk/platform-tools/adb"),
        serial="emulator-5554",
        expected_target=("Medium_Phone", 26, "x86"),
        peer_backend="process",
        lost_acknowledgement=True,
    )
    assert code == 0 and reports == [report]
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["DECENT_REGISTRY_TEST_FIXTURE"] == "versioned-lost-acknowledgement"


def test_promotion_staging_runtime_wires_fault_label_and_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    report = tmp_path / "TEST-promotion.xml"
    report.write_text(
        '<testsuites tests="1"><testsuite name="runtime" tests="1">'
        f'<testcase name="{HARNESS.ROTATION_TEST_NAME}" '
        f'classname="{HARNESS.ROTATION_TEST_CLASS}" />'
        "</testsuite></testsuites>",
        encoding="utf-8",
    )
    captured = patch_versioned_android_runtime(monkeypatch, report=report)
    code, reports = HARNESS.run_versioned_android_runtime(
        tmp_path,
        60.0,
        adb=Path("/sdk/platform-tools/adb"),
        serial="emulator-5554",
        expected_target=("Medium_Phone", 26, "x86"),
        peer_backend="process",
        promotion_staging_failure=True,
    )
    assert code == 0
    assert HARNESS.verify_android_test_result(reports)["tests"] == 1
    env = captured["env"]
    fixture_args = captured["fixture_args"]
    command = captured["command"]
    cleanup = captured["cleanup"]
    assert isinstance(env, dict)
    assert isinstance(fixture_args, dict)
    assert isinstance(command, list)
    assert isinstance(cleanup, tuple)
    assert env["DECENT_REGISTRY_TEST_FIXTURE"] == "versioned-promotion-staging-failure"
    assert fixture_args["predecessor_format"] == "versioned"
    assert fixture_args["history_fault"] == "none"
    assert (
        f"-Pissue18AndroidTestClass={HARNESS.ROTATION_TEST_CLASS}#{HARNESS.ROTATION_TEST_NAME}"
        in command
    )
    assert cleanup[2] == {31457: 39101, 31458: 39102}


@pytest.mark.parametrize(
    "failed_fault",
    [
        None,
        "conditional_rejection",
        "promotion_rollback",
        "promotion_unknown",
        "competing_write",
    ],
)
def test_all_device_faults_runs_in_order_and_stops_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failed_fault: str | None
) -> None:
    report = tmp_path / "TEST-runtime.xml"
    patch_versioned_android_runtime(monkeypatch, report=report)
    monkeypatch.setattr(HARNESS, "adb_path", lambda: Path("/sdk/platform-tools/adb"))
    monkeypatch.setattr(
        HARNESS.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0, stdout="List of devices attached\nemulator-5554 device\n"
        ),
    )
    monkeypatch.setattr(
        HARNESS, "verify_android_target", lambda *_args: ("Medium_Phone", 26, "x86")
    )
    monkeypatch.setattr(
        HARNESS,
        "verify_android_test_result",
        lambda *_args, **_kwargs: {
            "tests": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
        },
    )
    phases = []

    def run_phase(*_args: object, **kwargs: object) -> tuple[int, list[Path]]:
        phases.append(kwargs)
        return (9 if failed_fault and kwargs.get(failed_fault) else 0), [report]

    monkeypatch.setattr(HARNESS, "run_versioned_android_runtime", run_phase)
    assert HARNESS.run_android_runtime(
        tmp_path, "emulator-5554", 60.0
    ) == (9 if failed_fault else 0)
    faults = [
        "conditional_rejection",
        "promotion_rollback",
        "promotion_unknown",
        "competing_write",
    ]
    expected = faults[: faults.index(failed_fault) + 1] if failed_fault else faults
    assert len(phases) == 5 + len(expected)
    assert [
        next(key for key in faults if phase.get(key)) for phase in phases[5:]
    ] == expected


def test_all_device_faults_cli_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "sys.argv", ["acceptance", "--android-only", "--all-device-faults"]
    )
    assert HARNESS.parse_args().all_device_faults is True


@pytest.mark.parametrize("selection", ["--desktop-only", "--jvm-only"])
def test_all_device_faults_rejects_nondevice_cli_mode(
    monkeypatch: pytest.MonkeyPatch, selection: str
) -> None:
    monkeypatch.setattr("sys.argv", ["acceptance", selection, "--all-device-faults"])
    with pytest.raises(SystemExit) as caught:
        HARNESS.parse_args()
    assert caught.value.code == 2


@pytest.mark.parametrize("promotion_code", [0, 7])
def test_default_device_sequence_runs_promotion_phase_and_propagates_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, promotion_code: int
) -> None:
    report = tmp_path / "TEST-runtime.xml"
    patch_versioned_android_runtime(monkeypatch, report=report)
    monkeypatch.setattr(HARNESS, "adb_path", lambda: Path("/sdk/platform-tools/adb"))
    monkeypatch.setattr(
        HARNESS.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout="List of devices attached\nemulator-5554 device\n",
        ),
    )
    monkeypatch.setattr(
        HARNESS, "verify_android_target", lambda *_args: ("Medium_Phone", 26, "x86")
    )
    monkeypatch.setattr(
        HARNESS,
        "verify_android_test_result",
        lambda *_args, **_kwargs: {
            "tests": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
        },
    )
    phases = []

    def run_phase(*_args: object, **kwargs: object) -> tuple[int, list[Path]]:
        phases.append(kwargs)
        return (promotion_code if kwargs.get("promotion_staging_failure") else 0), [
            report
        ]

    monkeypatch.setattr(HARNESS, "run_versioned_android_runtime", run_phase)
    assert (
        HARNESS.run_android_runtime(tmp_path, "emulator-5554", 60.0) == promotion_code
    )
    assert len(phases) == (4 if promotion_code else 9)
    expected_history_faults = ["none", "missing", "corrupt", "none"]
    if not promotion_code:
        expected_history_faults.extend(["none"] * 5)
    assert [
        phase.get("history_fault", "none") for phase in phases
    ] == expected_history_faults
    assert phases[3]["promotion_staging_failure"] is True
    if not promotion_code:
        assert phases[4]["lost_acknowledgement"] is True


def test_promotion_phase_rejects_combined_history_fault(tmp_path: Path) -> None:
    with pytest.raises(HARNESS.HarnessError, match="cannot use a history-fault"):
        HARNESS.run_versioned_android_runtime(
            tmp_path,
            60.0,
            adb=Path("/sdk/platform-tools/adb"),
            serial="emulator-5554",
            expected_target=("Medium_Phone", 26, "x86"),
            peer_backend="process",
            promotion_staging_failure=True,
            history_fault="missing",
        )


def test_versioned_android_runtime_preserves_gradle_failure_when_cleanup_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    primary_error = HARNESS.HarnessError("simulated Gradle failure")
    patch_versioned_android_runtime(
        monkeypatch,
        report=tmp_path / "unused.xml",
        gradle_error=primary_error,
        cleanup_errors=["simulated adb reverse cleanup failure"],
    )

    with pytest.raises(
        HARNESS.HarnessError, match="simulated Gradle failure"
    ) as caught:
        HARNESS.run_versioned_android_runtime(
            tmp_path,
            60.0,
            adb=Path("/sdk/platform-tools/adb"),
            serial="emulator-5554",
            expected_target=("Medium_Phone", 26, "x86"),
            peer_backend="process",
        )

    assert any(
        "simulated adb reverse cleanup failure" in note
        for note in getattr(caught.value, "__notes__", [])
    )


def test_versioned_android_runtime_reports_gradle_exit_with_cleanup_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    patch_versioned_android_runtime(
        monkeypatch,
        report=tmp_path / "unused.xml",
        gradle_result=1,
        cleanup_errors=["simulated adb reverse cleanup failure"],
    )

    with pytest.raises(
        HARNESS.HarnessError,
        match="versioned owner-key rotation Android Gradle run exited with status 1.*reverse-mapping cleanup failed",
    ):
        HARNESS.run_versioned_android_runtime(
            tmp_path,
            60.0,
            adb=Path("/sdk/platform-tools/adb"),
            serial="emulator-5554",
            expected_target=("Medium_Phone", 26, "x86"),
            peer_backend="process",
        )


def test_main_reports_cleanup_note_when_android_fixture_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture_error = HARNESS.HarnessError("simulated Registry fixture failure")
    patch_versioned_android_runtime(
        monkeypatch,
        report=tmp_path / "unused.xml",
        fixture_error=fixture_error,
        cleanup_errors=["simulated adb reverse cleanup failure"],
    )
    args = SimpleNamespace(
        desktop_only=False,
        jvm_only=False,
        android_only=True,
        peer_backend="process",
        fixture_timeout=60.0,
        registry_repo=tmp_path,
        serial="emulator-5554",
    )
    monkeypatch.setattr(HARNESS, "parse_args", lambda: args)
    monkeypatch.setattr(
        HARNESS, "run_jvm_registry_interop", lambda *_args, **_kwargs: 0
    )

    def run_android_with_fixture_failure(*_args: object, **_kwargs: object) -> int:
        HARNESS.run_versioned_android_runtime(
            tmp_path,
            60.0,
            adb=Path("/sdk/platform-tools/adb"),
            serial="emulator-5554",
            expected_target=("Medium_Phone", 26, "x86"),
            peer_backend="process",
        )
        return 0

    monkeypatch.setattr(
        HARNESS, "run_android_runtime", run_android_with_fixture_failure
    )
    stderr = io.StringIO()
    monkeypatch.setattr(HARNESS.sys, "stderr", stderr)

    assert HARNESS.main() == 1
    diagnostic = stderr.getvalue()
    assert "simulated Registry fixture failure" in diagnostic
    assert "simulated adb reverse cleanup failure" in diagnostic


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


def test_parse_args_accepts_podman_peer_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        HARNESS.sys,
        "argv",
        [
            "run_issue18_registry_acceptance.py",
            "--jvm-only",
            "--peer-backend",
            "podman",
        ],
    )

    args = HARNESS.parse_args()

    assert args.peer_backend == "podman"


def test_fixture_error_message_redacts_unrecognized_details() -> None:
    assert (
        HARNESS.safe_fixture_error_message(
            "Registry peer did not become ready before the startup deadline"
        )
        == "Registry peer did not become ready before the startup deadline"
    )
    assert (
        HARNESS.safe_fixture_error_message(
            "Registry peer readiness failed (bootstrap_records=0, address_error=bootstrap_count, tcp_ready=true)"
        )
        == "Registry peer readiness failed (bootstrap_records=0, address_error=bootstrap_count, tcp_ready=true)"
    )
    assert (
        HARNESS.safe_fixture_error_message(
            "Registry peer publication failed (error=ValueError)"
        )
        == "Registry peer publication failed (error=ValueError)"
    )
    assert (
        HARNESS.safe_fixture_error_message(
            "could not seed or confirm the synthetic Registry record (error=ValueError)"
        )
        == "could not seed or confirm the synthetic Registry record (error=ValueError)"
    )
    assert HARNESS.safe_fixture_error_message(
        "could not seed or confirm the synthetic Registry record "
        "(error=RuntimeError; detail=no tcp addr)"
    ) == (
        "could not seed or confirm the synthetic Registry record "
        "(error=RuntimeError; detail=no tcp addr)"
    )
    assert (
        HARNESS.safe_fixture_error_message(
            "Registry peer seed failed (error=RuntimeError; detail=no tcp addr)"
        )
        == "Registry peer seed failed (error=RuntimeError; detail=no tcp addr)"
    )
    assert (
        HARNESS.safe_fixture_error_message(
            "/home/ben/.hermes/cache/scratch/node_privkey.bin"
        )
        == "Registry peer fixture failed"
    )


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

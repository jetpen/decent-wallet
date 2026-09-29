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

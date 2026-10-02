from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from issue18_remote_registry import parse_remote_peer_address

spec = importlib.util.spec_from_file_location(
    "lan_host_acceptance", ROOT / "scripts/run_issue18_lan_host_acceptance.py"
)
assert spec and spec.loader
harness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(harness)


def test_gateway_address_preserves_real_remote_pinned_peer_id() -> None:
    peer = parse_remote_peer_address("/ip4/100.64.1.2/tcp/19001/p2p/" + "1" * 32)
    assert (
        harness.emulator_peer_address(peer, 19002)
        == "/ip4/10.0.2.2/tcp/19002/p2p/" + "1" * 32
    )


@pytest.mark.parametrize("port", [0, -1, 65536, True])
def test_gateway_address_rejects_invalid_forward_port(port: int) -> None:
    peer = parse_remote_peer_address("/ip4/100.64.1.2/tcp/19001/p2p/" + "1" * 32)
    with pytest.raises(ValueError):
        harness.emulator_peer_address(peer, port)


def test_instrumentation_success_requires_exact_executed_case() -> None:
    harness.verify_instrumentation(instrumentation_report())


def instrumentation_report() -> str:
    klass, method = harness.TEST.split("#")
    return "".join(
        f"INSTRUMENTATION_STATUS: class={klass}\n"
        "INSTRUMENTATION_STATUS: current=1\n"
        "INSTRUMENTATION_STATUS: numtests=1\n"
        f"INSTRUMENTATION_STATUS: test={method}\n"
        f"INSTRUMENTATION_STATUS_CODE: {code}\n"
        for code in (1, 0)
    ) + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n"


@pytest.mark.parametrize("mutation", ["class", "method", "count", "missing", "duplicate", "no-start", "duplicate-field"])
def test_instrumentation_rejects_wrong_identity_count_or_duplicate(mutation: str) -> None:
    report = instrumentation_report()
    if mutation == "class":
        report = report.replace("LanPermissionRuntimeTest", "OtherTest")
    elif mutation == "method":
        report = report.replace(harness.TEST.split("#")[1], "otherMethod")
    elif mutation == "count":
        report = report.replace("numtests=1", "numtests=2")
    elif mutation == "missing":
        report = report.replace("INSTRUMENTATION_STATUS: numtests=1\n", "")
    elif mutation == "duplicate":
        report = report + instrumentation_report()
    elif mutation == "no-start":
        report = report.replace("INSTRUMENTATION_STATUS_CODE: 1", "INSTRUMENTATION_STATUS_CODE: 0")
    else:
        report = report.replace("INSTRUMENTATION_STATUS: current=1", "INSTRUMENTATION_STATUS: current=1\nINSTRUMENTATION_STATUS: current=1")
    with pytest.raises(RuntimeError):
        harness.verify_instrumentation(report)


@pytest.mark.parametrize(
    "text",
    [
        "",
        "OK (1 test)",
        "INSTRUMENTATION_STATUS_CODE: -3\nOK (1 test)\nINSTRUMENTATION_CODE: -1",
        "INSTRUMENTATION_STATUS_CODE: -2\nFAILURES!!!\nINSTRUMENTATION_CODE: -1",
    ],
)
def test_instrumentation_rejects_empty_missing_skipped_or_failed_case(
    text: str,
) -> None:
    with pytest.raises(RuntimeError):
        harness.verify_instrumentation(text)


@pytest.mark.parametrize("fault", ["uninstall", "remains", "throws", "phase-and-cleanup", "none"])
def test_acceptance_verifies_both_package_cleanups_before_success(monkeypatch, tmp_path, fault):
    import json
    import subprocess
    from contextlib import nullcontext
    from types import SimpleNamespace

    # Cleanup behavior is a unit boundary: never consume local Android build output.
    repository = tmp_path / "isolated-repository"
    monkeypatch.setattr(harness, "ROOT", repository)
    monkeypatch.setattr(harness, "source_files", list)
    for relative in (
        "interop/android-lan-host/build/outputs/apk/debug/android-lan-host-debug.apk",
        "interop/android-lan-host/build/outputs/apk/androidTest/debug/android-lan-host-debug-androidTest.apk",
    ):
        apk = repository / relative
        apk.parent.mkdir(parents=True, exist_ok=True)
        apk.write_bytes(b"unit-only opaque hash fixture; not an executable APK")
    peer = parse_remote_peer_address("/ip4/100.64.1.2/tcp/19001/p2p/" + "1" * 32)
    fixture = SimpleNamespace(registry_revision="test", remote_root=Path("/test"), writer=peer, readback=peer)
    monkeypatch.setattr(harness, "adb_path", lambda: Path("adb"))
    monkeypatch.setattr(harness, "select_single_emulator", lambda *args: None)
    monkeypatch.setattr(harness, "verify_android_target", lambda *args: ("test", 26, "x86"))
    monkeypatch.setattr(harness, "RemoteRegistryPeerFixture", lambda *args, **kwargs: nullcontext(fixture))
    monkeypatch.setattr(harness, "gateway_forwards", lambda *args: nullcontext((["writer", "reader"], ["ssh"])))
    monkeypatch.setattr(harness.subprocess, "check_output", lambda *args, **kwargs: b"test diff")
    calls = []

    def subprocess_run(command, **kwargs):
        calls.append(command)
        if "instrument" in command:
            if fault == "phase-and-cleanup":
                raise RuntimeError("original phase failure")
            return subprocess.CompletedProcess(command, 0, instrumentation_report(), "")
        if "uninstall" in command and command[-1] == harness.PACKAGE + ".test":
            if fault in {"throws", "phase-and-cleanup"}:
                raise subprocess.TimeoutExpired(command, 30, output="timed out raw", stderr="cleanup stderr")
            if fault == "uninstall":
                return subprocess.CompletedProcess(command, 1, "Failure [DELETE_FAILED]", "cleanup stderr")
        if command[-3:-1] == ["list", "packages"]:
            return subprocess.CompletedProcess(command, 0, ("package:" + harness.PACKAGE + ".test\n") if fault == "remains" else "", "")
        return subprocess.CompletedProcess(command, 0, "Success\n", "")

    monkeypatch.setattr(harness.subprocess, "run", subprocess_run)
    tmp_path = tmp_path / "fresh-output"
    if fault == "none":
        harness.run_acceptance(host="test", serial="test", output=tmp_path)
        assert json.loads((tmp_path / "result.json").read_text())["app_cleanup_verified"]
    else:
        with pytest.raises(RuntimeError, match="original phase failure" if fault == "phase-and-cleanup" else "cleanup"):
            harness.run_acceptance(host="test", serial="test", output=tmp_path)
        assert not (tmp_path / "result.json").exists()
    assert [cmd[-1] for cmd in calls if "uninstall" in cmd] == [harness.PACKAGE + ".test", harness.PACKAGE]
    assert [cmd[-1] for cmd in calls if cmd[-3:-1] == ["list", "packages"]] == [harness.PACKAGE + ".test", harness.PACKAGE]
    cleanup = json.loads((tmp_path / "app-cleanup.json").read_text())
    assert len(cleanup["packages"]) == 2
    if fault == "uninstall":
        assert cleanup["packages"][0]["uninstall"]["stdout"] == "Failure [DELETE_FAILED]"
    if fault == "throws":
        assert "timed out raw" in cleanup["packages"][0]["uninstall"]["stdout"]


def test_source_snapshot_captures_all_consumed_build_sources_and_packaged_assets(monkeypatch, tmp_path):
    files = {str(path.relative_to(ROOT)) for path in harness.source_files()}
    required = {
        "platforms/android-wallet/build.gradle.kts", "platforms/android-wallet/gradle.lockfile",
        "scripts/run_issue18_registry_acceptance.py", "pyproject.toml", "gradle.properties",
        "gradle/wrapper/gradle-wrapper.properties", "gradle/wrapper/gradle-wrapper.jar", "gradlew",
        "interop/kotlin/src/test/kotlin/org/decentwallet/interop/WalletContainerV2Verifier.kt",
        "interop/kotlin/src/test/kotlin/org/decentwallet/interop/WireJson.kt",
    }
    required.update(str(path.relative_to(ROOT)) for path in (ROOT / "tests/vectors").rglob("*") if path.is_file())
    required.update(str(path.relative_to(ROOT)) for path in (ROOT / "platforms/android-wallet/src").rglob("*") if path.is_file())
    required.update(str(path.relative_to(ROOT)) for path in (ROOT / "src").rglob("*.py"))
    assert required <= files
    assert not any("build" in Path(path).parts or "target" in Path(path).parts or "__pycache__" in Path(path).parts for path in files)


def test_device_driver_archives_consumed_owned_helper_before_launch(tmp_path):
    import ast
    import os
    import shutil
    # Scratch archival drivers are not part of a clean checkout. Opt in explicitly.
    driver_path = os.environ.get("ISSUE18_LAN_HOST_DRIVER")
    if not driver_path:
        pytest.skip("set ISSUE18_LAN_HOST_DRIVER to verify a trusted local archival driver")
    driver = Path(driver_path).read_text()
    tree = ast.parse(driver)
    helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "archive_owned_helper"]
    assert len(helpers) == 1
    scope = {"shutil": shutil, "Path": Path, "hashlib": __import__("hashlib"), "json": __import__("json")}
    exec(compile(ast.Module(body=list(helpers), type_ignores=[]), "driver", "exec"), scope)  # noqa: S102 - Extract trusted local driver helper without launching devices.
    source = tmp_path / "original.py"
    source.write_text("def run_owned_matrix(): pass\n")
    output = tmp_path / "archive"
    output.mkdir()
    captured = scope["archive_owned_helper"](source, output)
    assert captured.read_bytes() == source.read_bytes()
    assert driver.index("archive_owned_helper(source, out)") < driver.index("assert len(run([adb, 'devices'])")
    assert "ast.parse(captured_helper.read_text())" in driver

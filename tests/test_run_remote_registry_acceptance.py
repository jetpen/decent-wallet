from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
REMOTE_PATH = ROOT / "scripts" / "remote_registry_fixture.py"
REMOTE_SPEC = importlib.util.spec_from_file_location("remote_registry_fixture", REMOTE_PATH)
assert REMOTE_SPEC is not None and REMOTE_SPEC.loader is not None
REMOTE = importlib.util.module_from_spec(REMOTE_SPEC)
sys.modules[REMOTE_SPEC.name] = REMOTE
REMOTE_SPEC.loader.exec_module(REMOTE)

MODULE_PATH = ROOT / "scripts" / "run_remote_registry_acceptance.py"
SPEC = importlib.util.spec_from_file_location("run_remote_registry_acceptance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


def test_test_environment_discovers_a_default_android_sdk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ANDROID_HOME", raising=False)
    monkeypatch.delenv("ANDROID_SDK_ROOT", raising=False)

    environment = RUNNER._test_environment(
        "writer",
        "readback",
        sdk_default=tmp_path,
    )

    assert environment["ANDROID_HOME"] == str(tmp_path)
    assert environment["ANDROID_SDK_ROOT"] == str(tmp_path)


def test_android_command_targets_the_nested_gradle_project() -> None:
    command = RUNNER.android_test_command()

    assert ":platforms:android-wallet:testDebugUnitTest" in command

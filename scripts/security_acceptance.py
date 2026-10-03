#!/usr/bin/env python3
"""Run wallet security acceptance and write a values-free receipt."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NoReturn

ROOT = Path(__file__).resolve().parents[1]
RECEIPT_SCHEMA = "decent-wallet-security-acceptance-receipt-v1"
ANDROID_RESULTS = ROOT / "platforms/android-wallet/build/test-results/testDebugUnitTest"
ANDROID_COMMAND = [
    "./gradlew", "--no-daemon", "--dependency-verification=strict",
    ":platforms:android-wallet:testDebugUnitTest", "--rerun-tasks",
]
ARTIFACT_ENV = "PORTABLE_LATCH_ARTIFACT_DIR"
ANDROID_OPTIONAL_SKIPS = frozenset(
    {
        "org.decentwallet.wallet.android.AndroidDirectDhtRegistryInteropTest::readsHistoryPublishesAndFreshReadsAgainstPythonRegistryPeer",
    }
)
ANDROID_OPTIONAL_RECEIPT_TRANSITIONS = {
    f"optional-live-peer-case-{status}-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
    for name in ANDROID_OPTIONAL_SKIPS
    for status in ("passed", "skipped")
}
OPTIONAL_SKIPS = frozenset(
    {
        "tests.test_android_lan_host_harness::test_device_driver_archives_consumed_owned_helper_before_launch",
        "tests.test_portable_latch::test_actual_kotlin_authored_ciphertext_through_python_public_reader[kotlin-bound.dw-False]",
        "tests.test_portable_latch::test_actual_kotlin_authored_ciphertext_through_python_public_reader[kotlin-legacy.dw-True]",
        "tests.test_portable_latch::test_large_positive_integer_real_encrypted_public_readers[kotlin]",
    }
)
OPTIONAL_PASSED_CASES = frozenset(
    {"tests.test_portable_latch::test_concrete_transport_has_explicit_environment_configuration"}
)
PYTHON_OPTIONAL_CASES = OPTIONAL_SKIPS | OPTIONAL_PASSED_CASES

_OPTIONAL_CASE_STATES = {
    f"optional-case-{status}-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
    for name in PYTHON_OPTIONAL_CASES
    for status in (("skipped",) if name in OPTIONAL_SKIPS else ("passed",))
}
ANDROID_OPTIONAL_RECEIPT_TRANSITIONS = {
    f"optional-live-peer-case-{status}-" + hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
    for name in ANDROID_OPTIONAL_SKIPS
    for status in ("passed", "skipped")
}
CORE_RECEIPT_TRANSITIONS = {
    "mandatory-cases-passed",
    *_OPTIONAL_CASE_STATES,
}

VECTORS = (
    "tests/vectors/wallet-container-v2.json",
    "tests/vectors/identity-owner-key-rotation-legacy.json",
    "tests/vectors/identity-owner-key-rotation-versioned-history.json",
    "tests/vectors/wallet-v2-portable-rotation-latch.json",
)


class ReceiptValidationError(ValueError):
    """A report or receipt does not satisfy the acceptance contract."""


@dataclass(frozen=True)
class SuiteResult:
    tests: int
    failures: int
    errors: int
    skipped: int


def _fail(message: str) -> NoReturn:
    # Keep diagnostics to fixed, non-sensitive descriptions. Never include
    # subprocess output, arguments, exception values, paths, or test data.
    raise ReceiptValidationError(message)


def _exact_keys(value: Any, expected: set[str], field: str) -> dict[str, Any]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        _fail(f"{field} must be an object")
    if set(value) - expected:
        _fail(f"{field} contains an unapproved field")
    if expected - set(value):
        _fail(f"{field} is missing a required field")
    return value


def _is_digest(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def validate_receipt(value: Any) -> dict[str, Any]:
    """Validate strict receipt fields, profile suites, skips, and artifacts."""
    receipt = _exact_keys(
        value,
        {"schema", "created_at", "profile", "verdict", "commit", "environment", "suites", "artifacts"},
        "receipt",
    )
    if receipt["schema"] != RECEIPT_SCHEMA:
        _fail("receipt schema is unsupported")
    if not isinstance(receipt["created_at"], str):
        _fail("receipt timestamp is invalid")
    try:
        timestamp = datetime.fromisoformat(receipt["created_at"].replace("Z", "+00:00"))
    except ValueError:
        _fail("receipt timestamp is invalid")
    if timestamp.tzinfo is None:
        _fail("receipt timestamp requires a timezone")
    profile = receipt["profile"]
    if profile not in {"core", "android-jvm", "full"}:
        _fail("receipt profile is invalid")
    if receipt["verdict"] != "passed":
        _fail("receipt verdict is not passing")
    if not isinstance(receipt["commit"], str) or re.fullmatch(r"[0-9a-f]{40}", receipt["commit"]) is None:
        _fail("receipt commit identifier is invalid")

    environment = _exact_keys(
        receipt["environment"],
        {"python", "platform", "implementation", "android_test_artifacts"},
        "environment",
    )
    if not isinstance(environment["python"], str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[A-Za-z0-9.+-]*)?", environment["python"]):
        _fail("receipt Python version metadata is invalid")
    if not isinstance(environment["platform"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", environment["platform"]):
        _fail("receipt platform metadata is invalid")
    if not isinstance(environment["implementation"], str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", environment["implementation"]):
        _fail("receipt implementation metadata is invalid")
    if not isinstance(environment["android_test_artifacts"], bool):
        _fail("receipt Android-artifact metadata is invalid")
    if environment["android_test_artifacts"] != (profile != "core"):
        _fail("receipt Android-artifact metadata disagrees with its profile")

    raw_suites = receipt["suites"]
    if not isinstance(raw_suites, list) or not raw_suites:
        _fail("receipt contains no test suites")
    suite_ids: set[str] = set()
    suite_transitions: dict[str, set[str]] = {}
    for index, raw_suite in enumerate(raw_suites):
        suite = _exact_keys(
            raw_suite,
            {"id", "status", "tests", "failures", "errors", "skipped", "state_transitions"},
            f"suite[{index}]",
        )
        suite_id = suite["id"]
        if not isinstance(suite_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", suite_id) is None:
            _fail(f"suite[{index}] identifier is invalid")
        if suite_id in suite_ids:
            _fail("receipt contains duplicate suite identifiers")
        suite_ids.add(suite_id)
        transitions = suite["state_transitions"]
        if not isinstance(transitions, list) or not transitions or any(
            not isinstance(state, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", state) is None
            for state in transitions
        ) or len(set(transitions)) != len(transitions):
            _fail(f"suite[{index}] state transitions are invalid")
        transition_set = set(transitions)
        suite_transitions[suite_id] = transition_set
        counts = []
        for key in ("tests", "failures", "errors", "skipped"):
            number = suite[key]
            if isinstance(number, bool) or not isinstance(number, int) or number < 0:
                _fail(f"suite[{index}] counts are invalid")
            counts.append(number)
        tests, failures, errors, skipped = counts
        if tests < 1 or failures + errors + skipped > tests:
            _fail(f"suite[{index}] counts are inconsistent")
        optional_skip_allowed = (
            suite_id == "android-wallet-jvm-security"
            and skipped == 1
            and any(state.startswith("optional-live-peer-case-skipped-") for state in transitions)
        )
        if suite["status"] != "passed" or failures or errors or (skipped and not optional_skip_allowed):
            _fail(f"suite[{index}] did not pass without unapproved skips")
        if suite_id == "android-wallet-jvm-security":
            optional_identity = next(iter(ANDROID_OPTIONAL_SKIPS))
            digest = hashlib.sha256(optional_identity.encode("utf-8")).hexdigest()[:12]
            optional_outcomes = {
                f"optional-live-peer-case-passed-{digest}",
                f"optional-live-peer-case-skipped-{digest}",
            }
            if len(transitions) != 2 or len(transition_set & optional_outcomes) != 1:
                _fail("Android receipt has an invalid optional-case transition")
            optional_is_skipped = f"optional-live-peer-case-skipped-{digest}" in transition_set
            if skipped != int(optional_is_skipped):
                _fail("Android receipt skip count disagrees with its transition")

        if suite_id == "python-security-matrix":
            expected = {
                hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]: name
                for name in PYTHON_OPTIONAL_CASES
            }
            optional_always_skippable = OPTIONAL_SKIPS
            mandatory_inventory = OPTIONAL_SKIPS
            if "mandatory-cases-passed" not in transition_set:
                _fail("Python receipt is missing the mandatory-pass transition")
            disclosed = {
                match.group(2): match.group(1)
                for state in transition_set
                if (match := re.fullmatch(r"optional-case-(passed|skipped)-([0-9a-f]{12})", state))
            }
            if (
                transition_set - {"mandatory-cases-passed"} != {
                    f"optional-case-{status}-{digest}" for digest, status in disclosed.items()
                }
                or set(disclosed) != set(expected)
            ):
                _fail("Python receipt has unexpected optional-case transitions")
            if any(disclosed[digest] == "passed" and name in mandatory_inventory for digest, name in expected.items()):
                _fail("Python receipt optional-case status is inconsistent")
            if any(disclosed[digest] == "skipped" and name not in optional_always_skippable for digest, name in expected.items()):
                _fail("Python receipt optional-case status is inconsistent")

            if skipped != 0:
                _fail("Python receipt suite counts may not include accepted optional skips")
            if suite["tests"] < 1:
                _fail("Python receipt mandatory-case count is invalid")
        elif suite_id == "android-wallet-jvm-security":
            if "android-jvm-cases-passed" not in transition_set:
                _fail("Android receipt is missing the mandatory-pass transition")
            optional_name = next(iter(ANDROID_OPTIONAL_SKIPS))
            digest = hashlib.sha256(optional_name.encode("utf-8")).hexdigest()[:12]
            outcomes = transition_set & {
                f"optional-live-peer-case-passed-{digest}",
                f"optional-live-peer-case-skipped-{digest}",
            }
            if len(transition_set) != 2 or any(
                state != "android-jvm-cases-passed" and state not in outcomes
                for state in transition_set
            ) or len(outcomes) != 1 or skipped != int(f"optional-live-peer-case-skipped-{digest}" in outcomes) or suite["tests"] < 1:
                _fail("Android receipt live-peer disclosure or mandatory-case counts are invalid")
        elif suite_id == "local-registry-integration":
            if skipped:
                _fail("Registry integration suite skipped a mandatory test")
            if transition_set != {"mandatory-cases-passed", "receipt-emitted"}:
                _fail("Registry receipt has unexpected state transitions")
        else:
            _fail("receipt contains an unrecognized test suite")

    required_suites = {
        "core": {"python-security-matrix"},
        "android-jvm": {"android-wallet-jvm-security"},
        "full": {"python-security-matrix", "android-wallet-jvm-security", "local-registry-integration"},
    }[profile]
    if suite_ids != required_suites:
        _fail("receipt suite set does not match the selected profile")

    raw_artifacts = receipt["artifacts"]
    if not isinstance(raw_artifacts, list):
        _fail("receipt artifacts must be a list")
    artifact_ids: set[str] = set()
    for index, raw_artifact in enumerate(raw_artifacts):
        artifact = _exact_keys(raw_artifact, {"id", "sha256"}, f"artifact[{index}]")
        artifact_id = artifact["id"]
        if not isinstance(artifact_id, str) or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", artifact_id) is None:
            _fail(f"artifact[{index}] identifier is invalid")
        if not _is_digest(artifact["sha256"]):
            _fail(f"artifact[{index}] digest is invalid")
        if artifact_id in artifact_ids:
            _fail("receipt has duplicate artifact identifiers")
        artifact_ids.add(artifact_id)


    required_artifacts = {
        "core": {"wallet-container-known-answer"},
        "android-jvm": {"kotlin-bound", "kotlin-legacy", "kotlin-bignum"},
        "full": {"wallet-container-known-answer", "kotlin-bound", "kotlin-legacy", "kotlin-bignum"},
    }[profile]
    allowed_artifacts = required_artifacts | {
        "identity-owner-key-rotation-legacy-candidate-envelope",
        "identity-owner-key-rotation-versioned-history-candidate-envelope",
    }
    if profile == "android-jvm":
        allowed_artifacts.add("wallet-container-known-answer")
    if not required_artifacts <= artifact_ids or artifact_ids - allowed_artifacts:
        _fail("receipt artifact set does not match the selected profile")
    return receipt


def junit_result(report_paths: list[Path]) -> SuiteResult:
    """Aggregate JUnit reports; missing, malformed, failed, or skipped blocks."""
    if not report_paths:
        _fail("mandatory test report is missing")
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for path in report_paths:
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            _fail("mandatory test report is unreadable")
        if root.tag not in {"testsuite", "testsuites"}:
            _fail("mandatory test report has an unexpected format")
        test_suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
        if not test_suites:
            _fail("mandatory test report contains no suites")
        for suite in test_suites:
            for key in totals:
                try:
                    count = int(suite.attrib.get(key, "0"))
                except ValueError:
                    _fail("mandatory test report has invalid counts")
                if count < 0:
                    _fail("mandatory test report has invalid counts")
                totals[key] += count
    result = SuiteResult(**totals)
    if result.tests <= 0:
        _fail("mandatory test report contains no tests")
    if result.failures or result.errors or result.skipped:
        _fail("mandatory suite failed or skipped a test")
    return result


def _junit_cases(report_paths: list[Path]) -> list[tuple[str, str, str]]:
    if not report_paths:
        _fail("mandatory test report is missing")
    cases = []
    for path in report_paths:
        try:
            root = ET.parse(path).getroot()
        except (OSError, ET.ParseError):
            _fail("mandatory test report is unreadable")
        if root.tag not in {"testsuite", "testsuites"}:
            _fail("mandatory test report has an unexpected format")
        for case in root.iter("testcase"):
            skipped = case.find("skipped")
            failed = case.find("failure") is not None or case.find("error") is not None
            name = f"{case.attrib.get('classname', '')}::{case.attrib.get('name', '')}"
            status = "skipped" if skipped is not None else "failed" if failed else "passed"
            reason = skipped.attrib.get("message", "") if skipped is not None else ""
            cases.append((name, status, reason))
    if not cases:
        _fail("mandatory test report contains no cases")
    return cases


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError:
        _fail("required acceptance artifact is unreadable")
    return digest.hexdigest()


def _suite(suite_id: str, reports: list[Path], cases: list[tuple[str, str, str]]) -> dict[str, Any]:
    result = junit_result(reports)
    if result.tests != len(cases):
        _fail("mandatory report summary is inconsistent")
    return {
        "id": suite_id,
        "status": "passed",
        **asdict(result),
        "state_transitions": ["mandatory-cases-passed", "receipt-emitted"],
    }


def _run(command: list[str], *, env: dict[str, str], timeout: int) -> None:
    actual_command = list(command)
    if actual_command and actual_command[0] == "./gradlew":
        actual_command[0] = str(ROOT / "gradlew")
    try:
        result = subprocess.run(
            actual_command,
            cwd=ROOT,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("mandatory acceptance command could not complete")
    if result.returncode:
        if actual_command and "gradlew" in actual_command[0]:
            print("Android Gradle acceptance task failed.", file=sys.stderr, flush=True)
        else:
            print("Python acceptance test command failed.", file=sys.stderr, flush=True)
        _fail("mandatory acceptance command failed")


def _test_only_artifacts(*, include_identity_vectors: bool = True) -> list[dict[str, str]]:
    artifacts: list[dict[str, str]] = []
    for relative in VECTORS:
        path = ROOT / relative
        try:
            fixture = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            _fail("required public test vector is missing or unreadable")
        if not isinstance(fixture, dict):
            _fail("required public test vector is malformed")
        if path.name == "wallet-container-v2.json":
            notice = fixture.get("notice")
            if fixture.get("test_only") is not True or not isinstance(notice, str) or "Never use with a real wallet" not in notice:
                _fail("wallet-container vector is not marked synthetic test-only")
            artifacts.append({"id": "wallet-container-known-answer", "sha256": _hash_file(path)})
        elif path.name == "wallet-v2-portable-rotation-latch.json":
            if fixture.get("identity_vector") != "identity-owner-key-rotation-legacy.json":
                _fail("portable-latch vector references an unexpected Identity vector")
            for field in ("python_bound_container_base64", "legacy_unbound_container_base64", "python_bignum_container_base64"):
                try:
                    base64.b64decode(fixture[field], validate=True)
                except (KeyError, TypeError, ValueError, binascii.Error):
                    _fail("portable-latch vector is malformed")
        else:
            if not include_identity_vectors:
                continue
            try:
                raw = bytes.fromhex(fixture["candidate_envelope_cbor_hex"])
            except (KeyError, TypeError, ValueError):
                _fail("Identity candidate vector is malformed")
            artifacts.append({
                "id": f"{Path(relative).stem.replace('_', '-')}-candidate-envelope",
                "sha256": hashlib.sha256(raw).hexdigest(),
            })
    return artifacts


def _pinned_provider_path() -> Path:
    provider = Path(os.environ.get("DECENT_REGISTRY_PATH", ROOT.parent / "decent-registry"))
    if not provider.is_absolute():
        provider = (ROOT / provider).resolve()
    lock_path = ROOT / "uv.lock"
    try:
        lock_data = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        _fail("locked Registry revision could not be verified")
    registry_package = next(
        (package for package in lock_data.get("package", []) if package.get("name") == "decent-registry"),
        None,
    )
    source = registry_package.get("source", {}) if isinstance(registry_package, dict) else {}
    revision = source.get("rev") or source.get("git", "").rsplit("#", 1)[-1]
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
        _fail("uv.lock does not pin a valid Registry revision")
    if not (provider / "pyproject.toml").is_file():
        _fail("full profile requires the pinned local Registry checkout")
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=provider, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=10, text=True,
        )
        status = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"], cwd=provider,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            check=False, timeout=10, text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("local Registry revision could not be identified")
    if result.returncode or result.stdout.strip() != revision or status.returncode or status.stdout.strip():
        _fail("local Registry checkout does not match the uv.lock revision")
    return provider


def _commit() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=10, text=True,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("source revision could not be identified")
    value = result.stdout.strip()
    if result.returncode or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        _fail("source revision could not be identified")
    return value


def _runtime_metadata(android: bool) -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(terse=True)[:160],
        "implementation": platform.python_implementation(),
        "android_test_artifacts": android,
    }


def _python_profile(python: str, env: dict[str, str], report: Path) -> tuple[dict[str, Any], list[str]]:
    # These Registry integration modules are deliberately exercised by the
    # separate pinned-provider profile. Avoid collection-time import skips in
    # core-only installs; pytest must still report skips inside included modules.
    registry_module_exclusions = {
        "test_android_registry_peer.py",
        "test_podman_registry_deployment.py",
        "test_remote_registry_acceptance.py",
    }
    test_files = sorted(
        str(path.relative_to(ROOT))
        for path in (ROOT / "tests").glob("test_*.py")
        if path.name not in registry_module_exclusions
    )
    test_env = dict(env)
    test_env.pop("PYTEST_ADDOPTS", None)
    _run(
        [python, "-m", "pytest", "-q", "--junitxml", str(report), *test_files],
        env=test_env,
        timeout=1800,
    )
    cases = _junit_cases([report])
    skipped_cases = {name for name, status, _reason in cases if status == "skipped"}
    skipped_mandatory = skipped_cases - OPTIONAL_SKIPS - OPTIONAL_PASSED_CASES
    if skipped_mandatory:
        _fail("Python suite skipped an unapproved mandatory case")
    collected = {name for name, _status, _reason in cases}
    if not PYTHON_OPTIONAL_CASES <= collected:
        _fail("an approved environmental test was not collected")
    failure_cases = {name for name, status, _reason in cases if status == "failed"}
    if failure_cases:
        _fail("Python suite reported a failed mandatory case")
    unexpected_skipped_nodes = {
        name for name, _status, reason in cases
        if "deselected" in reason.lower() or "not run" in reason.lower()
    }
    if unexpected_skipped_nodes:
        _fail("Python suite reported unapproved deselection metadata")
    mandatory_passing = [
        (name, status, reason)
        for name, status, reason in cases
        if status == "passed" and name not in PYTHON_OPTIONAL_CASES
    ]
    transitions = ["mandatory-cases-passed"]
    skipped_cases_set = set(skipped_cases)
    for name in sorted(PYTHON_OPTIONAL_CASES):
        digest = hashlib.sha256(name.encode("utf-8")).hexdigest()[:12]
        status = "skipped" if name in skipped_cases_set else "passed"
        transitions.append(f"optional-case-{status}-{digest}")
    passed_summary = {
        "id": "python-security-matrix",
        "status": "passed",
        "tests": len(mandatory_passing),
        "failures": len(failure_cases),
        "errors": 0,
        "skipped": 0,
        "state_transitions": transitions,
    }
    return passed_summary, sorted(skipped_cases)


def _android_profile(gradle: str, env: dict[str, str], scratch: Path) -> tuple[dict[str, Any], list[dict[str, str]]]:
    if not (ROOT / "gradlew").is_file():
        _fail("Gradle Wrapper is required for Android JVM acceptance")
    artifacts_dir = scratch / "kotlin-artifacts"
    artifacts_dir.mkdir(parents=True)
    result_dir = ANDROID_RESULTS
    result_dir.mkdir(parents=True, exist_ok=True)
    for old_report in result_dir.glob("TEST-*.xml"):
        old_report.unlink()
    for expected in ANDROID_OPTIONAL_SKIPS:
        if expected.split("::", 1)[0] != "org.decentwallet.wallet.android.AndroidDirectDhtRegistryInteropTest":
            _fail("Android optional-case allowlist is invalid")
    command = list(ANDROID_COMMAND)
    if gradle != str(ROOT / "gradlew"):
        command[0] = gradle
    _run(
        command,
        env={**env, ARTIFACT_ENV: str(artifacts_dir)},
        timeout=1800,
    )
    reports = sorted(result_dir.glob("TEST-*.xml"))
    cases = _junit_cases(reports)
    failed_cases = [name for name, status, _reason in cases if status == "failed"]
    if failed_cases:
        _fail("Android JVM suite reported a failed mandatory test")
    expected = ANDROID_OPTIONAL_SKIPS
    actual_skips = {name for name, status, _reason in cases if status == "skipped"}
    if actual_skips - expected:
        _fail("Android JVM suite skipped an unapproved mandatory case")
    case_ids = {name for name, _status, _reason in cases}
    if expected - case_ids:
        _fail("Android live-peer optional case was not collected")
    optional_case = next(
        (
            (name, status)
            for name, status, _ in cases
            if "AndroidDirectDhtRegistryInteropTest" in name
            and "readsHistoryPublishesAndFreshReadsAgainstPythonRegistryPeer" in name
        ),
        None,
    )
    if optional_case is None:
        _fail("Android peer integration case was not collected")
    if optional_case[1] == "failed":
        _fail("Android peer integration case failed")
    if optional_case[1] == "skipped" and not any(
        "AndroidDirectDhtRegistryInteropTest" in name
        and "readsHistoryPublishesAndFreshReadsAgainstPythonRegistryPeer" in name
        and status == "skipped"
        for name, status, _ in cases
    ):
        _fail("Android peer integration case did not report its environment-gated status")
    producer_cases = [case for case in cases if case[1] == "passed"]
    android_optional_name = next(iter(ANDROID_OPTIONAL_SKIPS))
    android_optional_digest = hashlib.sha256(android_optional_name.encode("utf-8")).hexdigest()[:12]
    android_optional_state = (
        "skipped" if android_optional_name in actual_skips else "passed"
    )
    suite = {
        "id": "android-wallet-jvm-security",
        "status": "passed",
        "tests": len(producer_cases),
        "failures": 0,
        "errors": 0,
        "skipped": int(android_optional_state == "skipped"),
        "state_transitions": [
            "android-jvm-cases-passed",
            f"optional-live-peer-case-{android_optional_state}-{android_optional_digest}",
        ],
    }
    artifacts = []
    producers = (
        ("kotlin-bound.dw", "actualKotlinPublicAuthoringExportsBoundAndLegacyCiphertext"),
        ("kotlin-legacy.dw", "actualKotlinPublicAuthoringExportsBoundAndLegacyCiphertext"),
        ("kotlin-bignum.dw", "largePositiveIntegerRealEncryptedPublicReadersAndWriter"),
    )
    for filename, test_name in producers:
        path = artifacts_dir / filename
        if not path.is_file() or path.stat().st_size == 0:
            _fail("Android tests did not produce a required Kotlin artifact")
        if not any("PortableLatchTest" in name and test_name in name and status == "passed" for name, status, _ in cases):
            _fail("Kotlin artifact producer test did not pass")
        artifacts.append({"id": Path(filename).stem.replace("_", "-"), "sha256": _hash_file(path)})
    return suite, artifacts


def _registry_profile(env: dict[str, str], report: Path) -> dict[str, Any]:
    provider = _pinned_provider_path()
    registry_env = dict(env)
    registry_env.pop("PYTEST_ADDOPTS", None)
    for name in ("DECENT_REGISTRY_TEST_PEER", "DECENT_REGISTRY_TEST_READBACK_PEER"):
        registry_env.pop(name, None)
    integration_jobs = (
        ("tests/test_android_registry_peer.py", None, 11),
        ("tests/test_registry_transport_integration.py", "registry_integration", 11),
        ("tests/test_portable_latch_registry_integration.py", "registry_integration", 4),
    )
    reports: list[Path] = []
    for index, (test_file, marker, expected_count) in enumerate(integration_jobs):
        report_path = report.with_name(f"{report.stem}-{index}.xml")
        test_args = ["-m", marker] if marker else []
        _run(
            [
                "uv", "run", "--locked", "--extra", "test", "--extra", "registry",
                "--with-editable", str(provider), "python", "-m", "pytest", "-q",
                "--junitxml", str(report_path), *test_args, test_file,
            ],
            env={**registry_env, "DECENT_REGISTRY_PATH": str(provider)},
            timeout=2400,
        )
        reports.append(report_path)
    cases = _junit_cases(reports)
    cases_by_file: dict[str, list[tuple[str, str, str]]] = {}
    for index, (test_file, _marker, _expected_count) in enumerate(integration_jobs):
        report_path = report.with_name(f"{report.stem}-{index}.xml")
        cases_by_file[test_file] = _junit_cases([report_path])
    if any(
        len(file_cases) != expected_count
        or any(status != "passed" for _name, status, _reason in file_cases)
        for expected_count, file_cases in zip(
            (job[2] for job in integration_jobs),
            cases_by_file.values(),
            strict=True,
        )
    ):
        _fail("Registry integration case inventory is incomplete")
    skipped = {name for name, status, _reason in cases if status == "skipped"}
    if skipped:
        _fail("Registry integration suite skipped a mandatory test")
    return _suite("local-registry-integration", reports, cases)


def run_acceptance(args: argparse.Namespace) -> dict[str, Any]:
    env = os.environ.copy()
    for name in (ARTIFACT_ENV, "DECENT_REGISTRY_TEST_PEER", "DECENT_REGISTRY_TEST_READBACK_PEER"):
        env.pop(name, None)
    for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT", "JAVA_HOME"):
        if key in os.environ:
            env[key] = os.environ[key]
    try:
        import pytest
    except ImportError:
        _fail("locked pytest dependency is required")
    profile = "android-jvm" if args.android_jvm_only else args.profile
    python = args.python or sys.executable
    if "ANDROID_HOME" in os.environ:
        env["ANDROID_HOME"] = os.environ["ANDROID_HOME"]
    if "ANDROID_SDK_ROOT" in os.environ:
        env["ANDROID_SDK_ROOT"] = os.environ["ANDROID_SDK_ROOT"]
    if "JAVA_HOME" in os.environ:
        env["JAVA_HOME"] = os.environ["JAVA_HOME"]
    artifacts = _test_only_artifacts(include_identity_vectors=profile != "core")
    if profile == "core":
        artifacts = [item for item in artifacts if item["id"] == "wallet-container-known-answer"]
    elif profile == "android-jvm":
        artifacts = [item for item in artifacts if item["id"] != "wallet-container-known-answer"]
    with tempfile.TemporaryDirectory(prefix="wallet-security-acceptance-") as directory:
        scratch = Path(directory)
        suites = []
        if profile in {"core", "full"}:
            python_suite, _optional = _python_profile(python, env, scratch / "python-security.xml")
            suites.append(python_suite)
        if profile in {"android-jvm", "full"}:
            android_suite, kotlin_artifacts = _android_profile(
                args.gradle or str(ROOT / "gradlew"), env, scratch
            )
            suites.append(android_suite)
            artifacts.extend(kotlin_artifacts)
        if profile == "full":
            # Use Kotlin artifacts authored by this run only; do not trust a
            # stale, externally configured artifact directory.
            env[ARTIFACT_ENV] = str(scratch / "kotlin-artifacts")
            registry_suite = _registry_profile(env, scratch / "registry-integration.xml")
            suites.append(registry_suite)
        metadata: dict[str, Any] = {
            "python": platform.python_version(),
            "platform": platform.platform(terse=True)[:160],
            "implementation": platform.python_implementation(),
            "android_test_artifacts": profile != "core",
        }
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "profile": profile,
            "verdict": "passed",
            "commit": _commit(),
            "environment": metadata,
            "suites": suites,
            "artifacts": artifacts,
        }
        return validate_receipt(receipt)


def write_receipt(receipt: dict[str, Any], destination: Path) -> None:
    payload = (json.dumps(validate_receipt(receipt), sort_keys=True, indent=2) + "\n").encode("utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except OSError:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        _fail("receipt could not be written safely")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("core", "android-jvm", "full"), default="core")
    parser.add_argument("--android-jvm-only", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--receipt", type=Path, default=Path("security-acceptance-receipt.json"))
    parser.add_argument("--python", help="Python interpreter for mandatory tests")
    parser.add_argument("--gradle", help="Gradle Wrapper executable for Android tests")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        receipt = run_acceptance(args)
        write_receipt(receipt, args.receipt)
    except ReceiptValidationError as exc:
        print(f"Security acceptance blocked: {exc}", file=sys.stderr)
        return 1
    print(
        f"Security acceptance passed: profile={receipt['profile']} "
        f"suites={len(receipt['suites'])} receipt_sha256={_hash_file(args.receipt)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

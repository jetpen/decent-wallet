from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


SPEC = importlib.util.spec_from_file_location(
    "security_acceptance", Path(__file__).resolve().parents[1] / "scripts/security_acceptance.py"
)
assert SPEC is not None and SPEC.loader is not None
ACCEPTANCE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ACCEPTANCE
SPEC.loader.exec_module(ACCEPTANCE)
ReceiptValidationError = ACCEPTANCE.ReceiptValidationError
SuiteResult = ACCEPTANCE.SuiteResult
junit_result = ACCEPTANCE.junit_result
validate_receipt = ACCEPTANCE.validate_receipt


def controlled_report(path: Path, identities: list[str], outcomes: dict[str, str] | None = None) -> None:
    outcomes = outcomes or {}
    counts = {key: sum(outcomes.get(name) == key for name in identities) for key in ("failure", "error", "skipped")}
    root = ET.Element("testsuite", tests=str(len(identities)), failures=str(counts["failure"]), errors=str(counts["error"]), skipped=str(counts["skipped"]))
    for identity in identities:
        classname, name = identity.split("::", 1)
        case = ET.SubElement(root, "testcase", classname=classname, name=name)
        if identity in outcomes:
            ET.SubElement(case, outcomes[identity], message="synthetic prerequisite")
    ET.ElementTree(root).write(path, encoding="unicode")


def test_python_runner_rejects_duplicate_native_case_ids(monkeypatch, tmp_path):
    identities = ["synthetic::mandatory", "synthetic::mandatory", *sorted(ACCEPTANCE.PYTHON_OPTIONAL_CASES)]
    def run(command, *, env, timeout):
        controlled_report(Path(command[command.index("--junitxml") + 1]), identities)
    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    with pytest.raises(ReceiptValidationError, match="duplicate"):
        ACCEPTANCE._python_profile("python", {}, tmp_path / "report.xml")


@pytest.mark.parametrize("corruption", ["aggregate-failure", "aggregate-error", "aggregate-skip", "aggregate-tests", "skip-and-failure", "skip-and-error", "repeated-outcome", "wrapper-count", "missing-count", "missing-identity"])
def test_python_runner_rejects_inconsistent_native_results(monkeypatch, tmp_path, corruption):
    identities = ["synthetic::mandatory", *sorted(ACCEPTANCE.PYTHON_OPTIONAL_CASES)]
    def run(command, *, env, timeout):
        report = Path(command[command.index("--junitxml") + 1])
        controlled_report(report, identities)
        root = ET.parse(report).getroot()
        if corruption.startswith("aggregate-"):
            key = {"failure": "failures", "error": "errors", "skip": "skipped", "tests": "tests"}[corruption.removeprefix("aggregate-")]
            root.set(key, str(int(root.attrib[key]) + 1))
        elif corruption == "missing-count":
            del root.attrib["tests"]
        elif corruption == "missing-identity":
            del root[0].attrib["name"]
        elif corruption == "wrapper-count":
            wrapper = ET.Element("testsuites", tests="999", failures="0", errors="0", skipped="0")
            wrapper.append(root)
            root = wrapper
        else:
            optional_case = list(root)[1]
            ET.SubElement(optional_case, "skipped")
            ET.SubElement(optional_case, "failure" if corruption == "skip-and-failure" else "error" if corruption == "skip-and-error" else "skipped")
            root.set("skipped", "1")
        ET.ElementTree(root).write(report, encoding="unicode")
    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    monkeypatch.setattr(ACCEPTANCE, "_expected_inventory", lambda suite_id, test_file=None: frozenset({"synthetic::mandatory"}))
    with pytest.raises(ReceiptValidationError):
        ACCEPTANCE._python_profile("python", {}, tmp_path / "report.xml")


def test_python_runner_rejects_truncated_reviewed_inventory(monkeypatch, tmp_path):
    def run(command, *, env, timeout):
        mandatory = sorted(ACCEPTANCE._expected_inventory("python-security-matrix"))
        controlled_report(Path(command[command.index("--junitxml") + 1]), [*mandatory[:-1], *sorted(ACCEPTANCE.PYTHON_OPTIONAL_CASES)])
    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    with pytest.raises(ReceiptValidationError, match="inventory"):
        ACCEPTANCE._python_profile("python", {}, tmp_path / "report.xml")


def test_android_runner_rejects_truncated_reviewed_inventory(monkeypatch, tmp_path):
    results = tmp_path / "reports"
    monkeypatch.setattr(ACCEPTANCE, "ANDROID_RESULTS", results)
    def run(command, *, env, timeout):
        mandatory = sorted(ACCEPTANCE._expected_inventory("android-wallet-jvm-security"))
        controlled_report(results / "TEST-synthetic.xml", [*mandatory[:-1], *sorted(ACCEPTANCE.ANDROID_OPTIONAL_SKIPS)])
        for name in ("kotlin-bound.dw", "kotlin-legacy.dw", "kotlin-bignum.dw"):
            (Path(env[ACCEPTANCE.ARTIFACT_ENV]) / name).write_bytes(b"synthetic")
    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    with pytest.raises(ReceiptValidationError, match="inventory"):
        ACCEPTANCE._android_profile(str(ACCEPTANCE.ROOT / "gradlew"), {}, tmp_path)


@pytest.mark.parametrize("optional_status", ["passed", "skipped"])
def test_android_optional_outcome_does_not_inflate_mandatory_count(monkeypatch, tmp_path, optional_status):
    mandatory = [
        "org.decentwallet.wallet.android.PortableLatchTest::actualKotlinPublicAuthoringExportsBoundAndLegacyCiphertext",
        "org.decentwallet.wallet.android.PortableLatchTest::largePositiveIntegerRealEncryptedPublicReadersAndWriter",
    ]
    optional = next(iter(ACCEPTANCE.ANDROID_OPTIONAL_SKIPS))
    results = tmp_path / "reports"
    monkeypatch.setattr(ACCEPTANCE, "ANDROID_RESULTS", results)
    monkeypatch.setattr(ACCEPTANCE, "_expected_inventory", lambda suite_id, test_file=None: frozenset(mandatory))
    def run(command, *, env, timeout):
        controlled_report(results / "TEST-synthetic.xml", [*mandatory, optional], {optional: "skipped"} if optional_status == "skipped" else {})
        for name in ("kotlin-bound.dw", "kotlin-legacy.dw", "kotlin-bignum.dw"):
            (Path(env[ACCEPTANCE.ARTIFACT_ENV]) / name).write_bytes(b"synthetic")
    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    suite, _artifacts = ACCEPTANCE._android_profile(str(ACCEPTANCE.ROOT / "gradlew"), {}, tmp_path)
    assert suite["tests"] == len(mandatory)
    assert suite["skipped"] == int(optional_status == "skipped")


@pytest.mark.parametrize("corruption", ["duplicate", "aggregate-failure", "aggregate-error", "aggregate-skip", "skip-and-failure"])
def test_android_runner_rejects_corrupt_native_results(monkeypatch, tmp_path, corruption):
    mandatory = "synthetic::mandatory"
    optional = next(iter(ACCEPTANCE.ANDROID_OPTIONAL_SKIPS))
    results = tmp_path / "reports"
    monkeypatch.setattr(ACCEPTANCE, "ANDROID_RESULTS", results)
    monkeypatch.setattr(ACCEPTANCE, "_expected_inventory", lambda suite_id, test_file=None: frozenset({mandatory}))
    def run(command, *, env, timeout):
        report = results / "TEST-synthetic.xml"
        controlled_report(report, [mandatory, optional])
        root = ET.parse(report).getroot()
        if corruption == "duplicate":
            root.append(ET.fromstring(ET.tostring(root[0])))
            root.set("tests", "3")
        elif corruption == "skip-and-failure":
            ET.SubElement(root[1], "skipped")
            ET.SubElement(root[1], "failure")
            root.set("skipped", "1")
            root.set("failures", "1")
        else:
            key = {"aggregate-failure": "failures", "aggregate-error": "errors", "aggregate-skip": "skipped"}[corruption]
            root.set(key, "1")
        ET.ElementTree(root).write(report, encoding="unicode")
    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    with pytest.raises(ReceiptValidationError, match="duplicate|inconsistent|contradictory"):
        ACCEPTANCE._android_profile(str(ACCEPTANCE.ROOT / "gradlew"), {}, tmp_path)


def write_junit(path: Path, *, tests: int, failures: int = 0, errors: int = 0, skipped: int = 0) -> None:
    identities = [f"synthetic::case{index}" for index in range(tests)]
    statuses = ["failure"] * failures + ["error"] * errors + ["skipped"] * skipped
    controlled_report(path, identities, dict(zip(identities, statuses)))


def test_gradle_failure_diagnostics_never_echo_subprocess_output(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    class Result:
        returncode = 2
        stdout = "SYNTHETIC-SECRET-OUTPUT"
        stderr = "failure text containing SYNTHETIC-SECRET-OUTPUT"

    monkeypatch.setattr(ACCEPTANCE.subprocess, "run", lambda *args, **kwargs: Result())
    with pytest.raises(ReceiptValidationError):
        ACCEPTANCE._run(["/repo/gradlew", "test"], env={}, timeout=1)
    output = capsys.readouterr()
    assert "SYNTHETIC-SECRET-OUTPUT" not in output.out + output.err
    assert "Android Gradle acceptance task failed." in output.err


@pytest.mark.parametrize(
    ("failures", "errors", "skipped"),
    [(1, 0, 0), (0, 1, 0), (0, 0, 1)],
)
def test_junit_result_rejects_any_failed_or_skipped_mandatory_case(
    tmp_path: Path, failures: int, errors: int, skipped: int
) -> None:
    report = tmp_path / "TEST-security.xml"
    write_junit(report, tests=2, failures=failures, errors=errors, skipped=skipped)

    with pytest.raises(ReceiptValidationError):
        junit_result([report])


def test_junit_result_rejects_missing_or_empty_reports(tmp_path: Path) -> None:
    with pytest.raises(ReceiptValidationError):
        junit_result([])

    report = tmp_path / "TEST-empty.xml"
    write_junit(report, tests=0)
    with pytest.raises(ReceiptValidationError):
        junit_result([report])


def test_junit_result_rejects_invalid_counts_and_xml(tmp_path: Path) -> None:
    report = tmp_path / "invalid.xml"
    report.write_text('<testsuite tests="unknown" />', encoding="utf-8")
    with pytest.raises(ReceiptValidationError):
        junit_result([report])

    report.write_text("not xml", encoding="utf-8")
    with pytest.raises(ReceiptValidationError):
        junit_result([report])


def test_python_profile_clears_inherited_pytest_selection(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, str] = {}
    report = tmp_path / "selection.xml"

    def run(command: list[str], *, env: dict[str, str], timeout: int) -> None:
        captured.update(env)
        report_path = Path(command[command.index("--junitxml") + 1])
        report_path.write_text(
            '<testsuite tests="1" failures="0" errors="0" skipped="1">'
            '<testcase classname="tests.test_fake" name="only-case">'
            '<skipped message="deselected by -k"/></testcase></testsuite>',
            encoding="utf-8",
        )

    monkeypatch.setenv("PYTEST_ADDOPTS", "-k impossible")
    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    with pytest.raises(ReceiptValidationError):
        ACCEPTANCE._python_profile("python", __import__("os").environ.copy(), report)
    assert "PYTEST_ADDOPTS" not in captured


def test_python_profile_preserves_configured_default_exclusions(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    expected_passing_optional = ACCEPTANCE.OPTIONAL_PASSED_CASES
    commands: list[list[str]] = []


    def run(command: list[str], *, env: dict[str, str], timeout: int) -> None:
        commands.append(command)
        assert "PYTEST_ADDOPTS" not in env
        report = Path(command[command.index("--junitxml") + 1])
        cases = ['<testcase classname="tests.test_synthetic" name="mandatory_case"/>']
        for node_id in sorted(ACCEPTANCE.PYTHON_OPTIONAL_CASES):
            classname, name = node_id.split("::", 1)
            is_skipped = node_id not in expected_passing_optional
            skipped_xml = '<skipped message="optional external prerequisite absent"/>' if is_skipped else ""
            cases.append(f'<testcase classname="{classname}" name="{name}">{skipped_xml}</testcase>')
        skipped_count = sum("<skipped" in case for case in cases)
        report.write_text(
            f'<testsuite tests="{len(cases)}" failures="0" errors="0" skipped="{skipped_count}">'
            + "".join(cases)
            + "</testsuite>", encoding="utf-8",
        )

    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    monkeypatch.setattr(ACCEPTANCE, "_expected_inventory", lambda suite_id, test_file=None: frozenset({"tests.test_synthetic::mandatory_case"}))
    summary, optional = ACCEPTANCE._python_profile("python", {}, tmp_path / "python.xml")
    assert len(commands) == 1
    assert "--junitxml" in commands[0]
    assert not ("-o" in commands[0] and "addopts=" in commands[0])
    assert {
        "tests/test_android_registry_peer.py",
        "tests/test_remote_registry_acceptance.py",
        "tests/test_podman_registry_deployment.py",
    }.isdisjoint(commands[0])
    assert optional == sorted(name for name in ACCEPTANCE.PYTHON_OPTIONAL_CASES if name not in expected_passing_optional)
    assert summary["tests"] == 1
    assert summary["skipped"] == 0
    assert len(summary["state_transitions"]) == 1 + len(ACCEPTANCE.PYTHON_OPTIONAL_CASES)
    assert summary["state_transitions"][0] == "mandatory-cases-passed"
    expected_outcomes = {
        "tests.test_portable_latch::test_concrete_transport_has_explicit_environment_configuration": "passed",
        "tests.test_android_lan_host_harness::test_device_driver_archives_consumed_owned_helper_before_launch": "skipped",
        "tests.test_portable_latch::test_actual_kotlin_authored_ciphertext_through_python_public_reader[kotlin-bound.dw-False]": "skipped",
        "tests.test_portable_latch::test_actual_kotlin_authored_ciphertext_through_python_public_reader[kotlin-legacy.dw-True]": "skipped",
        "tests.test_portable_latch::test_large_positive_integer_real_encrypted_public_readers[kotlin]": "skipped",
    }
    for name, status in expected_outcomes.items():
        digest = hashlib.sha256(name.encode()).hexdigest()[:12]
        assert f"optional-case-{status}-{digest}" in summary["state_transitions"]


def test_python_profile_optional_passing_cases_do_not_inflate_mandatory_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    report = tmp_path / "python.xml"
    approved_pass = next(name for name in ACCEPTANCE.OPTIONAL_PASSED_CASES if "concrete_transport" in name)

    def run(command: list[str], *, env: dict[str, str], timeout: int) -> None:
        cases = ['<testcase classname="tests.test_synthetic" name="mandatory_case"/>']
        for node_id in sorted(ACCEPTANCE.PYTHON_OPTIONAL_CASES):
            classname, name = node_id.split("::", 1)
            skipped = '<skipped message="optional prerequisite absent"/>' if node_id != approved_pass else ""
            cases.append(f'<testcase classname="{classname}" name="{name}">{skipped}</testcase>')
        report_path = Path(command[command.index("--junitxml") + 1])
        report_path.write_text(
            f'<testsuite tests="{len(cases)}" failures="0" errors="0" skipped="{len(cases) - 2}">'
            + "".join(cases) + "</testsuite>", encoding="utf-8"
        )

    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    monkeypatch.setattr(ACCEPTANCE, "_expected_inventory", lambda suite_id, test_file=None: frozenset({"tests.test_synthetic::mandatory_case"}))
    summary, _optional = ACCEPTANCE._python_profile("python", {}, report)
    assert summary["tests"] == 1
    assert summary["state_transitions"][0] == "mandatory-cases-passed"


def test_python_profile_rejects_unapproved_skip(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    report = tmp_path / "python.xml"
    mandatory = '<testcase classname="tests.test_synthetic" name="mandatory_case"/>'
    optional = []
    for node_id in sorted(ACCEPTANCE.PYTHON_OPTIONAL_CASES):
        classname, name = node_id.split("::", 1)
        is_passing = node_id in ACCEPTANCE.OPTIONAL_PASSED_CASES
        skipped = '<skipped message="optional prerequisite absent"/>' if not is_passing else ""
        optional.append(f'<testcase classname="{classname}" name="{name}">{skipped}</testcase>')
    unexpected = '<testcase classname="tests.test_unlisted" name="environmental_case"><skipped message="environmental dependency"/></testcase>'

    def run(command: list[str], *, env: dict[str, str], timeout: int) -> None:
        report_path = Path(command[command.index("--junitxml") + 1])
        report_path.write_text(
            f'<testsuite tests="{len(optional) + 2}" failures="0" errors="0" skipped="{len(optional) - len(ACCEPTANCE.OPTIONAL_PASSED_CASES) + 1}">'
            + mandatory + "".join(optional) + unexpected + "</testsuite>",
            encoding="utf-8",
        )

    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    with pytest.raises(ACCEPTANCE.ReceiptValidationError, match="unapproved mandatory case"):
        ACCEPTANCE._python_profile("python", {}, report)


def test_receipt_schema_is_allowlisted_and_verdict_matches_suite_results() -> None:
    passed_case = "tests.test_portable_latch::test_concrete_transport_has_explicit_environment_configuration"
    receipt = {
        "schema": "decent-wallet-security-acceptance-receipt-v1",
        "created_at": "2026-10-02T00:00:00Z",
        "profile": "core",
        "verdict": "passed",
        "commit": "1" * 40,
        "environment": {"python": "3.14.0", "platform": "Linux-x86_64", "implementation": "CPython", "android_test_artifacts": False},
        "suites": [
            {
                "id": "python-security-matrix",
                "status": "passed",
                "tests": 4,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "state_transitions": [
                    "mandatory-cases-passed",
                    *[f"optional-case-skipped-{hashlib.sha256(item.encode()).hexdigest()[:12]}" for item in ACCEPTANCE.OPTIONAL_SKIPS],
                    "optional-case-passed-" + hashlib.sha256(passed_case.encode()).hexdigest()[:12],
                ],
            }
        ],
        "artifacts": [{"id": "wallet-container-known-answer", "sha256": "b" * 64}],
    }

    assert validate_receipt(receipt) == receipt

    malformed_digest = json.loads(json.dumps(receipt))
    malformed_digest["artifacts"][0]["sha256"] = "not-a-digest"
    with pytest.raises(ReceiptValidationError, match="digest"):
        validate_receipt(malformed_digest)

    unapproved_transition = json.loads(json.dumps(receipt))
    unapproved_transition["suites"][0]["state_transitions"].append("private-key-material")
    with pytest.raises(ReceiptValidationError):
        validate_receipt(unapproved_transition)

    wrong_optional_outcome = json.loads(json.dumps(receipt))
    passed_transition = "optional-case-passed-" + hashlib.sha256(passed_case.encode()).hexdigest()[:12]
    skipped_transition = "optional-case-skipped-" + hashlib.sha256(passed_case.encode()).hexdigest()[:12]
    wrong_optional_outcome["suites"][0]["state_transitions"].remove(passed_transition)
    wrong_optional_outcome["suites"][0]["state_transitions"].append(skipped_transition)
    assert validate_receipt(wrong_optional_outcome) == wrong_optional_outcome

    with pytest.raises(ReceiptValidationError, match="unapproved field"):
        validate_receipt(receipt | {"secret": "must never appear"})

    failed = json.loads(json.dumps(receipt))
    failed["suites"][0]["status"] = "failed"
    with pytest.raises(ReceiptValidationError, match="pass"):
        validate_receipt(failed)


def test_receipt_profiles_require_exact_suites_artifacts_and_optional_case_disclosures() -> None:
    passed_case = "tests.test_portable_latch::test_concrete_transport_has_explicit_environment_configuration"
    receipt = {
        "schema": "decent-wallet-security-acceptance-receipt-v1",
        "created_at": "2026-10-02T00:00:00Z",
        "profile": "core",
        "verdict": "passed",
        "commit": "1" * 40,
        "environment": {"python": "3.14.0", "platform": "Linux-x86_64", "implementation": "CPython", "android_test_artifacts": False},
        "suites": [
            {
                "id": "python-security-matrix",
                "status": "passed",
                "tests": 4,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "state_transitions": [
                    "mandatory-cases-passed",
                    *[f"optional-case-skipped-{hashlib.sha256(item.encode()).hexdigest()[:12]}" for item in ACCEPTANCE.OPTIONAL_SKIPS],
                    "optional-case-passed-" + hashlib.sha256(passed_case.encode()).hexdigest()[:12],
                ],
            }
        ],
        "artifacts": [{"id": "wallet-container-known-answer", "sha256": "b" * 64}],
    }
    assert validate_receipt(receipt) == receipt

    unexpected_suite = json.loads(json.dumps(receipt))
    unexpected_suite["suites"].append(dict(unexpected_suite["suites"][0]))
    unexpected_suite["suites"][1]["id"] = "another-suite"
    with pytest.raises(ReceiptValidationError):
        validate_receipt(unexpected_suite)

    missing_disclosure = json.loads(json.dumps(receipt))
    name = sorted(ACCEPTANCE.OPTIONAL_SKIPS)[0]
    expected_transition = "optional-case-skipped-" + hashlib.sha256(name.encode()).hexdigest()[:12]
    missing_disclosure["suites"][0]["state_transitions"].remove(expected_transition)
    with pytest.raises(ReceiptValidationError):
        validate_receipt(missing_disclosure)


def test_android_profile_rejects_mandatory_skips_but_accepts_listed_live_peer_case() -> None:
    receipt = {
        "schema": "decent-wallet-security-acceptance-receipt-v1",
        "created_at": "2026-10-02T00:00:00Z",
        "profile": "android-jvm",
        "verdict": "passed",
        "commit": "1" * 40,
        "environment": {"python": "3.14.0", "platform": "Linux-x86_64", "implementation": "CPython", "android_test_artifacts": True},
        "suites": [
            {
                "id": "android-wallet-jvm-security",
                "status": "passed",
                "tests": 100,
                "failures": 0,
                "errors": 0,
                "skipped": 1,
                "state_transitions": [
                    "android-jvm-cases-passed",
                    f"optional-live-peer-case-skipped-{hashlib.sha256(next(iter(ACCEPTANCE.ANDROID_OPTIONAL_SKIPS)).encode()).hexdigest()[:12]}",
                ],
            }
        ],
        "artifacts": [
            {"id": name, "sha256": "b" * 64}
            for name in ("kotlin-bound", "kotlin-legacy", "kotlin-bignum", "wallet-container-known-answer")
        ],
    }
    assert validate_receipt(receipt) == receipt

    mandatory_skip = json.loads(json.dumps(receipt))
    mandatory_skip["suites"][0]["skipped"] = 2
    mandatory_skip["suites"][0]["tests"] = 101
    with pytest.raises(ReceiptValidationError):
        validate_receipt(mandatory_skip)

    missing_omission = json.loads(json.dumps(receipt))
    mandatory_skip_state = "optional-live-peer-case-skipped-" + hashlib.sha256(
        next(iter(ACCEPTANCE.ANDROID_OPTIONAL_SKIPS)).encode()
    ).hexdigest()[:12]
    missing_omission["suites"][0]["state_transitions"].remove(mandatory_skip_state)
    with pytest.raises(ReceiptValidationError):
        validate_receipt(missing_omission)


def test_android_profile_receipt_requires_suite_artifacts_and_omission_disclosure() -> None:
    receipt = {
        "schema": "decent-wallet-security-acceptance-receipt-v1",
        "created_at": "2026-10-02T00:00:00Z",
        "profile": "android-jvm",
        "verdict": "passed",
        "commit": "1" * 40,
        "environment": {"python": "3.14.0", "platform": "Linux-x86_64", "implementation": "CPython", "android_test_artifacts": True},
        "suites": [{
            "id": "android-wallet-jvm-security", "status": "passed", "tests": 100,
            "failures": 0, "errors": 0, "skipped": 1,
            "state_transitions": [
                "android-jvm-cases-passed",
                f"optional-live-peer-case-skipped-{hashlib.sha256(next(iter(ACCEPTANCE.ANDROID_OPTIONAL_SKIPS)).encode()).hexdigest()[:12]}",
            ],
        }],
        "artifacts": [
            {"id": name, "sha256": "b" * 64}
            for name in (
                "kotlin-bound", "kotlin-legacy", "kotlin-bignum", "wallet-container-known-answer",
                "identity-owner-key-rotation-legacy-candidate-envelope",
                "identity-owner-key-rotation-versioned-history-candidate-envelope",
            )
        ],
    }
    assert validate_receipt(receipt) == receipt

    wrong_suite = json.loads(json.dumps(receipt))
    wrong_suite["suites"][0]["id"] = "python-security-matrix"
    with pytest.raises(ReceiptValidationError):
        validate_receipt(wrong_suite)

    missing_artifact = json.loads(json.dumps(receipt))
    missing_artifact["artifacts"] = [item for item in missing_artifact["artifacts"] if item["id"] != "kotlin-bound"]
    with pytest.raises(ReceiptValidationError):
        validate_receipt(missing_artifact)

    unexpected_artifact = json.loads(json.dumps(receipt))
    unexpected_artifact["artifacts"].append({"id": "unexpected-data", "sha256": "c" * 64})
    with pytest.raises(ReceiptValidationError):
        validate_receipt(unexpected_artifact)

    mandatory_skip = json.loads(json.dumps(receipt))
    mandatory_skip["suites"][0]["skipped"] = 2
    mandatory_skip["suites"][0]["tests"] = 101
    with pytest.raises(ReceiptValidationError):
        validate_receipt(mandatory_skip)

    missing_omission = json.loads(json.dumps(receipt))
    mandatory_skip_state = "optional-live-peer-case-skipped-" + hashlib.sha256(
        next(iter(ACCEPTANCE.ANDROID_OPTIONAL_SKIPS)).encode()
    ).hexdigest()[:12]
    missing_omission["suites"][0]["state_transitions"].remove(mandatory_skip_state)
    with pytest.raises(ReceiptValidationError):
        validate_receipt(missing_omission)


def test_full_receipt_rejects_unapproved_registry_transitions() -> None:
    passed_case = "tests.test_portable_latch::test_concrete_transport_has_explicit_environment_configuration"
    receipt = {
        "schema": ACCEPTANCE.RECEIPT_SCHEMA,
        "created_at": "2026-10-02T00:00:00Z",
        "profile": "full",
        "verdict": "passed",
        "commit": "1" * 40,
        "environment": {
            "python": "3.14.0",
            "platform": "Linux-x86_64",
            "implementation": "CPython",
            "android_test_artifacts": True,
        },
        "suites": [
            {
                "id": "python-security-matrix",
                "status": "passed",
                "tests": 4,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "state_transitions": [
                    "mandatory-cases-passed",
                    *[f"optional-case-skipped-{hashlib.sha256(item.encode()).hexdigest()[:12]}" for item in ACCEPTANCE.OPTIONAL_SKIPS],
                    "optional-case-passed-" + hashlib.sha256(passed_case.encode()).hexdigest()[:12],
                ],
            },
            {
                "id": "android-wallet-jvm-security",
                "status": "passed",
                "tests": 100,
                "failures": 0,
                "errors": 0,
                "skipped": 1,
                "state_transitions": [
                    "android-jvm-cases-passed",
                    f"optional-live-peer-case-skipped-{hashlib.sha256(next(iter(ACCEPTANCE.ANDROID_OPTIONAL_SKIPS)).encode()).hexdigest()[:12]}",
                ],
            },
            {
                "id": "local-registry-integration",
                "status": "passed",
                "tests": 1,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "state_transitions": ["mandatory-cases-passed", "receipt-emitted"],
            },
        ],
        "artifacts": [
            {"id": name, "sha256": "b" * 64}
            for name in (
                "wallet-container-known-answer",
                "kotlin-bound",
                "kotlin-legacy",
                "kotlin-bignum",
                "identity-owner-key-rotation-legacy-candidate-envelope",
                "identity-owner-key-rotation-versioned-history-candidate-envelope",
            )
        ],
    }
    assert validate_receipt(receipt) == receipt

    injected_transition = json.loads(json.dumps(receipt))
    injected_transition["suites"][2]["state_transitions"].append("secret-material-approved")
    with pytest.raises(ReceiptValidationError):
        validate_receipt(injected_transition)


def test_registry_provider_revision_must_match_uv_lock(monkeypatch, tmp_path):
    provider = tmp_path / "decent-registry"
    provider.mkdir()
    (provider / "pyproject.toml").write_text("[project]\nname='decent-registry'\n")
    monkeypatch.setenv("DECENT_REGISTRY_PATH", str(provider))
    monkeypatch.setattr(ACCEPTANCE, "ROOT", tmp_path)
    (tmp_path / "uv.lock").write_text('''version = 1
[[package]]
name = "decent-registry"
version = "0.1.0"
source = { git = "https://example.invalid/decent-registry.git?rev=0123456789abcdef0123456789abcdef01234567#0123456789abcdef0123456789abcdef01234567" }
''')

    class Result:
        returncode = 0
        stdout = "fedcba9876543210fedcba9876543210fedcba98\n"

    monkeypatch.setattr(ACCEPTANCE.subprocess, "run", lambda *args, **kwargs: Result())
    with pytest.raises(ACCEPTANCE.ReceiptValidationError):
        ACCEPTANCE._pinned_provider_path()


def test_registry_profile_clears_pytest_selection_options(monkeypatch, tmp_path):
    captured = []
    files = (
        "tests/test_android_registry_peer.py",
        "tests/test_registry_transport_integration.py",
        "tests/test_portable_latch_registry_integration.py",
    )
    inventory = {file: frozenset({f"synthetic.job{index}::case"}) for index, file in enumerate(files)}
    monkeypatch.setattr(ACCEPTANCE, "_pinned_provider_path", lambda: tmp_path)
    monkeypatch.setattr(ACCEPTANCE, "_expected_inventory", lambda suite_id, test_file=None: inventory[test_file] if test_file else frozenset().union(*inventory.values()))
    def run(command, *, env, timeout):
        captured.append((command, dict(env)))
        controlled_report(Path(command[command.index("--junitxml") + 1]), sorted(inventory[command[-1]]))
    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    suite = ACCEPTANCE._registry_profile({"PYTEST_ADDOPTS": "--deselect=tests/test_secret.py::test_case"}, tmp_path / "report.xml")
    assert suite["tests"] == 3
    assert len(captured) == 3
    assert all("PYTEST_ADDOPTS" not in env for _command, env in captured)


@pytest.mark.parametrize("corruption", ["duplicate", "wrong-identities", "truncated"])
def test_registry_runner_rejects_unreviewed_native_inventory(monkeypatch, tmp_path, corruption):
    monkeypatch.setattr(ACCEPTANCE, "_pinned_provider_path", lambda: tmp_path)
    def run(command, *, env, timeout):
        ids = sorted(ACCEPTANCE._expected_inventory("local-registry-integration", command[-1]))
        if corruption == "duplicate":
            ids[-1] = ids[0]
        elif corruption == "truncated":
            ids.pop()
        else:
            ids[-1] = f"synthetic.{Path(command[-1]).stem}::unreviewed"
        controlled_report(Path(command[command.index("--junitxml") + 1]), ids)
    monkeypatch.setattr(ACCEPTANCE, "_run", run)
    with pytest.raises(ReceiptValidationError, match="duplicate" if corruption == "duplicate" else "inventory"):
        ACCEPTANCE._registry_profile({}, tmp_path / "report.xml")


def test_registry_provider_must_be_clean(monkeypatch, tmp_path):
    provider = tmp_path / "decent-registry"
    provider.mkdir()
    (provider / "pyproject.toml").write_text("[project]\nname='decent-registry'\n")
    monkeypatch.setenv("DECENT_REGISTRY_PATH", str(provider))
    monkeypatch.setattr(ACCEPTANCE, "ROOT", tmp_path)
    (tmp_path / "uv.lock").write_text('''version = 1
[[package]]
name = "decent-registry"
version = "0.1.0"
source = { git = "https://example.invalid/decent-registry.git?rev=0123456789abcdef0123456789abcdef01234567#0123456789abcdef0123456789abcdef01234567" }
''')
    calls = iter((
        type("Result", (), {"returncode": 0, "stdout": "0123456789abcdef0123456789abcdef01234567\n"})(),
        type("Result", (), {"returncode": 0, "stdout": " M pyproject.toml\n"})(),
    ))
    monkeypatch.setattr(ACCEPTANCE.subprocess, "run", lambda *args, **kwargs: next(calls))
    with pytest.raises(ACCEPTANCE.ReceiptValidationError):
        ACCEPTANCE._pinned_provider_path()

    passed_case = "tests.test_portable_latch::test_concrete_transport_has_explicit_environment_configuration"
    receipt = {
        "schema": "decent-wallet-security-acceptance-receipt-v1",
        "created_at": "2026-10-02T00:00:00Z",
        "profile": "core",
        "verdict": "passed",
        "commit": "1" * 40,
        "environment": {"python": "3.14.0", "platform": "Linux-x86_64", "implementation": "CPython", "android_test_artifacts": False},
        "suites": [
            {
                "id": "python-security-matrix",
                "status": "passed",
                "tests": 4,
                "failures": 0,
                "errors": 0,
                "skipped": 0,
                "state_transitions": [
                    "mandatory-cases-passed",
                    *[f"optional-case-skipped-{hashlib.sha256(item.encode()).hexdigest()[:12]}" for item in ACCEPTANCE.OPTIONAL_SKIPS],
                    "optional-case-passed-" + hashlib.sha256(passed_case.encode()).hexdigest()[:12],
                ],
            }
        ],
        "artifacts": [{"id": "wallet-container-known-answer", "sha256": "b" * 64}],
    }
    target = tmp_path / "receipt.json"
    ACCEPTANCE.write_receipt(receipt, target)
    assert json.loads(target.read_text(encoding="utf-8")) == receipt
    assert not list(tmp_path.glob("*.tmp"))


def test_receipt_rejects_secret_bearing_or_untyped_metadata() -> None:
    receipt = {
        "schema": "decent-wallet-security-acceptance-receipt-v1",
        "created_at": "2026-10-02T00:00:00Z",
        "profile": "core",
        "verdict": "passed",
        "commit": "1" * 40,
        "environment": {
            "python": "3.14.0",
            "platform": "Linux-x86_64",
            "implementation": "CPython",
            "android_test_artifacts": False,
        },
        "suites": [{
            "id": "python-security-matrix",
            "status": "passed",
            "tests": 1,
            "failures": 0,
            "errors": 0,
            "skipped": 0,
            "state_transitions": [
                "mandatory-cases-passed",
                *[f"optional-case-skipped-{hashlib.sha256(item.encode()).hexdigest()[:12]}" for item in ACCEPTANCE.OPTIONAL_SKIPS],
                *[f"optional-case-passed-{hashlib.sha256(item.encode()).hexdigest()[:12]}" for item in ACCEPTANCE.OPTIONAL_PASSED_CASES],
            ],
        }],
        "artifacts": [{"id": "wallet-container-known-answer", "sha256": "b" * 64}],
    }
    receipt["environment"]["private_seed"] = "synthetic-secret"

    with pytest.raises(ReceiptValidationError):
        validate_receipt(receipt)

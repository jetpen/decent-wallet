from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import socket
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

from issue18_remote_registry import (
    RemotePeerAddress,
    RemoteRegistryPeerFixture,
    ssh_command,
)
from run_issue18_registry_acceptance import (
    adb_path,
    select_single_emulator,
    verify_android_target,
)

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "org.decentwallet.interop.lanhost"
PERMISSION = "android.permission.ACCESS_LOCAL_NETWORK"
TEST = (
    PACKAGE
    + ".LanPermissionRuntimeTest#consumingHostChecksPermissionBeforeRealRemoteRegistryReads"
)


def emulator_peer_address(peer: RemotePeerAddress, port: int) -> str:
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("forward port must be an integer in 1..65535")
    return f"/ip4/10.0.2.2/tcp/{port}/p2p/{peer.peer_id}"


def verify_instrumentation(output: str) -> None:
    expected_class, expected_method = TEST.split("#")
    records = []
    fields: dict[str, str] = {}
    invalid = False
    for line in output.splitlines():
        if line.startswith("INSTRUMENTATION_STATUS: "):
            key, separator, value = line.removeprefix("INSTRUMENTATION_STATUS: ").partition("=")
            if not separator or key in fields:
                invalid = True
            fields[key] = value
        elif line.startswith("INSTRUMENTATION_STATUS_CODE: "):
            records.append((dict(fields), line.removeprefix("INSTRUMENTATION_STATUS_CODE: ")))
            fields.clear()
    expected = {"class": expected_class, "test": expected_method, "numtests": "1", "current": "1"}
    if (
        invalid or fields
        or [code for _, code in records] != ["1", "0"]
        or any(any(record.get(key) != value for key, value in expected.items()) for record, _ in records)
        or len(re.findall(r"^OK \(1 test\)\s*$", output, re.MULTILINE)) != 1
        or re.findall(r"^INSTRUMENTATION_CODE: (.+)$", output, re.MULTILINE) != ["-1"]
        or "INSTRUMENTATION_FAILED" in output
        or "FAILURES!!!" in output
    ):
        raise RuntimeError("expected exactly one executed passing, unskipped host testcase")


def run(command: list[str], *, timeout: float = 30) -> str:
    return subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, check=True, timeout=timeout
    ).stdout


@contextmanager
def gateway_forwards(host: str, peers: list[RemotePeerAddress], output: Path):
    listeners = [socket.socket() for _ in peers]
    try:
        for listener in listeners:
            listener.bind(("127.0.0.1", 0))
        ports = [listener.getsockname()[1] for listener in listeners]
    finally:
        for listener in listeners:
            listener.close()
    command = ssh_command(host, remote_args=[])
    options = ["-N", "-oExitOnForwardFailure=yes"]
    for peer, port in zip(peers, ports, strict=True):
        options.extend(["-L", f"127.0.0.1:{port}:{peer.host}:{peer.port}"])
    command[command.index(host) : command.index(host)] = options
    with (output / "ssh-forward.log").open("w") as log:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 30
            while True:
                if process.poll() is not None:
                    raise RuntimeError("owned SSH forward failed to start")
                try:
                    for port in ports:
                        with socket.create_connection(("127.0.0.1", port), timeout=1):
                            pass
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("owned SSH forwards did not become ready")
                    time.sleep(0.1)
            yield (
                [
                    emulator_peer_address(peer, port)
                    for peer, port in zip(peers, ports, strict=True)
                ],
                command,
            )
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)


def cleanup_packages(adb: str, serial: str, output: Path) -> None:
    packages = []
    failures = []
    for package in (PACKAGE + ".test", PACKAGE):
        record: dict[str, object] = {"package": package}
        for operation, command in (
            ("uninstall", [adb, "-s", serial, "uninstall", package]),
            ("absence", [adb, "-s", serial, "shell", "pm", "list", "packages", package]),
        ):
            try:
                result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30, check=False)
                raw = {"command": command, "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
                if result.returncode != 0 or (operation == "uninstall" and result.stdout.strip() != "Success"):
                    failures.append(f"{package}: {operation} failed")
                if operation == "absence" and f"package:{package}" in result.stdout.splitlines():
                    failures.append(f"{package}: package remains installed")
            except Exception as failure:  # noqa: BLE001 - Record failure and attempt both owned packages.
                def text(value):
                    return value.decode(errors="replace") if isinstance(value, bytes) else (value or "")
                raw = {"command": command, "error": repr(failure), "stdout": text(getattr(failure, "stdout", None)), "stderr": text(getattr(failure, "stderr", None))}
                failures.append(f"{package}: {operation} raised {type(failure).__name__}")
            record[operation] = raw
        packages.append(record)
    (output / "app-cleanup.json").write_text(json.dumps({"packages": packages, "failures": failures}, indent=2) + "\n")
    if failures:
        raise RuntimeError("app cleanup failed: " + "; ".join(failures))


def source_files() -> list[Path]:
    # Current pre-run inputs only. Never add these to historical run manifests.
    files = {ROOT / name for name in (
        "build.gradle.kts", "settings.gradle.kts", "gradle.properties", "gradlew", "gradlew.bat",
        "pyproject.toml", "uv.lock",
    )}
    for directory in ("gradle", "interop/android-lan-host", "interop/android-runtime", "interop/kotlin", "platforms/android-wallet", "tests/vectors", "tests/fixtures"):
        base = ROOT / directory
        files.update(path for path in base.rglob("*") if path.is_file() and not {"build", "target", ".gradle", "__pycache__"}.intersection(path.relative_to(base).parts))
    for directory in ("scripts", "src", "tests"):
        files.update(path for path in (ROOT / directory).rglob("*.py") if "__pycache__" not in path.parts)
    return sorted(files)


def run_acceptance(*, host: str, serial: str, output: Path) -> None:
    if output.exists():
        raise FileExistsError("use a fresh output directory; historical attempts are immutable")
    output.mkdir(parents=True, exist_ok=False)
    adb = str(adb_path())
    select_single_emulator(run([adb, "devices", "-l"]), serial)
    avd, api, abi = verify_android_target(Path(adb), serial)
    files = source_files()
    module = ROOT / "interop/android-lan-host"
    metadata = {
        "source_capture_policy": "complete-current-pre-run-v2; historical captures remain old revisions",
        "ssh_host": host,
        "serial": serial,
        "avd": avd,
        "api": api,
        "abi": abi,
        "git_head": run(["git", "rev-parse", "HEAD"]).strip(),
        "source_sha256": {
            str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in files
        },
    }
    (output / "run-time.diff").write_bytes(
        subprocess.check_output(["git", "diff", "--binary"], cwd=ROOT)
    )
    metadata["dirty_diff_sha256"] = hashlib.sha256(
        (output / "run-time.diff").read_bytes()
    ).hexdigest()
    for path in files:
        dest = output / "source" / path.relative_to(ROOT)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dest)
    app = module / "build/outputs/apk/debug/android-lan-host-debug.apk"
    tests = (
        module
        / "build/outputs/apk/androidTest/debug/android-lan-host-debug-androidTest.apk"
    )
    metadata["apk_sha256"] = {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (app, tests)
    }
    phase_error: BaseException | None = None
    try:
        run([adb, "-s", serial, "install", "-t", "-r", str(app)], timeout=120)
        run([adb, "-s", serial, "install", "-t", "-r", str(tests)], timeout=120)
        run([adb, "-s", serial, "shell", "pm", "clear", PACKAGE])
        (output / "package-before.txt").write_text(
            run([adb, "-s", serial, "shell", "dumpsys", "package", PACKAGE])
        )
        with RemoteRegistryPeerFixture(host, repository_root=ROOT) as fixture:
            metadata["registry_revision"] = fixture.registry_revision
            metadata["remote_root"] = str(fixture.remote_root)
            metadata["writer"] = fixture.writer.multiaddr
            metadata["readback"] = fixture.readback.multiaddr
            with gateway_forwards(host, [fixture.writer, fixture.readback], output) as (
                peers,
                ssh,
            ):
                metadata["ssh_forward_command"] = ssh
                metadata["emulator_peers"] = peers
                phases = []
                for scenario in (
                    ["legacy"] if api == 26 else ["denied", "granted", "revoked"]
                ):
                    run([adb, "-s", serial, "shell", "am", "force-stop", PACKAGE])
                    if api >= 37:
                        run(
                            [
                                adb,
                                "-s",
                                serial,
                                "shell",
                                "pm",
                                "revoke",
                                PACKAGE,
                                PERMISSION,
                            ]
                        )
                        run(
                            [
                                adb,
                                "-s",
                                serial,
                                "shell",
                                "pm",
                                "clear-permission-flags",
                                PACKAGE,
                                PERMISSION,
                                "user-set",
                                "user-fixed",
                            ]
                        )
                    assert verify_android_target(Path(adb), serial) == (avd, api, abi)
                    command = [
                        adb,
                        "-s",
                        serial,
                        "shell",
                        "am",
                        "instrument",
                        "-w",
                        "-r",
                        "-e",
                        "class",
                        TEST,
                        "-e",
                        "scenario",
                        scenario,
                        "-e",
                        "expectedApi",
                        str(api),
                        "-e",
                        "expectedAbi",
                        abi,
                        "-e",
                        "writerPeer",
                        peers[0],
                        "-e",
                        "readbackPeer",
                        peers[1],
                        PACKAGE + ".test/androidx.test.runner.AndroidJUnitRunner",
                    ]
                    text = run(command, timeout=240)
                    (output / f"{scenario}-instrumentation.txt").write_text(text)
                    (output / f"{scenario}-logcat.txt").write_text(
                        run(
                            [
                                adb,
                                "-s",
                                serial,
                                "logcat",
                                "-d",
                                "-s",
                                "LAN_HOST",
                                "System.out",
                            ]
                        )
                    )
                    verify_instrumentation(text)
                    phases.append(
                        {
                            "scenario": scenario,
                            "command": command,
                            "tests": 1,
                            "failures": 0,
                            "errors": 0,
                            "skipped": 0,
                        }
                    )
                    metadata["phases"] = phases
                    (output / "progress.json").write_text(
                        json.dumps(metadata, indent=2) + "\n"
                    )
        # Fixture __exit__ verifies temporary root cleanup before returning.
        metadata["remote_cleanup_verified"] = True
    except BaseException as failure:
        phase_error = failure
        raise
    finally:
        try:
            cleanup_packages(adb, serial, output)
        except Exception as cleanup_error:
            if phase_error is None:
                raise
            phase_error.add_note(f"Additional app cleanup failure: {cleanup_error}")
    metadata["app_cleanup_verified"] = True
    metadata["result"] = "passed"
    (output / "result.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(json.dumps({key: value for key, value in metadata.items() if key not in {"source_sha256", "apk_sha256"}}, indent=2), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Test-only consuming Android host against approved ephemeral remote Registry; local emulator only, no adb reverse or permission auto-grant."
    )
    parser.add_argument("--ssh-host", required=True)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run_acceptance(host=args.ssh_host, serial=args.serial, output=args.output)


if __name__ == "__main__":
    main()

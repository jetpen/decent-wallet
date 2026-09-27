#!/usr/bin/env python3
"""Run Issue #36 instrumentation on exactly the approved two-AVD matrix."""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[1]
AVDS = (
    {
        "name": "Medium_Phone",
        "port": 5554,
        "api": 26,
        "image_api": "26",
        "abi": "x86",
        "release": "8.0.0",
        "image": "system-images/android-26/google_apis_playstore/x86",
    },
    {
        "name": "Pixel_9",
        "port": 5556,
        "api": 37,
        "image_api": "37.2",
        "abi": "x86_64",
        "release": "17",
        "image": "system-images/android-37.2/google_apis_playstore_ps16k/x86_64",
    },
)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"Issue #36 conformance runner: {message}")


def run(command: list[str], *, env: dict[str, str], timeout: int = 60) -> str:
    result = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    if result.returncode:
        fail(f"command failed ({result.returncode}): {shlex.join(command)}\n{result.stdout}")
    return result.stdout.strip()


def properties(path: Path) -> dict[str, str]:
    if not path.is_file():
        fail(f"required metadata is missing: {path}")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    return values


def jdk17() -> Path:
    candidates = []
    if os.environ.get("JAVA_HOME"):
        candidates.append(Path(os.environ["JAVA_HOME"]))
    candidates.extend((Path.home() / ".local/share/mise/installs/java/17.0.2", Path("/usr/lib/jvm/java-17-openjdk")))
    for home in candidates:
        java, javac = home / "bin/java", home / "bin/javac"
        if java.is_file() and javac.is_file():
            version = subprocess.run(
                [str(java), "-version"], text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, check=False,
            ).stdout
            if re.search(r'version "17(?:[.+-]|\")', version):
                return home
            fail(f"approved build JDK is 17; JAVA_HOME points to {version.strip()}")
    fail("JDK 17 is required. Install/select it and set JAVA_HOME.")


def avd_metadata(sdk: Path, avd_home: Path, spec: dict[str, object]) -> dict[str, str]:
    name = str(spec["name"])
    avd_root = avd_home / f"{name}.avd"
    avd_ini = properties(avd_home / f"{name}.ini")
    config = properties(avd_root / "config.ini")
    image_path = str(spec["image"])
    if config.get("image.sysdir.1", "").rstrip("/") != image_path:
        fail(f"{name} is not configured with the approved image {image_path}")
    if config.get("abi.type") != spec["abi"]:
        fail(f"{name} AVD ABI is {config.get('abi.type')!r}, expected {spec['abi']!r}")
    image = properties(sdk / image_path / "source.properties")
    if image.get("AndroidVersion.ApiLevel") != spec["image_api"]:
        fail(f"{name} system-image API does not match the approved matrix")
    return {
        "avd_target": avd_ini.get("target", ""),
        "avd_config_abi": config.get("abi.type", ""),
        "avd_image_sysdir": config.get("image.sysdir.1", ""),
        "system_image_package": image_path,
        "system_image_description": image.get("Pkg.Desc", ""),
        "system_image_revision": image.get("Pkg.Revision", ""),
        "system_image_tag": image.get("SystemImage.TagId", ""),
        "system_image_abi": image.get("SystemImage.Abi", ""),
    }


def prop(adb: str, serial: str, name: str, env: dict[str, str]) -> str:
    return run([adb, "-s", serial, "shell", "getprop", name], env=env, timeout=15).strip()


def wait_for_device(adb: str, serial: str, process: subprocess.Popen[bytes], name: str,
                    log_path: Path, env: dict[str, str]) -> None:
    deadline = time.monotonic() + 360
    while time.monotonic() < deadline:
        if process.poll() is not None:
            fail(f"{name} emulator exited {process.returncode}; see {log_path}")
        state = subprocess.run(
            [adb, "-s", serial, "get-state"], env=env, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False,
        )
        if state.returncode == 0 and state.stdout.strip() == "device":
            boot = subprocess.run(
                [adb, "-s", serial, "shell", "getprop", "sys.boot_completed"], env=env,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False,
            )
            if boot.returncode == 0 and boot.stdout.strip() == "1":
                return
        time.sleep(3)
    fail(f"{name} did not boot within six minutes; see {log_path}")


def main() -> int:
    sdk = Path(os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT") or (Path.home() / "Android/Sdk"))
    avd_home = Path(os.environ.get("ANDROID_AVD_HOME") or (Path.home() / ".android/avd"))
    jdk = jdk17()
    env = os.environ.copy()
    env.update({"JAVA_HOME": str(jdk), "ANDROID_HOME": str(sdk), "ANDROID_SDK_ROOT": str(sdk)})
    env["PATH"] = f"{jdk / 'bin'}:{sdk / 'platform-tools'}:{sdk / 'emulator'}:{env.get('PATH', '')}"
    adb, emulator = sdk / "platform-tools/adb", sdk / "emulator/emulator"
    if not adb.is_file() or not emulator.is_file():
        fail(f"Android Platform-Tools and Emulator must be installed under {sdk}")
    sdk_packages = {
        "emulator": properties(sdk / "emulator/source.properties").get("Pkg.Revision", ""),
        "platform_tools": properties(sdk / "platform-tools/source.properties").get("Pkg.Revision", ""),
        "build_tools": properties(sdk / "build-tools/37.0.0/source.properties").get("Pkg.Revision", ""),
        "compile_sdk_api": properties(sdk / "platforms/android-37.0/source.properties").get("AndroidVersion.ApiLevel", ""),
        "compile_sdk_package_revision": properties(sdk / "platforms/android-37.0/source.properties").get("Pkg.Revision", ""),
    }
    image_metadata = {str(spec["name"]): avd_metadata(sdk, avd_home, spec) for spec in AVDS}
    run([str(adb), "start-server"], env=env, timeout=30)
    connected = run([str(adb), "devices"], env=env, timeout=15)
    if re.search(r"^emulator-(5554|5556)\s+device\s*$", connected, re.MULTILINE):
        fail("reserved emulator port 5554 or 5556 is occupied; stop that emulator and retry")

    report_dir = ROOT / "docs/reports/issue-36" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir.mkdir(parents=True, exist_ok=False)
    java_version = run([str(jdk / "bin/java"), "-version"], env=env)
    reports_root = ROOT / "interop/android-runtime/build/outputs/androidTest-results/connected/debug"
    target_results: list[dict[str, object]] = []
    processes: list[tuple[dict[str, object], subprocess.Popen[bytes], Path]] = []

    try:
        # Start and independently validate both approved AVDs before the single Gradle invocation.
        for spec in AVDS:
            name = str(spec["name"])
            log_path = report_dir / f"{name}-emulator.log"
            with log_path.open("w", encoding="utf-8") as log_file:
                process = subprocess.Popen(
                    [str(emulator), "-avd", name, "-port", str(spec["port"]),
                     "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot"],
                    cwd=ROOT, env=env, stdout=log_file, stderr=subprocess.STDOUT, start_new_session=True,
                )
            processes.append((spec, process, log_path))

        for spec, process, log_path in processes:
            name = str(spec["name"])
            serial = f"emulator-{spec['port']}"
            wait_for_device(str(adb), serial, process, name, log_path, env)
            actual_name = run([str(adb), "-s", serial, "emu", "avd", "name"], env=env, timeout=15).splitlines()[0].strip()
            api = prop(str(adb), serial, "ro.build.version.sdk", env)
            abi = prop(str(adb), serial, "ro.product.cpu.abi", env)
            release = prop(str(adb), serial, "ro.build.version.release", env)
            fingerprint = prop(str(adb), serial, "ro.build.fingerprint", env)
            if actual_name != name or api != str(spec["api"]) or abi != str(spec["abi"]):
                fail(f"runtime identity mismatch on {serial}: AVD={actual_name}, API={api}, ABI={abi}")
            if release != spec["release"] or not fingerprint:
                fail(f"unexpected Android release/build fingerprint on {name}: release={release}")
            target_results.append({
                "avd_name": name, "avd_serial": serial, "android_api": int(api),
                "android_release": release, "abi": abi,
                "supported_abis": prop(str(adb), serial, "ro.product.cpu.abilist", env).split(","),
                "build_fingerprint": fingerprint, "image": image_metadata[name],
            })

        expected_serials = {f"emulator-{spec['port']}" for spec in AVDS}
        attached = run([str(adb), "devices"], env=env, timeout=15)
        actual_serials = {
            line.split()[0] for line in attached.splitlines()[1:]
            if len(line.split()) >= 2 and line.split()[1] == "device"
        }
        if actual_serials != expected_serials:
            fail(f"only the two approved emulator devices may be attached: {sorted(actual_serials)}")

        matrix = {
            str(spec["name"]): {"api": spec["api"], "abi": spec["abi"]}
            for spec in AVDS
        }
        invocation = [
            "./gradlew", "--no-daemon", "--dependency-verification=strict",
            ":interop:android-runtime:connectedDebugAndroidTest",
        ]
        command_text = shlex.join(invocation)
        print(f"\n=== Running one locked Gradle invocation on Medium_Phone and Pixel_9 ===\n$ {command_text}", flush=True)
        previous_reports = set(reports_root.glob("TEST-*.xml"))
        completed = subprocess.run(
            invocation, cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=2400, check=False,
        )
        gradle_log = report_dir / "gradle-connectedAndroidTest.log"
        gradle_log.write_text(completed.stdout, encoding="utf-8")
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n", flush=True)
        if completed.returncode:
            fail(f"the combined Gradle instrumentation task failed with exit {completed.returncode}")

        current_reports = set(reports_root.glob("TEST-*.xml"))
        fresh_reports = current_reports - previous_reports
        selected_reports = fresh_reports if len(fresh_reports) == len(AVDS) else current_reports
        if len(selected_reports) != len(AVDS):
            fail(f"expected {len(AVDS)} per-device XML reports, found {len(selected_reports)}")
        matched_names: set[str] = set()
        for report_xml in selected_reports:
            suite = ET.parse(report_xml).getroot()
            device_props = {p.attrib.get("name"): p.attrib.get("value", "") for p in suite.findall(".//property")}
            device_label = device_props.get("device", "")
            matches = [entry for entry in target_results if str(entry["avd_name"]) in device_label]
            if len(matches) != 1:
                fail(f"cannot associate test report with one approved AVD: {device_label!r}")
            result = matches[0]
            name = str(result["avd_name"])
            if name in matched_names:
                fail(f"duplicate instrumentation report for {name}")
            matched_names.add(name)
            counts = {key: int(suite.attrib.get(key, "0")) for key in ("tests", "failures", "errors", "skipped")}
            if counts["tests"] != 9 or any(counts[key] for key in ("failures", "errors", "skipped")):
                fail(f"{name} did not pass all 9 instrumentation tests: {counts}")
            saved_xml = report_dir / f"{name}-instrumentation.xml"
            shutil.copyfile(report_xml, saved_xml)
            result.update({
                "test_report_device_property": device_label,
                "tests": counts,
                "instrumentation_xml": saved_xml.name,
                "gradle_log": gradle_log.name,
                "command": command_text,
                "dependency_locking": "checked-in Gradle lockfile",
                "dependency_verification": "strict SHA-256 verification metadata",
            })
        if matched_names != {str(spec["name"]) for spec in AVDS}:
            fail(f"matrix is incomplete; reports found for {sorted(matched_names)}")

        summary = {
            "issue": 36,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "git_commit": run(["git", "rev-parse", "HEAD"], env=env),
            "git_branch": run(["git", "branch", "--show-current"], env=env),
            "git_worktree_status": run(["git", "status", "--short"], env=env),
            "java_version": java_version,
            "java_home": str(jdk),
            "android_sdk": str(sdk),
            "sdk_package_revisions": sdk_packages,
            "gradle_wrapper": "9.5.0",
            "android_gradle_plugin": "9.3.1",
            "kotlin_gradle_plugin": "2.4.20",
            "build_tools": "37.0.0",
            "command": command_text,
            "locked_build": True,
            "targets": target_results,
            "api26_matrix_scope": "Medium_Phone Google Play x86 is the sole API 26 target in this acceptance matrix.",
        }
        result_path = report_dir / "results.json"
        result_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print(f"\nBoth accepted AVDs passed. Evidence manifest: {result_path}", flush=True)
        return 0
    finally:
        for spec, process, _ in reversed(processes):
            serial = f"emulator-{spec['port']}"
            subprocess.run([str(adb), "-s", serial, "emu", "kill"], env=env, text=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20, check=False)
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


if __name__ == "__main__":
    sys.exit(main())
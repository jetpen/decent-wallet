from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from issue18_remote_registry import RemoteRegistryPeerFixture

ROOT = Path(__file__).resolve().parents[1]
ANDROID_TEST = (
    "org.decentwallet.wallet.android.AndroidDirectDhtRegistryInteropTest."
    "readsHistoryPublishesAndFreshReadsAgainstPythonRegistryPeer"
)
DESKTOP_TEST = "tests/test_issue18_remote_registry_acceptance.py"


def desktop_test_command() -> list[str]:
    return [
        "uv",
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
        "-m",
        "registry_integration",
        DESKTOP_TEST,
    ]


def android_test_command() -> list[str]:
    return [
        "./gradlew",
        "--no-daemon",
        "--dependency-verification=strict",
        ":platforms:android-wallet:testDebugUnitTest",
        "--rerun-tasks",
        "--tests",
        ANDROID_TEST,
    ]


def _test_environment(
    writer_peer: str,
    readback_peer: str,
    *,
    sdk_default: Path | None = None,
) -> dict[str, str]:
    env = os.environ.copy()
    env["DECENT_REGISTRY_TEST_PEER"] = writer_peer
    env["DECENT_REGISTRY_TEST_READBACK_PEER"] = readback_peer
    if not env.get("ANDROID_HOME") and not env.get("ANDROID_SDK_ROOT"):
        default_sdk = sdk_default or (Path.home() / "Android" / "Sdk")
        if default_sdk.is_dir():
            env["ANDROID_HOME"] = str(default_sdk)
            env["ANDROID_SDK_ROOT"] = str(default_sdk)
    return env


def _run(command: list[str], *, env: dict[str, str]) -> None:
    print(f"Running: {' '.join(command)}", flush=True)
    result = subprocess.run(command, cwd=ROOT, env=env, check=False)
    if result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, command)


def run_acceptance(
    *,
    ssh_host: str,
    host_key_alias: str | None = None,
    phase: str = "both",
) -> None:
    if phase not in {"desktop", "jvm", "both"}:
        raise ValueError("phase must be desktop, jvm, or both")
    with RemoteRegistryPeerFixture(
        ssh_host,
        host_key_alias=host_key_alias,
        repository_root=ROOT,
    ) as fixture:
        if phase in {"desktop", "both"}:
            env = _test_environment(fixture.writer.multiaddr, fixture.readback.multiaddr)
            _run(desktop_test_command(), env=env)
        if phase == "both":
            fixture.reset()
        if phase in {"jvm", "both"}:
            env = _test_environment(fixture.writer.multiaddr, fixture.readback.multiaddr)
            _run(android_test_command(), env=env)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Deploy pinned Registry peers in a fresh temporary directory on a remote host, "
            "exercise desktop and Android host-JVM clients, and tear down the deployment."
        )
    )
    parser.add_argument("--ssh-host", required=True, help="SSH host alias or DNS name")
    parser.add_argument(
        "--host-key-alias",
        help="existing known_hosts name to verify when --ssh-host is a DNS alias",
    )
    parser.add_argument(
        "--phase",
        choices=("desktop", "jvm", "both"),
        default="both",
        help="which client path to exercise (both uses fresh peer stores between clients)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        run_acceptance(
            ssh_host=args.ssh_host,
            host_key_alias=args.host_key_alias,
            phase=args.phase,
        )
    except (OSError, RuntimeError, subprocess.CalledProcessError, TimeoutError, ValueError) as exc:
        print(f"Issue #18 remote acceptance failed: {exc}", file=sys.stderr, flush=True)
        return 1
    print("Issue #18 remote acceptance completed; temporary Registry deployment was removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

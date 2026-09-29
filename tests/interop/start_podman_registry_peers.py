from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from typing import Any


CONTAINER_PORT = 4001
STARTUP_TIMEOUT_SECONDS = 60.0
BUILD_TIMEOUT_SECONDS = 300.0
COMMAND_TIMEOUT_SECONDS = 30.0
CLEANUP_TIMEOUT_SECONDS = 3.0
CLEANUP_POLL_INTERVAL_SECONDS = 0.1
SEED_TIMEOUT_SECONDS = 90.0
FIXTURE_RELATIVE_PATH = Path("tests/vectors/identity-owner-key-rotation-legacy.json")
_BOOTSTRAP_LINE = re.compile(
    r"\[BOOTSTRAP\]\s+(/ip4/([^/\s]+)/tcp/(\d+)/p2p/([1-9A-HJ-NP-Za-km-z]{20,100}))"
    r"(?=$|[^1-9A-HJ-NP-Za-km-z])"
)
_PEER_ID = re.compile(r"[1-9A-HJ-NP-Za-km-z]{20,100}\Z")


class FixtureError(RuntimeError):
    """A safe, actionable fixture setup failure without container or record data."""


class _FixtureInterrupted(Exception):
    pass


def build_network_command(podman: str, network: str) -> list[str]:
    return [podman, "network", "create", "--driver", "bridge", "--internal", network]


def parse_rootless_status(output: str) -> bool:
    return output.strip().lower() == "true"


def build_image_command(podman: str, wallet_repo: Path, image: str) -> list[str]:
    root = wallet_repo.expanduser().resolve()
    return [
        podman,
        "build",
        "--file",
        str(root / "platforms" / "desktop-wallet" / "Containerfile"),
        "--target",
        "registry-peer",
        "--tag",
        image,
        str(root),
    ]


def build_peer_command(
    podman: str,
    *,
    name: str,
    network: str,
    image: str,
    host_port: int,
    data_path: Path,
    bootstrap: str | None,
) -> list[str]:
    if not 1 <= host_port <= 65535:
        raise FixtureError("host port is outside the valid TCP range")
    node_prefix = shlex.join(
        ["/opt/venv/bin/python", "/opt/registry_peer_node.py", "--host"]
    )
    node_suffix = [
        "--port",
        str(CONTAINER_PORT),
        "--datastore-path",
        f"/registry-data/{data_path.name}.lmdb",
    ]
    if bootstrap is not None:
        node_suffix.extend(["--bootstrap", bootstrap])
    host_lookup = (
        "/opt/venv/bin/python -c "
        + shlex.quote("import socket; print(socket.gethostbyname(socket.gethostname()))")
    )
    shell_command = (
        f"NODE_HOST=$({host_lookup}); exec {node_prefix} \"$NODE_HOST\" "
        f"{shlex.join(node_suffix)}"
    )
    return [
        podman,
        "run",
        "--detach",
        "--name",
        name,
        "--hostname",
        name,
        "--network",
        network,
        "--user",
        "0:0",
        "--log-driver",
        "k8s-file",
        "--publish",
        f"127.0.0.1:{host_port}:{CONTAINER_PORT}/tcp",
        "--volume",
        f"{data_path.resolve()}:/registry-data:Z",
        "--entrypoint",
        "/bin/sh",
        image,
        "-c",
        shell_command,
    ]


def parse_bootstrap_peer_id(logs: str) -> tuple[str | None, str]:
    bootstrap_lines = [line.strip() for line in logs.splitlines() if "[BOOTSTRAP]" in line]
    if len(bootstrap_lines) != 1:
        return None, "bootstrap_count"
    bootstrap_line = bootstrap_lines[0]
    match = _BOOTSTRAP_LINE.search(bootstrap_line)
    if match is None:
        tail = bootstrap_line.split("[BOOTSTRAP]", 1)[1].strip()
        if not tail.startswith("/ip4/"):
            return None, "bootstrap_prefix"
        return None, "bootstrap_format"
    try:
        ipaddress.IPv4Address(match.group(2))
        reported_port = int(match.group(3))
    except ValueError:
        return None, "address_value"
    if reported_port != CONTAINER_PORT:
        return None, "container_port"
    peer_id = match.group(4)
    if _PEER_ID.fullmatch(peer_id) is None:
        if re.match(r"[1-9A-HJ-NP-Za-km-z]{20,100}[^1-9A-HJ-NP-Za-km-z]", peer_id):
            return None, "bootstrap_suffix"
        return None, "peer_id"
    return peer_id, "none"


def _peer_id_from_logs(logs: str) -> str:
    peer_id, _error_code = parse_bootstrap_peer_id(logs)
    if peer_id is None:
        raise FixtureError("Registry peer did not report a valid peer address")
    return peer_id


def ready_address_from_logs(logs: str, host_port: int) -> str:
    if not 1 <= host_port <= 65535:
        raise FixtureError("host port is outside the valid TCP range")
    peer_id = _peer_id_from_logs(logs)
    return f"/ip4/127.0.0.1/tcp/{host_port}/p2p/{peer_id}"


def _resource_is_absent(
    exists_command: Sequence[str], runner: Callable[..., Any]
) -> bool:
    deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
    while True:
        try:
            probe = runner(
                list(exists_command),
                capture_output=True,
                text=True,
                timeout=CLEANUP_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        if probe.returncode == 1:
            return True
        if probe.returncode != 0 or time.monotonic() >= deadline:
            return False
        time.sleep(CLEANUP_POLL_INTERVAL_SECONDS)


def cleanup_resources(
    podman: str,
    *,
    containers: Sequence[str],
    network: str,
    image: str,
    runner: Callable[..., Any] = subprocess.run,
) -> None:
    resources = [
        (
            [podman, "rm", "--force", "--time", "0", container],
            [podman, "container", "exists", container],
        )
        for container in containers
    ]
    resources.extend(
        (
            ([podman, "network", "rm", network], [podman, "network", "exists", network]),
            ([podman, "image", "rm", "--force", image], [podman, "image", "exists", image]),
        )
    )
    leftovers = False
    for remove_command, exists_command in resources:
        try:
            runner(
                remove_command,
                capture_output=True,
                text=True,
                timeout=CLEANUP_TIMEOUT_SECONDS,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        if not _resource_is_absent(exists_command, runner):
            leftovers = True
    if leftovers:
        raise FixtureError("could not fully tear down Podman Registry resources")


def ensure_data_dir(path: Path) -> Path:
    if path.is_symlink():
        raise FixtureError("data directory must be a real, empty directory")
    try:
        path.mkdir(parents=True, exist_ok=True)
        root = path.resolve(strict=True)
        if not root.is_dir() or any(root.iterdir()):
            raise FixtureError("data directory must be empty")
        (root / "writer").mkdir()
        (root / "readback").mkdir()
    except FixtureError:
        raise
    except OSError:
        raise FixtureError("could not prepare the empty data directory") from None
    return root


def _run_command(
    command: Sequence[str], *, timeout: float = COMMAND_TIMEOUT_SECONDS
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        raise FixtureError("Podman executable was not found") from None
    except subprocess.TimeoutExpired:
        raise FixtureError("Podman command exceeded its time limit") from None
    except OSError:
        raise FixtureError("Podman command could not be started") from None


def _run_checked(command: Sequence[str], *, timeout: float = COMMAND_TIMEOUT_SECONDS) -> str:
    result = _run_command(command, timeout=timeout)
    if result.returncode != 0:
        raise FixtureError("Podman could not prepare the Registry peer fixture")
    return result.stdout


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _port_is_ready(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.25):
            return True
    except OSError:
        return False


def _wait_for_peer(podman: str, name: str, host_port: int) -> str:
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    bootstrap_records = 0
    address_error = "bootstrap_count"
    tcp_ready = False
    while time.monotonic() < deadline:
        state = _run_command(
            [podman, "inspect", "--format", "{{.State.Running}}", name]
        )
        if state.returncode == 0 and state.stdout.strip().lower() == "false":
            raise FixtureError("Registry peer container exited during startup")
        logs = _run_command([podman, "logs", name])
        if logs.returncode == 0:
            output = f"{logs.stdout}\n{logs.stderr}"
            bootstrap_records = sum("[BOOTSTRAP]" in line for line in output.splitlines())
            peer_id, address_error = parse_bootstrap_peer_id(output)
            tcp_ready = _port_is_ready(host_port)
            if peer_id is not None and tcp_ready:
                return peer_id
        else:
            address_error = "logs_unavailable"
        time.sleep(0.2)
    raise FixtureError(
        "Registry peer readiness failed "
        f"(bootstrap_records={bootstrap_records}, address_error={address_error}, "
        f"tcp_ready={str(tcp_ready).lower()})"
    )


def _container_ip(podman: str, name: str) -> str:
    output = _run_checked(
        [podman, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name]
    ).strip()
    try:
        return str(ipaddress.IPv4Address(output))
    except ipaddress.AddressValueError:
        raise FixtureError("could not determine the writer peer's internal address") from None


def _load_legacy_vector(wallet_repo: Path) -> tuple[str, bytes]:
    try:
        vector = json.loads((wallet_repo / FIXTURE_RELATIVE_PATH).read_text(encoding="utf-8"))
        owner_name = bytes.fromhex(vector["owner_name_utf8_hex"])
        envelope = bytes.fromhex(vector["predecessor_envelope_cbor_hex"])
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise FixtureError("could not load the synthetic legacy Registry vector") from None
    return owner_name.hex(), envelope


def safe_exception_type(exc: BaseException) -> str:
    nested = getattr(exc, "exceptions", ())
    if nested:
        return safe_exception_type(nested[0])
    name = type(exc).__name__
    return name if re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,39}", name) else "OtherError"


def safe_exception_detail(exc: BaseException) -> str:
    nested = getattr(exc, "exceptions", ())
    if nested:
        return safe_exception_detail(nested[0])
    detail = str(exc).strip()
    lowered = detail.lower()
    for marker in (
        "password=", "password:", "passwd=", "passwd:", "token=", "token:",
        "secret=", "secret:", "credential=", "credential:", "api_key=", "api_key:",
        "api key=", "api key:", "private_key=", "private_key:", "access_key=",
        "access_key:", "client_secret=", "client_secret:", "refresh_token=",
        "refresh_token:",
    ):
        position = lowered.find(marker)
        if position >= 0:
            detail = detail[:position].rstrip() + " [REDACTED]"
            break
    safe_tokens: list[str] = []
    for token in detail.split():
        if token.startswith(("/ip4/", "/ip6/")):
            token = "[ADDRESS]"
        elif token.startswith("/"):
            token = "[PATH]"
        elif token.startswith(("http://", "https://")) and "@" in token:
            token = "[REDACTED]"
        elif token.startswith("0x") and len(token) >= 10 and all(
            character in "0123456789abcdefABCDEF" for character in token[2:]
        ):
            token = "[REDACTED]"
        elif len(token) >= 32 and all(
            character.isalnum() or character in "+/=_-" for character in token
        ):
            token = "[REDACTED]"
        elif token.count(".") == 3 and all(
            part.isdigit() for part in token.split(".")
        ):
            token = "[ADDRESS]"
        else:
            token = "".join(
                character if character.isalnum() or character in " .,:;_()-[]" else "?"
                for character in token
            )
        safe_tokens.append(token)
    return " ".join(safe_tokens)[:200] or "no detail"


async def _seed_peer(
    peer_address: str,
    *,
    owner_name_hex: str,
    envelope: bytes,
    seed_store_path: Path,
) -> None:
    from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT
    from decent_registry.durable_store import LMDBDatastore
    from decent_registry.registry_service import RegistryService

    async with Libp2pKadDHT(
        listen="/ip4/127.0.0.1/tcp/0",
        durable_store=LMDBDatastore(path=seed_store_path),
        dht_mode=DHTMode.CLIENT,
    ) as writer:
        try:
            await writer.bootstrap(peer_address)
        except Exception as exc:
            raise FixtureError(
                f"Registry peer bootstrap failed (error={safe_exception_type(exc)}; detail={safe_exception_detail(exc)})"
            ) from None
        try:
            await RegistryService(dht=writer).put_identity_envelope(
                owner_name_hex=owner_name_hex,
                envelope_cbor=envelope,
            )
        except Exception as exc:
            raise FixtureError(
                f"Registry peer publication failed (error={safe_exception_type(exc)}; detail={safe_exception_detail(exc)})"
            ) from None



def _seed_registry_peer(
    peer_address: str,
    *,
    owner_name_hex: str,
    envelope: bytes,
    seed_store_path: Path,
) -> None:
    import trio

    async def seed() -> None:
        with trio.fail_after(SEED_TIMEOUT_SECONDS):
            await _seed_peer(
                peer_address,
                owner_name_hex=owner_name_hex,
                envelope=envelope,
                seed_store_path=seed_store_path,
            )

    try:
        trio.run(seed)
    except FixtureError:
        raise
    except trio.TooSlowError:
        raise FixtureError("Registry peer seed timed out") from None
    except Exception as exc:
        raise FixtureError(
            "Registry peer seed failed "
            f"(error={safe_exception_type(exc)}; detail={safe_exception_detail(exc)})"
        ) from None


def _read_peer(peer_address: str, *, owner_name_hex: str) -> bytes | None:
    import trio
    from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT
    from libp2p.peer.peerinfo import info_from_p2p_addr
    from multiaddr import Multiaddr

    try:
        owner_name = bytes.fromhex(owner_name_hex)
    except ValueError:
        raise FixtureError("synthetic Registry Owner Name must be valid hex") from None
    identity_key = hashlib.sha256(owner_name).hexdigest()

    async def read() -> bytes | None:
        with trio.fail_after(SEED_TIMEOUT_SECONDS):
            async with Libp2pKadDHT(
                listen="/ip4/127.0.0.1/tcp/0",
                durable_store=None,
                dht_mode=DHTMode.CLIENT,
            ) as dht:
                peer_info = info_from_p2p_addr(Multiaddr(peer_address))
                await dht.bootstrap(peer_address)
                record = await dht.dht.value_store._get_from_peer(
                    peer_info.peer_id,
                    dht._kad_key(identity_key, kind="identity").encode("utf-8"),
                    return_record=True,
                )
                candidate = getattr(record, "value", None)
                return (
                    bytes(candidate)
                    if isinstance(candidate, (bytes, bytearray))
                    else None
                )

    try:
        return trio.run(read)
    except trio.TooSlowError:
        raise FixtureError("Registry peer did not return the synthetic record") from None
    except Exception as exc:
        raise FixtureError(
            "Registry peer readback failed "
            f"(error={safe_exception_type(exc)}; detail={safe_exception_detail(exc)})"
        ) from None


def _seed_registry_peers(
    writer_address: str,
    readback_address: str,
    *,
    owner_name_hex: str,
    envelope: bytes,
    client_data_dir: Path,
) -> None:
    for role, peer_address in (
        ("writer", writer_address),
        ("readback", readback_address),
    ):
        current = _read_peer(peer_address, owner_name_hex=owner_name_hex)
        if current == envelope:
            continue
        if current is not None:
            raise FixtureError("Registry peer did not have the expected synthetic record")
        _seed_registry_peer(
            peer_address,
            owner_name_hex=owner_name_hex,
            envelope=envelope,
            seed_store_path=client_data_dir / f"seed-client-{role}.lmdb",
        )
        if _read_peer(peer_address, owner_name_hex=owner_name_hex) != envelope:
            raise FixtureError("Registry peer did not confirm the synthetic legacy record")


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Start two local rootless Podman Registry peers")
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--wallet-repo", required=True, type=Path)
    return parser.parse_args(argv)


def _handle_sigterm(_signum: int, _frame: Any) -> None:
    raise _FixtureInterrupted


def run_fixture(data_dir: Path, wallet_repo: Path) -> None:
    podman = shutil.which("podman")
    if podman is None:
        raise FixtureError("Podman executable was not found")
    rootless = _run_command([podman, "info", "--format", "{{.Host.Security.Rootless}}"])
    if rootless.returncode != 0 or not parse_rootless_status(rootless.stdout):
        raise FixtureError("the Registry fixture requires rootless Podman")
    data_root = ensure_data_dir(data_dir)
    wallet_root = wallet_repo.expanduser().resolve()
    fixture_id = uuid.uuid4().hex
    network = f"registry-peer-{fixture_id}"
    image = f"localhost/registry-peer:{fixture_id}"
    containers = [f"registry-peer-{fixture_id}-writer", f"registry-peer-{fixture_id}-readback"]
    old_sigterm = signal.signal(signal.SIGTERM, _handle_sigterm)
    try:
        writer_port = _free_loopback_port()
        readback_port = _free_loopback_port()
        _run_checked(build_network_command(podman, network))
        _run_checked(
            build_image_command(podman, wallet_root, image),
            timeout=BUILD_TIMEOUT_SECONDS,
        )
        _run_checked(
            build_peer_command(
                podman,
                name=containers[1],
                network=network,
                image=image,
                host_port=readback_port,
                data_path=data_root / "readback",
                bootstrap=None,
            )
        )
        readback_peer_id = _wait_for_peer(podman, containers[1], readback_port)
        readback_ip = _container_ip(podman, containers[1])
        readback_internal = f"/ip4/{readback_ip}/tcp/{CONTAINER_PORT}/p2p/{readback_peer_id}"
        _run_checked(
            build_peer_command(
                podman,
                name=containers[0],
                network=network,
                image=image,
                host_port=writer_port,
                data_path=data_root / "writer",
                bootstrap=readback_internal,
            )
        )
        writer_peer_id = _wait_for_peer(podman, containers[0], writer_port)
        writer_address = ready_address_from_logs(
            f"[BOOTSTRAP] /ip4/0.0.0.0/tcp/{CONTAINER_PORT}/p2p/{writer_peer_id}",
            writer_port,
        )
        readback_address = ready_address_from_logs(
            f"[BOOTSTRAP] /ip4/0.0.0.0/tcp/{CONTAINER_PORT}/p2p/{readback_peer_id}",
            readback_port,
        )
        if writer_peer_id == readback_peer_id:
            raise FixtureError("Registry peers did not receive distinct peer identities")
        owner_name_hex, envelope = _load_legacy_vector(wallet_root)
        try:
            _seed_registry_peers(
                writer_address,
                readback_address,
                owner_name_hex=owner_name_hex,
                envelope=envelope,
                client_data_dir=data_root,
            )
        except FixtureError:
            raise
        except Exception as exc:
            raise FixtureError(
                "could not seed or confirm the synthetic Registry record "
                f"(error={safe_exception_type(exc)}; detail={safe_exception_detail(exc)})"
            ) from None
        print("Synthetic legacy Identity is independently available from both peers.", flush=True)
        print(f"READY_WRITE\t{writer_address}", flush=True)
        print(f"READY_READBACK\t{readback_address}", flush=True)
        while True:
            time.sleep(60)
    finally:
        cleanup_resources(
            podman,
            containers=containers,
            network=network,
            image=image,
        )
        signal.signal(signal.SIGTERM, old_sigterm)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        run_fixture(args.data_dir, args.wallet_repo)
    except (_FixtureInterrupted, KeyboardInterrupt):
        return 0
    except FixtureError as exc:
        print(f"FIXTURE_ERROR\t{exc}", file=sys.stderr, flush=True)
        return 1
    except Exception:
        print("FIXTURE_ERROR\tRegistry peer fixture failed", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

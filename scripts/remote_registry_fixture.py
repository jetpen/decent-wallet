from __future__ import annotations

import ipaddress
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Self

_REMOTE_ROOT_NAME = re.compile(r"decent-wallet-registry-[A-Za-z0-9]{8,64}\Z")
_TAILSCALE_IPV4 = ipaddress.IPv4Network("100.64.0.0/10")
_PEER_ID = re.compile(r"[1-9A-HJ-NP-Za-km-z]{20,100}\Z")
_REGISTRY_GIT_REVISION = re.compile(r"(?:[?&]rev=|#)([0-9a-f]{40})(?=$|[&#])")


@dataclass(frozen=True)
class RemotePeerAddress:
    multiaddr: str
    host: str
    port: int
    peer_id: str


@dataclass(frozen=True)
class RemoteReady:
    phase: int
    writer: RemotePeerAddress
    readback: RemotePeerAddress


def validate_temp_root(value: str) -> Path:
    path = Path(value)
    if (
        not path.is_absolute()
        or path.parent != Path("/tmp")
        or _REMOTE_ROOT_NAME.fullmatch(path.name) is None
        or path.is_symlink()
    ):
        raise ValueError("remote Registry root must be a dedicated temporary directory")
    return path


def isolated_environment(
    root: Path,
    base_env: Mapping[str, str] | None = None,
) -> dict[str, str]:
    env = dict(os.environ if base_env is None else base_env)
    root = root.resolve()
    env.update(
        {
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
            "XDG_CACHE_HOME": str(root / "cache"),
            "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_DATA_HOME": str(root / "data-home"),
            "XDG_STATE_HOME": str(root / "state"),
            "PIP_CACHE_DIR": str(root / "pip-cache"),
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "UV_CACHE_DIR": str(root / "uv-cache"),
            "UV_PROJECT_ENVIRONMENT": str(root / "registry-venv"),
            "UV_LINK_MODE": "copy",
            "UV_NO_CONFIG": "1",
            "CARGO_HOME": str(root / "cargo"),
            "RUSTUP_HOME": str(root / "rustup"),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
            "PYTHONNOUSERSITE": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )
    return env


def registry_revision_from_lock_text(lock_text: str) -> str:
    try:
        lock = tomllib.loads(lock_text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError("wallet uv.lock is invalid TOML") from exc
    packages = [item for item in lock.get("package", []) if item.get("name") == "decent-registry"]
    if len(packages) != 1:
        raise ValueError("wallet uv.lock must pin exactly one decent-registry source")
    source = packages[0].get("source")
    git_url = source.get("git") if isinstance(source, dict) else None
    if not isinstance(git_url, str) or not git_url.startswith(
        "https://github.com/jetpen/decent-registry.git?"
    ):
        raise ValueError("wallet uv.lock does not pin the expected decent-registry repository")
    revisions = _REGISTRY_GIT_REVISION.findall(git_url)
    if len(revisions) < 1 or len(set(revisions)) != 1:
        raise ValueError("wallet uv.lock must pin a single immutable decent-registry commit")
    return revisions[0]


def parse_remote_peer_address(
    value: str,
    *,
    expected_host: str | None = None,
) -> RemotePeerAddress:
    match = re.fullmatch(
        r"/ip4/([^/]+)/tcp/([0-9]+)/p2p/([1-9A-HJ-NP-Za-km-z]{20,100})",
        value.strip(),
    )
    if match is None:
        raise ValueError("fixture emitted an invalid or unpinned Registry peer multiaddr")
    raw_host, raw_port, peer_id = match.groups()
    try:
        host = str(ipaddress.IPv4Address(raw_host))
        port = int(raw_port)
    except ipaddress.AddressValueError as exc:
        raise ValueError("fixture emitted an invalid Registry peer multiaddr") from exc
    except ValueError as exc:
        raise ValueError("fixture emitted an invalid Registry peer multiaddr") from exc
    if (
        not 1 <= port <= 65535
        or _PEER_ID.fullmatch(peer_id) is None
        or ipaddress.IPv4Address(host) not in _TAILSCALE_IPV4
    ):
        raise ValueError("fixture emitted an invalid or non-Tailscale Registry peer multiaddr")
    if expected_host is not None and host != str(ipaddress.IPv4Address(expected_host)):
        raise ValueError("Registry peer is not bound to the expected remote interface")
    return RemotePeerAddress(value.strip(), host, port, peer_id)


def parse_remote_ready_record(
    line: str,
    *,
    expected_phase: int,
    expected_host: str | None = None,
) -> RemoteReady:
    tag, separator, payload = line.strip().partition("\t")
    if tag != "REMOTE_READY" or not separator:
        raise ValueError("remote Registry fixture did not report readiness")
    try:
        value = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ValueError("remote Registry fixture reported invalid readiness data") from exc
    if not isinstance(value, dict):
        raise ValueError("remote Registry fixture reported invalid readiness data")  # noqa: TRY004
    phase = value.get("phase")
    if (
        isinstance(phase, bool)
        or not isinstance(phase, int)
        or phase != expected_phase
    ):
        raise ValueError("remote Registry fixture reported an unexpected test phase")
    writer_value = value.get("writer")
    readback_value = value.get("readback")
    if not isinstance(writer_value, str) or not isinstance(readback_value, str):
        raise TypeError("remote Registry fixture reported invalid readiness data")
    writer = parse_remote_peer_address(writer_value, expected_host=expected_host)
    readback_host = expected_host or writer.host
    readback = parse_remote_peer_address(readback_value, expected_host=readback_host)
    if writer.peer_id == readback.peer_id or writer.port == readback.port:
        raise ValueError("remote deployment requires distinct writer and read-back peers")
    return RemoteReady(phase, writer, readback)


def _validate_ssh_token(value: str, description: str) -> str:
    if not value or value.startswith("-") or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value) is None:
        raise ValueError(f"invalid SSH {description}")
    return value


def ssh_command(
    host: str,
    *,
    host_key_alias: str | None = None,
    remote_args: Sequence[str],
) -> list[str]:
    host = _validate_ssh_token(host, "host")
    command = [
        "ssh",
        "-T",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oConnectTimeout=15",
        "-oServerAliveInterval=15",
        "-oServerAliveCountMax=4",
    ]
    if host_key_alias is not None:
        alias = _validate_ssh_token(host_key_alias, "host-key alias")
        command.append(f"-oHostKeyAlias={alias}")
    command.extend([host, *remote_args])
    return command


def validate_temp_destination(value: str) -> Path:
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or len(path.parts) < 4:
        raise ValueError("remote file destination must stay inside the temporary Registry directory")
    root = Path("/tmp") / path.parts[2]
    try:
        validate_temp_root(str(root))
    except ValueError as exc:
        raise ValueError("remote file destination must stay inside the temporary Registry directory") from exc
    if root not in path.parents:
        raise ValueError("remote file destination must stay inside the temporary Registry directory")
    return path


def scp_command(
    host: str,
    *,
    host_key_alias: str | None = None,
    source: Path,
    remote_path: str,
) -> list[str]:
    host = _validate_ssh_token(host, "host")
    remote_path = str(validate_temp_destination(remote_path))
    command = [
        "scp",
        "-q",
        "-oBatchMode=yes",
        "-oStrictHostKeyChecking=yes",
        "-oConnectTimeout=15",
        "-oServerAliveInterval=15",
        "-oServerAliveCountMax=4",
    ]
    if host_key_alias is not None:
        alias = _validate_ssh_token(host_key_alias, "host-key alias")
        command.append(f"-oHostKeyAlias={alias}")
    command.extend([str(source), f"{host}:{remote_path}"])
    return command


class RemoteRegistryPeerFixture:
    """Own an isolated, temporary Registry peer mesh on an SSH host."""

    def __init__(
        self,
        host: str,
        *,
        host_key_alias: str | None = None,
        repository_root: Path | None = None,
        startup_timeout: float = 2400,
        shutdown_timeout: float = 120,
    ) -> None:
        self.host = _validate_ssh_token(host, "host")
        self.host_key_alias = host_key_alias
        if host_key_alias is not None:
            _validate_ssh_token(host_key_alias, "host-key alias")
        self.repository_root = (repository_root or Path(__file__).resolve().parents[1]).resolve()
        self.startup_timeout = startup_timeout
        self.shutdown_timeout = shutdown_timeout
        self.registry_revision = ""
        self.remote_root: Path | None = None
        self.process: subprocess.Popen[str] | None = None
        self.ready: RemoteReady | None = None
        self._messages: queue.Queue[str | None] = queue.Queue()
        self._reader: threading.Thread | None = None
        self._stopped_event = threading.Event()
        self._phase = 0

    @property
    def writer(self) -> RemotePeerAddress:
        if self.ready is None:
            raise RuntimeError("remote Registry fixture is not ready")
        return self.ready.writer

    @property
    def readback(self) -> RemotePeerAddress:
        if self.ready is None:
            raise RuntimeError("remote Registry fixture is not ready")
        return self.ready.readback

    def _ssh(self, remote_args: Sequence[str]) -> list[str]:
        return ssh_command(
            self.host,
            host_key_alias=self.host_key_alias,
            remote_args=remote_args,
        )

    def _run_remote(self, remote_args: Sequence[str], *, timeout: float = 45) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                self._ssh(remote_args),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=timeout,
                text=True,
                cwd=self.repository_root,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("remote Registry fixture SSH command failed") from exc

    def _allocate_remote_root(self) -> Path:
        result = self._run_remote(
            ["mktemp", "-d", "--tmpdir=/tmp", "decent-wallet-registry-XXXXXXXXXXXX"]
        )
        if result.returncode != 0:
            raise RuntimeError("could not create the temporary Registry test directory")
        lines = result.stdout.splitlines()
        if len(lines) != 1:
            raise RuntimeError("remote mktemp returned an invalid directory path")
        return validate_temp_root(lines[0])

    def _copy_inputs(self, root: Path) -> None:
        directories = [
            str(root / "fixtures" / "tests" / "interop"),
            str(root / "fixtures" / "tests" / "vectors"),
        ]
        result = self._run_remote(["mkdir", "-p", *directories])
        if result.returncode != 0:
            raise RuntimeError("could not prepare the temporary Registry test directory")
        files = (
            (
                self.repository_root / "tests" / "interop" / "remote_registry_host.py",
                root / "remote_registry_host.py",
            ),
            (
                self.repository_root / "tests" / "interop" / "start_android_registry_peer.py",
                root / "fixtures" / "tests" / "interop" / "start_android_registry_peer.py",
            ),
            (
                self.repository_root / "tests" / "vectors" / "identity-owner-key-rotation-legacy.json",
                root / "fixtures" / "tests" / "vectors" / "identity-owner-key-rotation-legacy.json",
            ),
        )
        for source, remote_path in files:
            if not source.is_file():
                raise RuntimeError(f"required remote fixture input is missing: {source.name}")
            try:
                result = subprocess.run(
                    scp_command(
                        self.host,
                        host_key_alias=self.host_key_alias,
                        source=source,
                        remote_path=str(remote_path),
                    ),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=False,
                    timeout=90,
                    text=True,
                    cwd=self.repository_root,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise RuntimeError("could not copy the temporary Registry fixture inputs") from exc
            if result.returncode != 0:
                raise RuntimeError("could not copy the temporary Registry fixture inputs")

    def _read_stdout(self) -> None:
        assert self.process is not None and self.process.stdout is not None
        try:
            for line in self.process.stdout:
                normalized = line.rstrip("\r\n")
                if normalized.startswith("REMOTE_STOPPED\t"):
                    self._stopped_event.set()
                self._messages.put(normalized)
        finally:
            self._messages.put(None)

    def _wait_ready(self, expected_phase: int) -> RemoteReady:
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            if self.process is None:
                raise RuntimeError("remote Registry fixture process is missing")
            if self.process.poll() is not None and self._messages.empty():
                raise RuntimeError("remote Registry fixture exited before becoming ready")
            try:
                line = self._messages.get(timeout=min(0.25, max(0.01, deadline - time.monotonic())))
            except queue.Empty:
                continue
            if line is None:
                raise RuntimeError("remote Registry fixture closed its output before readiness")
            if line.startswith("REMOTE_STAGE\t"):
                stage = line.partition("\t")[2]
                print(f"remote Registry preflight: {stage}", file=sys.stderr, flush=True)
                continue
            if line.startswith("REMOTE_ERROR\t"):
                code = line.partition("\t")[2]
                raise RuntimeError(f"remote Registry preflight failed: {code}")
            if line.startswith("REMOTE_CLEANUP_REQUIRED\t"):
                raise RuntimeError("remote Registry preflight could not clean its temporary deployment")
            if line.startswith("REMOTE_READY\t"):
                try:
                    return parse_remote_ready_record(line, expected_phase=expected_phase)
                except ValueError as exc:
                    raise RuntimeError("remote Registry fixture reported invalid peer addresses") from exc
        raise TimeoutError("remote Registry preflight did not become ready before its deadline")

    def __enter__(self) -> Self:
        try:
            lock_path = self.repository_root / "uv.lock"
            self.registry_revision = registry_revision_from_lock_text(
                lock_path.read_text(encoding="utf-8")
            )
            self.remote_root = self._allocate_remote_root()
            self._copy_inputs(self.remote_root)
            command = self._ssh(
                [
                    "python3",
                    "-B",
                    str(self.remote_root / "remote_registry_host.py"),
                    "serve",
                    "--root",
                    str(self.remote_root),
                    "--registry-revision",
                    self.registry_revision,
                ]
            )
            self.process = subprocess.Popen(
                command,
                cwd=self.repository_root,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
            self._reader = threading.Thread(target=self._read_stdout, daemon=True)
            self._reader.start()
            self.ready = self._wait_ready(1)
            self._phase = 1
            return self
        except BaseException as error:
            try:
                self.close()
            except Exception as cleanup_error:  # noqa: BLE001 -- preserve the original error while recording any cleanup failure
                error.add_note(f"remote temporary deployment cleanup also failed: {cleanup_error}")
            raise

    def reset(self) -> RemoteReady:
        if self.process is None or self.process.stdin is None or self.ready is None:
            raise RuntimeError("remote Registry fixture is not running")
        if self.process.poll() is not None:
            raise RuntimeError("remote Registry fixture exited before reset")
        self._phase += 1
        try:
            self.process.stdin.write("RESET\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            self._phase -= 1
            raise RuntimeError("remote Registry fixture could not reset its peer stores") from exc
        self.ready = self._wait_ready(self._phase)
        return self.ready

    def _remote_exists(self, path: Path) -> bool:
        result = self._run_remote(["test", "-e", str(path)])
        if result.returncode == 0:
            return True
        if result.returncode == 1:
            return False
        raise RuntimeError("could not verify remote temporary-directory state")

    def _remove_remote_root(self) -> None:
        if self.remote_root is None or not self._remote_exists(self.remote_root):
            return
        helper = self.remote_root / "remote_registry_host.py"
        if self._remote_exists(helper):
            result = self._run_remote(
                ["python3", "-B", str(helper), "cleanup", "--root", str(self.remote_root)],
                timeout=self.shutdown_timeout,
            )
            if result.returncode == 0 and not self._remote_exists(self.remote_root):
                return
            marker = self.remote_root / ".decent-wallet-registry-test"
            worker_stopped = self.process is None or self.process.poll() is not None
            if self._remote_exists(marker) or not worker_stopped:
                raise RuntimeError("remote Registry cleanup refused to remove its temporary root")
        if self.process is not None and self.process.poll() is None:
            raise RuntimeError("remote cleanup helper is missing while a peer process may still run")
        # This path came directly from mktemp and passed validate_temp_root; no home or system path is eligible.
        result = self._run_remote(["rm", "-rf", "--", str(self.remote_root)], timeout=45)
        if result.returncode != 0 or self._remote_exists(self.remote_root):
            raise RuntimeError("remote temporary Registry directory could not be removed")

    def close(self) -> None:
        cleanup_error: Exception | None = None
        process = self.process
        if process is not None:
            return_code: int | None = None
            try:
                if process.poll() is None and process.stdin is not None:
                    try:
                        process.stdin.write("STOP\n")
                        process.stdin.flush()
                    except (BrokenPipeError, OSError):
                        pass
                try:
                    return_code = process.wait(timeout=self.shutdown_timeout)
                except subprocess.TimeoutExpired:
                    try:
                        process.terminate()
                        return_code = process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        try:
                            process.kill()
                            return_code = process.wait(timeout=10)
                        except Exception as exc:  # noqa: BLE001 -- preserve wait failure for the caller
                            cleanup_error = exc
                    except Exception as exc:  # noqa: BLE001 -- preserve wait failure for the caller
                        cleanup_error = exc
                except Exception as exc:  # noqa: BLE001 -- preserve wait failure for the caller
                    cleanup_error = exc
                if self._reader is not None:
                    self._reader.join(timeout=5)
                if cleanup_error is None:
                    if return_code != 0:
                        cleanup_error = RuntimeError(
                            f"remote Registry fixture exited with status {return_code} during teardown"
                        )
                    elif not self._stopped_event.is_set():
                        cleanup_error = RuntimeError(
                            "remote Registry fixture did not confirm teardown completion"
                        )
            except Exception as exc:  # noqa: BLE001 -- cleanup must still run after any worker error
                cleanup_error = cleanup_error or exc
            finally:
                try:
                    self._remove_remote_root()
                except (RuntimeError, OSError, ValueError) as exc:
                    cleanup_error = cleanup_error or exc
                self.process = None
        elif self.remote_root is not None:
            try:
                self._remove_remote_root()
            except (RuntimeError, OSError, ValueError) as exc:
                cleanup_error = exc
        if cleanup_error is not None:
            raise cleanup_error

    def __exit__(self, exc_type: object, exc: BaseException | None, traceback: object) -> bool:
        try:
            self.close()
        except Exception as cleanup_error:
            if exc is not None:
                exc.add_note(f"remote temporary deployment cleanup also failed: {cleanup_error}")
                return False
            raise
        return False

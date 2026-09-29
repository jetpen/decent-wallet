from __future__ import annotations

import argparse
import ipaddress
import json
import os
import queue
import re
import resource
import select
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

ROOT_PATTERN = re.compile(r"issue18-registry-[A-Za-z0-9]{8,64}\Z")
REVISION_PATTERN = re.compile(r"[0-9a-f]{40}\Z")
REGISTRY_URL = "https://github.com/jetpen/decent-registry.git"
UV_VERSION = "0.12.19"
MARKER_NAME = ".issue18-remote-test"
MAX_LIFETIME_SECONDS = 3600
STARTUP_TIMEOUT_SECONDS = 180
_ACTIVE_SETUP_PROCESS: subprocess.Popen[bytes] | None = None
_ACTIVE_PEER_PROCESS: subprocess.Popen[str] | None = None
_UNSET = object()


class RemoteSetupError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def validate_registry_revision(value: str) -> str:
    if REVISION_PATTERN.fullmatch(value) is None:
        raise ValueError("Registry revision must be a full commit hash")
    return value


def tailscale_ipv4(output: str) -> str:
    addresses = [line.strip() for line in output.splitlines() if line.strip()]
    if len(addresses) != 1:
        raise ValueError("expected exactly one Tailscale IPv4 address")
    try:
        address = ipaddress.IPv4Address(addresses[0])
    except ipaddress.AddressValueError as exc:
        raise ValueError("Tailscale did not return an IPv4 address") from exc
    if address not in ipaddress.IPv4Network("100.64.0.0/10"):
        raise ValueError("Registry test peers must bind only to a Tailscale IPv4 address")
    return str(address)


def validate_root(root_text: str, *, require_marker: bool = False) -> Path:
    root = Path(root_text)
    if (
        not root.is_absolute()
        or root.parent != Path("/tmp")
        or ROOT_PATTERN.fullmatch(root.name) is None
        or root.is_symlink()
        or not root.is_dir()
    ):
        raise ValueError("remote root is not an owned Issue #18 temporary directory")
    if root.stat().st_uid != os.getuid():
        raise ValueError("remote temporary directory is not owned by the current user")
    if require_marker:
        marker = root / MARKER_NAME
        if not marker.is_file() or marker.read_text(encoding="utf-8") != "issue18-remote-test\n":
            raise ValueError("remote temporary directory marker does not match")
    return root


def _isolated_env(root: Path) -> dict[str, str]:
    root = root.resolve()
    paths = {
        "HOME": root / "home",
        "TMPDIR": root / "tmp",
        "XDG_CACHE_HOME": root / "cache",
        "XDG_CONFIG_HOME": root / "config",
        "XDG_DATA_HOME": root / "data-home",
        "XDG_STATE_HOME": root / "state",
        "PIP_CACHE_DIR": root / "pip-cache",
        "UV_CACHE_DIR": root / "uv-cache",
        "UV_PROJECT_ENVIRONMENT": root / "registry-venv",
        "CARGO_HOME": root / "cargo",
        "RUSTUP_HOME": root / "rustup",
    }
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "UV_LINK_MODE": "copy",
        "UV_NO_CONFIG": "1",
    }
    env.update({key: str(path) for key, path in paths.items()})
    return env


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    session_id = getattr(process, "_issue18_session_id", None) or _process_session_id(process.pid)
    leader_start_time = getattr(process, "_issue18_start_time", None) or _process_start_time(process.pid)
    if not _stop_process_group(
        process.pid,
        lambda _pid: True,
        gentle_signal=signal.SIGTERM,
        validated_group=True,
        process=process,
        session_id=session_id,
        leader_start_time=leader_start_time,
    ):
        raise RemoteSetupError("registry_setup_process_would_not_stop")


def _run_setup_command(
    root: Path,
    command: list[str],
    *,
    env: dict[str, str],
    log_path: Path,
    timeout: int,
    stage: str,
    cwd: Path | None = None,
) -> None:
    global _ACTIVE_SETUP_PROCESS
    with log_path.open("ab") as log:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        _ACTIVE_SETUP_PROCESS = process
        try:
            process_session_id = _process_session_id(process.pid)
            process_start_time = _process_start_time(process.pid)
            if process_session_id is None or process_start_time is None:
                raise RemoteSetupError("registry_setup_process_identity_unavailable")
            process_metadata: Any = process
            process_metadata._issue18_session_id = process_session_id
            process_metadata._issue18_start_time = process_start_time
            _write_manifest(
                root,
                setup_pid=process.pid,
                setup_group_id=process.pid,
                setup_session_id=process_session_id,
                setup_start_time=process_start_time,
            )
            try:
                return_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired as exc:
                _terminate_process_group(process)
                raise RemoteSetupError(f"{stage}_timeout") from exc
            if return_code != 0:
                raise RemoteSetupError(f"{stage}_failed_{return_code}")
        except BaseException:
            _terminate_process_group(process)
            raise
        finally:
            _ACTIVE_SETUP_PROCESS = None
            if root.exists():
                _write_manifest(root, setup_pid=None)


def _prepare_environment(root: Path, revision: str) -> tuple[Path, dict[str, str]]:
    env = _isolated_env(root)
    for variable in (
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "PIP_CACHE_DIR",
        "UV_CACHE_DIR",
        "CARGO_HOME",
        "RUSTUP_HOME",
    ):
        Path(env[variable]).mkdir(parents=True, exist_ok=True)
    uv_site = root / "uv-site"
    uv_site.mkdir()
    source = root / "decent-registry"
    log_path = root / "setup.log"
    log_path.touch()

    print("REMOTE_STAGE\tinstall-uv-in-temporary-directory", flush=True)
    _run_setup_command(
        root,
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-warn-script-location",
            "--target",
            str(uv_site),
            f"uv=={UV_VERSION}",
        ],
        env=env,
        log_path=log_path,
        timeout=600,
        stage="uv_install",
    )
    uv_env = dict(env)
    uv_env["PYTHONPATH"] = str(uv_site)

    print("REMOTE_STAGE\tfetching-pinned-registry-source", flush=True)
    _run_setup_command(
        root,
        ["git", "init", "--quiet", str(source)],
        env=uv_env,
        log_path=log_path,
        timeout=60,
        stage="registry_git_init",
    )
    _run_setup_command(
        root,
        ["git", "-C", str(source), "remote", "add", "origin", REGISTRY_URL],
        env=uv_env,
        log_path=log_path,
        timeout=60,
        stage="registry_git_remote",
    )
    _run_setup_command(
        root,
        ["git", "-C", str(source), "fetch", "--quiet", "--depth=1", "origin", revision],
        env=uv_env,
        log_path=log_path,
        timeout=300,
        stage="registry_git_fetch",
    )
    _run_setup_command(
        root,
        ["git", "-C", str(source), "checkout", "--quiet", "--detach", "FETCH_HEAD"],
        env=uv_env,
        log_path=log_path,
        timeout=60,
        stage="registry_git_checkout",
    )
    print("REMOTE_STAGE\tinstalling-registry-dependencies-in-temporary-directory", flush=True)
    _run_setup_command(
        root,
        [
            sys.executable,
            "-m",
            "uv",
            "sync",
            "--locked",
            "--no-dev",
            "--project",
            str(source),
        ],
        env=uv_env,
        log_path=log_path,
        timeout=900,
        stage="registry_dependency_sync",
        cwd=source,
    )
    python = root / "registry-venv" / "bin" / "python"
    if not python.is_file():
        raise RemoteSetupError("registry_venv_missing")
    return python, uv_env


def _tailscale_address(root: Path, env: dict[str, str]) -> str:
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
            text=True,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RemoteSetupError("tailscale_lookup_failed") from exc
    if result.returncode != 0:
        raise RemoteSetupError("tailscale_lookup_failed")
    try:
        return tailscale_ipv4(result.stdout)
    except ValueError as exc:
        raise RemoteSetupError("tailscale_address_invalid") from exc


def _parse_peer_address(value: str, expected_host: str) -> tuple[str, int, str]:
    match = re.fullmatch(
        r"/ip4/([^/]+)/tcp/([0-9]+)/p2p/([1-9A-HJ-NP-Za-km-z]{20,100})",
        value.strip(),
    )
    if match is None:
        raise ValueError("invalid peer address")
    host_text, port_text, peer_id = match.groups()
    host = str(ipaddress.IPv4Address(host_text))
    port = int(port_text)
    if (
        host != expected_host
        or ipaddress.IPv4Address(host) not in ipaddress.IPv4Network("100.64.0.0/10")
        or not 1 <= port <= 65535
    ):
        raise ValueError("peer address is outside the temporary Tailscale deployment")
    return host, port, peer_id


def _peer_address_from_line(line: str, expected_tag: str, expected_host: str) -> str:
    tag, separator, address = line.strip().partition("\t")
    if tag != expected_tag or not separator:
        raise RemoteSetupError("registry_peer_ready_line_invalid")
    try:
        _parse_peer_address(address, expected_host)
    except ValueError as exc:
        raise RemoteSetupError("registry_peer_address_invalid") from exc
    return address.strip()


def _read_manifest(root: Path) -> dict[str, Any]:
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        return {}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RemoteSetupError("remote_manifest_invalid") from exc
    if not isinstance(manifest, dict):
        raise RemoteSetupError("remote_manifest_invalid")
    return manifest


def _write_manifest(
    root: Path,
    *,
    phase: int | None = None,
    pid: int | None | object = _UNSET,
    process_group_id: int | None | object = _UNSET,
    process_session_id: int | None | object = _UNSET,
    process_start_time: int | None | object = _UNSET,
    setup_pid: int | None | object = _UNSET,
    setup_group_id: int | None | object = _UNSET,
    setup_session_id: int | None | object = _UNSET,
    setup_start_time: int | None | object = _UNSET,
    supervisor_session_id: int | None | object = _UNSET,
    supervisor_start_time: int | None | object = _UNSET,
    supervisor_pid: int | None | object = _UNSET,
) -> None:
    manifest = _read_manifest(root)
    if phase is not None:
        manifest["phase"] = phase
    if pid is not _UNSET:
        manifest["peer_fixture_pid"] = pid
    if process_group_id is not _UNSET:
        manifest["peer_process_group_id"] = process_group_id
    if process_session_id is not _UNSET:
        manifest["peer_process_session_id"] = process_session_id
    if process_start_time is not _UNSET:
        manifest["peer_process_start_time"] = process_start_time
    if setup_pid is not _UNSET:
        manifest["setup_pid"] = setup_pid
    if setup_group_id is not _UNSET:
        manifest["setup_process_group_id"] = setup_group_id
    if setup_session_id is not _UNSET:
        manifest["setup_process_session_id"] = setup_session_id
    if setup_start_time is not _UNSET:
        manifest["setup_process_start_time"] = setup_start_time
    if supervisor_session_id is not _UNSET:
        manifest["supervisor_session_id"] = supervisor_session_id
    if supervisor_start_time is not _UNSET:
        manifest["supervisor_start_time"] = supervisor_start_time
    if supervisor_pid is not _UNSET:
        manifest["supervisor_pid"] = supervisor_pid
    temporary = root / "manifest.json.tmp"
    temporary.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    temporary.replace(root / "manifest.json")


def _start_peer_phase(
    root: Path,
    *,
    python: Path,
    env: dict[str, str],
    host: str,
    phase: int,
) -> tuple[subprocess.Popen[str], threading.Thread, str, str]:
    global _ACTIVE_PEER_PROCESS
    fixture = root / "fixtures" / "tests" / "interop" / "start_android_registry_peer.py"
    data_dir = root / "data" / f"phase-{phase}"
    data_dir.mkdir(parents=True, exist_ok=False)
    log_path = root / f"phase-{phase}.log"
    child_env = dict(env)
    child_env["PYTHONPATH"] = str(root / "uv-site")
    command = [
        str(python),
        str(fixture),
        "--listen-host",
        host,
        "--advertise-host",
        host,
        "--data-dir",
        str(data_dir),
    ]
    process = subprocess.Popen(
        command,
        cwd=root,
        env=child_env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    _ACTIVE_PEER_PROCESS = process
    try:
        process_session_id = _process_session_id(process.pid)
        process_start_time = _process_start_time(process.pid)
        if process_session_id is None or process_start_time is None:
            raise RemoteSetupError("registry_peer_process_identity_unavailable")
        process_metadata: Any = process
        process_metadata._issue18_session_id = process_session_id
        process_metadata._issue18_start_time = process_start_time
        _write_manifest(
            root,
            phase=phase,
            pid=process.pid,
            process_group_id=process.pid,
            process_session_id=process_session_id,
            process_start_time=process_start_time,
        )
    except BaseException:
        _stop_peer_process(process)
        _ACTIVE_PEER_PROCESS = None
        raise
    messages: queue.Queue[str] = queue.Queue()

    def capture_output() -> None:
        assert process.stdout is not None
        with log_path.open("w", encoding="utf-8") as log:
            for output_line in process.stdout:
                log.write(output_line)
                log.flush()
                if output_line.startswith(("READY_WRITE\t", "READY_READBACK\t")):
                    messages.put(output_line)

    thread = threading.Thread(target=capture_output, daemon=True)
    thread.start()
    try:
        ready: dict[str, str] = {}
        deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
        while len(ready) < 2:
            if process.poll() is not None:
                raise RemoteSetupError("registry_peer_fixture_exited_during_startup")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RemoteSetupError("registry_peer_fixture_startup_timeout")
            try:
                line = messages.get(timeout=min(0.25, remaining))
            except queue.Empty:
                continue
            tag = line.split("\t", 1)[0]
            if tag in ready:
                raise RemoteSetupError("registry_peer_fixture_duplicate_ready_line")
            ready[tag] = line
        writer = _peer_address_from_line(ready["READY_WRITE"], "READY_WRITE", host)
        readback = _peer_address_from_line(ready["READY_READBACK"], "READY_READBACK", host)
        writer_id = _parse_peer_address(writer, host)[2]
        readback_id = _parse_peer_address(readback, host)[2]
        if writer_id == readback_id:
            raise RemoteSetupError("registry_peers_not_independent")
        _write_manifest(root, phase=phase, pid=process.pid)
        return process, thread, writer, readback
    except BaseException:
        _stop_peer_process(process)
        _ACTIVE_PEER_PROCESS = None
        thread.join(timeout=2)
        raise


def _stop_peer_process(process: subprocess.Popen[str] | None) -> bool:
    if process is None:
        return True
    session_id = getattr(process, "_issue18_session_id", None) or _process_session_id(process.pid)
    leader_start_time = getattr(process, "_issue18_start_time", None) or _process_start_time(process.pid)
    return _stop_process_group(
        process.pid,
        lambda _pid: True,
        gentle_signal=signal.SIGINT,
        validated_group=True,
        process=process,
        session_id=session_id,
        leader_start_time=leader_start_time,
    )


def _process_parts(pid: int) -> list[bytes] | None:
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return None


def _process_ids() -> list[int]:
    try:
        return [
            int(entry.name)
            for entry in Path("/proc").iterdir()
            if entry.name.isdecimal()
        ]
    except OSError:
        return []


def _process_start_time(pid: int) -> int | None:
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (OSError, UnicodeError):
        return None
    fields = stat.rsplit(") ", 1)
    if len(fields) != 2:
        return None
    values = fields[1].split()
    try:
        return int(values[19])
    except (IndexError, ValueError):
        return None


def _process_session_id(pid: int) -> int | None:
    try:
        return os.getsid(pid)
    except OSError:
        return None


def _group_identity_matches(
    group_id: int,
    session_id: int | None,
    leader_start_time: int | None,
    members: list[int] | None = None,
) -> bool:
    if session_id is None or leader_start_time is None:
        return False
    members = _process_group_pids(group_id) if members is None else members
    for member in members:
        if _process_session_id(member) != session_id:
            return False
    return group_id not in members or _process_start_time(group_id) == leader_start_time


def _process_identity_matches(pid: int, session_id: int | None, start_time: int | None) -> bool:
    return (
        session_id is not None
        and start_time is not None
        and _process_session_id(pid) == session_id
        and _process_start_time(pid) == start_time
    )


def _is_peer_process(pid: int, root: Path) -> bool:
    parts = _process_parts(pid)
    if parts is None:
        return False
    fixture = str(root / "fixtures" / "tests" / "interop" / "start_android_registry_peer.py").encode()
    data_prefix = str(root / "data").encode()
    return fixture in parts and any(data_prefix in part for part in parts)


def _is_own_process_group(pid: int, root: Path) -> bool:
    try:
        is_group_leader = os.getpgid(pid) == pid
    except OSError:
        return False
    return is_group_leader and _is_peer_process(pid, root)


def _is_setup_process(pid: int, root: Path) -> bool:
    parts = _process_parts(pid)
    if parts is None:
        return False
    return any(str(root).encode() in part for part in parts)


def _is_setup_process_group(pid: int, root: Path) -> bool:
    try:
        is_group_leader = os.getpgid(pid) == pid
    except OSError:
        return False
    return is_group_leader and _is_setup_process(pid, root)


def _process_group_pids(group_id: int) -> list[int]:
    members: list[int] = []
    for pid in _process_ids():
        try:
            if os.getpgid(pid) == group_id:
                members.append(pid)
        except OSError:
            continue
    return members


def _owned_process_group_pids(group_id: int, predicate: Any) -> list[int]:
    members: list[int] = []
    for pid in _process_ids():
        try:
            if os.getpgid(pid) == group_id and predicate(pid):
                members.append(pid)
        except OSError:
            continue
    return members


def _owned_process_group_ids(root: Path, predicate: Any) -> set[int]:
    groups: set[int] = set()
    for pid in _process_ids():
        if not predicate(pid):
            continue
        try:
            groups.add(os.getpgid(pid))
        except OSError:
            continue
    return groups


def _is_supervisor(pid: int, root: Path) -> bool:
    parts = _process_parts(pid)
    if parts is None:
        return False
    script = str(root / "remote_registry_host.py").encode()
    return (
        script in parts
        and b"serve" in parts
        and b"--root" in parts
        and str(root).encode() in parts
    )


def _valid_pid(value: object) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and value > 1:
        return value
    return None


def _stop_process_group(
    group_id: int,
    predicate: Any,
    *,
    gentle_signal: int,
    validated_group: bool = False,
    process: subprocess.Popen[Any] | None = None,
    session_id: int | None = None,
    leader_start_time: int | None = None,
) -> bool:
    if validated_group:
        members = _process_group_pids(group_id)
        if not members:
            return True
        if not _group_identity_matches(group_id, session_id, leader_start_time, members):
            return False
    elif not _owned_process_group_pids(group_id, predicate):
        return True
    for wait_seconds, signal_number in (
        (20, gentle_signal),
        (5, signal.SIGTERM),
        (5, signal.SIGKILL),
    ):
        try:
            os.killpg(group_id, signal_number)
        except ProcessLookupError:
            return True
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            if process is not None:
                try:
                    process.wait(timeout=0)
                except subprocess.TimeoutExpired:
                    pass
            if not _process_group_pids(group_id):
                return True
            time.sleep(0.1)
    return not _process_group_pids(group_id)


def _signal_owned_process_group(process: subprocess.Popen[Any], signal_number: int) -> bool:
    session_id = getattr(process, "_issue18_session_id", None) or _process_session_id(process.pid)
    leader_start_time = getattr(process, "_issue18_start_time", None) or _process_start_time(process.pid)
    members = _process_group_pids(process.pid)
    if not members:
        return True
    if not _group_identity_matches(process.pid, session_id, leader_start_time, members):
        return False
    try:
        os.killpg(process.pid, signal_number)
    except ProcessLookupError:
        return True
    return True


def cleanup_root(root_text: str, *, stop_supervisor: bool = False) -> None:
    root = validate_root(root_text, require_marker=True)
    manifest = _read_manifest(root)
    if stop_supervisor:
        supervisor_pid = _valid_pid(manifest.get("supervisor_pid"))
        supervisor_session_id = _valid_pid(manifest.get("supervisor_session_id"))
        supervisor_start_time = _valid_pid(manifest.get("supervisor_start_time"))
        if (
            supervisor_pid is not None
            and supervisor_pid != os.getpid()
            and _is_supervisor(supervisor_pid, root)
        ):
            if not _process_identity_matches(
                supervisor_pid,
                supervisor_session_id,
                supervisor_start_time,
            ):
                raise RemoteSetupError("registry_supervisor_identity_mismatch")
            try:
                os.kill(supervisor_pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline and _is_supervisor(supervisor_pid, root):
                time.sleep(0.1)
            if _is_supervisor(supervisor_pid, root):
                try:
                    os.kill(supervisor_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline and _is_supervisor(supervisor_pid, root):
                    time.sleep(0.1)
            if _is_supervisor(supervisor_pid, root):
                raise RemoteSetupError("registry_supervisor_would_not_stop")
        if not root.exists():
            return
        root = validate_root(root_text, require_marker=True)
        manifest = _read_manifest(root)

    peer_group_id = _valid_pid(manifest.get("peer_process_group_id"))
    peer_session_id = _valid_pid(manifest.get("peer_process_session_id"))
    peer_start_time = _valid_pid(manifest.get("peer_process_start_time"))
    peer_groups: dict[int, tuple[bool, int | None, int | None]] = {
        group_id: (False, None, None)
        for group_id in _owned_process_group_ids(root, lambda pid: _is_peer_process(pid, root))
    }
    if peer_group_id is not None:
        peer_groups[peer_group_id] = (True, peer_session_id, peer_start_time)
    for group_id, (validated, session_id, start_time) in sorted(peer_groups.items()):
        if not _stop_process_group(
            group_id,
            lambda pid: _is_peer_process(pid, root),
            gentle_signal=signal.SIGINT,
            validated_group=validated,
            session_id=session_id,
            leader_start_time=start_time,
        ):
            raise RemoteSetupError("registry_peer_process_would_not_stop")

    setup_group_id = _valid_pid(manifest.get("setup_process_group_id"))
    setup_session_id = _valid_pid(manifest.get("setup_process_session_id"))
    setup_start_time = _valid_pid(manifest.get("setup_process_start_time"))
    setup_groups: dict[int, tuple[bool, int | None, int | None]] = {
        group_id: (False, None, None)
        for group_id in _owned_process_group_ids(
            root,
            lambda pid: pid != os.getpid() and _is_setup_process(pid, root),
        )
    }
    if setup_group_id is not None:
        setup_groups[setup_group_id] = (True, setup_session_id, setup_start_time)
    for group_id, (validated, session_id, start_time) in sorted(setup_groups.items()):
        if not _stop_process_group(
            group_id,
            lambda pid: pid != os.getpid() and _is_setup_process(pid, root),
            gentle_signal=signal.SIGTERM,
            validated_group=validated,
            session_id=session_id,
            leader_start_time=start_time,
        ):
            raise RemoteSetupError("registry_setup_process_would_not_stop")

    if root.exists():
        shutil.rmtree(root)


def _finalize_return_code(
    return_code: int,
    *,
    setup_complete: bool,
    stop_requested: bool,
) -> int:
    if return_code == 0 and setup_complete and stop_requested:
        return 0
    return return_code


def _serve(root_text: str, revision: str) -> int:
    global _ACTIVE_PEER_PROCESS
    root = validate_root(root_text)
    revision = validate_registry_revision(revision)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    (root / MARKER_NAME).write_text("issue18-remote-test\n", encoding="utf-8")
    for name in ("fixtures/tests/interop", "fixtures/tests/vectors", "data"):
        (root / name).mkdir(parents=True, exist_ok=True)
    supervisor_session_id = _process_session_id(os.getpid())
    supervisor_start_time = _process_start_time(os.getpid())
    if supervisor_session_id is None or supervisor_start_time is None:
        raise RemoteSetupError("registry_supervisor_identity_unavailable")
    _write_manifest(
        root,
        phase=0,
        pid=None,
        setup_pid=None,
        supervisor_pid=os.getpid(),
        supervisor_session_id=supervisor_session_id,
        supervisor_start_time=supervisor_start_time,
    )
    host: str | None = None
    process: subprocess.Popen[str] | None = None
    reader: threading.Thread | None = None
    stop_requested = False
    setup_complete = False
    started_at = time.monotonic()

    def handle_signal(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True
        active_setup = _ACTIVE_SETUP_PROCESS
        if active_setup is not None and active_setup.poll() is None:
            _signal_owned_process_group(active_setup, signal.SIGTERM)
        active_peer = _ACTIVE_PEER_PROCESS
        if active_peer is not None and active_peer.poll() is None:
            _signal_owned_process_group(active_peer, signal.SIGINT)

    previous_handlers: dict[int, Any] = {}
    for signal_number in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        previous_handlers[signal_number] = signal.signal(signal_number, handle_signal)

    try:
        env = _isolated_env(root)
        python, env = _prepare_environment(root, revision)
        host = _tailscale_address(root, env)
        print("REMOTE_STAGE\tstarting-registry-peers", flush=True)
        process, reader, writer, readback = _start_peer_phase(
            root,
            python=python,
            env=env,
            host=host,
            phase=1,
        )
        print(
            "REMOTE_READY\t"
            + json.dumps(
                {"phase": 1, "writer": writer, "readback": readback},
                separators=(",", ":"),
            ),
            flush=True,
        )
        phase = 1
        while not stop_requested and time.monotonic() - started_at < MAX_LIFETIME_SECONDS:
            if process.poll() is not None:
                raise RemoteSetupError("registry_peer_fixture_exited")
            if select.select([sys.stdin], [], [], 0.25)[0]:
                command = sys.stdin.readline()
                if not command or command.strip() == "STOP":
                    break
                if command.strip() == "RESET":
                    if not _stop_peer_process(process):
                        raise RemoteSetupError("registry_peer_fixture_would_not_stop")
                    _ACTIVE_PEER_PROCESS = None
                    if reader is not None:
                        reader.join(timeout=2)
                    old_data = root / "data" / f"phase-{phase}"
                    shutil.rmtree(old_data, ignore_errors=False)
                    phase += 1
                    process, reader, writer, readback = _start_peer_phase(
                        root,
                        python=python,
                        env=env,
                        host=host,
                        phase=phase,
                    )
                    print(
                        "REMOTE_READY\t"
                        + json.dumps(
                            {"phase": phase, "writer": writer, "readback": readback},
                            separators=(",", ":"),
                        ),
                        flush=True,
                    )
                else:
                    print("REMOTE_ERROR\tinvalid_control", flush=True)
        setup_complete = True
        return_code = 0
    except RemoteSetupError as exc:
        print(f"REMOTE_ERROR\t{exc.code}", flush=True)
        return_code = 1
    except BaseException as exc:  # noqa: BLE001 -- the supervisor must enter teardown for every exit path
        print(f"REMOTE_ERROR\tremote_setup_{type(exc).__name__}", flush=True)
        return_code = 1
    finally:
        stopped = _stop_peer_process(process)
        _ACTIVE_PEER_PROCESS = None
        if reader is not None:
            reader.join(timeout=2)
        for signal_number, handler in previous_handlers.items():
            signal.signal(signal_number, handler)
        if stopped:
            try:
                cleanup_root(str(root))
                print(
                    "REMOTE_STOPPED\t"
                    + json.dumps({"root_removed": True}, separators=(",", ":")),
                    flush=True,
                )
            except Exception as exc:  # noqa: BLE001 -- report cleanup failures without hiding process status
                print(f"REMOTE_CLEANUP_REQUIRED\t{type(exc).__name__}", flush=True)
                return_code = 1
        else:
            print("REMOTE_CLEANUP_REQUIRED\tpeer_process_would_not_stop", flush=True)
            return_code = 1
    return _finalize_return_code(
        return_code,
        setup_complete=setup_complete,
        stop_requested=stop_requested,
    )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Temporary Issue #18 Registry test host")
    subparsers = parser.add_subparsers(dest="command", required=True)
    serve = subparsers.add_parser("serve")
    serve.add_argument("--root", required=True)
    serve.add_argument("--registry-revision", required=True)
    cleanup = subparsers.add_parser("cleanup")
    cleanup.add_argument("--root", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        if args.command == "serve":
            return _serve(args.root, args.registry_revision)
        cleanup_root(args.root, stop_supervisor=True)
        print("REMOTE_STOPPED\t{\"root_removed\":true}", flush=True)
        return 0
    except RemoteSetupError as exc:
        print(f"REMOTE_ERROR\t{exc.code}", flush=True)
        return 1
    except (OSError, ValueError) as exc:
        print(f"REMOTE_ERROR\t{type(exc).__name__}", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

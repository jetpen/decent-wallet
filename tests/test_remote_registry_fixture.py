from __future__ import annotations

import importlib.util
import io
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts" / "remote_registry_fixture.py"
SPEC = importlib.util.spec_from_file_location("remote_registry_fixture", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
REMOTE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REMOTE
SPEC.loader.exec_module(REMOTE)
HOST_SCRIPT = ROOT / "tests" / "interop" / "remote_registry_host.py"
HOST_SPEC = importlib.util.spec_from_file_location("remote_registry_host", HOST_SCRIPT)
assert HOST_SPEC is not None and HOST_SPEC.loader is not None
HOST = importlib.util.module_from_spec(HOST_SPEC)
sys.modules[HOST_SPEC.name] = HOST
HOST_SPEC.loader.exec_module(HOST)


def test_remote_root_must_be_a_dedicated_tmp_directory() -> None:
    root = REMOTE.validate_temp_root("/tmp/decent-wallet-registry-a1b2c3d4")
    assert root == Path("/tmp/decent-wallet-registry-a1b2c3d4")

    for path in (
        "/home/ben/projects/decent-registry",
        "/tmp/registry-data",
        "/tmp/decent-wallet-registry-../other",
    ):
        with pytest.raises(ValueError, match="dedicated temporary directory"):
            REMOTE.validate_temp_root(path)


def test_remote_environment_redirects_all_install_caches_into_temp_root() -> None:
    root = Path("/tmp/decent-wallet-registry-a1b2c3d4")
    env = REMOTE.isolated_environment(root, {"HOME": "/home/ben", "PATH": "/custom/bin"})

    for key in (
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "PIP_CACHE_DIR",
        "UV_CACHE_DIR",
        "UV_PROJECT_ENVIRONMENT",
        "CARGO_HOME",
        "RUSTUP_HOME",
    ):
        assert Path(env[key]).is_relative_to(root), key
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"


def test_registry_revision_is_resolved_from_the_wallet_lock() -> None:
    revision = "3e561bbdaf7c6da85528a717dd555445d5e7dff7"
    lock = (
        '[[package]]\nname = "decent-registry"\nversion = "0.1.0"\n'
        f'source = {{ git = "https://github.com/jetpen/decent-registry.git?rev={revision}#{revision}" }}\n'
    )

    assert REMOTE.registry_revision_from_lock_text(lock) == revision
    with pytest.raises(ValueError, match="expected decent-registry repository"):
        REMOTE.registry_revision_from_lock_text(
            lock.replace("jetpen/decent-registry.git", "someone-else/decent-registry.git")
        )


def test_remote_peer_address_accepts_only_one_pinned_peer_suffix() -> None:
    peer = REMOTE.parse_remote_peer_address(
        "/ip4/100.65.77.72/tcp/39101/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB",
        expected_host="100.65.77.72",
    )
    assert peer.host == "100.65.77.72"
    assert peer.port == 39101
    assert peer.peer_id == "12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"
    with pytest.raises(ValueError, match="non-Tailscale"):
        REMOTE.parse_remote_peer_address(
            "/ip4/192.168.86.42/tcp/39101/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB",
            expected_host="192.168.86.42",
        )

    with pytest.raises(ValueError, match="invalid or unpinned Registry peer multiaddr"):
        REMOTE.parse_remote_peer_address(
            "/ip4/100.65.77.72/tcp/39101/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB",
            expected_host="100.65.77.72",
        )


def test_remote_ready_record_rejects_a_shared_peer_id() -> None:
    address = "/ip4/100.65.77.72/tcp/39101/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"
    line = f"REMOTE_READY\t{{\"phase\":1,\"writer\":\"{address}\",\"readback\":\"{address}\"}}"

    with pytest.raises(ValueError, match="distinct writer and read-back peers"):
        REMOTE.parse_remote_ready_record(line, expected_phase=1, expected_host="100.65.77.72")


def test_remote_ready_record_rejects_non_string_peer_fields() -> None:
    line = 'REMOTE_READY\t{"phase":1,"writer":123,"readback":[]}'
    with pytest.raises(TypeError, match="invalid readiness data"):
        REMOTE.parse_remote_ready_record(line, expected_phase=1, expected_host="100.65.77.72")


def test_ssh_command_requires_batch_mode_and_host_key_verification() -> None:
    command = REMOTE.ssh_command(
        "ben-x260.tailca8b51.ts.net",
        host_key_alias="ben-x260",
        remote_args=["hostname"],
    )

    assert "-oBatchMode=yes" in command
    assert "-oStrictHostKeyChecking=yes" in command
    assert "-oHostKeyAlias=ben-x260" in command
    assert command[-2:] == ["ben-x260.tailca8b51.ts.net", "hostname"]
    assert all("StrictHostKeyChecking=no" not in argument for argument in command)


def test_remote_host_only_binds_to_a_tailscale_ipv4_address() -> None:
    assert HOST.tailscale_ipv4("100.65.77.72\n") == "100.65.77.72"
    for output in ("192.168.86.42\n", "100.65.77.72\n100.64.0.2\n", "not-an-ip\n"):
        with pytest.raises(ValueError):
            HOST.tailscale_ipv4(output)


def test_remote_host_accepts_only_full_registry_commit_hashes() -> None:
    revision = "3e561bbdaf7c6da85528a717dd555445d5e7dff7"
    assert HOST.validate_registry_revision(revision) == revision
    for value in ("main", "3e561bb", "../decent-registry"):
        with pytest.raises(ValueError, match="full commit hash"):
            HOST.validate_registry_revision(value)


def test_remote_host_roots_all_install_and_test_storage_in_temp_directory(tmp_path: Path) -> None:
    root = tmp_path / "remote-test"
    env = HOST._isolated_env(root)
    expected = (
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_DATA_HOME",
        "XDG_STATE_HOME",
        "PIP_CACHE_DIR",
        "UV_CACHE_DIR",
        "UV_PROJECT_ENVIRONMENT",
        "CARGO_HOME",
        "RUSTUP_HOME",
    )
    for name in expected:
        assert Path(env[name]).is_relative_to(root.resolve())
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert env["GIT_CONFIG_GLOBAL"] == os.devnull


def test_remote_root_validator_refuses_host_paths() -> None:
    with pytest.raises(ValueError, match="temporary directory"):
        HOST.validate_root("/home/ben/projects/decent-registry")
    with pytest.raises(ValueError, match="temporary directory"):
        HOST.validate_root("/tmp/registry-data")


def test_remote_host_peer_parser_rejects_duplicate_suffix_and_lan_ip() -> None:
    valid = "/ip4/100.65.77.72/tcp/39101/p2p/11111111111111111111"
    assert HOST._parse_peer_address(valid, "100.65.77.72")[1] == 39101
    with pytest.raises(ValueError):
        HOST._parse_peer_address(f"{valid}/p2p/11111111111111111111", "100.65.77.72")
    with pytest.raises(ValueError):
        HOST._parse_peer_address(
            "/ip4/192.168.1.20/tcp/39101/p2p/11111111111111111111",
            "192.168.1.20",
        )


def test_remote_worker_rejects_non_tailnet_or_malformed_peer_addresses() -> None:
    with pytest.raises(ValueError):
        HOST._parse_peer_address(
            "/ip4/192.168.86.42/tcp/39101/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB",
            "192.168.86.42",
        )
    with pytest.raises(ValueError):
        HOST._parse_peer_address(
            "/ip4/100.65.77.72/tcp/39101/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB",
            "100.65.77.72",
        )


def test_remote_ready_record_accepts_distinct_tailscale_peers() -> None:
    writer = "/ip4/100.65.77.72/tcp/39101/p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"
    readback = "/ip4/100.65.77.72/tcp/39102/p2p/11111111111111111111"
    line = (
        "REMOTE_READY\t"
        + '{"phase":1,"writer":"' + writer + '","readback":"' + readback + '"}'
    )

    ready = REMOTE.parse_remote_ready_record(
        line,
        expected_phase=1,
        expected_host="100.65.77.72",
    )

    assert ready.writer.multiaddr == writer
    assert ready.readback.multiaddr == readback


def test_scp_copies_only_into_the_created_temporary_root() -> None:
    command = REMOTE.scp_command(
        "ben-x260.tailca8b51.ts.net",
        host_key_alias="ben-x260",
        source=Path("/tmp/source.py"),
        remote_path="/tmp/decent-wallet-registry-a1b2c3d4/source.py",
    )
    assert command[-1] == "ben-x260.tailca8b51.ts.net:/tmp/decent-wallet-registry-a1b2c3d4/source.py"
    with pytest.raises(ValueError, match="temporary Registry directory"):
        REMOTE.scp_command(
            "ben-x260.tailca8b51.ts.net",
            source=Path("/tmp/source.py"),
            remote_path="/home/ben/.ssh/authorized_keys",
        )
    with pytest.raises(ValueError, match="temporary Registry directory"):
        REMOTE.scp_command(
            "ben-x260.tailca8b51.ts.net",
            source=Path("/tmp/source.py"),
            remote_path="/tmp/decent-wallet-registry-a1b2c3d4/../outside.py",
        )


def test_remote_fixture_defaults_to_repository_root() -> None:
    fixture = REMOTE.RemoteRegistryPeerFixture("ben-x260.tailca8b51.ts.net")
    assert fixture.repository_root == ROOT


def test_remote_fixture_deploys_resets_and_tears_down_in_one_temp_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import queue
    import subprocess

    root = "/tmp/decent-wallet-registry-a1b2c3d4"
    writer_id = "12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"
    readback_id = "11111111111111111111"

    def ready_line(phase: int) -> str:
        writer = f"/ip4/100.65.77.72/tcp/{39100 + phase}/p2p/{writer_id}"
        readback = f"/ip4/100.65.77.72/tcp/{39200 + phase}/p2p/{readback_id}"
        payload = f'{{"phase":{phase},"writer":"{writer}","readback":"{readback}"}}'
        return f"REMOTE_READY\t{payload}\n"

    class FakeStdout:
        def __init__(self, messages: queue.Queue[str | None]) -> None:
            self.messages = messages

        def __iter__(self):
            while True:
                line = self.messages.get()
                if line is None:
                    return
                yield line

    class FakeStdin:
        def __init__(self, process: FakeProcess) -> None:
            self.process = process

        def write(self, command: str) -> int:
            if command == "RESET\n":
                self.process.messages.put(ready_line(2))
            elif command == "STOP\n":
                self.process.code = 0
                self.process.messages.put("REMOTE_STOPPED\t{}\n")
                self.process.messages.put(None)
            return len(command)

        def flush(self) -> None:
            return None

    class FakeProcess:
        def __init__(self) -> None:
            self.messages: queue.Queue[str | None] = queue.Queue()
            self.messages.put("REMOTE_STAGE\tinstalling\n")
            self.messages.put(ready_line(1))
            self.stdout = FakeStdout(self.messages)
            self.stdin = FakeStdin(self)
            self.code: int | None = None

        def poll(self) -> int | None:
            return self.code

        def wait(self, timeout: float | None = None) -> int:
            assert self.code is not None
            return self.code

        def terminate(self) -> None:
            self.code = 1

        def kill(self) -> None:
            self.code = 1

    fake_process = FakeProcess()
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append(command)
        if command[0] == "scp":
            return subprocess.CompletedProcess(command, 0, "", "")
        remote_args = command[command.index("ben-x260.tailca8b51.ts.net") + 1 :]
        if remote_args[0] == "mktemp":
            return subprocess.CompletedProcess(command, 0, root + "\n", "")
        if remote_args[0] == "test":
            return subprocess.CompletedProcess(command, 1, "", "")
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(REMOTE.subprocess, "run", fake_run)
    monkeypatch.setattr(REMOTE.subprocess, "Popen", lambda *_args, **_kwargs: fake_process)

    fixture = REMOTE.RemoteRegistryPeerFixture(
        "ben-x260.tailca8b51.ts.net",
        host_key_alias="ben-x260",
        repository_root=ROOT,
        startup_timeout=1,
    )
    with fixture:
        assert fixture.writer.peer_id == writer_id
        assert fixture.readback.peer_id == readback_id
        assert fixture.reset().phase == 2
    assert fixture.process is None
    assert any(command[0] == "scp" for command in commands)
    assert all(
        command[0] != "scp"
        or command[-1].startswith("ben-x260.tailca8b51.ts.net:/tmp/decent-wallet-registry-a1b2c3d4/")
        for command in commands
    )
    assert fake_process.code == 0
    assert fake_process.messages.empty()


def test_remote_fixture_close_removes_root_after_wait_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailedWaitProcess:
        stdin = None

        def poll(self) -> int:
            return 1

        def wait(self, *, timeout: float) -> int:
            raise RuntimeError("wait failed")

        def terminate(self) -> None:
            raise AssertionError("terminate should not be needed")

        def kill(self) -> None:
            raise AssertionError("kill should not be needed")

    fixture = REMOTE.RemoteRegistryPeerFixture("ben-x260.tailca8b51.ts.net")
    fixture.process = FailedWaitProcess()  # type: ignore[assignment]
    removed: list[bool] = []
    monkeypatch.setattr(fixture, "_remove_remote_root", lambda: removed.append(True))

    with pytest.raises(RuntimeError, match="wait failed"):
        fixture.close()

    assert removed == [True]
    assert fixture.process is None


def test_remote_process_group_cleanup_handles_a_dead_leader_with_live_descendants(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    group_snapshots = [[202], []]
    signals: list[tuple[int, int]] = []

    def owned_members(_group_id: int, _predicate: object) -> list[int]:
        return []

    def group_members(_group_id: int) -> list[int]:
        return group_snapshots.pop(0) if group_snapshots else []

    class DeadLeader:
        pid = 101

        def wait(self, *, timeout: float) -> None:
            assert timeout == 0

    monkeypatch.setattr(HOST, "_owned_process_group_pids", owned_members)
    monkeypatch.setattr(HOST, "_process_group_pids", group_members)
    monkeypatch.setattr(HOST, "_process_session_id", lambda _pid: 101)
    monkeypatch.setattr(HOST, "_process_start_time", lambda _pid: 1)
    monkeypatch.setattr(HOST.os, "killpg", lambda group_id, signum: signals.append((group_id, signum)))
    monkeypatch.setattr(HOST.time, "sleep", lambda _seconds: None)
    clock = [0.0]
    monkeypatch.setattr(HOST.time, "monotonic", lambda: clock.__setitem__(0, clock[0] + 5.0) or clock[0])

    assert HOST._stop_process_group(
        101,
        lambda _pid: True,
        gentle_signal=HOST.signal.SIGINT,
        validated_group=True,
        process=DeadLeader(),
        session_id=101,
        leader_start_time=1,
    )
    assert (101, HOST.signal.SIGINT) in signals


def test_validated_process_group_rejects_identity_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(HOST, "_process_group_pids", lambda _group_id: [202])
    monkeypatch.setattr(HOST, "_process_session_id", lambda _pid: 999)
    signals: list[tuple[int, int]] = []
    monkeypatch.setattr(HOST.os, "killpg", lambda group_id, signum: signals.append((group_id, signum)))

    assert not HOST._stop_process_group(
        101,
        lambda _pid: True,
        gentle_signal=HOST.signal.SIGINT,
        validated_group=True,
        session_id=101,
        leader_start_time=1,
    )
    assert signals == []


def test_remote_cleanup_failure_cannot_be_masked_by_requested_stop() -> None:
    assert HOST._finalize_return_code(
        1,
        setup_complete=True,
        stop_requested=True,
    ) == 1
    assert HOST._finalize_return_code(
        0,
        setup_complete=True,
        stop_requested=True,
    ) == 0


def test_peer_pid_is_recorded_before_readiness_wait(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    writer = "/ip4/100.65.77.72/tcp/39101/p2p/11111111111111111111"
    readback = "/ip4/100.65.77.72/tcp/39102/p2p/22222222222222222222"
    output = io.StringIO(f"READY_WRITE\t{writer}\nREADY_READBACK\t{readback}\n")
    manifest_calls: list[dict[str, object]] = []

    class FakeProcess:
        pid = 12345
        stdout = output

        def poll(self) -> None:
            return None

    process = FakeProcess()
    monkeypatch.setattr(HOST.subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(
        HOST,
        "_write_manifest",
        lambda _root, **kwargs: manifest_calls.append(kwargs),
    )
    monkeypatch.setattr(HOST, "_process_session_id", lambda _pid: 12345)
    monkeypatch.setattr(HOST, "_process_start_time", lambda _pid: 67890)

    fixture_root = tmp_path / "deployment"
    fixture_root.mkdir()
    _process, reader, _writer, _readback = HOST._start_peer_phase(
        fixture_root,
        python=Path("/tmp/registry-python"),
        env={},
        host="100.65.77.72",
        phase=1,
    )
    reader.join(timeout=2)
    monkeypatch.setattr(HOST, "_ACTIVE_PEER_PROCESS", None)

    assert manifest_calls[0] == {
        "phase": 1,
        "pid": process.pid,
        "process_group_id": process.pid,
        "process_session_id": 12345,
        "process_start_time": 67890,
    }

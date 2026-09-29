import json
from pathlib import Path

import pytest

from tests.interop import podman_registry_node as node
from tests.interop import start_podman_registry_peers as peers


WRITER_PEER_ID = "12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"
READBACK_PEER_ID = "12D3KooWR54dTmSuXSKDGdNrnjWxLRykPgcukgbiEJP69h1VJr6V"


def test_build_image_command_selects_registry_peer_stage(tmp_path: Path) -> None:
    command = peers.build_image_command(
        "podman", tmp_path, "localhost/registry-peer:unique"
    )

    assert command == [
        "podman",
        "build",
        "--file",
        str(tmp_path / "platforms" / "desktop-wallet" / "Containerfile"),
        "--target",
        "registry-peer",
        "--tag",
        "localhost/registry-peer:unique",
        str(tmp_path),
    ]


def test_peer_command_uses_loopback_publish_and_separate_bind_mounts(
    tmp_path: Path,
) -> None:
    command = peers.build_peer_command(
        "podman",
        name="writer-name",
        network="private-network",
        image="registry-peer-image",
        host_port=43127,
        data_path=tmp_path / "writer",
        bootstrap=None,
    )

    assert command[:3] == ["podman", "run", "--detach"]
    assert "--network" in command
    assert command[command.index("--network") + 1] == "private-network"
    assert "--publish" in command
    assert command[command.index("--publish") + 1] == "127.0.0.1:43127:4001/tcp"
    assert "--log-driver" in command
    assert command[command.index("--log-driver") + 1] == "k8s-file"
    assert "--volume" in command
    assert command[command.index("--volume") + 1] == f"{tmp_path / 'writer'}:/registry-data:Z"
    assert command[command.index("--entrypoint") + 1] == "/bin/sh"
    assert command[-2] == "-c"
    script = command[-1]
    assert "NODE_HOST=$(/opt/venv/bin/python -c" in script
    assert '--host "$NODE_HOST"' in script
    assert "/opt/registry_peer_node.py --host \"$NODE_HOST\"" in script
    assert "--port 4001 --datastore-path /registry-data/writer.lmdb" in script
    assert script.startswith("NODE_HOST=$(")
    assert command[-3] == "registry-peer-image"


def test_peer_command_bootstraps_writer_to_readback_inside_network(
    tmp_path: Path,
) -> None:
    command = peers.build_peer_command(
        "podman",
        name="writer-name",
        network="private-network",
        image="registry-peer-image",
        host_port=43128,
        data_path=tmp_path / "writer",
        bootstrap=f"/ip4/10.89.0.3/tcp/4001/p2p/{READBACK_PEER_ID}",
    )

    assert command[command.index("--publish") + 1] == "127.0.0.1:43128:4001/tcp"
    script = command[-1]
    assert (
        f"--bootstrap /ip4/10.89.0.3/tcp/4001/p2p/{READBACK_PEER_ID}"
    ) in script
    assert "--datastore-path /registry-data/writer.lmdb" in script
    assert "--host \"$NODE_HOST\"" in script


def test_announce_address_adds_exactly_one_matching_peer_id() -> None:
    listen = "/ip4/10.89.0.2/tcp/4001"
    suffix = f"/p2p/{WRITER_PEER_ID}"

    assert node.announce_address(listen, WRITER_PEER_ID) == listen + suffix
    assert node.announce_address(listen + suffix, WRITER_PEER_ID) == listen + suffix
    with pytest.raises(ValueError, match="peer id"):
        node.announce_address(listen + suffix + suffix, WRITER_PEER_ID)


def test_safe_exception_type_omits_exception_message() -> None:
    assert peers.safe_exception_type(ValueError("synthetic path and value")) == "ValueError"


def test_seed_registry_peers_each_use_independent_client_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, Path]] = []
    current: dict[str, bytes] = {}

    def seed(
        peer: str,
        *,
        owner_name_hex: str,
        envelope: bytes,
        seed_store_path: Path,
    ) -> None:
        assert owner_name_hex == "01"
        assert envelope == b"synthetic-envelope"
        calls.append((peer, seed_store_path))
        current[peer] = envelope

    def read(peer: str, *, owner_name_hex: str) -> bytes | None:
        assert owner_name_hex == "01"
        return current.get(peer)

    monkeypatch.setattr(peers, "_seed_registry_peer", seed)
    monkeypatch.setattr(peers, "_read_peer", read, raising=False)

    peers._seed_registry_peers(
        "writer-peer",
        "readback-peer",
        owner_name_hex="01",
        envelope=b"synthetic-envelope",
        client_data_dir=tmp_path,
    )

    assert calls == [
        ("writer-peer", tmp_path / "seed-client-writer.lmdb"),
        ("readback-peer", tmp_path / "seed-client-readback.lmdb"),
    ]


def test_seed_failure_is_reported_by_stage(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    async def fail_seed(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("private detail")

    monkeypatch.setattr(peers, "_seed_peer", fail_seed)

    with pytest.raises(peers.FixtureError, match="Registry peer seed failed"):
        peers._seed_registry_peer(
            "writer-peer",
            owner_name_hex="01",
            envelope=b"synthetic-envelope",
            seed_store_path=tmp_path / "seed-client.lmdb",
        )

def test_safe_exception_type_unwraps_exception_groups() -> None:
    try:
        raise ExceptionGroup("synthetic failure", [ValueError("private detail")])
    except ExceptionGroup as exc:
        assert peers.safe_exception_type(exc) == "ValueError"


def test_safe_exception_detail_redacts_paths_addresses_and_credentials() -> None:
    detail = peers.safe_exception_detail(
        RuntimeError(
            "connection failed at /ip4/127.0.0.1/tcp/4001 "
            "password=do-not-retain /home/user/private-data"
        )
    )

    assert "127.0.0.1" not in detail
    assert "4001" not in detail
    assert "do-not-retain" not in detail
    assert "/home/user/private-data" not in detail
    assert "[REDACTED]" in detail
    assert "0x1234abcd" not in peers.safe_exception_detail(
        RuntimeError("nursery at 0x1234abcd closed")
    )


def test_load_legacy_vector_returns_owner_name_hex_not_object_key() -> None:
    wallet_repo = Path(peers.__file__).resolve().parents[2]
    vector = json.loads((wallet_repo / peers.FIXTURE_RELATIVE_PATH).read_text(encoding="utf-8"))

    owner_name_hex, _envelope = peers._load_legacy_vector(wallet_repo)

    assert owner_name_hex == vector["owner_name_utf8_hex"]


def test_bootstrap_parser_classifies_address_prefix_without_echoing_it() -> None:
    logs = f"[BOOTSTRAP] listening on /ip4/0.0.0.0/tcp/4001/p2p/{WRITER_PEER_ID}\n"

    peer_id, error_code = peers.parse_bootstrap_peer_id(logs)

    assert peer_id is None
    assert error_code == "bootstrap_prefix"


def test_bootstrap_parser_ignores_trailing_log_decoration() -> None:
    logs = f"[BOOTSTRAP] /ip4/0.0.0.0/tcp/4001/p2p/{WRITER_PEER_ID})\n"

    peer_id, error_code = peers.parse_bootstrap_peer_id(logs)

    assert peer_id == WRITER_PEER_ID
    assert error_code == "none"


def test_bootstrap_parser_returns_safe_error_code_for_wrong_container_port() -> None:
    logs = f"[BOOTSTRAP] /ip4/0.0.0.0/tcp/4002/p2p/{WRITER_PEER_ID}\n"

    peer_id, error_code = peers.parse_bootstrap_peer_id(logs)

    assert peer_id is None
    assert error_code == "container_port"


def test_ready_address_uses_host_loopback_port_and_peer_id() -> None:
    logs = f"[BOOTSTRAP] /ip4/0.0.0.0/tcp/4001/p2p/{WRITER_PEER_ID}\n"

    assert peers.ready_address_from_logs(logs, host_port=43127) == (
        f"/ip4/127.0.0.1/tcp/43127/p2p/{WRITER_PEER_ID}"
    )


def test_ready_address_parses_podman_timestamp_prefix() -> None:
    logs = f"2026-09-28T12:00:00.000000000Z [BOOTSTRAP] /ip4/0.0.0.0/tcp/4001/p2p/{WRITER_PEER_ID}" + chr(10)

    assert peers.ready_address_from_logs(logs, host_port=43127) == (
        f"/ip4/127.0.0.1/tcp/43127/p2p/{WRITER_PEER_ID}"
    )


def test_wait_for_peer_validates_container_port_not_host_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    peer_id = "12D3KooWEsJ9JZHe8C7Gg5KG3sY9VJHttMte8Qh7vAjj6CkF9M2x"
    results = iter(
        [
            type("Result", (), {"returncode": 0, "stdout": "true", "stderr": ""})(),
            type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stdout": f"[BOOTSTRAP] /ip4/0.0.0.0/tcp/4001/p2p/{peer_id}\n",
                    "stderr": "",
                },
            )(),
        ]
    )
    monkeypatch.setattr(peers, "_run_command", lambda *_args: next(results))
    monkeypatch.setattr(peers, "_port_is_ready", lambda port: port == 43127)
    monkeypatch.setattr(peers.time, "monotonic", lambda: 0.0)

    assert peers._wait_for_peer("podman", "writer", 43127) == peer_id


def test_wait_for_peer_reports_safe_readiness_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = iter(
        [
            type("Result", (), {"returncode": 0, "stdout": "true", "stderr": ""})(),
            type("Result", (), {"returncode": 0, "stdout": "", "stderr": ""})(),
        ]
    )
    clock = iter([0.0, 0.0, 61.0])
    monkeypatch.setattr(peers, "_run_command", lambda *_args: next(results))
    monkeypatch.setattr(peers, "_port_is_ready", lambda _port: True)
    monkeypatch.setattr(peers.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(peers.time, "sleep", lambda _delay: None)

    with pytest.raises(peers.FixtureError, match="bootstrap_records=0, address_error=bootstrap_count, tcp_ready=true"):
        peers._wait_for_peer("podman", "writer", 43127)


def test_wait_for_peer_parses_registry_address_from_either_log_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    results = iter(
        [
            type("Result", (), {"returncode": 0, "stdout": "true", "stderr": ""})(),
            type(
                "Result",
                (),
                {
                    "returncode": 0,
                    "stdout": "",
                    "stderr": f"[BOOTSTRAP] /ip4/0.0.0.0/tcp/4001/p2p/{WRITER_PEER_ID}",
                },
            )(),
        ]
    )
    clock = iter([0.0, 0.0, 61.0])
    monkeypatch.setattr(peers, "_run_command", lambda *_args: next(results))
    monkeypatch.setattr(peers, "_port_is_ready", lambda _port: True)
    monkeypatch.setattr(peers.time, "monotonic", lambda: next(clock))
    monkeypatch.setattr(peers.time, "sleep", lambda _delay: None)

    assert peers._wait_for_peer("podman", "writer", 43127) == WRITER_PEER_ID


def test_ready_address_rejects_missing_or_ambiguous_peer_address() -> None:
    with pytest.raises(peers.FixtureError, match="did not report a valid peer address"):
        peers.ready_address_from_logs("starting node\n", host_port=43127)

    two_peers = (
        f"[BOOTSTRAP] /ip4/0.0.0.0/tcp/4001/p2p/{WRITER_PEER_ID}\n"
        f"[BOOTSTRAP] /ip4/0.0.0.0/tcp/4001/p2p/{READBACK_PEER_ID}\n"
    )
    with pytest.raises(peers.FixtureError, match="did not report a valid peer address"):
        peers.ready_address_from_logs(two_peers, host_port=43127)


def test_cleanup_uses_zero_grace_and_verifies_resources_are_gone() -> None:
    calls: list[list[str]] = []

    def run(command: list[str], **_kwargs: object) -> object:
        calls.append(command)
        absent_probe = command[:3] in (
            ["podman", "container", "exists"],
            ["podman", "network", "exists"],
            ["podman", "image", "exists"],
        )
        result = type("Result", (), {"returncode": 1 if absent_probe else 0})()
        return result

    peers.cleanup_resources(
        "podman",
        containers=["writer-name"],
        network="private-network",
        image="localhost/registry-peer:unique",
        runner=run,
    )

    assert ["podman", "rm", "--force", "--time", "0", "writer-name"] in calls
    assert ["podman", "container", "exists", "writer-name"] in calls
    assert ["podman", "network", "exists", "private-network"] in calls
    assert ["podman", "image", "exists", "localhost/registry-peer:unique"] in calls


def test_cleanup_waits_for_asynchronous_container_removal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer_checks = 0

    def run(command: list[str], **_kwargs: object) -> object:
        nonlocal writer_checks
        if command == ["podman", "container", "exists", "writer-name"]:
            writer_checks += 1
            return type("Result", (), {"returncode": 0 if writer_checks == 1 else 1})()
        if command[:2] in (["podman", "container"], ["podman", "network"], ["podman", "image"]):
            return type("Result", (), {"returncode": 1})()
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(peers.time, "sleep", lambda _delay: None)
    peers.cleanup_resources(
        "podman",
        containers=["writer-name"],
        network="private-network",
        image="localhost/registry-peer:unique",
        runner=run,
    )

    assert writer_checks == 2


def test_cleanup_attempts_every_resource_and_reports_leftovers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    monkeypatch.setattr(peers, "CLEANUP_TIMEOUT_SECONDS", 0.0)
    monkeypatch.setattr(peers.time, "sleep", lambda _delay: None)

    def run(command: list[str], **_kwargs: object) -> object:
        calls.append(command)
        exists_probe = command[:3] in (
            ["podman", "container", "exists"],
            ["podman", "network", "exists"],
            ["podman", "image", "exists"],
        )
        left_writer = command[:3] == ["podman", "container", "exists"] and command[-1] == "writer-name"
        failed_remove = command[:3] == ["podman", "rm", "--force"] and command[-1] == "writer-name"
        result = type(
            "Result",
            (),
            {"returncode": 0 if left_writer else 1 if exists_probe or failed_remove else 0},
        )()
        return result

    with pytest.raises(peers.FixtureError, match="could not fully tear down"):
        peers.cleanup_resources(
            "podman",
            containers=["writer-name", "readback-name"],
            network="private-network",
            image="localhost/registry-peer:unique",
            runner=run,
        )

    assert ["podman", "rm", "--force", "--time", "0", "writer-name"] in calls
    assert ["podman", "rm", "--force", "--time", "0", "readback-name"] in calls
    assert ["podman", "network", "rm", "private-network"] in calls
    assert ["podman", "image", "rm", "--force", "localhost/registry-peer:unique"] in calls
    assert ["podman", "container", "exists", "writer-name"] in calls
    assert ["podman", "network", "exists", "private-network"] in calls
    assert ["podman", "image", "exists", "localhost/registry-peer:unique"] in calls


def test_build_network_command_creates_an_internal_network() -> None:
    assert peers.build_network_command("podman", "private-network") == [
        "podman",
        "network",
        "create",
        "--driver",
        "bridge",
        "--internal",
        "private-network",
    ]


def test_parse_rootless_status_requires_explicit_true() -> None:
    assert peers.parse_rootless_status("true") is True
    assert peers.parse_rootless_status("false") is False
    assert peers.parse_rootless_status("") is False


def test_ensure_data_dir_creates_separate_peer_directories(tmp_path: Path) -> None:
    data_root = peers.ensure_data_dir(tmp_path / "fixture")

    assert (data_root / "writer").is_dir()
    assert (data_root / "readback").is_dir()


def test_ensure_data_dir_rejects_nonempty_directory(tmp_path: Path) -> None:
    (tmp_path / "unexpected").touch()

    with pytest.raises(peers.FixtureError, match="data directory must be empty"):
        peers.ensure_data_dir(tmp_path)

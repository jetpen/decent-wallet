"""Concrete Registry peer acceptance for portable encrypted rotation latches.

The fixture starts two independent local Registry peer processes, each with its
own LMDB store. It is not a deployed/ben-x260 acceptance. CI's default selection
runs the Python-authored cases; Kotlin variants require PORTABLE_LATCH_ARTIFACT_DIR
with actual writer outputs.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from decent_wallet import RegistryAdapter, RegistryTransport, Wallet

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "correct horse battery staple"
ENVIRONMENT = "testnet"
VECTOR_PATH = (
    ROOT / "tests" / "vectors" / "wallet-v2-portable-rotation-latch.json"
)
IDENTITY_VECTOR_PATH = (
    ROOT / "tests" / "vectors" / "identity-owner-key-rotation-legacy.json"
)
PEER_FIXTURE = ROOT / "tests" / "interop" / "start_android_registry_peer.py"


def _parse_peer_address(address: str) -> tuple[str, int]:
    match = re.fullmatch(r"/ip4/127\.0\.0\.1/tcp/(\d+)/p2p/([^/]+)", address)
    if match is None:
        raise AssertionError(
            f"Registry fixture announced an unexpected peer address: {address!r}"
        )
    return match.group(2), int(match.group(1))


def _start_peer_process(label: str, data_dir: Path) -> dict[str, Any]:
    command = [
        sys.executable,
        str(PEER_FIXTURE),
        "--single-peer",
        "--data-dir",
        str(data_dir),
        "--predecessor-format",
        "legacy",
        "--seed-candidate",
    ]
    process = subprocess.Popen(
        command,
        cwd=ROOT,
        env=os.environ.copy(),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert process.stdout is not None
    lines: queue.Queue[str | None] = queue.Queue()

    def read_output() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            lines.put(line.rstrip("\n"))
        lines.put(None)

    reader = threading.Thread(
        target=read_output,
        name=f"registry-peer-{label}-output",
        daemon=True,
    )
    reader.start()
    return {
        "label": label,
        "process": process,
        "lines": lines,
        "reader": reader,
        "output": [],
    }


def _wait_for_peer(peer: dict[str, Any]) -> str:
    process: subprocess.Popen[str] = peer["process"]
    lines: queue.Queue[str | None] = peer["lines"]
    output: list[str] = peer["output"]
    deadline = time.monotonic() + 180
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError(
                f"timed out starting local Registry peer {peer['label']}; output:\n"
                + "\n".join(output[-40:])
            )
        try:
            line = lines.get(timeout=min(remaining, 1.0))
        except queue.Empty:
            if process.poll() is not None:
                raise RuntimeError(
                    f"local Registry peer {peer['label']} exited {process.returncode}; "
                    "output:\n" + "\n".join(output[-40:])
                )
            continue
        if line is None:
            raise RuntimeError(
                f"local Registry peer {peer['label']} closed stdout; output:\n"
                + "\n".join(output[-40:])
            )
        output.append(line)
        tag, separator, address = line.partition("\t")
        if separator and tag == "READY":
            return address


def _stop_peer_process(peer: dict[str, Any]) -> None:
    process: subprocess.Popen[str] = peer["process"]
    if process.poll() is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            process.wait(timeout=10)
    if process.stdout is not None:
        process.stdout.close()
    peer["reader"].join(timeout=5)


@pytest.fixture(scope="module")
def local_registry_peers(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[dict[str, Any]]:
    """Start two independent local Registry peer processes and stores."""
    pytest.importorskip("decent_registry")
    root = tmp_path_factory.mktemp("portable-latch-registry")
    peers: list[dict[str, Any]] = []
    try:
        for label in ("writer", "readback"):
            data_dir = root / label
            data_dir.mkdir()
            peers.append(_start_peer_process(label, data_dir))
        addresses = {peer["label"]: _wait_for_peer(peer) for peer in peers}
        writer_id, writer_port = _parse_peer_address(addresses["writer"])
        readback_id, readback_port = _parse_peer_address(addresses["readback"])
        writer_process, readback_process = (peer["process"] for peer in peers)
        if writer_process.pid == readback_process.pid:
            raise AssertionError("Registry peers must run in separate OS processes")
        if writer_id == readback_id or writer_port == readback_port:
            raise AssertionError(
                "Registry peers must have distinct IDs and listener ports"
            )
        writer_store = root / "writer" / "peer.lmdb"
        readback_store = root / "readback" / "peer.lmdb"
        if not writer_store.exists() or not readback_store.exists():
            raise AssertionError(
                "Registry peer processes did not create both LMDB stores"
            )
        if writer_store.samefile(readback_store):
            raise AssertionError("Registry peer processes share an LMDB store")
        print(
            "LOCAL_REGISTRY_PEERS "
            f"writer_pid={writer_process.pid} readback_pid={readback_process.pid} "
            f"writer_id={writer_id} readback_id={readback_id} "
            f"writer_lmdb={writer_store} readback_lmdb={readback_store}"
        )
        yield {
            "writer": addresses["writer"],
            "readback": addresses["readback"],
            "writer_store": writer_store,
            "readback_store": readback_store,
            "writer_pid": writer_process.pid,
            "readback_pid": readback_process.pid,
            "data_dir": root,
        }
    finally:
        for peer in reversed(peers):
            _stop_peer_process(peer)


def _read_peer_lmdb_head(store_path: Path, record_key: bytes) -> bytes | None:
    from decent_registry.durable_store import LMDBDatastore

    store = LMDBDatastore(path=store_path)
    store.open()
    try:
        return store.get(kind="identity", key=record_key)
    finally:
        store.close()


def _remote_head(peer: str, store_path: Path, owner_name_hex: str) -> bytes | None:
    transport = RegistryTransport(
        bootstrap_peers=[peer],
        store_path=store_path,
    )
    return transport.get_remote_identity_envelope(owner_name_hex=owner_name_hex)


def _ciphertext(source: str, shape: str, fixture: dict[str, Any]) -> bytes:
    if source == "python":
        field = (
            "python_bound_container_base64"
            if shape == "bound"
            else "legacy_unbound_container_base64"
        )
        return base64.b64decode(fixture[field], validate=True)

    artifact_dir = os.environ.get("PORTABLE_LATCH_ARTIFACT_DIR")
    if artifact_dir is None:
        pytest.skip("Kotlin ciphertext requires PORTABLE_LATCH_ARTIFACT_DIR")
    # If the directory is explicitly configured, a missing artifact is a failure,
    # not a skip: this run claims to exercise the actual Kotlin writer output.
    return (Path(artifact_dir) / f"kotlin-{shape}.dw").read_bytes()


@pytest.mark.registry_integration
@pytest.mark.parametrize(
    ("source", "shape"),
    [
        ("python", "bound"),
        ("python", "legacy"),
        pytest.param(
            "kotlin",
            "bound",
            marks=pytest.mark.skipif(
                os.environ.get("PORTABLE_LATCH_ARTIFACT_DIR") is None,
                reason="Kotlin ciphertext requires PORTABLE_LATCH_ARTIFACT_DIR",
            ),
        ),
        pytest.param(
            "kotlin",
            "legacy",
            marks=pytest.mark.skipif(
                os.environ.get("PORTABLE_LATCH_ARTIFACT_DIR") is None,
                reason="Kotlin ciphertext requires PORTABLE_LATCH_ARTIFACT_DIR",
            ),
        ),
    ],
)
def test_imported_portable_latch_confirms_from_distinct_registry_peer_readonly(
    tmp_path: Path,
    local_registry_peers: dict[str, Any],
    source: str,
    shape: str,
) -> None:
    fixture = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    identity_vector = json.loads(IDENTITY_VECTOR_PATH.read_text(encoding="utf-8"))
    raw = _ciphertext(source, shape, fixture)
    owner_name = bytes.fromhex(identity_vector["owner_name_utf8_hex"])
    owner_name_hex = owner_name.hex()
    record_key = hashlib.sha256(owner_name).digest()
    predecessor = bytes.fromhex(identity_vector["predecessor_envelope_cbor_hex"])
    candidate = bytes.fromhex(identity_vector["candidate_envelope_cbor_hex"])
    predecessor_hash = bytes.fromhex(identity_vector["predecessor_state_hash_hex"])
    active_key = bytes.fromhex(identity_vector["predecessor_owner_public_key_hex"])
    successor_key = bytes.fromhex(identity_vector["successor_owner_public_key_hex"])

    # Each actual Registry peer has its own current head and LMDB. Capture both
    # local durable heads, then independently GET from each configured peer.
    peer_heads_before = (
        _read_peer_lmdb_head(local_registry_peers["writer_store"], record_key),
        _read_peer_lmdb_head(local_registry_peers["readback_store"], record_key),
    )
    assert peer_heads_before == (candidate, candidate)
    remote_heads_before = (
        _remote_head(
            local_registry_peers["writer"],
            tmp_path / "writer-head-reader.lmdb",
            owner_name_hex,
        ),
        _remote_head(
            local_registry_peers["readback"],
            tmp_path / "readback-head-reader.lmdb",
            owner_name_hex,
        ),
    )
    assert remote_heads_before == (candidate, candidate)

    receiver_transport = RegistryTransport(
        bootstrap_peers=[local_registry_peers["writer"]],
        readback_peer=local_registry_peers["readback"],
        store_path=tmp_path / "receiver.lmdb",
        supports_owner_key_rotation=True,
        registry_environment=ENVIRONMENT,
    )
    rpc: dict[str, list[Any]] = {"current": [], "remote": [], "history": [], "put": []}
    real_current_read = receiver_transport.get_identity_envelope
    real_remote_read = receiver_transport.get_remote_identity_envelope
    real_history_read = receiver_transport.get_identity_envelope_by_hash

    def tracked_current_read(*, owner_name_hex: str) -> bytes | None:
        entry: dict[str, Any] = {"owner": owner_name_hex}
        rpc["current"].append(entry)
        try:
            value = real_current_read(owner_name_hex=owner_name_hex)
        except Exception as exc:
            entry["error"] = repr(exc)
            raise
        entry["value"] = value
        return value

    receiver_transport.get_identity_envelope = (  # type: ignore[method-assign]
        tracked_current_read
    )

    def tracked_remote_read(*, owner_name_hex: str) -> bytes | None:
        entry: dict[str, Any] = {"owner": owner_name_hex}
        rpc["remote"].append(entry)
        try:
            value = real_remote_read(owner_name_hex=owner_name_hex)
        except Exception as exc:
            entry["error"] = repr(exc)
            raise
        entry["value"] = value
        return value

    def tracked_history_read(
        *, owner_name_hex: str, state_hash: bytes
    ) -> bytes | None:
        entry: dict[str, Any] = {
            "owner": owner_name_hex,
            "state_hash": state_hash.hex(),
        }
        rpc["history"].append(entry)
        try:
            value = real_history_read(
                owner_name_hex=owner_name_hex,
                state_hash=state_hash,
            )
        except Exception as exc:
            entry["error"] = repr(exc)
            raise
        entry["value"] = value
        return value

    def forbidden_receiver_put(**kwargs: Any) -> None:
        rpc["put"].append(kwargs)
        raise AssertionError("portable latch recovery must never issue a receiver PUT")

    # Keep the production concrete transport and its real GET implementations;
    # these wrappers only record calls and make any receiver PUT fail immediately.
    receiver_transport.get_remote_identity_envelope = (  # type: ignore[method-assign]
        tracked_remote_read
    )
    receiver_transport.get_identity_envelope_by_hash = (  # type: ignore[method-assign]
        tracked_history_read
    )
    receiver_transport.put_identity_envelope = (  # type: ignore[method-assign]
        forbidden_receiver_put
    )

    wallet_path = tmp_path / f"{source}-{shape}.dw"
    wallet = Wallet.import_container(wallet_path, raw, PASSWORD)
    try:
        intent = wallet.signing_key_rotation_dispatch_intent
        assert intent is not None
        assert wallet.export_container() == raw
        assert wallet.public_key == active_key
        assert wallet.pending_signing_public_key == successor_key
        assert intent.environment == (None if shape == "legacy" else ENVIRONMENT)
        assert intent.predecessor_state_hash == predecessor_hash
        assert intent.envelope_hash == hashlib.sha256(candidate).digest()

        # Exact import survives close/reopen before any recovery action.
        wallet.lock()
        wallet = Wallet.open(wallet_path, PASSWORD)
        assert wallet.export_container() == raw
        assert wallet.signing_key_rotation_dispatch_intent == intent

        matching_adapter = RegistryAdapter(
            receiver_transport,
            registry_environment=ENVIRONMENT,
        )
        if shape == "legacy":
            assert matching_adapter.confirm_owner_key_rotation(intent) is None
            assert rpc == {"current": [], "remote": [], "history": [], "put": []}
            intent = wallet.bind_legacy_rotation_dispatch_environment(
                ENVIRONMENT,
                consent=lambda original, requested: (
                    original == intent and requested == ENVIRONMENT
                ),
            )
            assert intent.environment == ENVIRONMENT
            wallet.lock()
            wallet = Wallet.open(wallet_path, PASSWORD)
            assert wallet.signing_key_rotation_dispatch_intent == intent
            assert wallet.public_key == active_key
            assert wallet.pending_signing_public_key == successor_key

        # A mismatched adapter/realm must be rejected before either real GET.
        assert RegistryAdapter(
            receiver_transport,
            registry_environment="different-local-realm",
        ).confirm_owner_key_rotation(intent) is None
        assert rpc == {"current": [], "remote": [], "history": [], "put": []}

        # Prime the concrete client's accepted history with an ordinary Registry GET.
        # Confirmation will still perform its own uncached remote readback from the
        # separately configured peer before it can mint promotion authority.
        assert receiver_transport.get_identity_envelope(
            owner_name_hex=owner_name_hex
        ) == candidate
        assert rpc["current"][-1] == {"owner": owner_name_hex, "value": candidate}

        confirmation = matching_adapter.confirm_owner_key_rotation(intent)
        assert confirmation is not None, (
            f"concrete Registry reads did not confirm: {rpc!r}"
        )
        assert len(rpc["remote"]) >= 1
        assert rpc["remote"][-1]["owner"] == owner_name_hex
        assert rpc["remote"][-1]["value"] == candidate
        assert any(
            entry.get("owner") == owner_name_hex
            and entry.get("state_hash") == predecessor_hash.hex()
            and entry.get("value") == predecessor
            for entry in rpc["history"]
        )
        assert rpc["put"] == []

        assert wallet.finalize_signing_key_rotation(confirmation) == successor_key
        assert wallet.public_key == successor_key
        assert wallet.pending_signing_public_key is None
        assert wallet.signing_key_rotation_dispatch_intent is None
        wallet.lock()

        # Promotion is a durable local write. Reopening proves the successor-only
        # wallet state while both independently owned Registry heads remain exact.
        promoted = Wallet.open(wallet_path, PASSWORD)
        try:
            assert promoted.public_key == successor_key
            assert promoted.pending_signing_public_key is None
            assert promoted.signing_key_rotation_dispatch_intent is None
            assert rpc["put"] == []
        finally:
            promoted.lock()

        peer_heads_after = (
            _read_peer_lmdb_head(local_registry_peers["writer_store"], record_key),
            _read_peer_lmdb_head(local_registry_peers["readback_store"], record_key),
        )
        remote_heads_after = (
            _remote_head(
                local_registry_peers["writer"],
                tmp_path / "writer-head-reader-after.lmdb",
                owner_name_hex,
            ),
            _remote_head(
                local_registry_peers["readback"],
                tmp_path / "readback-head-reader-after.lmdb",
                owner_name_hex,
            ),
        )
        assert peer_heads_after == peer_heads_before == (candidate, candidate)
        assert remote_heads_after == remote_heads_before == (candidate, candidate)
        assert rpc["put"] == []
    finally:
        if wallet.is_unlocked:
            wallet.lock()

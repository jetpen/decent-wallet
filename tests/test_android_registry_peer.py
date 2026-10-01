from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("decent_registry")

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tests" / "interop" / "start_android_registry_peer.py"
SPEC = importlib.util.spec_from_file_location("android_registry_peer_fixture", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
PEER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PEER
SPEC.loader.exec_module(PEER)


class _PeerId:
    def to_string(self) -> str:
        return "12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"


class _Host:
    def get_id(self) -> _PeerId:
        return _PeerId()


class _DHT:
    host = _Host()

    def get_listen_multiaddr(self) -> str:
        return "/ip4/100.65.77.72/tcp/39101"


def test_peer_address_advertises_the_remote_interface() -> None:
    address = PEER.peer_address(
        _DHT(),
        advertise_host="100.65.77.72",
        listen_host="100.65.77.72",
    )

    assert address == (
        "/ip4/100.65.77.72/tcp/39101/"
        "p2p/12D3KooWPSZfHTwEMA91h9NVw3ocpuNWAzKLjBEU9ofioP795EHB"
    )


def test_parse_args_accepts_an_explicit_listen_host(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(SCRIPT),
            "--listen-host",
            "100.65.77.72",
            "--advertise-host",
            "100.65.77.72",
            "--data-dir",
            str(tmp_path),
        ],
    )

    args = PEER.parse_args()

    assert args.listen_host == "100.65.77.72"
    assert args.advertise_host == "100.65.77.72"


def test_peer_address_rejects_a_listener_address_that_does_not_match() -> None:
    with pytest.raises(RuntimeError, match="did not bind to its configured IPv4 listener"):
        PEER.peer_address(
            _DHT(),
            advertise_host="100.65.77.72",
            listen_host="192.168.1.20",
        )


def test_parse_args_selects_versioned_predecessor_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--predecessor-format", "versioned"])

    args = PEER.parse_args()

    assert args.predecessor_format == "versioned"


def test_parse_args_selects_missing_history_fault(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "--predecessor-format", "versioned", "--history-fault", "missing"],
    )

    args = PEER.parse_args()

    assert args.predecessor_format == "versioned"
    assert args.history_fault == "missing"


def test_parse_args_rejects_history_fault_for_legacy_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), "--history-fault", "missing"])

    with pytest.raises(SystemExit):
        PEER.parse_args()


def test_load_versioned_fixture_has_legacy_anchor_and_verified_non_genesis_history() -> None:
    fixture = PEER.load_fixture("versioned")
    vector = json.loads(PEER.VERSIONED_FIXTURE.read_text(encoding="utf-8"))
    owner_name = bytes.fromhex(vector["owner_name_utf8_hex"])
    record_key = hashlib.sha256(owner_name).digest()
    state = PEER.validate_multisignature_history(
        record_key=record_key,
        envelopes=fixture.history,
    )
    candidate_state = PEER.validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=fixture.candidate,
        current_state=state,
    )

    assert fixture.owner_name == owner_name
    assert fixture.identity_key == record_key.hex()
    assert len(fixture.history) == 3
    assert fixture.history_state_hashes[-1] == fixture.predecessor_state_hash
    assert fixture.predecessor == fixture.history[-1]
    assert fixture.predecessor_sequence == 6
    assert state.seq == fixture.predecessor_sequence
    assert state.history == fixture.history
    assert state.state_hash == fixture.predecessor_state_hash
    assert candidate_state.seq == fixture.candidate_sequence == state.seq + 1
    assert candidate_state.history == (*fixture.history, fixture.candidate)


@pytest.mark.parametrize("fault", ["missing", "corrupt"])
def test_history_fault_injection_keeps_current_but_rejects_chain(
    tmp_path: Path,
    fault: str,
) -> None:
    fixture = PEER.load_fixture("versioned")
    store = PEER.LMDBDatastore(path=tmp_path / "writer.lmdb")
    record_key = bytes.fromhex(fixture.identity_key)
    try:
        assert store.put_if_newer(
            kind="identity",
            key=record_key,
            value=fixture.predecessor,
            seq=fixture.predecessor_sequence,
            state_hash=fixture.predecessor_state_hash,
            history=fixture.history,
        )

        history = PEER.inject_history_fault(
            SimpleNamespace(_durable_store=store), fixture, fault
        )

        assert store.get(kind="identity", key=record_key) == fixture.predecessor
        assert history != fixture.history
        with pytest.raises((TypeError, ValueError)):
            PEER.validate_multisignature_history(
                record_key=record_key,
                envelopes=history,
            )
    finally:
        store.close()


def test_history_fault_injection_rejects_legacy_fixture() -> None:
    with pytest.raises(ValueError, match="requires versioned predecessor history"):
        PEER.inject_history_fault(
            SimpleNamespace(_durable_store=None), PEER.load_fixture("legacy"), "missing"
        )


def test_parse_args_selects_single_peer_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        [str(SCRIPT), "--single-peer", "--seed-candidate", "--data-dir", str(tmp_path)],
    )

    args = PEER.parse_args()

    assert args.single_peer is True
    assert args.seed_candidate is True

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

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

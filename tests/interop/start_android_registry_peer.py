from __future__ import annotations

import argparse
from contextlib import nullcontext
import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

import trio
from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.durable_store import LMDBDatastore


REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "vectors" / "identity-owner-key-rotation-legacy.json"


def load_fixture() -> tuple[str, bytes]:
    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    owner_name = bytes.fromhex(vector["owner_name_utf8_hex"])
    identity_key = hashlib.sha256(owner_name).hexdigest()
    predecessor = bytes.fromhex(vector["predecessor_envelope_cbor_hex"])
    return identity_key, predecessor


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a two-peer local Registry interop mesh")
    parser.add_argument(
        "--advertise-host",
        default="127.0.0.1",
        help="address clients use to reach this host (Android emulators should normally use adb reverse)",
    )
    parser.add_argument(
        "--seed-candidate",
        action="store_true",
        help="also publish the shared versioned rotation candidate before reporting READY",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        help="use this empty directory for separate writer.lmdb and readback.lmdb files",
    )
    return parser.parse_args()


def peer_address(dht: Libp2pKadDHT, advertise_host: str) -> str:
    address = dht.get_listen_multiaddr()
    expected_prefix = "/ip4/127.0.0.1/"
    if not address.startswith(expected_prefix):
        raise RuntimeError("local Registry listener did not bind to IPv4 loopback")
    if advertise_host != "127.0.0.1":
        address = f"/ip4/{advertise_host}/" + address[len(expected_prefix) :]
    peer_id = dht.host.get_id().to_string()
    if "/p2p/" in address:
        observed_peer_id = address.rsplit("/p2p/", 1)[1].split("/", 1)[0]
        if observed_peer_id != peer_id:
            raise RuntimeError("Registry listener address contains a different peer ID")
        return address
    return f"{address}/p2p/{peer_id}"


def result_sequence(result: object) -> int | None:
    if isinstance(result, dict):
        sequence = result.get("seq")
        return sequence if isinstance(sequence, int) else None
    sequence = getattr(result, "seq", None)
    return sequence if isinstance(sequence, int) else None


async def main() -> None:
    args = parse_args()
    identity_key, predecessor = load_fixture()
    vector = json.loads(FIXTURE.read_text(encoding="utf-8"))
    candidate = bytes.fromhex(vector["candidate_envelope_cbor_hex"])
    predecessor_hash = bytes.fromhex(vector["predecessor_state_hash_hex"])
    scratch = Path(os.environ.get("TMPDIR", Path.home() / ".cache" / "decent-wallet"))
    scratch.mkdir(parents=True, exist_ok=True)

    if args.data_dir is None:
        root_context = tempfile.TemporaryDirectory(prefix="android-registry-mesh-", dir=scratch)
    else:
        root_path = args.data_dir.expanduser().resolve()
        root_path.mkdir(parents=True, exist_ok=True)
        if any(root_path.iterdir()):
            raise RuntimeError("--data-dir must be empty")
        root_context = nullcontext(str(root_path))

    with root_context as root:
        root_path = Path(root)
        async with Libp2pKadDHT(
            listen="/ip4/127.0.0.1/tcp/0",
            durable_store=LMDBDatastore(path=root_path / "writer.lmdb"),
        ) as writer:
            async with Libp2pKadDHT(
                listen="/ip4/127.0.0.1/tcp/0",
                durable_store=LMDBDatastore(path=root_path / "readback.lmdb"),
            ) as readback:
                writer_peer = peer_address(writer, args.advertise_host)
                readback_peer = peer_address(readback, args.advertise_host)
                writer_local_peer = peer_address(writer, "127.0.0.1")
                readback_local_peer = peer_address(readback, "127.0.0.1")
                await readback.bootstrap(writer_local_peer)
                await writer.bootstrap(readback_local_peer)
                await writer.put_signed_identity_record(identity_key, predecessor)

                anchor = await readback.get_signed_identity_record(identity_key)
                if anchor is None:
                    raise RuntimeError("readback Registry peer did not accept the legacy anchor")

                if args.seed_candidate:
                    await writer.put_signed_identity_record_if_current(
                        identity_key,
                        candidate,
                        expected_state_hash=predecessor_hash,
                        expires_at=int(time.time()) + 300,
                    )
                    expected_sequence = int(vector["candidate_sequence"])
                    for _attempt in range(40):
                        observed = await readback.get_signed_identity_record(identity_key)
                        if result_sequence(observed) == expected_sequence:
                            break
                        await trio.sleep(0.25)
                    else:
                        raise RuntimeError("readback Registry peer did not accept the rotation candidate")

                print(f"READY_WRITE\t{writer_peer}", flush=True)
                print(f"READY_READBACK\t{readback_peer}", flush=True)

                await trio.sleep_forever()


if __name__ == "__main__":
    trio.run(main)

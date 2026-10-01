from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import tempfile
import time
from collections.abc import Mapping
from contextlib import nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import cbor2
import trio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from decent_registry.dht.libp2p_dht import Libp2pKadDHT
from decent_registry.durable_store import LMDBDatastore
from decent_registry.encoding import (
    OPERATION_ORDINARY_UPDATE,
    OPERATION_OWNER_KEY_ROTATION,
    OPERATION_UPGRADE,
    RECORD_KIND_IDENTITY,
    encode_multisignature_signed_update,
    encode_signed_update,
)
from decent_registry.signed_envelope import (
    encode_multisignature_envelope,
    encode_signed_envelope,
)
from decent_registry.verification import (
    make_signed_update_signature,
    validate_multisignature_history,
    validate_multisignature_update,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURE = REPO_ROOT / "tests" / "vectors" / "identity-owner-key-rotation-legacy.json"
VERSIONED_FIXTURE = (
    REPO_ROOT / "tests" / "vectors" / "identity-owner-key-rotation-versioned-history.json"
)


@dataclass(frozen=True)
class IdentityFixture:
    owner_name: bytes
    identity_key: str
    history: tuple[bytes, ...]
    history_state_hashes: tuple[bytes, ...]
    predecessor: bytes
    predecessor_state_hash: bytes
    predecessor_sequence: int
    candidate: bytes
    candidate_sequence: int


def load_fixture(predecessor_format: str = "legacy") -> IdentityFixture:
    if predecessor_format not in ("legacy", "versioned"):
        raise ValueError("unsupported synthetic Registry predecessor format")
    fixture_path = FIXTURE if predecessor_format == "legacy" else VERSIONED_FIXTURE
    vector = json.loads(fixture_path.read_text(encoding="utf-8"))
    owner_name = bytes.fromhex(vector["owner_name_utf8_hex"])
    identity_key = hashlib.sha256(owner_name).hexdigest()
    predecessor = bytes.fromhex(vector["predecessor_envelope_cbor_hex"])
    candidate_sequence = int(vector["candidate_sequence"])
    if predecessor_format == "legacy":
        predecessor_hash = bytes.fromhex(vector["predecessor_state_hash_hex"])
        return IdentityFixture(
            owner_name=owner_name,
            identity_key=identity_key,
            history=(predecessor,),
            history_state_hashes=(predecessor_hash,),
            predecessor=predecessor,
            predecessor_state_hash=predecessor_hash,
            predecessor_sequence=int(
                vector.get("predecessor_sequence", candidate_sequence - 1)
            ),
            candidate=bytes.fromhex(vector["candidate_envelope_cbor_hex"]),
            candidate_sequence=candidate_sequence,
        )
    return _build_versioned_fixture(owner_name, vector)


def _build_versioned_fixture(
    owner_name: bytes,
    vector: Mapping[str, Any],
) -> IdentityFixture:
    """Build a Registry-valid non-genesis predecessor from deterministic test keys."""
    seed_starts = (1, 33, 65, 129)
    private_keys = [
        Ed25519PrivateKey.from_private_bytes(bytes((start + i) & 0xFF for i in range(32)))
        for start in seed_starts
    ]
    public_keys = [
        key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        for key in private_keys
    ]
    expected_signers = vector["signer_set"]
    if [key.hex() for key in public_keys[:3]] != [entry["public_key_hex"] for entry in expected_signers]:
        raise ValueError("deterministic test keys do not match the versioned-history vector")
    if public_keys[3].hex() != vector["successor_owner_public_key_hex"]:
        raise ValueError("deterministic successor key does not match the versioned-history vector")

    record_key = hashlib.sha256(owner_name).digest()
    signer_set = [
        {1: signer_id, 2: public_key}
        for signer_id, public_key in zip(("alice", "bob", "carol"), public_keys[:3], strict=True)
    ]

    legacy_update = encode_signed_update(
        record_fields={1: owner_name, 2: public_keys[0]},
        payload={},
        seq=4,
    )
    legacy_signature = make_signed_update_signature(
        signed_update_bytes_canonical=legacy_update,
        owner_private_key=private_keys[0],
    )
    legacy_envelope = encode_signed_envelope(
        signed_update_bytes=legacy_update,
        signature=legacy_signature,
    )
    legacy_state_hash = hashlib.sha256(legacy_update).digest()

    def versioned_update(*, sequence: int, operation: int, previous_hash: bytes) -> bytes:
        return encode_multisignature_signed_update(
            record_fields={1: owner_name, 2: public_keys[0]},
            payload={},
            seq=sequence,
            authorization={
                1: 1,
                2: RECORD_KIND_IDENTITY,
                3: operation,
                4: 1,
                5: 2,
                6: signer_set,
                7: previous_hash,
            },
        )

    def make_envelope(signed_update: bytes, signer_indexes: tuple[int, ...]) -> bytes:
        proofs: list[Mapping[int, Any]] = []
        for index in signer_indexes:
            proofs.append(
                {
                1: signer_set[index][1],
                2: make_signed_update_signature(
                    signed_update_bytes_canonical=signed_update,
                    owner_private_key=private_keys[index],
                ),
                }
            )
        return encode_multisignature_envelope(
            signed_update_bytes=signed_update,
            proofs=proofs,
        )

    upgrade_update = versioned_update(
        sequence=5,
        operation=OPERATION_UPGRADE,
        previous_hash=legacy_state_hash,
    )
    upgrade_envelope = make_envelope(upgrade_update, (0,))
    upgrade_state_hash = hashlib.sha256(upgrade_update).digest()

    predecessor_update = versioned_update(
        sequence=6,
        operation=OPERATION_ORDINARY_UPDATE,
        previous_hash=upgrade_state_hash,
    )
    predecessor_envelope = make_envelope(predecessor_update, (0, 1))
    predecessor_state_hash = hashlib.sha256(predecessor_update).digest()
    history = (legacy_envelope, upgrade_envelope, predecessor_envelope)
    history_state_hashes = (legacy_state_hash, upgrade_state_hash, predecessor_state_hash)

    state = validate_multisignature_history(record_key=record_key, envelopes=history)
    if state.seq != 6 or state.state_hash != predecessor_state_hash:
        raise RuntimeError("synthetic versioned predecessor did not validate to the expected state")

    candidate_update = encode_multisignature_signed_update(
        record_fields={1: owner_name, 2: public_keys[3]},
        payload={},
        seq=state.seq + 1,
        authorization={
            1: 1,
            2: RECORD_KIND_IDENTITY,
            3: OPERATION_OWNER_KEY_ROTATION,
            4: state.epoch,
            5: state.threshold,
            6: signer_set,
            7: state.state_hash,
        },
    )
    candidate = make_envelope(candidate_update, (0, 1))
    candidate_state = validate_multisignature_update(
        record_key=record_key,
        envelope_cbor=candidate,
        current_state=state,
    )
    return IdentityFixture(
        owner_name=owner_name,
        identity_key=record_key.hex(),
        history=history,
        history_state_hashes=history_state_hashes,
        predecessor=predecessor_envelope,
        predecessor_state_hash=predecessor_state_hash,
        predecessor_sequence=state.seq,
        candidate=candidate,
        candidate_sequence=candidate_state.seq,
    )


async def seed_peer_with_fixture(peer: Libp2pKadDHT, fixture: IdentityFixture) -> None:
    if len(fixture.history) < 2:
        raise ValueError("versioned Registry fixture must include an anchor and a successor")
    for index, envelope in enumerate(fixture.history):
        if index == 0:
            await peer.put_signed_identity_record(fixture.identity_key, envelope)
        else:
            await peer.put_signed_identity_record_if_current(
                fixture.identity_key,
                envelope,
                expected_state_hash=fixture.history_state_hashes[index - 1],
                expires_at=int(time.time()) + 300,
            )
    record_key = bytes.fromhex(fixture.identity_key)
    if peer._durable_get(kind="identity", key=record_key) != fixture.predecessor:
        raise RuntimeError("Registry peer did not retain the synthetic versioned predecessor")
    if peer._durable_history(kind="identity", key=record_key) != fixture.history:
        raise RuntimeError("Registry peer did not retain complete synthetic predecessor history")


def inject_history_fault(
    peer: Libp2pKadDHT,
    fixture: IdentityFixture,
    fault: str,
) -> tuple[bytes, ...]:
    if fault not in {"missing", "corrupt"}:
        raise ValueError("unsupported Registry history fault")
    if len(fixture.history) < 3:
        raise ValueError("history fault injection requires versioned predecessor history")
    store = peer._durable_store
    if not isinstance(store, LMDBDatastore):
        raise TypeError("history fault injection requires the durable LMDB Registry store")
    store.open()
    env = store._env
    accepted_db = store._accepted_db
    if env is None or accepted_db is None:
        raise RuntimeError("Registry durable history store is not open")

    record_key = bytes.fromhex(fixture.identity_key)
    history_key = store._history_key(kind="identity", key=record_key)
    with env.begin(write=True) as txn:
        encoded_history = txn.get(history_key, db=accepted_db)
        if encoded_history is None:
            raise RuntimeError("Registry predecessor history is missing before fault injection")
        history = cbor2.loads(encoded_history)
        if not isinstance(history, list) or tuple(history) != fixture.history:
            raise RuntimeError("Registry predecessor history changed before fault injection")
        if fault == "missing":
            del history[-2]
        else:
            corrupted = bytearray(history[-2])
            corrupted[-1] ^= 1
            history[-2] = bytes(corrupted)
        txn.put(history_key, cbor2.dumps(history, canonical=True), db=accepted_db)

    observed = store.get_history(kind="identity", key=record_key)
    if observed is None or store.get(kind="identity", key=record_key) != fixture.predecessor:
        raise RuntimeError("history fault injection changed or removed the current Registry head")
    try:
        validate_multisignature_history(record_key=record_key, envelopes=observed)
    except (TypeError, ValueError):
        return observed
    raise RuntimeError("injected Registry history fault still validates")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run local Registry DHT integration peers"
    )
    parser.add_argument(
        "--single-peer",
        action="store_true",
        help="run a single Registry DHT peer in this OS process",
    )
    parser.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="IPv4 interface address to bind the Registry peers to",
    )
    parser.add_argument(
        "--advertise-host",
        default="127.0.0.1",
        help="IPv4 address clients use to reach this host (Android emulators should normally use adb reverse)",
    )
    parser.add_argument(
        "--predecessor-format",
        choices=("legacy", "versioned"),
        default="legacy",
        help="seed a legacy anchor or a complete versioned genesis/predecessor history",
    )
    parser.add_argument(
        "--history-fault",
        choices=("none", "missing", "corrupt"),
        default="none",
        help="inject a missing or corrupt versioned predecessor into both durable test peers",
    )
    parser.add_argument(
        "--seed-candidate",
        action="store_true",
        help="also publish the shared rotation candidate before reporting READY",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        help=(
            "use an empty directory: peer.lmdb for --single-peer, otherwise "
            "writer.lmdb and readback.lmdb"
        ),
    )
    args = parser.parse_args()
    if args.history_fault != "none" and args.predecessor_format != "versioned":
        parser.error("--history-fault requires --predecessor-format versioned")
    if args.history_fault != "none" and args.seed_candidate:
        parser.error("--seed-candidate cannot be combined with --history-fault")
    if args.single_peer and args.history_fault != "none":
        parser.error("--history-fault is not supported with --single-peer")
    return args


def peer_address(
    dht: Libp2pKadDHT,
    advertise_host: str,
    *,
    listen_host: str = "127.0.0.1",
) -> str:
    try:
        listen_host = str(ipaddress.IPv4Address(listen_host))
        advertise_host = str(ipaddress.IPv4Address(advertise_host))
    except ipaddress.AddressValueError as exc:
        raise ValueError("Registry listener and advertised hosts must be IPv4 addresses") from exc
    address = dht.get_listen_multiaddr()
    expected_prefix = f"/ip4/{listen_host}/"
    if not address.startswith(expected_prefix):
        raise RuntimeError("Registry listener did not bind to its configured IPv4 listener")
    if advertise_host != listen_host:
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


async def run_single_peer(args: argparse.Namespace, fixture: IdentityFixture) -> None:
    scratch = Path(os.environ.get("TMPDIR", Path.home() / ".cache" / "decent-wallet"))
    scratch.mkdir(parents=True, exist_ok=True)
    if args.data_dir is None:
        root_context = tempfile.TemporaryDirectory(prefix="registry-peer-", dir=scratch)
    else:
        root_path = args.data_dir.expanduser().resolve()
        root_path.mkdir(parents=True, exist_ok=True)
        if any(root_path.iterdir()):
            raise RuntimeError("--data-dir must be empty")
        root_context = nullcontext(str(root_path))

    with root_context as root:
        root_path = Path(root)
        async with Libp2pKadDHT(
            listen=f"/ip4/{args.listen_host}/tcp/0",
            durable_store=LMDBDatastore(path=root_path / "peer.lmdb"),
        ) as peer:
            if args.predecessor_format == "legacy":
                await peer.put_signed_identity_record(
                    fixture.identity_key,
                    fixture.predecessor,
                )
            else:
                await seed_peer_with_fixture(peer, fixture)

            if args.seed_candidate:
                await peer.put_signed_identity_record_if_current(
                    fixture.identity_key,
                    fixture.candidate,
                    expected_state_hash=fixture.predecessor_state_hash,
                    expires_at=int(time.time()) + 300,
                )
                observed = await peer.get_signed_identity_record(fixture.identity_key)
                if result_sequence(observed) != fixture.candidate_sequence:
                    raise RuntimeError(
                        "single Registry peer did not retain the rotation candidate"
                    )

            address = peer_address(
                peer,
                args.advertise_host,
                listen_host=args.listen_host,
            )
            print(f"READY\t{address}", flush=True)
            await trio.sleep_forever()


async def main() -> None:
    args = parse_args()
    fixture = load_fixture(args.predecessor_format)
    if args.single_peer:
        await run_single_peer(args, fixture)
        return
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
        listen_multiaddr = f"/ip4/{args.listen_host}/tcp/0"
        async with (
            Libp2pKadDHT(
                listen=listen_multiaddr,
                durable_store=LMDBDatastore(path=root_path / "writer.lmdb"),
            ) as writer,
            Libp2pKadDHT(
                listen=listen_multiaddr,
                durable_store=LMDBDatastore(path=root_path / "readback.lmdb"),
            ) as readback,
        ):
            writer_peer = peer_address(
                writer, args.advertise_host, listen_host=args.listen_host
            )
            readback_peer = peer_address(
                readback, args.advertise_host, listen_host=args.listen_host
            )
            writer_local_peer = peer_address(
                writer, args.listen_host, listen_host=args.listen_host
            )
            readback_local_peer = peer_address(
                readback, args.listen_host, listen_host=args.listen_host
            )

            if args.predecessor_format == "legacy":
                await readback.bootstrap(writer_local_peer)
                await writer.bootstrap(readback_local_peer)
                await writer.put_signed_identity_record(
                    fixture.identity_key, fixture.predecessor
                )
                anchor = await readback.get_signed_identity_record(fixture.identity_key)
                if anchor is None:
                    raise RuntimeError("readback Registry peer did not accept the legacy anchor")
            else:
                # Seed each peer's authenticated history before connecting them. This avoids
                # one peer's newer head masking the predecessor expected by the other peer.
                await seed_peer_with_fixture(writer, fixture)
                await seed_peer_with_fixture(readback, fixture)
                if args.history_fault != "none":
                    for peer in (writer, readback):
                        inject_history_fault(peer, fixture, args.history_fault)
                await readback.bootstrap(writer_local_peer)
                await writer.bootstrap(readback_local_peer)
                if args.history_fault == "none":
                    for peer in (writer, readback):
                        observed = await peer.get_signed_identity_record(fixture.identity_key)
                        if result_sequence(observed) != fixture.predecessor_sequence:
                            raise RuntimeError(
                                "Registry peer did not retain the synthetic versioned predecessor"
                            )
                else:
                    record_key = bytes.fromhex(fixture.identity_key)
                    for peer in (writer, readback):
                        if peer._durable_get(kind="identity", key=record_key) != fixture.predecessor:
                            raise RuntimeError(
                                "history fault injection changed the versioned current head"
                            )

            if args.seed_candidate:
                await writer.put_signed_identity_record_if_current(
                    fixture.identity_key,
                    fixture.candidate,
                    expected_state_hash=fixture.predecessor_state_hash,
                    expires_at=int(time.time()) + 300,
                )
                for _attempt in range(40):
                    observed = await readback.get_signed_identity_record(fixture.identity_key)
                    if result_sequence(observed) == fixture.candidate_sequence:
                        break
                    await trio.sleep(0.25)
                else:
                    raise RuntimeError("readback Registry peer did not accept the rotation candidate")

            print(f"READY_WRITE\t{writer_peer}", flush=True)
            print(f"READY_READBACK\t{readback_peer}", flush=True)

            await trio.sleep_forever()


if __name__ == "__main__":
    trio.run(main)

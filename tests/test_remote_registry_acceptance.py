from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import cbor2
import pytest
import trio

pytest.importorskip("decent_registry")

from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT

from decent_wallet import RegistryTransport
from decent_wallet.identity import ExpiredPublication, StalePublication

VECTOR_PATH = Path(__file__).parent / "vectors" / "identity-owner-key-rotation-legacy.json"


@pytest.mark.registry_integration
def test_remote_registry_accepts_and_independently_confirms_the_exact_candidate(
    tmp_path: Path,
) -> None:
    writer_peer = os.environ.get("DECENT_REGISTRY_TEST_PEER")
    readback_peer = os.environ.get("DECENT_REGISTRY_TEST_READBACK_PEER")
    if writer_peer is None and readback_peer is None:
        pytest.skip("the on-demand remote Registry deployment is not configured")
    if not writer_peer or not readback_peer:
        pytest.fail("both remote Registry peer addresses are required")

    writer_peer_id = writer_peer.rsplit("/p2p/", 1)[-1].split("/", 1)[0]
    readback_peer_id = readback_peer.rsplit("/p2p/", 1)[-1].split("/", 1)[0]
    if writer_peer_id == readback_peer_id:
        pytest.fail("the independent read-back peer must have a distinct peer ID")

    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    owner_name = bytes.fromhex(vector["owner_name_utf8_hex"])
    owner_name_hex = owner_name.hex()
    object_key = hashlib.sha256(owner_name).hexdigest()
    predecessor = bytes.fromhex(vector["predecessor_envelope_cbor_hex"])
    candidate = bytes.fromhex(vector["candidate_envelope_cbor_hex"])
    predecessor_hash = bytes.fromhex(vector["predecessor_state_hash_hex"])
    candidate_hash = hashlib.sha256(cbor2.loads(candidate)[2]).digest()

    writer_transport = RegistryTransport(
        bootstrap_peers=[writer_peer],
        store_path=tmp_path / "wallet-registry-writer.lmdb",
        supports_owner_key_rotation=True,
    )
    readback_transport = RegistryTransport(
        bootstrap_peers=[writer_peer],
        readback_peer=readback_peer,
        store_path=tmp_path / "wallet-registry-readback.lmdb",
        supports_owner_key_rotation=True,
    )

    assert readback_transport.get_remote_identity_envelope(owner_name_hex=owner_name_hex) == predecessor

    with pytest.raises(StalePublication):
        writer_transport.put_identity_envelope(
            owner_name_hex=owner_name_hex,
            envelope_cbor=candidate,
            expected_state_hash=bytes(32),
            expires_at=int(time.time()) + 300,
        )
    assert readback_transport.get_remote_identity_envelope(owner_name_hex=owner_name_hex) == predecessor

    with pytest.raises(ExpiredPublication):
        writer_transport.put_identity_envelope(
            owner_name_hex=owner_name_hex,
            envelope_cbor=candidate,
            expected_state_hash=predecessor_hash,
            expires_at=int(time.time()) - 1,
        )
    assert readback_transport.get_remote_identity_envelope(owner_name_hex=owner_name_hex) == predecessor

    class LostAcknowledgement:
        def __init__(self, transport: RegistryTransport) -> None:
            self.transport = transport
            self.write_attempts = 0

        def put_identity_envelope(self, **kwargs: object) -> None:
            self.write_attempts += 1
            self.transport.put_identity_envelope(**kwargs)  # type: ignore[arg-type]
            raise TimeoutError("simulated lost acknowledgement after dispatch")

    lost_ack = LostAcknowledgement(writer_transport)
    with pytest.raises(TimeoutError, match="lost acknowledgement"):
        lost_ack.put_identity_envelope(
            owner_name_hex=owner_name_hex,
            envelope_cbor=candidate,
            expected_state_hash=predecessor_hash,
            expires_at=int(time.time()) + 300,
        )
    assert lost_ack.write_attempts == 1

    observed_candidate = readback_transport.get_remote_identity_envelope(
        owner_name_hex=owner_name_hex
    )
    assert observed_candidate == candidate

    async def read_history(peer_address: str, state_hash: bytes) -> bytes | None:
        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as reader:
            await reader.bootstrap(peer_address)
            return await reader.read_remote_identity_envelope_by_hash(object_key, state_hash)

    assert trio.run(read_history, readback_peer, predecessor_hash) == predecessor
    assert trio.run(read_history, readback_peer, candidate_hash) == candidate
    assert trio.run(read_history, writer_peer, candidate_hash) == candidate

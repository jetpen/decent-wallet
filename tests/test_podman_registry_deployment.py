from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import cbor2
import pytest
import trio

pytest.importorskip("decent_registry.dht.libp2p_dht")

from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT
from decent_wallet import RegistryTransport
from decent_wallet.identity import ExpiredPublication, StalePublication


VECTOR_PATH = Path(__file__).parent / "vectors" / "identity-owner-key-rotation-legacy.json"


def test_podman_writer_publication_remains_peer_scoped(tmp_path: Path) -> None:
    """Record the current diagnostic; this does not satisfy independent confirmation."""
    writer_peer = os.environ.get("DECENT_REGISTRY_ACCEPTANCE_WRITER_PEER")
    readback_peer = os.environ.get("DECENT_REGISTRY_ACCEPTANCE_READBACK_PEER")
    if writer_peer is None and readback_peer is None:
        pytest.skip("the managed Podman Registry deployment is not configured")
    if not writer_peer or not readback_peer:
        pytest.fail("both managed Registry peer addresses are required")

    vector = json.loads(VECTOR_PATH.read_text(encoding="utf-8"))
    owner_name = bytes.fromhex(vector["owner_name_utf8_hex"])
    owner_name_hex = owner_name.hex()
    identity_key = hashlib.sha256(owner_name).hexdigest()
    predecessor = bytes.fromhex(vector["predecessor_envelope_cbor_hex"])
    candidate = bytes.fromhex(vector["candidate_envelope_cbor_hex"])
    predecessor_hash = bytes.fromhex(vector["predecessor_state_hash_hex"])
    candidate_sequence = int(vector["candidate_sequence"])

    readback_transport = RegistryTransport(
        bootstrap_peers=[writer_peer],
        readback_peer=readback_peer,
        store_path=tmp_path / "wallet-registry-readback.lmdb",
        supports_owner_key_rotation=True,
    )
    writer_transport = RegistryTransport(
        bootstrap_peers=[writer_peer],
        store_path=tmp_path / "wallet-registry-writer.lmdb",
        supports_owner_key_rotation=True,
    )

    observed_predecessor = readback_transport.get_remote_identity_envelope(
        owner_name_hex=owner_name_hex
    )
    if observed_predecessor != predecessor:
        pytest.fail("independent Registry peer did not return the seeded predecessor")

    def try_publish(expected_state_hash: bytes, expires_at: int) -> None:
        readback_transport.put_identity_envelope(
            owner_name_hex=owner_name_hex,
            envelope_cbor=candidate,
            expected_state_hash=expected_state_hash,
            expires_at=expires_at,
        )

    try:
        try_publish(bytes(32), int(time.time()) + 300)
    except StalePublication:
        pass
    else:
        pytest.fail("stale conditional publication was not rejected")
    if readback_transport.get_remote_identity_envelope(owner_name_hex=owner_name_hex) != predecessor:
        pytest.fail("stale conditional publication changed the Registry head")

    try:
        try_publish(predecessor_hash, int(time.time()) - 1)
    except ExpiredPublication:
        pass
    else:
        pytest.fail("expired publication was not rejected")
    if readback_transport.get_remote_identity_envelope(owner_name_hex=owner_name_hex) != predecessor:
        pytest.fail("expired publication changed the Registry head")

    class LostAcknowledgement:
        def __init__(self, transport: RegistryTransport) -> None:
            self.transport = transport
            self.write_attempts = 0

        def put_identity_envelope(self, **kwargs: object) -> None:
            self.write_attempts += 1
            self.transport.put_identity_envelope(**kwargs)  # type: ignore[arg-type]
            raise TimeoutError("simulated lost acknowledgement after dispatch")

    lost_ack = LostAcknowledgement(readback_transport)
    try:
        lost_ack.put_identity_envelope(
            owner_name_hex=owner_name_hex,
            envelope_cbor=candidate,
            expected_state_hash=predecessor_hash,
            expires_at=int(time.time()) + 300,
        )
    except TimeoutError:
        pass
    else:
        pytest.fail("simulated lost acknowledgement did not remain ambiguous")
    if lost_ack.write_attempts != 1:
        pytest.fail("ambiguous dispatch was automatically retried")

    writer_value = writer_transport.get_remote_identity_envelope(
        owner_name_hex=owner_name_hex
    )
    if writer_value != candidate:
        pytest.fail("writer Registry peer did not return the exact candidate")

    # ADR-0006 makes DHT publication best-effort; this distinct direct-read peer
    # is deliberately not a bootstrap/write target, so this is not acceptance.
    readback_value = readback_transport.get_remote_identity_envelope(
        owner_name_hex=owner_name_hex
    )
    if readback_value != predecessor:
        pytest.fail(
            "writer-only publication changed the distinct peer; review the diagnostic "
            "if Registry propagation semantics change"
        )

    signed_update_bytes = cbor2.loads(candidate)[2]
    candidate_state_hash = hashlib.sha256(signed_update_bytes).digest()
    if cbor2.loads(signed_update_bytes)[3] != candidate_sequence:
        pytest.fail("shared candidate fixture sequence did not match its metadata")

    async def read_history(peer_address: str, state_hash: bytes) -> bytes | None:
        async with Libp2pKadDHT(dht_mode=DHTMode.CLIENT) as reader:
            await reader.bootstrap(peer_address)
            return await reader.read_remote_identity_envelope_by_hash(
                identity_key, state_hash
            )

    writer_candidate_history = trio.run(
        read_history, writer_peer, candidate_state_hash
    )
    if writer_candidate_history != candidate:
        pytest.fail("writer Registry peer did not serve the accepted candidate history")
    readback_predecessor_history = trio.run(
        read_history, readback_peer, predecessor_hash
    )
    if readback_predecessor_history != predecessor:
        pytest.fail("independent Registry peer did not serve its seeded predecessor history")

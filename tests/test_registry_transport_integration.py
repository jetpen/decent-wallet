from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import cast

import pytest

import trio

from decent_wallet.identity import ExpiredPublication, StalePublication
from decent_wallet import (
    ConsentDecision,
    IdentityBundle,
    PublishStatus,
    RegistryAdapter,
    RegistryTransport,
    Wallet,
)


OWNER_NAME = b"wallet-direct-dht-integration"


def _identity_envelope(
    owner_name: bytes, owner_key_path: Path, *, seq: int
):
    import cbor2
    from decent_registry.envelope_builder import build_identity_envelope

    envelope = build_identity_envelope(
        owner_name_hex=owner_name.hex(),
        owner_privkey_pem_path=str(owner_key_path),
        seq=seq,
    )
    signed_update_bytes = cbor2.loads(envelope)[1]
    return envelope, hashlib.sha256(signed_update_bytes).digest()


def test_registry_transport_requires_distinct_readback_peer_id(tmp_path):
    bootstrap_peer = "/ip4/127.0.0.1/tcp/9000/p2p/12D3KooWBootstrap"
    same_peer_different_address = "/dns4/registry.example/tcp/9000/p2p/12D3KooWBootstrap"
    with pytest.raises(ValueError, match="readback_peer must have a distinct peer ID"):
        RegistryTransport(
            bootstrap_peers=[bootstrap_peer],
            readback_peer=same_peer_different_address,
            store_path=tmp_path / "wallet-registry.lmdb",
        )


@pytest.mark.registry_integration
@pytest.mark.trio
async def test_direct_dht_transport_conditionally_publishes_and_reads_exact_remote_bytes(
    tmp_path,
):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from decent_registry.dht.libp2p_dht import Libp2pKadDHT
    from decent_registry.durable_store import LMDBDatastore
    from decent_registry.registry_service import RegistryService

    owner_private_key = Ed25519PrivateKey.generate()
    owner_key_path = tmp_path / "owner.pem"
    owner_key_path.write_bytes(
        owner_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    genesis, genesis_hash = _identity_envelope(OWNER_NAME, owner_key_path, seq=1)
    successor, successor_hash = _identity_envelope(OWNER_NAME, owner_key_path, seq=2)
    following, following_hash = _identity_envelope(
        OWNER_NAME, owner_key_path, seq=3
    )

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "seed.lmdb")
    ) as seed:
        seed_peer = seed.get_listen_multiaddr()
        if "/p2p/" not in seed_peer:
            seed_peer = f"{seed_peer}/p2p/{seed.host.get_id().to_string()}"
        transport = RegistryTransport(
            bootstrap_peers=[seed_peer],
            store_path=tmp_path / "wallet-registry.lmdb",
        )
        assert transport.supports_owner_key_rotation is False
        with pytest.raises(
            TypeError,
            match="supports_owner_key_rotation must be a bool",
        ):
            RegistryTransport(
                bootstrap_peers=[seed_peer],
                store_path=tmp_path / "invalid-capability.lmdb",
                supports_owner_key_rotation=cast(bool, 1),
            )

        async def invoke(method, **kwargs):
            return await trio.to_thread.run_sync(lambda: method(**kwargs))

        # A missing predecessor is never treated as permission to create an
        # Identity: reject locally without sending an empty-state CAS to DHT.
        with pytest.raises(StalePublication):
            await invoke(
                transport.put_identity_envelope,
                owner_name_hex=OWNER_NAME.hex(),
                envelope_cbor=genesis,
                expected_state_hash=None,
                expires_at=int(time.time()) + 120,
            )

        seed_service = RegistryService(seed)
        assert await seed_service.get_identity_envelope(
            owner_name_hex=OWNER_NAME.hex()
        ) is None
        await seed_service.put_identity_envelope(
            owner_name_hex=OWNER_NAME.hex(), envelope_cbor=genesis
        )

        with pytest.raises(StalePublication):
            await invoke(
                transport.put_identity_envelope,
                owner_name_hex=OWNER_NAME.hex(),
                envelope_cbor=successor,
                expected_state_hash=b"\xff" * 32,
                expires_at=int(time.time()) + 120,
            )
        assert await seed_service.get_identity_envelope(
            owner_name_hex=OWNER_NAME.hex()
        ) == genesis
        with pytest.raises(ExpiredPublication):
            await invoke(
                transport.put_identity_envelope,
                owner_name_hex=OWNER_NAME.hex(),
                envelope_cbor=successor,
                expected_state_hash=genesis_hash,
                expires_at=int(time.time()) - 1,
            )
        assert await seed_service.get_identity_envelope(
            owner_name_hex=OWNER_NAME.hex()
        ) == genesis

        # Publish through the wallet transport, then read the exact value from
        # the independently queried seed peer.
        await invoke(
            transport.put_identity_envelope,
            owner_name_hex=OWNER_NAME.hex(),
            envelope_cbor=successor,
            expected_state_hash=genesis_hash,
            expires_at=int(time.time()) + 120,
        )
        assert await invoke(
            transport.get_remote_identity_envelope,
            owner_name_hex=OWNER_NAME.hex(),
        ) == successor
        # By-hash is intentionally local retained history, not a DHT lookup.
        assert await invoke(
            transport.get_identity_envelope_by_hash,
            owner_name_hex=OWNER_NAME.hex(),
            state_hash=successor_hash,
        ) == successor
        assert await invoke(
            transport.get_identity_envelope,
            owner_name_hex=OWNER_NAME.hex(),
        ) == successor
        # The peer can advance independently, leaving this client's retained
        # accepted head stale. Only the uncached peer path sees that update.
        await seed_service.put_identity_envelope_if_current(
            owner_name_hex=OWNER_NAME.hex(),
            envelope_cbor=following,
            expected_state_hash=successor_hash,
            expires_at=int(time.time()) + 120,
        )
        assert await invoke(
            transport.get_remote_identity_envelope,
            owner_name_hex=OWNER_NAME.hex(),
        ) == following
        assert await invoke(
            transport.get_identity_envelope,
            owner_name_hex=OWNER_NAME.hex(),
        ) == successor
        assert await invoke(
            transport.get_identity_envelope_by_hash,
            owner_name_hex=OWNER_NAME.hex(),
            state_hash=following_hash,
        ) is None


@pytest.mark.registry_integration
@pytest.mark.trio
async def test_remote_readback_uses_independent_peer_after_writer_stops(tmp_path):
    from decent_registry.dht.libp2p_dht import Libp2pKadDHT
    from decent_registry.durable_store import LMDBDatastore
    from decent_registry.record_validator import IdentityRecordResult

    vector_path = Path(__file__).parent / "vectors" / "identity-owner-key-rotation-legacy.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    owner_name = bytes.fromhex(vector["owner_name_utf8_hex"])
    identity_key = hashlib.sha256(owner_name).hexdigest()
    predecessor = bytes.fromhex(vector["predecessor_envelope_cbor_hex"])
    candidate = bytes.fromhex(vector["candidate_envelope_cbor_hex"])
    predecessor_hash = bytes.fromhex(vector["predecessor_state_hash_hex"])

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "independent-reader.lmdb")
    ) as reader:
        readback_peer = reader.get_listen_multiaddr()
        if "/p2p/" not in readback_peer:
            readback_peer = f"{readback_peer}/p2p/{reader.host.get_id().to_string()}"
        async with Libp2pKadDHT(
            durable_store=LMDBDatastore(path=tmp_path / "writer.lmdb")
        ) as writer:
            writer_peer = writer.get_listen_multiaddr()
            if "/p2p/" not in writer_peer:
                writer_peer = f"{writer_peer}/p2p/{writer.host.get_id().to_string()}"
            await reader.bootstrap(writer_peer)
            await writer.bootstrap(readback_peer)
            await writer.put_signed_identity_record(identity_key, predecessor)

            # The second Registry accepts the anchor into its own durable history.
            assert await reader.get_signed_identity_record(identity_key) is not None
            transport = RegistryTransport(
                bootstrap_peers=[writer_peer],
                readback_peer=readback_peer,
                store_path=tmp_path / "wallet-independent-readback.lmdb",
                supports_owner_key_rotation=True,
            )

            def publish_candidate():
                transport.put_identity_envelope(
                    owner_name_hex=owner_name.hex(),
                    envelope_cbor=candidate,
                    expected_state_hash=predecessor_hash,
                    expires_at=int(time.time()) + 120,
                )

            await trio.to_thread.run_sync(publish_candidate)
            fresh_remote = await trio.to_thread.run_sync(
                lambda: transport.get_remote_identity_envelope(
                    owner_name_hex=owner_name.hex()
                )
            )
            assert fresh_remote == candidate
            accepted_on_second = await reader.get_signed_identity_record(identity_key)
            assert isinstance(accepted_on_second, IdentityRecordResult)
            assert accepted_on_second.seq == int(vector["candidate_sequence"])
            assert await reader.get_identity_envelope_by_hash(
                identity_key, predecessor_hash
            ) == predecessor

        # The writer is now stopped. A fresh direct read must use the separately
        # configured peer, not the writer's durable cache or an unavailable writer.
        remote = await trio.to_thread.run_sync(
            lambda: transport.get_remote_identity_envelope(
                owner_name_hex=owner_name.hex()
            )
        )
        assert remote == candidate


@pytest.mark.registry_integration
@pytest.mark.trio
@pytest.mark.parametrize("outcome", ["success", "expired", "ambiguous"])
async def test_operation_five_desktop_api_handles_dispatch_outcomes(
    tmp_path,
    outcome: str,
):
    from decent_registry.dht.libp2p_dht import Libp2pKadDHT
    from decent_registry.durable_store import LMDBDatastore
    from decent_registry.registry_service import RegistryService

    password = "correct horse battery staple"
    expiry = int(time.time()) + 300
    owner_name_hex = OWNER_NAME.hex()

    async with Libp2pKadDHT(
        durable_store=LMDBDatastore(path=tmp_path / "rotation-seed.lmdb")
    ) as seed:
        seed_peer = seed.get_listen_multiaddr()
        if "/p2p/" not in seed_peer:
            seed_peer = f"{seed_peer}/p2p/{seed.host.get_id().to_string()}"
        transport = RegistryTransport(
            bootstrap_peers=[seed_peer],
            store_path=tmp_path / "rotation-client.lmdb",
            supports_owner_key_rotation=True,
        )
        seed_service = RegistryService(seed)

        def run_in_thread(callback):
            return trio.to_thread.run_sync(callback)

        owner, bob, carol = await run_in_thread(
            lambda: tuple(
                Wallet.create_with_generated_key(
                    tmp_path / f"{name}.dw", password, password
                )
                for name in ("owner", "bob", "carol")
            )
        )
        bootstrap_adapter = RegistryAdapter(transport)

        def create_genesis_bundle():
            draft = bootstrap_adapter.create_draft(
                owner_name=OWNER_NAME,
                owner_public_key=owner.public_key,
            )
            submission = bootstrap_adapter.sign_draft(
                draft=draft,
                signer_public_key=owner.public_key,
                signer_factory=owner.create_signer,
                consent=lambda _transcript: ConsentDecision.APPROVED,
                authenticated_origin="https://wallet.example",
                environment="local-registry-test",
                purpose="create test Identity",
                capability="identity.write",
                expires_at=expiry,
                replay_nonce=b"direct-dht-genesis-signature",
            )
            return IdentityBundle.from_submission(submission)

        genesis_bundle = await run_in_thread(create_genesis_bundle)
        genesis_envelope = genesis_bundle.finalize()
        await seed_service.put_identity_envelope(
            owner_name_hex=owner_name_hex,
            envelope_cbor=genesis_envelope,
        )

        class DispatchOutcomeTransport:
            def __init__(self, inner: RegistryTransport, outcome: str) -> None:
                self.inner = inner
                self.outcome = outcome
                self.supports_owner_key_rotation = (
                    inner.supports_owner_key_rotation
                )
                self.hide_remote_readback = False
                self.write_attempts = 0

            def get_identity_envelope(
                self, *, owner_name_hex: str
            ) -> bytes | None:
                return self.inner.get_identity_envelope(
                    owner_name_hex=owner_name_hex
                )

            def get_identity_envelope_by_hash(
                self, *, owner_name_hex: str, state_hash: bytes
            ) -> bytes | None:
                return self.inner.get_identity_envelope_by_hash(
                    owner_name_hex=owner_name_hex,
                    state_hash=state_hash,
                )

            def get_remote_identity_envelope(
                self, *, owner_name_hex: str
            ) -> bytes | None:
                if self.hide_remote_readback:
                    return None
                return self.inner.get_remote_identity_envelope(
                    owner_name_hex=owner_name_hex
                )

            def put_identity_envelope(
                self,
                *,
                owner_name_hex: str,
                envelope_cbor: bytes,
                expected_state_hash: bytes | None,
                expires_at: int,
            ) -> None:
                self.write_attempts += 1
                if self.outcome == "expired":
                    raise ExpiredPublication()
                self.inner.put_identity_envelope(
                    owner_name_hex=owner_name_hex,
                    envelope_cbor=envelope_cbor,
                    expected_state_hash=expected_state_hash,
                    expires_at=expires_at,
                )
                if self.outcome == "ambiguous":
                    self.hide_remote_readback = True
                    raise TimeoutError("simulated lost acknowledgement after dispatch")

        dispatch_transport = DispatchOutcomeTransport(transport, outcome)
        adapter = RegistryAdapter(dispatch_transport)

        def prepare_rotation():
            predecessor = adapter.read_state(owner_name=OWNER_NAME)
            assert predecessor is not None
            active_public_key = owner.public_key
            successor_public_key = owner.prepare_signing_key_rotation()
            rotation_draft = adapter.create_owner_key_rotation_draft(
                owner_name=OWNER_NAME,
                successor_owner_public_key=successor_public_key,
                successor_signer_set=[
                    {1: "owner", 2: successor_public_key},
                    {1: "bob", 2: bob.public_key},
                    {1: "carol", 2: carol.public_key},
                ],
            )
            owner.prove_pending_signing_key_rotation(rotation_draft)
            signed = adapter.sign_draft(
                draft=rotation_draft,
                signer_public_key=active_public_key,
                signer_factory=owner.create_signer,
                consent=lambda _transcript: ConsentDecision.APPROVED,
                authenticated_origin="https://wallet.example",
                environment="local-registry-test",
                purpose="authorize owner-key rotation",
                capability="identity.rotate-owner-key",
                expires_at=expiry,
                replay_nonce=b"direct-dht-rotation-signature",
            )
            bundle = IdentityBundle.from_submission(signed)
            prepared = adapter.prepare_owner_key_rotation_publication(
                bundle,
                consent=lambda _transcript: ConsentDecision.APPROVED,
                authenticated_origin="https://wallet.example",
                environment="local-registry-test",
                purpose="publish owner-key rotation",
                capability="identity.rotate-owner-key",
                expires_at=expiry,
                replay_nonce=b"direct-dht-rotation-publication",
            )
            assert prepared.status is PublishStatus.READY
            assert prepared.publication is not None
            permit = owner.latch_signing_key_rotation_dispatch_intent(
                bundle, prepared.publication
            )
            return active_public_key, successor_public_key, prepared.publication, permit

        (
            active_public_key,
            successor_public_key,
            publication,
            permit,
        ) = await run_in_thread(prepare_rotation)
        finalized_envelope = publication.envelope_bytes

        def dispatch():
            return adapter.dispatch_owner_key_rotation(publication, permit)

        dispatch_result = await run_in_thread(dispatch)
        assert dispatch_transport.write_attempts == 1
        assert owner.public_key == active_public_key
        assert owner.pending_signing_public_key == successor_public_key
        assert owner.signing_key_rotation_dispatch_intent == permit.intent

        if outcome == "expired":
            assert dispatch_result.status is PublishStatus.EXPIRED
            assert dispatch_result.confirmation is None
            rejection = dispatch_result.rejection
            assert rejection is not None
            assert await run_in_thread(
                lambda: transport.get_remote_identity_envelope(
                    owner_name_hex=owner_name_hex
                )
            ) == genesis_envelope
            await run_in_thread(
                lambda: owner.resolve_signing_key_rotation_rejection(rejection)
            )
            assert owner.signing_key_rotation_dispatch_intent is None
            assert owner.public_key == active_public_key
            assert owner.pending_signing_public_key == successor_public_key
            await run_in_thread(owner.cancel_signing_key_rotation)
            assert owner.pending_signing_public_key is None
            assert await seed_service.get_identity_envelope(
                owner_name_hex=owner_name_hex
            ) == genesis_envelope
            await run_in_thread(owner.lock)
            await run_in_thread(bob.lock)
            await run_in_thread(carol.lock)
            return

        if outcome == "ambiguous":
            assert dispatch_result.status is PublishStatus.UNKNOWN
            assert dispatch_result.confirmation is None
            remote_before_recovery = await run_in_thread(
                lambda: transport.get_remote_identity_envelope(
                    owner_name_hex=owner_name_hex
                )
            )
            assert remote_before_recovery == finalized_envelope
            dispatch_transport.hide_remote_readback = False
            confirmation = await run_in_thread(
                lambda: adapter.confirm_owner_key_rotation(permit.intent)
            )
        else:
            assert outcome == "success"
            assert dispatch_result.status is PublishStatus.CONFIRMED
            confirmation = dispatch_result.confirmation

        assert confirmation is not None
        await run_in_thread(lambda: owner.finalize_signing_key_rotation(confirmation))

        assert owner.public_key == successor_public_key
        assert owner.pending_signing_public_key is None
        assert owner.signing_key_rotation_dispatch_intent is None
        assert dispatch_transport.write_attempts == 1
        assert await seed_service.get_identity_envelope(
            owner_name_hex=owner_name_hex
        ) == finalized_envelope

        await run_in_thread(owner.lock)
        await run_in_thread(bob.lock)
        await run_in_thread(carol.lock)

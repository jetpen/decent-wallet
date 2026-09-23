from __future__ import annotations

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Event
from typing import Any, cast

import cbor2
import pytest

from decent_wallet import (
    ConsentDecision,
    ConsentTranscript,
    IdentityBundle,
    IdentityDraft,
    IdentityProof,
    InvalidContainer,
    InvalidIdentityRequest,
    InvalidIdentityState,
    PublishStatus,
    RegistryAdapter,
    RotationConfirmation,
    RotationDispatchIntent,
    RotationDispatchPermit,
    RotationDispatchRejection,
    RotationInProgress,
    RotationPublication,
    StalePublication,
    ExpiredPublication,
    SignerUnavailable,
    StorageFailure,
    Wallet,
    build_identity_update,
)

PASSWORD = "correct horse battery staple"
OWNER_NAME = b"multisig-owner"
EXPIRY = 2_000_000_000


class MemoryTransport:
    supports_owner_key_rotation = True

    def __init__(self) -> None:
        self.envelope: bytes | None = None
        self.remote_envelope: bytes | None = None
        self.writes: list[dict[str, Any]] = []
        self.history: dict[bytes, bytes] = {}
        self.drop_writes = False
        self.raise_after_write = False
        self.reject_conditional = False

    def get_identity_envelope(self, *, owner_name_hex: str) -> bytes | None:
        return self.envelope

    def get_remote_identity_envelope(self, *, owner_name_hex: str) -> bytes | None:
        return self.remote_envelope

    def get_identity_envelope_by_hash(
        self, *, owner_name_hex: str, state_hash: bytes
    ) -> bytes | None:
        return self.history.get(state_hash)

    def put_identity_envelope(
        self,
        *,
        owner_name_hex: str,
        envelope_cbor: bytes,
        expected_state_hash: bytes | None,
        expires_at: int,
    ) -> None:
        self.writes.append(
            {
                "owner_name_hex": owner_name_hex,
                "envelope_cbor": envelope_cbor,
                "expected_state_hash": expected_state_hash,
                "expires_at": expires_at,
            }
        )
        if expires_at <= int(time.time()):
            raise ExpiredPublication()
        if self.reject_conditional:
            raise StalePublication()
        if not self.drop_writes:
            if self.envelope is not None and expected_state_hash is not None:
                self.history[expected_state_hash] = self.envelope
            self.envelope = envelope_cbor
            self.remote_envelope = envelope_cbor
        if self.raise_after_write:
            raise TimeoutError("transport detail")


def approved(_transcript: ConsentTranscript) -> ConsentDecision:
    return ConsentDecision.APPROVED


def make_wallets(tmp_path, names=("alice", "bob", "carol", "dave")):
    return {
        name: Wallet.create_with_generated_key(tmp_path / f"{name}.dw", PASSWORD, PASSWORD)
        for name in names
    }


def signer_set(wallets, names):
    return [
        {1: name, 2: wallets[name].public_key}
        for name in sorted(names, key=lambda value: value.encode("utf-8"))
    ]


def authorization(wallets, names=("alice", "bob", "carol"), *, operation=1, epoch=1,
                  predecessor=bytes(32)):
    return {
        1: 1,
        2: 1,
        3: operation,
        4: epoch,
        5: 2,
        6: signer_set(wallets, names),
        7: predecessor,
    }


def sign_draft(adapter, draft, wallet, signer_id, nonce, *, consent=approved, expiry=EXPIRY):
    return adapter.sign_draft(
        draft=draft,
        signer_public_key=wallet.public_key,
        signer_factory=wallet.create_signer,
        consent=consent,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="authorize Identity update",
        capability="identity.write",
        expires_at=expiry,
        replay_nonce=nonce,
        signer_id=signer_id,
    )


def publish_bundle(adapter, bundle, nonce, *, consent=approved, expiry=EXPIRY):
    return adapter.publish_bundle(
        bundle,
        consent=consent,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="publish authorized Identity update",
        capability="identity.publish",
        expires_at=expiry,
        replay_nonce=nonce,
    )


def prepare_rotation_publication(adapter, bundle, nonce):
    result = adapter.prepare_owner_key_rotation_publication(
        bundle,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="publish owner-key rotation",
        capability="identity.rotate-owner-key",
        expires_at=EXPIRY,
        replay_nonce=nonce,
    )
    assert result.status is PublishStatus.READY
    assert result.publication is not None
    return result.publication


def test_independent_signers_exchange_public_bundle_and_publish_threshold_envelope(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    auth = authorization(wallets)
    draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=auth,
    )

    alice_result = sign_draft(adapter, draft, wallets["alice"], "alice", b"alice-nonce")
    bob_result = sign_draft(adapter, draft, wallets["bob"], "bob", b"bob-nonce")

    assert alice_result.status is PublishStatus.PROOF_READY
    assert bob_result.status is PublishStatus.PROOF_READY
    assert alice_result.signed_update_bytes == bob_result.signed_update_bytes
    assert alice_result.signed_update_bytes == draft.signed_update_bytes
    assert alice_result.transcript.payload_hash == bob_result.transcript.payload_hash
    assert alice_result.transcript.payload_hash == hashlib.sha256(draft.signed_update_bytes).digest()
    assert alice_result.transcript.review_payload == draft.signed_update_bytes
    assert bob_result.transcript.review_payload == draft.signed_update_bytes
    assert transport.writes == []

    bundle = IdentityBundle.from_submission(alice_result).merge(
        IdentityBundle.from_submission(bob_result)
    )
    exchanged_bytes = bundle.to_cbor()
    exchanged = IdentityBundle.from_cbor(exchanged_bytes)
    assert exchanged == bundle
    assert b"correct horse battery staple" not in exchanged_bytes
    assert b"private_seed" not in exchanged_bytes
    encoded_bundle = cbor2.loads(exchanged_bytes)
    assert set(encoded_bundle[3][0]) == {1, 2, 3}
    encoded_bundle[3][0][4] = EXPIRY + 86_400
    with pytest.raises(InvalidIdentityRequest):
        IdentityBundle.from_cbor(cbor2.dumps(encoded_bundle, canonical=True))

    envelope = exchanged.finalize()
    publication_transcripts = []

    def approve_publication(transcript):
        publication_transcripts.append(transcript)
        return ConsentDecision.APPROVED

    result = publish_bundle(
        adapter,
        exchanged,
        b"publish-v1",
        consent=approve_publication,
    )
    assert publication_transcripts[0].payload_hash == hashlib.sha256(envelope).digest()
    assert publication_transcripts[0].review_payload == envelope
    assert publication_transcripts[0].expires_at == EXPIRY
    assert result.status is PublishStatus.CONFIRMED
    assert result.envelope_bytes == envelope
    assert result.accepted_state is not None
    assert result.accepted_state.sequence == 1
    assert transport.envelope == envelope
    assert len(transport.writes) == 1
    assert transport.writes[0]["owner_name_hex"] == OWNER_NAME.hex()
    assert transport.writes[0]["expected_state_hash"] is None
    assert transport.writes[0]["expires_at"] == EXPIRY

    previous = result.accepted_state
    assert previous is not None
    next_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=previous.owner_public_key,
        authorization=authorization(
            wallets,
            operation=2,
            epoch=previous.generation or 1,
            predecessor=previous.state_hash,
        ),
    )
    next_bundle = IdentityBundle.from_submission(
        sign_draft(adapter, next_draft, wallets["alice"], "alice", b"next-alice")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(adapter, next_draft, wallets["bob"], "bob", b"next-bob")
        )
    )
    writes_before_replay = len(transport.writes)
    replayed = publish_bundle(adapter, next_bundle, b"publish-v1")
    assert replayed.status is PublishStatus.FAILED
    assert replayed.reason == "replay rejected"
    assert len(transport.writes) == writes_before_replay

    for wallet in wallets.values():
        wallet.lock()


def test_legacy_draft_finalizes_to_legacy_envelope_and_publishes(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallet = make_wallets(tmp_path, ("alice",))["alice"]
    draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallet.public_key,
    )

    result = adapter.sign_draft(
        draft=draft,
        signer_public_key=wallet.public_key,
        signer_factory=wallet.create_signer,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="create Identity",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"legacy-nonce",
    )
    bundle = IdentityBundle.from_submission(result)
    envelope = bundle.finalize()

    assert set(cbor2.loads(envelope)) == {1, 2}
    published = publish_bundle(adapter, bundle, b"publish-legacy")
    assert published.status is PublishStatus.CONFIRMED
    assert transport.envelope == envelope
    wallet.lock()


def test_legacy_to_versioned_upgrade_uses_one_legacy_owner_proof(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    legacy_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
    )
    legacy_result = adapter.sign_draft(
        draft=legacy_draft,
        signer_public_key=wallets["alice"].public_key,
        signer_factory=wallets["alice"].create_signer,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="create Identity",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"legacy-create",
    )
    assert publish_bundle(
        adapter,
        IdentityBundle.from_submission(legacy_result),
        b"legacy-publish",
    ).status is PublishStatus.CONFIRMED

    previous = adapter.read_state(owner_name=OWNER_NAME)
    assert previous is not None
    upgrade_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=previous.owner_public_key,
        authorization=authorization(
            wallets,
            operation=4,
            epoch=1,
            predecessor=previous.state_hash,
        ),
    )
    owner_proof = IdentityBundle.from_submission(
        sign_draft(adapter, upgrade_draft, wallets["alice"], "alice", b"upgrade-owner")
    )

    other_signer = wallets["bob"].create_signer()
    wrong_proof = IdentityBundle(
        upgrade_draft,
        (
            IdentityProof(
                signer_id="bob",
                signer_public_key=wallets["bob"].public_key,
                signature=other_signer.sign_identity_update(upgrade_draft.signed_update_bytes),
            ),
        ),
    )
    with pytest.raises(InvalidIdentityRequest):
        wrong_proof.finalize()

    envelope = owner_proof.finalize()
    assert len(cbor2.loads(envelope)[3]) == 1
    invalid_update = build_identity_update(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        sequence=1,
        authorization=authorization(
            wallets,
            operation=4,
            epoch=1,
            predecessor=b"x" * 32,
        ),
    )
    invalid_signer = wallets["alice"].create_signer()
    invalid_signature = invalid_signer.sign_identity_update(invalid_update)
    invalid_envelope = cbor2.dumps(
        {1: 1, 2: invalid_update, 3: [{1: "alice", 2: invalid_signature}]},
        canonical=True,
    )
    orphaned_transport = MemoryTransport()
    orphaned_transport.envelope = invalid_envelope
    with pytest.raises(InvalidIdentityState):
        RegistryAdapter(orphaned_transport).read_state(owner_name=OWNER_NAME)

    result = publish_bundle(adapter, owner_proof, b"upgrade-publish")
    assert result.status is PublishStatus.CONFIRMED
    assert result.envelope_bytes == envelope
    assert result.accepted_state is not None
    assert result.accepted_state.generation == 1
    readback = adapter.read_state(owner_name=OWNER_NAME)
    assert readback is not None
    assert readback.generation is not None
    assert readback == result.accepted_state

    next_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=authorization(
            wallets,
            operation=2,
            epoch=readback.generation,
            predecessor=readback.state_hash,
        ),
    )
    assert IdentityDraft.from_cbor(next_draft.to_cbor()) == next_draft
    for wallet in wallets.values():
        wallet.lock()


def test_partial_or_expired_bundle_never_enters_publication_path(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=authorization(wallets),
    )
    one_proof = IdentityBundle.from_submission(
        sign_draft(adapter, draft, wallets["alice"], "alice", b"one-proof")
    )

    with pytest.raises(InvalidIdentityRequest):
        one_proof.finalize()
    with pytest.raises(InvalidIdentityRequest):
        publish_bundle(adapter, one_proof, b"publish-partial")
    assert transport.writes == []

    expired = sign_draft(
        adapter, draft, wallets["bob"], "bob", b"expired-proof", expiry=1
    )
    assert expired.status is PublishStatus.EXPIRED
    assert transport.writes == []

    bob = IdentityBundle.from_submission(
        sign_draft(adapter, draft, wallets["bob"], "bob", b"bob-proof")
    )
    complete = one_proof.merge(bob)
    consent_calls = []
    expired_publication = publish_bundle(
        adapter,
        complete,
        b"expired-publication",
        consent=lambda transcript: consent_calls.append(transcript),
        expiry=1,
    )
    assert expired_publication.status is PublishStatus.EXPIRED
    assert consent_calls == []
    assert transport.writes == []
    for wallet in wallets.values():
        wallet.lock()

def test_duplicate_conflicting_wrong_signer_and_wrong_bytes_proofs_are_rejected(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=authorization(wallets),
    )
    alice = IdentityBundle.from_submission(
        sign_draft(adapter, draft, wallets["alice"], "alice", b"alice")
    )
    bob = IdentityBundle.from_submission(
        sign_draft(adapter, draft, wallets["bob"], "bob", b"bob")
    )

    with pytest.raises(InvalidIdentityRequest):
        alice.merge(alice)
    with pytest.raises(InvalidIdentityRequest):
        alice.merge(IdentityBundle(draft, (replace(alice.proofs[0], signature=b"x" * 64),)))

    wrong_signer = IdentityBundle(
        draft,
        (bob.proofs[0], replace(alice.proofs[0], signer_id="outsider")),
    )
    with pytest.raises(InvalidIdentityRequest):
        wrong_signer.finalize()
    with pytest.raises(InvalidIdentityRequest):
        publish_bundle(adapter, wrong_signer, b"publish-wrong-signer")

    other_draft = IdentityDraft.create(
        owner_name=b"other-owner",
        owner_public_key=wallets["alice"].public_key,
        sequence=1,
        authorization=authorization(wallets),
    )
    other_signer = wallets["alice"].create_signer()
    wrong_bytes_signature = other_signer.sign_identity_update(other_draft.signed_update_bytes)
    wrong_bytes = IdentityBundle(
        draft,
        (
            replace(
                alice.proofs[0],
                signature=wrong_bytes_signature,
            ),
            bob.proofs[0],
        ),
    )
    with pytest.raises(InvalidIdentityRequest):
        wrong_bytes.finalize()
    with pytest.raises(InvalidIdentityRequest):
        publish_bundle(adapter, wrong_bytes, b"publish-wrong-bytes")
    assert transport.writes == []
    for wallet in wallets.values():
        wallet.lock()


def test_out_of_order_and_conflicting_drafts_are_rejected(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=authorization(wallets),
    )
    results = [
        sign_draft(adapter, draft, wallets[name], name, f"{name}-nonce".encode())
        for name in ("alice", "bob", "carol")
    ]
    bundle = IdentityBundle.from_submission(results[0]).merge(
        IdentityBundle.from_submission(results[1])
    ).merge(IdentityBundle.from_submission(results[2]))

    encoded = cbor2.loads(bundle.to_cbor())
    encoded[3].reverse()
    with pytest.raises(InvalidIdentityRequest):
        IdentityBundle.from_cbor(cbor2.dumps(encoded, canonical=True))

    conflicting_draft = IdentityDraft.create(
        owner_name=b"different-owner",
        owner_public_key=wallets["alice"].public_key,
        sequence=1,
        authorization=authorization(wallets),
    )
    with pytest.raises(InvalidIdentityRequest):
        bundle.merge(IdentityBundle(conflicting_draft, ()))
    assert transport.writes == []
    for wallet in wallets.values():
        wallet.lock()


def test_forged_signer_replacement_requires_predecessor_and_valid_proofs(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    genesis = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=authorization(wallets),
    )
    genesis_bundle = IdentityBundle.from_submission(
        sign_draft(adapter, genesis, wallets["alice"], "alice", b"genesis-alice")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(adapter, genesis, wallets["bob"], "bob", b"genesis-bob")
        )
    )
    assert publish_bundle(adapter, genesis_bundle, b"publish-genesis").status is PublishStatus.CONFIRMED
    previous = adapter.read_state(owner_name=OWNER_NAME)
    assert previous is not None

    forged_update = build_identity_update(
        owner_name=OWNER_NAME,
        owner_public_key=previous.owner_public_key,
        sequence=previous.sequence + 1,
        authorization=authorization(
            wallets,
            names=("bob", "carol", "dave"),
            operation=3,
            epoch=2,
            predecessor=previous.state_hash,
        ),
    )
    forged_envelope = cbor2.dumps(
        {
            1: 1,
            2: forged_update,
            3: [
                {1: "dave", 2: bytes(64)},
                {1: "outsider", 2: bytes([1]) * 64},
            ],
        },
        canonical=True,
    )
    transport.history[previous.state_hash] = previous.envelope_bytes
    transport.envelope = forged_envelope
    with pytest.raises(InvalidIdentityState):
        adapter.read_state(owner_name=OWNER_NAME)
    assert len(transport.writes) == 1
    for wallet in wallets.values():
        wallet.lock()


def test_forged_ordinary_update_cannot_self_authorize_signer_set(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    forged_update = build_identity_update(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        sequence=0,
        authorization=authorization(
            wallets,
            names=("bob", "carol", "dave"),
            operation=2,
            epoch=999,
            predecessor=b"z" * 32,
        ),
    )
    signatures = []
    for signer_id in ("carol", "dave"):
        capability = wallets[signer_id].create_signer()
        signatures.append(
            {
                1: signer_id,
                2: capability.sign_identity_update(forged_update),
            }
        )
    transport.envelope = cbor2.dumps(
        {1: 1, 2: forged_update, 3: signatures}, canonical=True
    )
    with pytest.raises(InvalidIdentityState):
        adapter.read_state(owner_name=OWNER_NAME)
    assert transport.writes == []

    transport.envelope = None
    genesis = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=authorization(wallets),
    )
    genesis_bundle = IdentityBundle.from_submission(
        sign_draft(adapter, genesis, wallets["alice"], "alice", b"valid-genesis-alice")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(adapter, genesis, wallets["bob"], "bob", b"valid-genesis-bob")
        )
    )
    assert publish_bundle(adapter, genesis_bundle, b"publish-valid-genesis").status is PublishStatus.CONFIRMED
    previous = adapter.read_state(owner_name=OWNER_NAME)
    assert previous is not None
    wrong_generation_update = build_identity_update(
        owner_name=OWNER_NAME,
        owner_public_key=previous.owner_public_key,
        sequence=previous.sequence + 1,
        authorization=authorization(
            wallets,
            operation=2,
            epoch=(previous.generation or 0) + 1,
            predecessor=previous.state_hash,
        ),
    )
    wrong_generation_proofs = []
    for signer_id in ("alice", "bob"):
        capability = wallets[signer_id].create_signer()
        wrong_generation_proofs.append(
            {1: signer_id, 2: capability.sign_identity_update(wrong_generation_update)}
        )
    transport.history[previous.state_hash] = previous.envelope_bytes
    transport.envelope = cbor2.dumps(
        {1: 1, 2: wrong_generation_update, 3: wrong_generation_proofs}, canonical=True
    )
    with pytest.raises(InvalidIdentityState):
        adapter.read_state(owner_name=OWNER_NAME)
    assert len(transport.writes) == 1
    for wallet in wallets.values():
        wallet.lock()


def test_signer_not_authorized_by_predecessor_cannot_join_signer_replacement(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    genesis = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=authorization(wallets),
    )
    genesis_bundle = IdentityBundle.from_submission(
        sign_draft(adapter, genesis, wallets["alice"], "alice", b"g-alice")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(adapter, genesis, wallets["bob"], "bob", b"g-bob")
        )
    )
    assert publish_bundle(adapter, genesis_bundle, b"publish-genesis").status is PublishStatus.CONFIRMED

    current = adapter.read_state(owner_name=OWNER_NAME)
    assert current is not None
    replacement_auth = authorization(
        wallets,
        names=("bob", "carol", "dave"),
        operation=3,
        epoch=2,
        predecessor=current.state_hash,
    )
    replacement = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=current.owner_public_key,
        authorization=replacement_auth,
    )
    alice = IdentityBundle.from_submission(
        sign_draft(adapter, replacement, wallets["alice"], "alice", b"r-alice")
    )
    bob = IdentityBundle.from_submission(
        sign_draft(adapter, replacement, wallets["bob"], "bob", b"r-bob")
    )
    valid_bundle = alice.merge(bob)
    assert len(cbor2.loads(valid_bundle.finalize())[3]) == 2

    outsider_signer = wallets["dave"].create_signer()
    outsider_signature = outsider_signer.sign_identity_update(replacement.signed_update_bytes)
    outsider = IdentityBundle(
        replacement,
        valid_bundle.proofs
        + (
            IdentityProof(
                signer_id="dave",
                signer_public_key=wallets["dave"].public_key,
                signature=outsider_signature,
            ),
        ),
    )
    with pytest.raises(InvalidIdentityRequest):
        outsider.finalize()
    writes_before_rejection = len(transport.writes)
    with pytest.raises(InvalidIdentityRequest):
        publish_bundle(adapter, outsider, b"publish-outsider")
    assert len(transport.writes) == writes_before_rejection

    assert publish_bundle(adapter, valid_bundle, b"publish-replacement").status is PublishStatus.CONFIRMED
    updated = adapter.read_state(owner_name=OWNER_NAME)
    assert updated is not None
    ordinary_update = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=updated.owner_public_key,
        authorization=authorization(
            wallets,
            names=("bob", "carol", "dave"),
            operation=2,
            epoch=updated.generation or 2,
            predecessor=updated.state_hash,
        ),
    )
    with pytest.raises(InvalidIdentityRequest):
        sign_draft(adapter, ordinary_update, wallets["alice"], "alice", b"revoked-alice")
    assert len(transport.writes) == 2
    for wallet in wallets.values():
        wallet.lock()


def test_ambiguous_dispatch_stays_unknown_until_exact_readback_without_retry(tmp_path):
    transport = MemoryTransport()
    transport.drop_writes = True
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=authorization(wallets),
    )
    bundle = IdentityBundle.from_submission(
        sign_draft(adapter, draft, wallets["alice"], "alice", b"alice")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(adapter, draft, wallets["bob"], "bob", b"bob")
        )
    )

    result = publish_bundle(adapter, bundle, b"publish-ambiguous")
    assert result.status is PublishStatus.UNKNOWN
    assert len(transport.writes) == 1

    transport.envelope = result.envelope_bytes
    confirmation = adapter.confirm_bundle(bundle)
    assert confirmation.status is PublishStatus.CONFIRMED
    assert confirmation.accepted_state is not None
    assert len(transport.writes) == 1
    for wallet in wallets.values():
        wallet.lock()


def test_timeout_after_committed_dispatch_uses_exact_readback_without_retry(tmp_path):
    transport = MemoryTransport()
    transport.raise_after_write = True
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=authorization(wallets),
    )
    bundle = IdentityBundle.from_submission(
        sign_draft(adapter, draft, wallets["alice"], "alice", b"timeout-alice")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(adapter, draft, wallets["bob"], "bob", b"timeout-bob")
        )
    )

    result = publish_bundle(adapter, bundle, b"timeout-publication")
    assert result.status is PublishStatus.CONFIRMED
    assert result.envelope_bytes == transport.envelope
    assert result.accepted_state is not None
    assert len(transport.writes) == 1
    for wallet in wallets.values():
        wallet.lock()


def test_publication_after_state_change_is_stale_and_does_not_retry(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    first_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["alice"].public_key,
        authorization=authorization(wallets),
    )
    first_bundle = IdentityBundle.from_submission(
        sign_draft(adapter, first_draft, wallets["alice"], "alice", b"a1")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(adapter, first_draft, wallets["bob"], "bob", b"b1")
        )
    )
    assert publish_bundle(adapter, first_bundle, b"publish-first").status is PublishStatus.CONFIRMED

    current = adapter.read_state(owner_name=OWNER_NAME)
    assert current is not None
    update_auth = authorization(
        wallets,
        operation=2,
        epoch=current.generation or 1,
        predecessor=current.state_hash,
    )
    stale_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=current.owner_public_key,
        authorization=update_auth,
    )
    stale_bundle = IdentityBundle.from_submission(
        sign_draft(adapter, stale_draft, wallets["alice"], "alice", b"a2")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(adapter, stale_draft, wallets["bob"], "bob", b"b2")
        )
    )

    competing = RegistryAdapter(transport)
    competing_draft = competing.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=current.owner_public_key,
        authorization=update_auth,
    )
    competing_bundle = IdentityBundle.from_submission(
        sign_draft(competing, competing_draft, wallets["bob"], "bob", b"b3")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(competing, competing_draft, wallets["carol"], "carol", b"c3")
        )
    )
    assert publish_bundle(competing, competing_bundle, b"publish-competing").status is PublishStatus.CONFIRMED
    writes_before = len(transport.writes)

    stale_result = publish_bundle(adapter, stale_bundle, b"publish-stale")
    assert stale_result.status is PublishStatus.STALE
    assert len(transport.writes) == writes_before
    for wallet in wallets.values():
        wallet.lock()


def test_owner_key_rotation_draft_from_legacy_predecessor_is_state_bound(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    owner_wallet = wallets["alice"]
    successor_public_key = owner_wallet.prepare_signing_key_rotation()

    legacy_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=owner_wallet.public_key,
    )
    legacy_result = adapter.sign_draft(
        draft=legacy_draft,
        signer_public_key=owner_wallet.public_key,
        signer_factory=owner_wallet.create_signer,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="create Identity",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"legacy-rotation-seed",
    )
    assert publish_bundle(
        adapter,
        IdentityBundle.from_submission(legacy_result),
        b"publish-legacy-before-rotation",
    ).status is PublishStatus.CONFIRMED
    predecessor = adapter.read_state(owner_name=OWNER_NAME)
    assert predecessor is not None

    with pytest.raises(InvalidIdentityRequest):
        adapter.create_owner_key_rotation_draft(
            owner_name=OWNER_NAME,
            successor_owner_public_key=successor_public_key,
            successor_signer_set=[
                {1: "bob", 2: wallets["bob"].public_key},
                {1: "carol", 2: wallets["carol"].public_key},
                {1: "dave", 2: wallets["dave"].public_key},
            ],
        )

    rotation_draft = adapter.create_owner_key_rotation_draft(
        owner_name=OWNER_NAME,
        successor_owner_public_key=successor_public_key,
        successor_signer_set=[
            {1: "alice", 2: successor_public_key},
            {1: "bob", 2: wallets["bob"].public_key},
            {1: "carol", 2: wallets["carol"].public_key},
        ],
    )

    assert rotation_draft.owner_name == predecessor.owner_name == OWNER_NAME
    assert rotation_draft.owner_public_key == successor_public_key
    assert rotation_draft.sequence == predecessor.sequence + 1
    assert rotation_draft.previous_state_envelope == predecessor.envelope_bytes
    assert rotation_draft.authorization == {
        1: 1,
        2: 1,
        3: 5,
        4: 1,
        5: 2,
        6: [
            {1: "alice", 2: successor_public_key},
            {1: "bob", 2: wallets["bob"].public_key},
            {1: "carol", 2: wallets["carol"].public_key},
        ],
        7: predecessor.state_hash,
    }
    for wallet in wallets.values():
        wallet.lock()


def test_legacy_owner_key_rotation_proof_is_local_and_envelope_is_not_publishable(
    tmp_path,
):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    owner_wallet = wallets["alice"]
    active_public_key = owner_wallet.public_key
    successor_public_key = owner_wallet.prepare_signing_key_rotation()

    legacy_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=active_public_key,
    )
    legacy_result = adapter.sign_draft(
        draft=legacy_draft,
        signer_public_key=active_public_key,
        signer_factory=owner_wallet.create_signer,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="create Identity",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"legacy-rotation-seed",
    )
    assert publish_bundle(
        adapter,
        IdentityBundle.from_submission(legacy_result),
        b"publish-legacy-before-rotation",
    ).status is PublishStatus.CONFIRMED
    predecessor = adapter.read_state(owner_name=OWNER_NAME)
    assert predecessor is not None
    rotation_draft = adapter.create_owner_key_rotation_draft(
        owner_name=OWNER_NAME,
        successor_owner_public_key=successor_public_key,
        successor_signer_set=[
            {1: "alice", 2: successor_public_key},
            {1: "bob", 2: wallets["bob"].public_key},
            {1: "carol", 2: wallets["carol"].public_key},
        ],
    )

    with pytest.raises(InvalidIdentityRequest):
        adapter.submit_identity(
            owner_name=OWNER_NAME,
            owner_public_key=successor_public_key,
            signer_public_key=owner_wallet.public_key,
            signer_factory=owner_wallet.create_signer,
            consent=approved,
            authenticated_origin="https://wallet.example",
            environment="testnet",
            operation="owner-key-rotation",
            purpose="unauthorized direct rotation",
            capability="identity.rotate-owner-key",
            expires_at=EXPIRY,
            replay_nonce=b"direct-rotation-without-draft",
            authorization=rotation_draft.authorization,
            signer_id=None,
        )

    unrelated_draft = IdentityDraft.create(
        owner_name=OWNER_NAME,
        owner_public_key=wallets["bob"].public_key,
        sequence=rotation_draft.sequence,
        authorization=rotation_draft.authorization,
        previous_state_envelope=rotation_draft.previous_state_envelope,
        previous_state_history=rotation_draft.previous_state_history,
    )
    with pytest.raises(InvalidIdentityRequest):
        owner_wallet.prove_pending_signing_key_rotation(unrelated_draft)

    encrypted_before_pop = owner_wallet.export_container()
    assert owner_wallet.prove_pending_signing_key_rotation(rotation_draft) is None
    assert owner_wallet.export_container() == encrypted_before_pop
    assert owner_wallet.public_key == active_public_key
    assert owner_wallet.pending_signing_public_key == successor_public_key

    result = adapter.sign_draft(
        draft=rotation_draft,
        signer_public_key=active_public_key,
        signer_factory=owner_wallet.create_signer,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="authorize owner-key rotation",
        capability="identity.rotate-owner-key",
        expires_at=EXPIRY,
        replay_nonce=b"legacy-owner-key-proof",
    )
    assert result.status is PublishStatus.PROOF_READY
    assert result.identity_proof is not None
    assert result.identity_proof.signer_id is None
    assert result.identity_proof.signer_public_key == active_public_key
    bundle = IdentityBundle.from_submission(result)
    envelope = bundle.finalize()
    decoded = cbor2.loads(envelope)
    assert decoded[3] == [{1: None, 2: result.identity_proof.signature}]

    local_readback_transport = MemoryTransport()
    local_readback_transport.envelope = envelope
    local_readback_transport.history[predecessor.state_hash] = predecessor.envelope_bytes
    locally_parsed = RegistryAdapter(local_readback_transport).read_state(
        owner_name=OWNER_NAME
    )
    assert locally_parsed is not None
    assert locally_parsed.owner_public_key == successor_public_key
    assert locally_parsed.sequence == predecessor.sequence + 1

    consent_calls = []
    writes_before = len(transport.writes)
    with pytest.raises(InvalidIdentityRequest):
        publish_bundle(
            adapter,
            bundle,
            b"forbidden-rotation-publication",
            consent=lambda transcript: consent_calls.append(transcript),
        )
    with pytest.raises(InvalidIdentityRequest):
        adapter.confirm_bundle(bundle)
    assert consent_calls == []
    assert len(transport.writes) == writes_before
    assert adapter.read_state(owner_name=OWNER_NAME) == predecessor
    for wallet in wallets.values():
        wallet.lock()


def test_versioned_owner_key_rotation_preserves_signer_governance_and_stays_local(
    tmp_path,
):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallets = make_wallets(tmp_path)
    alice = wallets["alice"]

    genesis_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=alice.public_key,
        authorization=authorization(wallets),
    )
    genesis_bundle = IdentityBundle.from_submission(
        sign_draft(adapter, genesis_draft, alice, "alice", b"genesis-alice")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(adapter, genesis_draft, wallets["bob"], "bob", b"genesis-bob")
        )
    )
    assert publish_bundle(adapter, genesis_bundle, b"publish-genesis").status is PublishStatus.CONFIRMED
    predecessor = adapter.read_state(owner_name=OWNER_NAME)
    assert predecessor is not None

    successor_public_key = alice.prepare_signing_key_rotation()
    rotation_draft = adapter.create_owner_key_rotation_draft(
        owner_name=OWNER_NAME,
        successor_owner_public_key=successor_public_key,
    )
    assert rotation_draft.authorization == {
        1: 1,
        2: 1,
        3: 5,
        4: predecessor.generation,
        5: predecessor.threshold,
        6: [{1: name, 2: key} for name, key in predecessor.signer_set],
        7: predecessor.state_hash,
    }
    rotation_authorization = rotation_draft.authorization
    assert rotation_authorization is not None
    wrong_epoch = dict(rotation_authorization)
    wrong_epoch[4] += 1
    with pytest.raises(InvalidIdentityRequest):
        IdentityDraft.create(
            owner_name=OWNER_NAME,
            owner_public_key=successor_public_key,
            sequence=rotation_draft.sequence,
            authorization=wrong_epoch,
            previous_state_envelope=predecessor.envelope_bytes,
            previous_state_history=predecessor.predecessor_envelopes,
        )
    with pytest.raises(InvalidIdentityRequest):
        IdentityDraft.create(
            owner_name=OWNER_NAME,
            owner_public_key=successor_public_key,
            sequence=predecessor.sequence + 2,
            authorization=rotation_authorization,
            previous_state_envelope=predecessor.envelope_bytes,
            previous_state_history=predecessor.predecessor_envelopes,
        )
    alice.prove_pending_signing_key_rotation(rotation_draft)

    bundle = IdentityBundle.from_submission(
        sign_draft(adapter, rotation_draft, alice, "alice", b"rotation-alice")
    ).merge(
        IdentityBundle.from_submission(
            sign_draft(adapter, rotation_draft, wallets["bob"], "bob", b"rotation-bob")
        )
    )
    envelope = bundle.finalize()
    wire = cbor2.loads(envelope)
    assert len(wire[3]) == predecessor.threshold
    assert {proof[1] for proof in wire[3]} == {"alice", "bob"}

    outsider_signer = wallets["dave"].create_signer()
    outsider_signature = outsider_signer.sign_identity_update(
        rotation_draft.signed_update_bytes
    )
    unauthorized = bundle.merge(
        IdentityBundle(
            rotation_draft,
            (
                IdentityProof(
                    signer_id="dave",
                    signer_public_key=wallets["dave"].public_key,
                    signature=outsider_signature,
                ),
            ),
        )
    )
    with pytest.raises(InvalidIdentityRequest):
        unauthorized.finalize()

    writes_before = len(transport.writes)
    with pytest.raises(InvalidIdentityRequest):
        publish_bundle(adapter, bundle, b"forbidden-versioned-rotation")
    with pytest.raises(InvalidIdentityRequest):
        adapter.confirm_bundle(bundle)
    with pytest.raises(InvalidIdentityRequest):
        publish_bundle(adapter, unauthorized, b"forbidden-outsider-rotation-proof")
    assert len(transport.writes) == writes_before
    assert adapter.read_state(owner_name=OWNER_NAME) == predecessor

    local_readback_transport = MemoryTransport()
    local_readback_transport.envelope = envelope
    local_readback_transport.history[predecessor.state_hash] = predecessor.envelope_bytes
    local_state = RegistryAdapter(local_readback_transport).read_state(
        owner_name=OWNER_NAME
    )
    assert local_state is not None
    assert local_state.owner_public_key == successor_public_key
    assert local_state.sequence == predecessor.sequence + 1
    assert local_state.generation == predecessor.generation
    assert local_state.threshold == predecessor.threshold
    assert local_state.signer_set == predecessor.signer_set

    publication = prepare_rotation_publication(adapter, bundle, b"latch-v1-rotation")
    permit = alice.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    intent = permit.intent
    assert intent.owner_name == OWNER_NAME
    assert intent.predecessor_state_hash == predecessor.state_hash
    assert intent.sequence == predecessor.sequence + 1
    assert intent.envelope_hash == hashlib.sha256(envelope).digest()
    with pytest.raises(RotationInProgress):
        alice.create_signer()

    dispatched = adapter.dispatch_owner_key_rotation(publication, permit)
    assert dispatched.status is PublishStatus.CONFIRMED
    assert dispatched.confirmation is not None
    alice.finalize_signing_key_rotation(dispatched.confirmation)
    accepted = adapter.read_state(owner_name=OWNER_NAME)
    assert accepted is not None
    assert accepted.owner_public_key == successor_public_key
    assert accepted.signer_set == predecessor.signer_set
    assert accepted.generation == predecessor.generation
    assert accepted.threshold == predecessor.threshold
    for wallet in wallets.values():
        wallet.lock()


def make_legacy_rotation_bundle(tmp_path):
    wallets = make_wallets(tmp_path, names=("alice", "bob", "carol"))
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    owner = wallets["alice"]
    active_public_key = owner.public_key
    successor_public_key = owner.prepare_signing_key_rotation()

    initial_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=active_public_key,
    )
    initial = adapter.sign_draft(
        draft=initial_draft,
        signer_public_key=active_public_key,
        signer_factory=owner.create_signer,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="create Identity",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"dispatch-latch-initial",
    )
    assert publish_bundle(
        adapter,
        IdentityBundle.from_submission(initial),
        b"dispatch-latch-publish-initial",
    ).status is PublishStatus.CONFIRMED
    predecessor = adapter.read_state(owner_name=OWNER_NAME)
    assert predecessor is not None
    transport.history[predecessor.state_hash] = predecessor.envelope_bytes

    rotation_draft = adapter.create_owner_key_rotation_draft(
        owner_name=OWNER_NAME,
        successor_owner_public_key=successor_public_key,
        successor_signer_set=[
            {1: "alice", 2: successor_public_key},
            {1: "bob", 2: wallets["bob"].public_key},
            {1: "carol", 2: wallets["carol"].public_key},
        ],
    )
    rotation_result = adapter.sign_draft(
        draft=rotation_draft,
        signer_public_key=active_public_key,
        signer_factory=owner.create_signer,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="authorize owner-key rotation",
        capability="identity.rotate-owner-key",
        expires_at=EXPIRY,
        replay_nonce=b"dispatch-latch-rotation",
    )
    return (
        wallets,
        owner,
        predecessor,
        rotation_draft,
        IdentityBundle.from_submission(rotation_result),
        active_public_key,
        successor_public_key,
        adapter,
        transport,
    )


def test_rotation_dispatch_intent_is_bound_to_finalized_envelope_and_survives_transfer(
    tmp_path,
):
    (
        wallets,
        owner,
        predecessor,
        draft,
        bundle,
        active_public_key,
        successor_public_key,
        adapter,
        transport,
    ) = make_legacy_rotation_bundle(tmp_path)
    envelope = bundle.finalize()
    publication = prepare_rotation_publication(adapter, bundle, b"latch-transfer")

    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    intent = permit.intent

    assert isinstance(permit, RotationDispatchPermit)
    assert isinstance(intent, RotationDispatchIntent)
    assert intent.owner_name == OWNER_NAME
    assert intent.predecessor_owner_public_key == active_public_key
    assert intent.successor_owner_public_key == successor_public_key
    assert intent.predecessor_state_hash == predecessor.state_hash
    assert intent.sequence == draft.sequence == predecessor.sequence + 1
    assert intent.envelope_hash == hashlib.sha256(envelope).digest()
    assert owner.signing_key_rotation_dispatch_intent == intent

    exported = owner.export_container()
    assert b"rotation_dispatch_intent" not in exported
    assert OWNER_NAME not in exported
    assert active_public_key not in exported
    owner.lock()
    reopened = Wallet.open(tmp_path / "alice.dw", PASSWORD)
    assert reopened.signing_key_rotation_dispatch_intent == intent
    with pytest.raises(RotationInProgress):
        reopened.create_signer()
    imported = Wallet.import_container(tmp_path / "imported.dw", exported, PASSWORD)
    assert imported.signing_key_rotation_dispatch_intent == intent
    with pytest.raises(RotationInProgress):
        imported.create_signer()

    for wallet in wallets.values():
        wallet.lock()
    reopened.lock()
    imported.lock()


def test_latched_rotation_invalidates_and_blocks_signing_cancellation_and_replacement(
    tmp_path,
):
    wallets, owner, _, draft, bundle, _, _, adapter, _ = make_legacy_rotation_bundle(tmp_path)
    outstanding_signer = owner.create_signer()
    publication = prepare_rotation_publication(adapter, bundle, b"latch-blocking")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    intent = permit.intent

    assert owner.signing_key_rotation_dispatch_intent == intent
    with pytest.raises(SignerUnavailable):
        outstanding_signer.sign_identity_update(draft.signed_update_bytes)
    with pytest.raises(RotationInProgress):
        owner.create_signer()
    with pytest.raises(RotationInProgress):
        owner.prepare_signing_key_rotation()
    with pytest.raises(RotationInProgress):
        owner.prove_pending_signing_key_rotation(draft)
    with pytest.raises(RotationInProgress):
        owner.cancel_signing_key_rotation()
    with pytest.raises(RotationInProgress):
        owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)

    owner.update_payload({"local_note": "retained with unresolved intent"})
    assert owner.signing_key_rotation_dispatch_intent == intent
    for wallet in wallets.values():
        wallet.lock()


def test_invalid_or_incomplete_rotation_bundle_does_not_latch(tmp_path):
    wallets, owner, _, _, bundle, _, _, adapter, _ = make_legacy_rotation_bundle(tmp_path)
    publication = prepare_rotation_publication(adapter, bundle, b"latch-invalid")
    invalid_bundle = replace(
        bundle,
        proofs=(replace(bundle.proofs[0], signature=bytes(64)),),
    )
    consent_calls = []
    with pytest.raises(InvalidIdentityRequest):
        adapter.prepare_owner_key_rotation_publication(
            invalid_bundle,
            consent=lambda transcript: consent_calls.append(transcript) or approved(transcript),
            authenticated_origin="https://wallet.example",
            environment="testnet",
            purpose="publish owner-key rotation",
            capability="identity.rotate-owner-key",
            expires_at=EXPIRY,
            replay_nonce=b"invalid-rotation-prepare",
        )
    assert consent_calls == []

    with pytest.raises(InvalidIdentityRequest):
        owner.latch_signing_key_rotation_dispatch_intent(invalid_bundle, publication)

    assert owner.signing_key_rotation_dispatch_intent is None
    assert owner.create_signer().is_active
    for wallet in wallets.values():
        wallet.lock()


def test_failed_dispatch_intent_persistence_leaves_wallet_unlatched(
    tmp_path, monkeypatch
):
    import decent_wallet.container as container_module

    wallets, owner, _, _, bundle, _, _, adapter, _ = make_legacy_rotation_bundle(tmp_path)
    publication = prepare_rotation_publication(adapter, bundle, b"latch-storage-failure")
    before = owner.export_container()
    outstanding_signer = owner.create_signer()

    def fail_write(_path, _data):
        raise StorageFailure()

    monkeypatch.setattr(container_module, "_atomic_write", fail_write)
    with pytest.raises(StorageFailure):
        owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)

    assert owner.export_container() == before
    assert owner.signing_key_rotation_dispatch_intent is None
    assert not outstanding_signer.is_active
    assert owner.create_signer().is_active
    for wallet in wallets.values():
        wallet.lock()


def test_rotation_dispatch_requires_wallet_minted_permit_after_durable_latch(tmp_path):
    (
        wallets,
        owner,
        predecessor,
        draft,
        bundle,
        active_public_key,
        successor_public_key,
        adapter,
        transport,
    ) = make_legacy_rotation_bundle(tmp_path)
    publication = prepare_rotation_publication(adapter, bundle, b"dispatch-requires-latch")
    ordinary_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=active_public_key,
    )
    ordinary_submission = adapter.sign_draft(
        draft=ordinary_draft,
        signer_public_key=active_public_key,
        signer_factory=owner.create_signer,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="prepare competing ordinary update",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"ordinary-pre-latch-proof",
    )
    assert ordinary_submission.status is PublishStatus.PROOF_READY
    ordinary_bundle = IdentityBundle.from_submission(ordinary_submission)
    forged_intent = RotationDispatchIntent(
        owner_name=OWNER_NAME,
        predecessor_owner_public_key=active_public_key,
        successor_owner_public_key=successor_public_key,
        predecessor_state_hash=predecessor.state_hash,
        sequence=draft.sequence,
        envelope_hash=hashlib.sha256(bundle.finalize()).digest(),
    )
    writes_before = len(transport.writes)
    for capability_type in (
        RotationDispatchPermit,
        RotationPublication,
        RotationConfirmation,
        RotationDispatchRejection,
    ):
        assert not hasattr(capability_type, "_issue")
    with pytest.raises(InvalidContainer):
        RotationDispatchPermit(intent=forged_intent, seal=object())
    forged_permit = object.__new__(RotationDispatchPermit)
    object.__setattr__(forged_permit, "intent", forged_intent)
    object.__setattr__(forged_permit, "_seal", object())

    with pytest.raises(InvalidIdentityRequest):
        adapter.dispatch_owner_key_rotation(publication, forged_permit)
    with pytest.raises(InvalidIdentityRequest):
        adapter.dispatch_owner_key_rotation(
            publication, cast(RotationDispatchPermit, forged_intent)
        )

    assert len(transport.writes) == writes_before
    assert owner.signing_key_rotation_dispatch_intent is None

    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    blocked_signing_consent = []
    with pytest.raises(InvalidIdentityRequest):
        adapter.sign_draft(
            draft=ordinary_draft,
            signer_public_key=active_public_key,
            signer_factory=owner.create_signer,
            consent=lambda transcript: blocked_signing_consent.append(transcript) or approved(transcript),
            authenticated_origin="https://wallet.example",
            environment="testnet",
            purpose="sign while rotation unresolved",
            capability="identity.write",
            expires_at=EXPIRY,
            replay_nonce=b"ordinary-after-latch-sign",
        )
    assert blocked_signing_consent == []
    blocked_consent = []
    blocked_update = adapter.publish_bundle(
        ordinary_bundle,
        consent=lambda transcript: blocked_consent.append(transcript) or approved(transcript),
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="publish update",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"ordinary-after-latch-publish",
    )
    assert blocked_update.status is PublishStatus.FAILED
    assert blocked_consent == []
    assert len(transport.writes) == writes_before

    dispatched = adapter.dispatch_owner_key_rotation(publication, permit)
    assert dispatched.status is PublishStatus.CONFIRMED
    for wallet in wallets.values():
        wallet.lock()


def test_inflight_submit_identity_is_stopped_by_rotation_latch(tmp_path):
    (
        wallets,
        owner,
        _predecessor,
        _draft,
        bundle,
        active_public_key,
        _successor_public_key,
        adapter,
        transport,
    ) = make_legacy_rotation_bundle(tmp_path)
    publication = prepare_rotation_publication(adapter, bundle, b"submit-latch-race")
    consent_started = Event()
    release_consent = Event()
    signer_calls = []
    writes_before = len(transport.writes)

    def blocking_consent(_transcript: ConsentTranscript) -> ConsentDecision:
        consent_started.set()
        if not release_consent.wait(timeout=5):
            return ConsentDecision.CANCELLED
        return ConsentDecision.APPROVED

    def tracked_signer_factory():
        signer_calls.append(True)
        return owner.create_signer()

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            adapter.submit_identity,
            owner_name=OWNER_NAME,
            owner_public_key=active_public_key,
            signer_public_key=active_public_key,
            signer_factory=tracked_signer_factory,
            consent=blocking_consent,
            authenticated_origin="https://wallet.example",
            environment="testnet",
            operation="identity.update",
            purpose="submit concurrent ordinary update",
            capability="identity.write",
            expires_at=EXPIRY,
            replay_nonce=b"submit-before-latch-race",
        )
        assert consent_started.wait(timeout=5)
        owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
        release_consent.set()
        result = future.result(timeout=5)

    assert result.status is PublishStatus.FAILED
    assert signer_calls == []
    assert len(transport.writes) == writes_before
    assert result.reason == "owner-key rotation is unresolved"
    for wallet in wallets.values():
        wallet.lock()


def test_concurrent_dispatch_latch_attempts_have_one_durable_winner(tmp_path):
    wallets, owner, _, _, bundle, _, _, adapter, _ = make_legacy_rotation_bundle(tmp_path)
    publication = prepare_rotation_publication(adapter, bundle, b"latch-concurrent")
    barrier = Barrier(2)

    def latch_after_barrier():
        barrier.wait(timeout=5)
        try:
            return owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
        except RotationInProgress:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _index: latch_after_barrier(), range(2)))

    successful = [result for result in results if result is not None]
    assert len(successful) == 1
    assert owner.signing_key_rotation_dispatch_intent == successful[0].intent
    assert owner.pending_signing_public_key == successful[0].intent.successor_owner_public_key
    for wallet in wallets.values():
        wallet.lock()


def test_owner_rotation_requires_prepared_consent_before_dispatch_and_finalizes(
    tmp_path,
):
    (
        wallets,
        owner,
        predecessor,
        _draft,
        bundle,
        active_public_key,
        successor_public_key,
        adapter,
        transport,
    ) = make_legacy_rotation_bundle(tmp_path)
    consented = []
    writes_before_prepare = len(transport.writes)

    prepared = adapter.prepare_owner_key_rotation_publication(
        bundle,
        consent=lambda transcript: consented.append(transcript) or approved(transcript),
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="publish owner-key rotation",
        capability="identity.rotate-owner-key",
        expires_at=EXPIRY,
        replay_nonce=b"rotation-publication",
    )

    assert prepared.status is PublishStatus.READY
    assert prepared.publication is not None
    assert len(consented) == 1
    assert consented[0].review_payload == bundle.finalize()
    assert len(transport.writes) == writes_before_prepare
    assert owner.signing_key_rotation_dispatch_intent is None

    permit = owner.latch_signing_key_rotation_dispatch_intent(
        bundle, prepared.publication
    )
    intent = permit.intent
    result = adapter.dispatch_owner_key_rotation(prepared.publication, permit)

    assert result.status is PublishStatus.CONFIRMED
    assert result.confirmation is not None
    assert owner.public_key == active_public_key
    assert owner.pending_signing_public_key == successor_public_key
    assert owner.signing_key_rotation_dispatch_intent == intent
    assert intent.predecessor_state_hash == predecessor.state_hash

    owner.finalize_signing_key_rotation(result.confirmation)

    assert owner.public_key == successor_public_key
    assert owner.pending_signing_public_key is None
    assert owner.signing_key_rotation_dispatch_intent is None
    assert owner.create_signer().public_key == successor_public_key
    for wallet in wallets.values():
        wallet.lock()


def test_ambiguous_rotation_stays_latched_until_fresh_remote_confirmation_after_reopen(
    tmp_path,
):
    (
        wallets,
        owner,
        predecessor,
        _draft,
        bundle,
        active_public_key,
        successor_public_key,
        adapter,
        transport,
    ) = make_legacy_rotation_bundle(tmp_path)
    ordinary_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=active_public_key,
    )
    ordinary_submission = adapter.sign_draft(
        draft=ordinary_draft,
        signer_public_key=active_public_key,
        signer_factory=owner.create_signer,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="prepare update before ambiguous rotation",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"ordinary-before-unknown",
    )
    assert ordinary_submission.status is PublishStatus.PROOF_READY
    ordinary_bundle = IdentityBundle.from_submission(ordinary_submission)
    transport.drop_writes = True
    publication = prepare_rotation_publication(adapter, bundle, b"rotation-ambiguous")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    intent = permit.intent

    result = adapter.dispatch_owner_key_rotation(publication, permit)

    assert result.status is PublishStatus.UNKNOWN
    assert result.confirmation is None
    assert result.rejection is None
    assert owner.public_key == active_public_key
    assert owner.pending_signing_public_key == successor_public_key
    assert owner.signing_key_rotation_dispatch_intent == intent

    # A write-through/local candidate is not independent remote evidence.
    transport.envelope = bundle.finalize()
    assert adapter.confirm_owner_key_rotation(intent) is None
    assert owner.signing_key_rotation_dispatch_intent == intent

    owner.lock()
    reopened = Wallet.open(tmp_path / "alice.dw", PASSWORD)
    reopened_adapter = RegistryAdapter(transport)
    recovered_intent = reopened.signing_key_rotation_dispatch_intent
    assert recovered_intent is not None
    assert recovered_intent == intent
    assert reopened_adapter.confirm_owner_key_rotation(recovered_intent) is None
    assert reopened_adapter._rotation_latches.is_latched(recovered_intent)
    assert not reopened_adapter._rotation_latches.is_dispatch_ready(recovered_intent)
    blocked_consent = []
    writes_before_blocked_publish = len(transport.writes)
    blocked_update = reopened_adapter.publish_bundle(
        ordinary_bundle,
        consent=lambda transcript: blocked_consent.append(transcript) or approved(transcript),
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="publish update after reopen",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"ordinary-after-reopen-latched",
    )
    assert blocked_update.status is PublishStatus.FAILED
    assert blocked_consent == []
    assert len(transport.writes) == writes_before_blocked_publish

    transport.remote_envelope = bundle.finalize()
    confirmation = reopened_adapter.confirm_owner_key_rotation(recovered_intent)
    assert confirmation is not None
    reopened.finalize_signing_key_rotation(confirmation)

    next_successor_public_key = reopened.prepare_signing_key_rotation()
    next_rotation_draft = reopened_adapter.create_owner_key_rotation_draft(
        owner_name=OWNER_NAME,
        successor_owner_public_key=next_successor_public_key,
    )
    assert next_rotation_draft.owner_public_key == next_successor_public_key
    reopened.cancel_signing_key_rotation()

    assert reopened.public_key == successor_public_key
    assert reopened.pending_signing_public_key is None
    assert reopened.signing_key_rotation_dispatch_intent is None
    for wallet in wallets.values():
        wallet.lock()
    reopened.lock()


def test_prewrite_rotation_rejection_clears_only_matching_latch_once(tmp_path):
    (
        wallets,
        owner,
        _predecessor,
        _draft,
        bundle,
        active_public_key,
        successor_public_key,
        adapter,
        transport,
    ) = make_legacy_rotation_bundle(tmp_path)
    ordinary_draft = adapter.create_draft(
        owner_name=OWNER_NAME,
        owner_public_key=active_public_key,
    )
    ordinary_submission = adapter.sign_draft(
        draft=ordinary_draft,
        signer_public_key=active_public_key,
        signer_factory=owner.create_signer,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="prepare update before pre-write rejection",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"ordinary-before-safe-rejection",
    )
    assert ordinary_submission.status is PublishStatus.PROOF_READY
    ordinary_bundle = IdentityBundle.from_submission(ordinary_submission)
    publication = prepare_rotation_publication(adapter, bundle, b"rotation-stale")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    intent = permit.intent
    transport.reject_conditional = True

    rejected = adapter.dispatch_owner_key_rotation(publication, permit)

    assert rejected.status is PublishStatus.STALE
    assert rejected.confirmation is None
    assert rejected.rejection is not None
    assert owner.signing_key_rotation_dispatch_intent == intent
    owner.resolve_signing_key_rotation_rejection(rejected.rejection)

    assert owner.public_key == active_public_key
    assert owner.pending_signing_public_key == successor_public_key
    assert owner.signing_key_rotation_dispatch_intent is None
    assert owner.create_signer().public_key == active_public_key

    next_publication = prepare_rotation_publication(
        adapter, bundle, b"rotation-stale-retry-consent"
    )
    next_permit = owner.latch_signing_key_rotation_dispatch_intent(
        bundle, next_publication
    )
    next_intent = next_permit.intent
    with pytest.raises(InvalidIdentityRequest):
        owner.resolve_signing_key_rotation_rejection(rejected.rejection)
    assert owner.signing_key_rotation_dispatch_intent == next_intent

    repeated_rejection = adapter.dispatch_owner_key_rotation(
        next_publication, next_permit
    )
    assert repeated_rejection.status is PublishStatus.STALE
    assert repeated_rejection.rejection is not None
    owner.resolve_signing_key_rotation_rejection(repeated_rejection.rejection)
    transport.reject_conditional = False
    republished = adapter.publish_bundle(
        ordinary_bundle,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="publish after safe rejection",
        capability="identity.write",
        expires_at=EXPIRY,
        replay_nonce=b"ordinary-after-safe-rejection",
    )
    assert republished.status is PublishStatus.CONFIRMED
    for wallet in wallets.values():
        wallet.lock()


def test_rotation_finalization_failure_preserves_both_keys_and_intent(
    tmp_path, monkeypatch
):
    import decent_wallet.container as container_module

    (
        wallets,
        owner,
        _predecessor,
        _draft,
        bundle,
        active_public_key,
        successor_public_key,
        adapter,
        _transport,
    ) = make_legacy_rotation_bundle(tmp_path)
    publication = prepare_rotation_publication(adapter, bundle, b"rotation-finalize")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    intent = permit.intent
    dispatched = adapter.dispatch_owner_key_rotation(publication, permit)
    assert dispatched.status is PublishStatus.CONFIRMED
    assert dispatched.confirmation is not None
    before = owner.export_container()

    def fail_write(_path, _data):
        raise StorageFailure()

    monkeypatch.setattr(container_module, "_atomic_write", fail_write)
    with pytest.raises(StorageFailure):
        owner.finalize_signing_key_rotation(dispatched.confirmation)

    assert owner.export_container() == before
    assert owner.public_key == active_public_key
    assert owner.pending_signing_public_key == successor_public_key
    assert owner.signing_key_rotation_dispatch_intent == intent
    with pytest.raises(RotationInProgress):
        owner.create_signer()

    monkeypatch.undo()
    owner.finalize_signing_key_rotation(dispatched.confirmation)
    assert owner.public_key == successor_public_key
    assert owner.pending_signing_public_key is None
    assert owner.signing_key_rotation_dispatch_intent is None

    owner.lock()
    reopened = Wallet.open(tmp_path / "alice.dw", PASSWORD)
    assert reopened.public_key == successor_public_key
    assert reopened.pending_signing_public_key is None
    assert reopened.signing_key_rotation_dispatch_intent is None
    for wallet in wallets.values():
        wallet.lock()
    reopened.lock()


def test_rotation_refuses_unsupported_registry_before_consent_or_latch(tmp_path):
    (
        wallets,
        owner,
        _predecessor,
        _draft,
        bundle,
        _active_public_key,
        _successor_public_key,
        adapter,
        transport,
    ) = make_legacy_rotation_bundle(tmp_path)
    transport.supports_owner_key_rotation = False
    writes_before = len(transport.writes)
    consent_calls = []

    result = adapter.prepare_owner_key_rotation_publication(
        bundle,
        consent=lambda transcript: consent_calls.append(transcript) or approved(transcript),
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="publish owner-key rotation",
        capability="identity.rotate-owner-key",
        expires_at=EXPIRY,
        replay_nonce=b"unsupported-rotation",
    )

    assert result.status is PublishStatus.FAILED
    assert result.publication is None
    assert consent_calls == []
    assert len(transport.writes) == writes_before
    assert owner.signing_key_rotation_dispatch_intent is None

    transport.supports_owner_key_rotation = True
    setattr(transport, "get_remote_identity_envelope", None)
    no_remote_reader = adapter.prepare_owner_key_rotation_publication(
        bundle,
        consent=lambda transcript: consent_calls.append(transcript) or approved(transcript),
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="publish owner-key rotation",
        capability="identity.rotate-owner-key",
        expires_at=EXPIRY,
        replay_nonce=b"rotation-no-remote-reader",
    )
    assert no_remote_reader.status is PublishStatus.FAILED
    assert no_remote_reader.publication is None
    assert consent_calls == []
    assert len(transport.writes) == writes_before
    delattr(transport, "get_remote_identity_envelope")

    ready = prepare_rotation_publication(adapter, bundle, b"rotation-capability-change")

    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, ready)
    transport.supports_owner_key_rotation = False
    blocked = adapter.dispatch_owner_key_rotation(ready, permit)
    assert blocked.status is PublishStatus.FAILED
    assert blocked.rejection is not None
    assert len(transport.writes) == writes_before
    owner.resolve_signing_key_rotation_rejection(blocked.rejection)
    assert owner.signing_key_rotation_dispatch_intent is None
    for wallet in wallets.values():
        wallet.lock()


def test_state_change_during_rotation_consent_prevents_prepared_dispatch(tmp_path):
    (
        wallets,
        owner,
        predecessor,
        _rotation_draft,
        rotation_bundle,
        active_public_key,
        successor_public_key,
        adapter,
        transport,
    ) = make_legacy_rotation_bundle(tmp_path)
    writes_before = len(transport.writes)
    consent_calls = []

    def consent_after_competing_update(transcript):
        consent_calls.append(transcript)
        competing_draft = adapter.create_draft(
            owner_name=OWNER_NAME,
            owner_public_key=active_public_key,
        )
        competing_result = adapter.sign_draft(
            draft=competing_draft,
            signer_public_key=active_public_key,
            signer_factory=owner.create_signer,
            consent=approved,
            authenticated_origin="https://wallet.example",
            environment="testnet",
            purpose="authorize concurrent update",
            capability="identity.write",
            expires_at=EXPIRY,
            replay_nonce=b"concurrent-update-proof",
        )
        assert competing_result.status is PublishStatus.PROOF_READY
        competing_bundle = IdentityBundle.from_submission(competing_result)
        published = publish_bundle(adapter, competing_bundle, b"concurrent-update-publish")
        assert published.status is PublishStatus.CONFIRMED
        return ConsentDecision.APPROVED

    prepared = adapter.prepare_owner_key_rotation_publication(
        rotation_bundle,
        consent=consent_after_competing_update,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="publish owner-key rotation",
        capability="identity.rotate-owner-key",
        expires_at=EXPIRY,
        replay_nonce=b"rotation-after-race",
    )

    assert prepared.status is PublishStatus.STALE
    assert prepared.publication is None
    assert len(consent_calls) == 1
    assert len(transport.writes) == writes_before + 1
    assert owner.signing_key_rotation_dispatch_intent is None
    assert owner.public_key == active_public_key
    assert owner.pending_signing_public_key == successor_public_key
    current = adapter.read_state(owner_name=OWNER_NAME)
    assert current is not None
    assert current.sequence == predecessor.sequence + 1
    assert current.owner_public_key == active_public_key
    for wallet in wallets.values():
        wallet.lock()

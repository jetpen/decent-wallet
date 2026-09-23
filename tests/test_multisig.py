from __future__ import annotations

import hashlib
import time
from dataclasses import replace
from typing import Any

import cbor2
import pytest

from decent_wallet import (
    ConsentDecision,
    ConsentTranscript,
    IdentityBundle,
    IdentityDraft,
    IdentityProof,
    InvalidIdentityRequest,
    InvalidIdentityState,
    PublishStatus,
    RegistryAdapter,
    StalePublication,
    ExpiredPublication,
    Wallet,
    build_identity_update,
)

PASSWORD = "correct horse battery staple"
OWNER_NAME = b"multisig-owner"
EXPIRY = 2_000_000_000


class MemoryTransport:
    def __init__(self) -> None:
        self.envelope: bytes | None = None
        self.writes: list[dict[str, Any]] = []
        self.history: dict[bytes, bytes] = {}
        self.drop_writes = False
        self.raise_after_write = False
        self.reject_conditional = False

    def get_identity_envelope(self, *, owner_name_hex: str) -> bytes | None:
        return self.envelope

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
    for wallet in wallets.values():
        wallet.lock()

import hashlib
import json
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from decent_wallet.identity import ConsentTranscript, IdentityBundle, IdentityDraft, IdentityProof


def test_legacy_operation5_vector_matches_python_identity_codec() -> None:
    vector_path = Path(__file__).parent / "vectors" / "identity-owner-key-rotation-legacy.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    owner_name = bytes.fromhex(vector["owner_name_utf8_hex"])
    predecessor_envelope = bytes.fromhex(vector["predecessor_envelope_cbor_hex"])
    predecessor_update = bytes.fromhex(vector["predecessor_signed_update_cbor_hex"])
    candidate_update = bytes.fromhex(vector["candidate_signed_update_cbor_hex"])
    candidate_envelope = bytes.fromhex(vector["candidate_envelope_cbor_hex"])
    predecessor_public_key = bytes.fromhex(vector["predecessor_owner_public_key_hex"])
    predecessor_state_hash = bytes.fromhex(vector["predecessor_state_hash_hex"])
    successor_public_key = bytes.fromhex(vector["successor_owner_public_key_hex"])
    successor_signers = [
        {1: item["signer_id"], 2: bytes.fromhex(item["public_key_hex"])}
        for item in vector["successor_signers"]
    ]

    assert hashlib.sha256(predecessor_update).digest() == predecessor_state_hash
    assert cbor2.dumps(cbor2.loads(predecessor_update), canonical=True) == predecessor_update
    assert cbor2.dumps(cbor2.loads(candidate_update), canonical=True) == candidate_update
    assert vector["proof_signer_id"] is None

    draft = IdentityDraft(
        signed_update_bytes=candidate_update,
        previous_state_envelope=predecessor_envelope,
    )
    assert draft.owner_name == owner_name
    assert draft.owner_public_key == successor_public_key
    assert draft.sequence == vector["candidate_sequence"]
    assert draft.sequence == vector["predecessor_sequence"] + 1
    assert draft.authorization is not None
    assert draft.authorization[3] == 5
    assert draft.authorization[7] == predecessor_state_hash
    assert draft.authorization[6] == successor_signers

    outer = cbor2.loads(candidate_envelope)
    assert outer == {1: 1, 2: candidate_update, 3: outer[3]}
    assert len(outer[3]) == 1
    proof = outer[3][0]
    assert proof[1] is None
    Ed25519PublicKey.from_public_bytes(predecessor_public_key).verify(
        proof[2],
        hashlib.sha256(candidate_update).digest(),
    )
    bundle = IdentityBundle(
        draft,
        (IdentityProof(None, predecessor_public_key, proof[2]),),
    )
    assert bundle.finalize() == candidate_envelope


def test_legacy_operation5_consent_transcript_matches_shared_vector() -> None:
    vector_path = Path(__file__).parent / "vectors" / "identity-owner-key-rotation-legacy.json"
    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    envelope = bytes.fromhex(vector["candidate_envelope_cbor_hex"])
    transcript = ConsentTranscript(
        authenticated_origin=vector["consent_authenticated_origin"],
        environment=vector["consent_environment"],
        operation=vector["consent_operation"],
        payload_hash=hashlib.sha256(envelope).digest(),
        purpose=vector["consent_purpose"],
        capability=vector["consent_capability"],
        expires_at=vector["consent_expires_at"],
        replay_nonce=bytes.fromhex(vector["consent_replay_nonce_hex"]),
        sequence=vector["candidate_sequence"],
        generation=vector["consent_generation"],
        review_payload=envelope,
    )
    canonical = bytes.fromhex(vector["consent_transcript_cbor_hex"])
    assert transcript.canonical_bytes() == canonical
    assert transcript.digest.hex() == vector["consent_transcript_digest_hex"]
    decoded = cbor2.loads(canonical)
    assert decoded[4] == hashlib.sha256(envelope).digest()
    assert decoded[9] == vector["candidate_sequence"]
    assert decoded[10] == vector["consent_generation"]
    assert decoded[13] == envelope

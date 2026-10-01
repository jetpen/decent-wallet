"""Regenerate synthetic Python-authored latched v2 fixtures; never use user wallets."""

import base64
import json
import sys
import tempfile
from pathlib import Path

import cbor2

from decent_wallet import (
    ConsentDecision,
    IdentityBundle,
    IdentityDraft,
    IdentityProof,
    RegistryAdapter,
    Wallet,
)

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from test_multisig import EXPIRY, PASSWORD, MemoryTransport  # noqa: E402


def generate():
    vector = json.loads(
        (ROOT / "tests/vectors/identity-owner-key-rotation-legacy.json").read_text()
    )

    def decode(name):
        return bytes.fromhex(vector[name])

    active = decode("predecessor_owner_public_key_hex")
    pending = decode("successor_owner_public_key_hex")
    draft = IdentityDraft(
        decode("candidate_signed_update_cbor_hex"),
        decode("predecessor_envelope_cbor_hex"),
    )
    signature = cbor2.loads(decode("candidate_envelope_cbor_hex"))[3][0][2]
    bundle = IdentityBundle(draft, (IdentityProof(None, active, signature),))
    transport = MemoryTransport()
    transport.envelope = decode("predecessor_envelope_cbor_hex")
    transport.remote_envelope = transport.envelope
    transport.history[decode("predecessor_state_hash_hex")] = transport.envelope
    adapter = RegistryAdapter(transport, registry_environment="testnet")
    with tempfile.TemporaryDirectory(prefix="portable-vector-") as directory:
        # The existing canonical identity fixture's synthetic seed sequences.
        wallet = Wallet._create_storage(
            Path(directory) / "fixture.dw",
            PASSWORD,
            PASSWORD,
            {
                "private_seed": bytes(range(32)),
                "public_key": active,
                "pending_private_seed": bytes(range(32, 64)),
                "pending_public_key": pending,
            },
        )
        publication = adapter.prepare_owner_key_rotation_publication(
            bundle,
            consent=lambda _: ConsentDecision.APPROVED,
            authenticated_origin="https://wallet.example",
            environment="testnet",
            purpose="publish owner-key rotation",
            capability="identity.rotate-owner-key",
            expires_at=EXPIRY,
            replay_nonce=bytes(range(32)),
        ).publication
        assert publication is not None
        wallet.latch_signing_key_rotation_dispatch_intent(bundle, publication)
        bound = wallet.export_container()
        payload = dict(wallet._payload)
        payload["rotation_dispatch_intent"] = dict(payload["rotation_dispatch_intent"])
        payload["rotation_dispatch_intent"].pop("environment")
        wallet._persist_envelope(wallet._build_envelope(payload))
        wallet.lock()
        legacy = Wallet.open(Path(directory) / "fixture.dw", PASSWORD)
        try:
            unbound = legacy.export_container()
        finally:
            legacy.lock()
    result = {
        "case_id": "portable-environment-bound-rotation-latch-v2",
        "identity_vector": "identity-owner-key-rotation-legacy.json",
        "environment": "testnet",
        "python_bound_container_base64": base64.b64encode(bound).decode(),
        "legacy_unbound_container_base64": base64.b64encode(unbound).decode(),
    }
    (ROOT / "tests/vectors/wallet-v2-portable-rotation-latch.json").write_text(
        json.dumps(result, indent=2) + "\n"
    )


def extend_bignum_fixture():
    """Add a real encrypted Python int fixture without rewriting existing ciphertext."""
    import decent_wallet.container as c

    path = ROOT / "tests/vectors/wallet-v2-portable-rotation-latch.json"
    fixture = json.loads(path.read_text())
    envelope = c._parse_container(base64.b64decode(fixture["python_bound_container_base64"]))
    dek, payload = c._unlock_envelope(envelope, PASSWORD)
    try:
        sequence = 2**130 + 17
        payload["rotation_dispatch_intent"]["sequence"] = sequence
        raw = c._serialize(c._build_v2_envelope(PASSWORD, bytes(dek), envelope["kdf"], payload))
        fixture["large_positive_sequence_decimal"] = str(sequence)
        fixture["python_bignum_container_base64"] = base64.b64encode(raw).decode()
        path.write_text(json.dumps(fixture, indent=2) + "\n")
    finally:
        c._wipe(dek)


if __name__ == "__main__":
    generate()
    extend_bignum_fixture()

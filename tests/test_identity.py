import cbor2
import pytest
import time
from typing import Any, cast

from decent_wallet import (
    ConsentDecision,
    ConsentTranscript,
    ExpiredPublication,
    IdentityState,
    InvalidIdentityRequest,
    StalePublication,
    InvalidIdentityState,
    PublishStatus,
    RegistryAdapter,
    Wallet,
    build_identity_update,
)


PASSWORD = "correct horse battery staple"
OWNER_NAME = b"adapter-owner"


class MemoryTransport:
    def __init__(self):
        self.envelope: bytes | None = None
        self.writes: list[tuple[str, bytes]] = []
        self.drop_writes = False
        self.reject_conditional = False

    def get_identity_envelope(self, *, owner_name_hex: str) -> bytes | None:
        return self.envelope

    def put_identity_envelope(
        self,
        *,
        owner_name_hex: str,
        envelope_cbor: bytes,
        expected_state_hash: bytes | None,
        expires_at: int,
    ) -> None:
        if expires_at <= int(time.time()):
            raise ExpiredPublication()
        if self.reject_conditional:
            raise StalePublication()
        self.writes.append((owner_name_hex, envelope_cbor))
        if not self.drop_writes:
            self.envelope = envelope_cbor


def approved(_transcript: ConsentTranscript) -> ConsentDecision:
    return ConsentDecision.APPROVED


def request_kwargs(consent=approved):
    return {
        "owner_name": OWNER_NAME,
        "consent": consent,
        "authenticated_origin": "https://wallet.example",
        "environment": "testnet",
        "operation": "identity.update",
        "purpose": "update identity record",
        "capability": "identity.write",
        "expires_at": 2_000_000_000,
        "replay_nonce": b"nonce-1",
    }


def signing_kwargs(wallet):
    public_key = wallet.public_key
    return {
        "owner_public_key": public_key,
        "signer_public_key": public_key,
        "signer_factory": wallet.create_signer,
    }


def test_consent_transcript_is_canonical_and_binds_required_fields():
    transcript = ConsentTranscript(
        authenticated_origin="https://wallet.example",
        environment="testnet",
        operation="identity.update",
        payload_hash=bytes(range(32)),
        purpose="update identity record",
        capability="identity.write",
        expires_at=2_000_000_000,
        replay_nonce=b"unique-request",
        sequence=4,
        generation=2,
    )
    decoded = cbor2.loads(transcript.canonical_bytes())
    assert set(decoded) == set(range(1, 11))
    assert decoded[1] == "https://wallet.example"
    assert decoded[4] == bytes(range(32))
    assert decoded[9] == 4
    assert decoded[10] == 2
    assert transcript.digest != bytes(32)


def test_adapter_reads_verifies_and_confirms_legacy_identity(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)

    result = adapter.submit_identity(
        **signing_kwargs(wallet),
        **request_kwargs(),
    )

    assert result.status is PublishStatus.CONFIRMED
    assert result.accepted_state is not None
    assert result.accepted_state.sequence == 1
    assert result.accepted_state.owner_name == OWNER_NAME
    assert len(transport.writes) == 1
    owner_name_hex, envelope = transport.writes[0]
    assert owner_name_hex == OWNER_NAME.hex()
    assert b"private_seed" not in envelope
    assert b"correct horse" not in envelope

    state = adapter.read_state(owner_name=OWNER_NAME)
    assert isinstance(state, IdentityState)
    assert state.envelope_bytes == envelope

    replay = adapter.submit_identity(
        **signing_kwargs(wallet),
        **request_kwargs(),
    )
    assert replay.status is PublishStatus.FAILED
    assert replay.reason == "replay rejected"
    assert len(transport.writes) == 1
    wallet.lock()


def test_adapter_supports_versioned_public_envelope(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    public_key = wallet.public_key
    authorization = {
        1: 1,
        2: 1,
        3: 1,
        4: 1,
        5: 2,
        6: [
            {1: "alice", 2: public_key},
            {1: "bob", 2: b"b" * 32},
            {1: "carol", 2: b"c" * 32},
        ],
        7: bytes(32),
    }

    v1_request = request_kwargs()
    v1_request["operation"] = "genesis"
    result = adapter.submit_identity(
        **signing_kwargs(wallet),
        authorization=authorization,
        signer_id="alice",
        **v1_request,
    )

    assert result.status is PublishStatus.PROOF_READY
    assert result.accepted_state is None
    assert result.signed_update_bytes is not None
    assert result.proof_bytes is not None
    assert transport.writes == []
    wallet.lock()


def test_expiry_and_threshold_never_publish_or_sign(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    expired = adapter.submit_identity(
        **signing_kwargs(wallet),
        expires_at=1,
        **{key: value for key, value in request_kwargs().items() if key != "expires_at"},
    )
    assert expired.status is PublishStatus.EXPIRED
    assert transport.writes == []

    public_key = wallet.public_key
    threshold_request = request_kwargs()
    threshold_request["operation"] = "genesis"
    threshold_request["replay_nonce"] = b"nonce-threshold"
    proof_result = adapter.submit_identity(
        **signing_kwargs(wallet),
        authorization={
            1: 1,
            2: 1,
            3: 1,
            4: 1,
            5: 2,
            6: [
                {1: "alice", 2: public_key},
                {1: "bob", 2: b"b" * 32},
                {1: "carol", 2: b"c" * 32},
            ],
            7: bytes(32),
        },
        signer_id="alice",
        **threshold_request,
    )
    assert proof_result.status is PublishStatus.PROOF_READY
    assert proof_result.signed_update_bytes is not None
    assert proof_result.proof_bytes is not None
    assert proof_result.envelope_bytes is None
    assert transport.writes == []
    wallet.lock()


def test_denial_and_consent_failure_do_not_sign_or_publish(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)

    denied = adapter.submit_identity(
        **signing_kwargs(wallet),
        consent=lambda _: ConsentDecision.DENIED,
        **{key: value for key, value in request_kwargs().items() if key != "consent"},
    )
    assert denied.status is PublishStatus.DENIED
    assert transport.writes == []

    failed = adapter.submit_identity(
        **signing_kwargs(wallet),
        consent=lambda _: (_ for _ in ()).throw(RuntimeError("ui failed")),
        **{key: value for key, value in request_kwargs().items() if key != "consent"},
    )
    assert failed.status is PublishStatus.FAILED
    assert transport.writes == []
    wallet.lock()


def test_stale_state_is_rejected_without_publication_or_retry(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    first = adapter.submit_identity(**signing_kwargs(wallet), **request_kwargs())
    assert first.status is PublishStatus.CONFIRMED
    writes_before = len(transport.writes)

    def consent_and_change(_transcript):
        update = build_identity_update(
            owner_name=OWNER_NAME,
            owner_public_key=wallet.public_key,
            sequence=2,
        )
        signer = wallet.create_signer()
        signature = signer.sign_identity_update(update)
        transport.envelope = cbor2.dumps({1: update, 2: signature}, canonical=True)
        return ConsentDecision.APPROVED

    stale_request = request_kwargs()
    stale_request["replay_nonce"] = b"nonce-stale"
    stale_request["consent"] = consent_and_change
    stale = adapter.submit_identity(
        **signing_kwargs(wallet),
        **stale_request,
    )
    assert stale.status is PublishStatus.STALE
    assert len(transport.writes) == writes_before
    wallet.lock()


def test_invalid_signer_output_is_rejected_and_invalidated(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    public_key = wallet.public_key

    class BadSigner:
        def __init__(self):
            self.public_key = public_key
            self.invalidated = False

        def sign_identity_update(self, _update):
            return b"bad"

        def invalidate(self):
            self.invalidated = True

    bad_signer = BadSigner()
    result = adapter.submit_identity(
        owner_name=OWNER_NAME,
        owner_public_key=public_key,
        signer_public_key=public_key,
        signer_factory=cast(Any, lambda: bad_signer),
        **{key: value for key, value in request_kwargs().items() if key != "owner_name"},
    )
    assert result.status is PublishStatus.FAILED
    assert bad_signer.invalidated
    assert transport.writes == []
    wallet.lock()


def test_unknown_dispatch_requires_exact_readback(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    transport.drop_writes = True

    result = adapter.submit_identity(**signing_kwargs(wallet), **request_kwargs())

    assert result.status is PublishStatus.UNKNOWN
    assert result.envelope_bytes is not None
    assert result.accepted_state is None
    assert len(transport.writes) == 1
    wallet.lock()


def test_malformed_ambiguous_readback_is_unknown(tmp_path):
    class MalformedTransport(MemoryTransport):
        def put_identity_envelope(self, **kwargs):
            self.envelope = b"malformed"
            raise RuntimeError("transport detail")

    transport = MalformedTransport()
    adapter = RegistryAdapter(transport)
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    result = adapter.submit_identity(**signing_kwargs(wallet), **request_kwargs())
    assert result.status is PublishStatus.UNKNOWN
    assert result.accepted_state is None
    wallet.lock()


def test_conditional_publication_rejects_toctou_without_retry(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    first = adapter.submit_identity(**signing_kwargs(wallet), **request_kwargs())
    assert first.status is PublishStatus.CONFIRMED
    writes_before = len(transport.writes)
    transport.reject_conditional = True

    second_request = request_kwargs()
    second_request["replay_nonce"] = b"nonce-2"
    result = adapter.submit_identity(**signing_kwargs(wallet), **second_request)

    assert result.status is PublishStatus.STALE
    assert len(transport.writes) == writes_before
    wallet.lock()


def test_tampered_or_wrong_owner_state_is_rejected(tmp_path):
    transport = MemoryTransport()
    adapter = RegistryAdapter(transport)
    with pytest.raises(InvalidIdentityRequest):
        adapter.read_state(owner_name=bytes([0xFF]))

    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    result = adapter.submit_identity(**signing_kwargs(wallet), **request_kwargs())
    assert result.status is PublishStatus.CONFIRMED

    assert transport.envelope is not None
    transport.envelope = transport.envelope[:-1] + bytes([transport.envelope[-1] ^ 1])
    with pytest.raises(InvalidIdentityState):
        adapter.read_state(owner_name=OWNER_NAME)
    wallet.lock()

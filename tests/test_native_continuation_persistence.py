from __future__ import annotations

import base64

import pytest

from decent_wallet import InvalidContainer, NativeContinuationCapability, StorageFailure, Wallet, WalletLockedError
from test_account_disclosure_lifecycle import _approved_wallet


def test_native_continuation_capability_persists_only_after_proof_and_is_closeable(tmp_path):
    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    capability = bytes(range(32))
    encoded = base64.urlsafe_b64encode(capability).decode("ascii").rstrip("=")
    with pytest.raises(ValueError):
        wallet.install_native_continuation_capability(pending, encoded, pending.expires_at)

    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    wallet.install_native_continuation_capability(pending, encoded, pending.expires_at)
    encrypted_file = (tmp_path / "wallet.json").read_bytes()
    assert capability not in encrypted_file
    assert encoded.encode("ascii") not in encrypted_file
    with pytest.raises(ValueError):
        wallet.install_native_continuation_capability(pending, encoded, pending.expires_at)
    wallet.background()

    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    value = reopened.native_continuation_capability(pending)
    assert value is not None
    assert reopened._payload["pending_account_disclosure_v1"]["context"]["decent_native_continuation"] is True
    assert isinstance(value, NativeContinuationCapability)
    assert value.expires_at == pending.expires_at
    with pytest.raises(AttributeError):
        setattr(value, "expires_at", pending.expires_at + 1)
    owned = value.copy_capability_bytes()
    assert owned == capability
    owned[:] = b"\x00" * len(owned)
    assert "".join(f"{byte:02x}" for byte in capability) not in repr(value)
    value.close()
    with pytest.raises(ValueError):
        value.copy_capability_bytes()
    reopened.lock()


def test_stale_session_cannot_release_capability_after_cancellation(tmp_path):
    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    encoded = base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("=")
    wallet.install_native_continuation_capability(pending, encoded, pending.expires_at)
    stale = Wallet.open(tmp_path / "wallet.json", "correct horse battery")

    wallet.cancel_account_disclosure(pending)
    after_cancellation = (tmp_path / "wallet.json").read_bytes()
    with pytest.raises(StorageFailure):
        stale.native_continuation_capability(pending)
    assert (tmp_path / "wallet.json").read_bytes() == after_cancellation
    assert not stale.is_unlocked
    wallet.lock()
    stale.lock()


def test_expired_native_continuation_is_durably_removed_before_absence(tmp_path, monkeypatch):
    import decent_wallet.container as container_module

    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    encoded = base64.urlsafe_b64encode(b"x" * 32).decode("ascii").rstrip("=")
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    wallet.install_native_continuation_capability(pending, encoded, pending.expires_at - 1)
    wallet.lock()
    monkeypatch.setattr(container_module.time, "time", lambda: pending.expires_at - 1)
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    assert reopened.native_continuation_capability(pending) is None
    reopened.lock()
    monkeypatch.setattr(container_module.time, "time", lambda: pending.expires_at - 300)
    recovered = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    assert recovered.native_continuation_capability(pending) is None
    recovered.lock()


def test_expired_and_approval_overrun_installations_reject_without_writing(tmp_path, monkeypatch):
    import decent_wallet.container as container_module

    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    encoded = base64.urlsafe_b64encode(b"e" * 32).decode("ascii").rstrip("=")
    created_at = pending.expires_at - 300
    monkeypatch.setattr(container_module.time, "time", lambda: created_at)
    before = (tmp_path / "wallet.json").read_bytes()
    for expiry in (created_at, pending.expires_at + 1):
        with pytest.raises(ValueError):
            wallet.install_native_continuation_capability(pending, encoded, expiry)
        assert (tmp_path / "wallet.json").read_bytes() == before
    wallet.install_native_continuation_capability(pending, encoded, pending.expires_at)
    wallet.lock()


def test_installation_enforces_300_second_limit_from_install_time_without_writing(tmp_path, monkeypatch):
    import decent_wallet.container as container_module

    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    encoded = base64.urlsafe_b64encode(b"l" * 32).decode("ascii").rstrip("=")
    before = (tmp_path / "wallet.json").read_bytes()
    created_at = pending.expires_at - 300
    monkeypatch.setattr(container_module.time, "time", lambda: created_at - 1)
    assert pending.expires_at <= created_at + 300
    assert pending.expires_at > created_at - 1 + 300
    with pytest.raises(ValueError):
        wallet.install_native_continuation_capability(pending, encoded, pending.expires_at)
    assert (tmp_path / "wallet.json").read_bytes() == before
    monkeypatch.setattr(container_module.time, "time", lambda: created_at)
    wallet.install_native_continuation_capability(pending, encoded, pending.expires_at)
    wallet.lock()


def test_invalid_native_continuation_writes_preserve_exact_encrypted_file(tmp_path):
    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    path = tmp_path / "wallet.json"
    capability = base64.urlsafe_b64encode(b"z" * 32).decode("ascii").rstrip("=")
    before = path.read_bytes()
    bad = (
        (pending, "!" * 43, pending.expires_at),
        (pending, capability + "=", pending.expires_at),
        (pending, base64.urlsafe_b64encode(b"z" * 31).decode().rstrip("="), pending.expires_at),
        (pending, capability, pending.expires_at + 1),
        (pending, capability, 1_800_000_001),
        (type(pending)(pending.handle, pending.expires_at - 1), capability, pending.expires_at),
        (type(pending)("A" * 43, pending.expires_at), capability, pending.expires_at),
    )
    for target, encoded, expiry in bad:
        with pytest.raises(ValueError):
            wallet.install_native_continuation_capability(target, encoded, expiry)
        assert path.read_bytes() == before
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    wallet.install_native_continuation_capability(pending, capability, pending.expires_at)
    before_duplicate = path.read_bytes()
    with pytest.raises(ValueError):
        wallet.install_native_continuation_capability(pending, capability, pending.expires_at)
    assert path.read_bytes() == before_duplicate
    wallet.lock()


def test_native_continuation_access_requires_unlocked_wallet_and_owned_copy_is_wipeable(tmp_path):
    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    encoded = base64.urlsafe_b64encode(b"w" * 32).decode().rstrip("=")
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    wallet.install_native_continuation_capability(pending, encoded, pending.expires_at)
    wallet.lock()
    with pytest.raises(WalletLockedError):
        wallet.native_continuation_capability(pending)


def test_returned_capability_expires_by_monotonic_time_even_if_wall_clock_moves_back(tmp_path, monkeypatch):
    import time
    import decent_wallet.container as container_module

    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    encoded = base64.urlsafe_b64encode(b"m" * 32).decode("ascii").rstrip("=")
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    wall_now = int(container_module.time.time())
    expires_at = min(pending.expires_at, wall_now + 3)
    wallet.install_native_continuation_capability(pending, encoded, expires_at)
    mono_now = time.monotonic()
    monkeypatch.setattr(container_module.time, "time", lambda: wall_now)
    monkeypatch.setattr(container_module.time, "monotonic", lambda: mono_now)
    value = wallet.native_continuation_capability(pending)
    assert value is not None
    mono_now += 4
    wall_now -= 1000
    with pytest.raises(ValueError):
        value.copy_capability_bytes()
    value.close()
    wallet.lock()


def test_native_continuation_survives_prepared_and_ambiguous_states_then_consumes(tmp_path):
    from decent_wallet import PresentationDeliveryOutcome
    from test_account_disclosure_lifecycle import continuation_artifacts
    import decent_wallet.container as container_module

    wallet, pending, context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    encoded = base64.urlsafe_b64encode(b"p" * 32).decode("ascii").rstrip("=")
    wallet.install_native_continuation_capability(pending, encoded, pending.expires_at)
    now = int(container_module.time.time())
    capability_hash = base64.urlsafe_b64encode(__import__("hashlib").sha256(b"p" * 32).digest()).decode().rstrip("=")
    binding, jwks, outer, request, registration = continuation_artifacts(
        context, wallet.public_key, now,
        request_expires_at=pending.expires_at,
        capability_hash=capability_hash,
        binding_expires_at=pending.expires_at,
    )
    submission = wallet.prepare_account_presentation(
        pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
        request_object=request, registration=registration,
    )
    assert wallet.native_continuation_capability(pending) is None
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    assert wallet.native_continuation_capability(pending) is None
    wallet.finish_account_presentation(
        pending, PresentationDeliveryOutcome.ACCEPTED, status_code=200,
        content_type="application/json",
        response_body=b'{"redirect_uri":"https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"}',
    )
    with pytest.raises(ValueError):
        wallet.native_continuation_capability(pending)
    wallet.lock()


def test_cancel_removes_persisted_native_continuation(tmp_path):
    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    wallet.install_native_continuation_capability(
        pending, base64.urlsafe_b64encode(b"q" * 32).decode().rstrip("="), pending.expires_at
    )
    wallet.cancel_account_disclosure(pending)
    with pytest.raises(ValueError):
        wallet.native_continuation_capability(pending)
    wallet.lock()


@pytest.mark.parametrize("mutation", ["null", "unissued"])
def test_authenticated_continuation_requires_object_and_issued_proof(tmp_path, mutation):
    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    wallet.install_native_continuation_capability(
        pending, base64.urlsafe_b64encode(b"r" * 32).decode().rstrip("="), pending.expires_at
    )
    payload = dict(wallet._payload)
    record = dict(payload["pending_account_disclosure_v1"])
    if mutation == "null":
        record["native_continuation"] = None
    else:
        record["proof_issued"] = False
        record["proof_challenge"] = None
    payload["pending_account_disclosure_v1"] = record
    wallet._persist_envelope(wallet._build_envelope(payload))
    wallet.lock()
    with pytest.raises(InvalidContainer):
        Wallet.open(tmp_path / "wallet.json", "correct horse battery")


def test_authenticated_parser_rechecks_continuation_duration_bound(tmp_path):
    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    wallet.install_native_continuation_capability(
        pending, base64.urlsafe_b64encode(b"d" * 32).decode().rstrip("="), pending.expires_at
    )
    payload = dict(wallet._payload)
    record = dict(payload["pending_account_disclosure_v1"])
    continuation = dict(record["native_continuation"])
    continuation["expires_at"] = record["created_at"] + 301
    record["expires_at"] = record["created_at"] + 350
    record["context"] = dict(record["context"])
    record["context"]["expires_at"] = record["created_at"] + 400
    record["native_continuation"] = continuation
    payload["pending_account_disclosure_v1"] = record
    wallet._persist_envelope(wallet._build_envelope(payload))
    wallet.lock()
    with pytest.raises(InvalidContainer):
        Wallet.open(tmp_path / "wallet.json", "correct horse battery")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value.update(extra=True),
        lambda value: value.update(capability="not bytes"),
        lambda value: value.update(capability=b"short"),
        lambda value: value.update(expires_at=True),
        lambda value: value.update(expires_at=1_800_000_302),
        lambda value: value.update(capability=None),
    ],
)
def test_authenticated_malformed_continuation_record_is_rejected_on_reopen(tmp_path, mutate):
    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    wallet.install_native_continuation_capability(
        pending, base64.urlsafe_b64encode(b"v" * 32).decode().rstrip("="), pending.expires_at
    )
    changed_payload = dict(wallet._payload)
    record = dict(changed_payload["pending_account_disclosure_v1"])
    continuation = dict(record["native_continuation"])
    mutate(continuation)
    record["native_continuation"] = continuation
    changed_payload["pending_account_disclosure_v1"] = record
    wallet._persist_envelope(wallet._build_envelope(changed_payload))
    wallet.lock()
    with pytest.raises(InvalidContainer):
        Wallet.open(tmp_path / "wallet.json", "correct horse battery")



def test_persisted_native_capability_is_rejected_when_context_is_browser_only(tmp_path):
    wallet, pending, _context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(
        pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    )
    wallet.install_native_continuation_capability(
        pending, base64.urlsafe_b64encode(b"x" * 32).decode().rstrip("="), pending.expires_at
    )
    payload = dict(wallet._payload)
    record = dict(payload["pending_account_disclosure_v1"])
    record["context"] = dict(record["context"])
    record["context"].pop("decent_native_continuation")
    payload["pending_account_disclosure_v1"] = record
    wallet._persist_envelope(wallet._build_envelope(payload))
    wallet.lock()
    with pytest.raises(InvalidContainer):
        Wallet.open(tmp_path / "wallet.json", "correct horse battery")

import hashlib
import pickle
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import cbor2
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from decent_wallet import (
    InvalidContainer,
    InvalidSigningInput,
    KeyGenerationError,
    SignerCapability,
    StorageFailure,
    SignerUnavailable,
    Wallet,
)
import decent_wallet.signer as signer_module


PASSWORD = "correct horse battery staple"


def identity_update(public_key: bytes, *, sequence: int = 1) -> bytes:
    return cbor2.dumps(
        {1: {1: b"alice", 2: public_key}, 2: {}, 3: sequence},
        canonical=True,
    )


def multisig_identity_update(public_key: bytes, authorization: dict | None = None) -> bytes:
    if authorization is None:
        authorization = {
            1: 1,
            2: 1,
            3: 1,
            4: 1,
            5: 1,
            6: [{1: "alice", 2: public_key}],
            7: bytes(32),
        }
    return cbor2.dumps(
        {1: {1: b"alice", 2: public_key}, 2: {}, 3: 1, 4: authorization},
        canonical=True,
    )


def test_generated_key_exposes_only_public_key_and_signs_identity_update(tmp_path: Path):
    with pytest.raises(SignerUnavailable):
        SignerCapability(cast(Any, None), b"", 1.0, None)

    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    assert "private_seed" not in wallet._payload
    with pytest.raises(InvalidContainer):
        wallet.update_payload({"private_seed": b"a" * 32})
    public_key = wallet.public_key
    signer = wallet.create_signer()
    assert not hasattr(signer, "_key")
    update = identity_update(public_key)

    signature = signer.sign_identity_update(update)
    Ed25519PublicKey.from_public_bytes(public_key).verify(
        signature,
        hashlib.sha256(update).digest(),
    )
    assert signer.public_key == public_key
    assert not signer.is_active
    assert "private" not in repr(signer).lower()
    with pytest.raises(SignerUnavailable):
        signer.sign_identity_update(update)
    with pytest.raises(TypeError):
        pickle.dumps(signer)


def test_signer_capability_is_single_use_under_concurrency(tmp_path: Path):
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    signer = wallet.create_signer()
    update = identity_update(wallet.public_key)

    def attempt():
        try:
            return signer.sign_identity_update(update)
        except Exception as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: attempt(), range(2)))
    assert sum(isinstance(result, bytes) for result in results) == 1
    assert sum(isinstance(result, SignerUnavailable) for result in results) == 1
    wallet.lock()


def test_signer_binds_legacy_owner_key_and_v1_signer_set(tmp_path: Path):
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    public_key = wallet.public_key
    signer = wallet.create_signer()
    with pytest.raises(InvalidSigningInput):
        signer.sign_identity_update(identity_update(b"o" * 32))
    assert not signer.is_active

    signer = wallet.create_signer()
    with pytest.raises(InvalidSigningInput):
        signer.sign_identity_update(multisig_identity_update(public_key, {1: 1, 2: 1, 3: 1}))
    assert not signer.is_active

    signer = wallet.create_signer()
    update = multisig_identity_update(public_key)
    signature = signer.sign_identity_update(update)
    Ed25519PublicKey.from_public_bytes(public_key).verify(
        signature,
        hashlib.sha256(update).digest(),
    )
    wallet.lock()


def test_noncanonical_or_wrong_identity_bytes_are_rejected_and_invalidate(tmp_path: Path):
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    signer = wallet.create_signer()
    public_key = wallet.public_key
    noncanonical = cbor2.dumps(
        {3: 1, 2: {}, 1: {1: b"alice", 2: public_key}},
        canonical=False,
    )
    with pytest.raises(InvalidSigningInput):
        signer.sign_identity_update(noncanonical)
    assert not signer.is_active

    signer = wallet.create_signer()
    boolean_key = cbor2.dumps(
        {True: {1: b"alice", 2: public_key}, 2: {}, 3: 1},
        canonical=True,
    )
    with pytest.raises(InvalidSigningInput):
        signer.sign_identity_update(boolean_key)
    assert not signer.is_active
    wallet.lock()


def test_stored_public_key_must_match_private_seed(tmp_path: Path):
    with pytest.raises(InvalidContainer):
        Wallet.create(
            tmp_path / "public.dw",
            PASSWORD,
            PASSWORD,
            {"private_seed": b"a" * 32, "public_key": b"b" * 32},
        )
    with pytest.raises(InvalidContainer):
        Wallet._create_storage(
            tmp_path / "wallet.dw",
            PASSWORD,
            PASSWORD,
            {"private_seed": b"a" * 32, "public_key": b"b" * 32},
        )
    assert not (tmp_path / "wallet.dw").exists()


def test_csrng_provider_replacement_fails_before_provider_use(tmp_path: Path, monkeypatch):
    calls: list[int] = []

    def replacement(size: int) -> bytes:
        calls.append(size)
        return b"x" * size

    monkeypatch.setattr(signer_module.secrets, "token_bytes", replacement)
    path = tmp_path / "wallet.dw"
    with pytest.raises(KeyGenerationError) as error:
        Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    assert calls == []
    assert not path.exists()
    assert str(error.value) == "key generation failed"


def test_csrng_failure_during_container_setup_is_redacted(tmp_path: Path, monkeypatch):
    calls = 0

    def fails_after_seed(size: int) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 1:
            return b"x" * size
        raise RuntimeError("secret provider detail")

    monkeypatch.setattr(signer_module, "_APPROVED_CSRNG", fails_after_seed)
    monkeypatch.setattr(signer_module.secrets, "token_bytes", fails_after_seed)
    path = tmp_path / "wallet.dw"
    with pytest.raises(StorageFailure) as error:
        Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    assert not path.exists()
    assert str(error.value) == "wallet storage operation failed"


def test_csrng_wrong_type_and_length_fail_without_fallback(monkeypatch):
    for malformed in (bytearray(32), b"short"):
        calls: list[int] = []

        def replacement(size: int, malformed=malformed):
            calls.append(size)
            return malformed

        monkeypatch.setattr(signer_module, "_APPROVED_CSRNG", replacement)
        monkeypatch.setattr(signer_module.secrets, "token_bytes", replacement)
        with pytest.raises(KeyGenerationError):
            signer_module._generate_seed()
        assert calls == [32]


def test_csrng_exception_is_redacted_and_has_no_fallback(monkeypatch):
    def raising(_size: int) -> bytes:
        raise RuntimeError("secret provider detail")

    monkeypatch.setattr(signer_module, "_APPROVED_CSRNG", raising)
    monkeypatch.setattr(signer_module.secrets, "token_bytes", raising)
    with pytest.raises(KeyGenerationError) as error:
        signer_module._generate_seed()
    assert str(error.value) == "key generation failed"
    assert "secret provider detail" not in repr(error.value)


def test_lock_and_timeout_invalidate_signer_capabilities(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    signer = wallet.create_signer()
    wallet.lock()
    with pytest.raises(SignerUnavailable):
        signer.sign_identity_update(identity_update(signer.public_key))

    wallet = Wallet.open(path, PASSWORD)
    signer = wallet.create_signer(timeout_seconds=0.001)
    time.sleep(0.01)
    assert not signer.is_active
    with pytest.raises(SignerUnavailable):
        signer.sign_identity_update(identity_update(wallet.public_key))
    assert not signer.is_active

import base64
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, BrokenBarrierError

import pytest

from decent_wallet import (
    InvalidContainer,
    KeyGenerationError,
    PasswordPolicyError,
    StorageFailure,
    UnlockFailed,
    UnsupportedFormat,
    Wallet,
    WalletLockedError,
)
import decent_wallet.container as container_module
import decent_wallet.signer as signer_module


PASSWORD = "correct horse battery staple"
NEW_PASSWORD = "another sufficiently long passphrase"


def test_initialize_unlock_and_secret_material_stays_encrypted(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    Wallet.create(
        path,
        PASSWORD,
        PASSWORD,
        {"secret_value": b"secret-seed", "owner": "alice"},
    )

    raw = path.read_bytes()
    assert b"secret-seed" not in raw
    assert b"private_seed" not in raw
    envelope = json.loads(raw)
    assert envelope["version"] == 2
    assert envelope["kdf"] == {
        "algorithm": "argon2id",
        "memory_kib": 65536,
        "parallelism": 4,
        "salt": envelope["kdf"]["salt"],
        "time_cost": 3,
    }
    assert envelope["payload"]["algorithm"] == "xchacha20-poly1305"
    assert path.stat().st_mode & 0o777 == 0o600

    wallet = Wallet.open(path, PASSWORD)
    assert wallet.is_unlocked
    wallet.lock()
    with pytest.raises(WalletLockedError):
        wallet.update_payload({})


def test_wrong_password_and_tampering_fail_closed(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    Wallet.create(path, PASSWORD, PASSWORD, {"owner": "alice"})

    with pytest.raises(UnlockFailed):
        Wallet.open(path, "wrong password that is long")

    envelope = json.loads(path.read_text())
    envelope["payload"]["ciphertext"] = (
        envelope["payload"]["ciphertext"][:-1]
        + ("A" if envelope["payload"]["ciphertext"][-1] != "A" else "B")
    )
    path.write_text(json.dumps(envelope, separators=(",", ":")))
    with pytest.raises(UnlockFailed):
        Wallet.open(path, PASSWORD)


def test_malformed_and_unsupported_containers_are_distinguished(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    path.write_text("not json")
    with pytest.raises(InvalidContainer):
        Wallet.open(path, PASSWORD)

    valid_path = tmp_path / "valid.dw"
    Wallet.create(valid_path, PASSWORD, PASSWORD, {})
    envelope = json.loads(valid_path.read_text())
    for version in (1, 99):
        envelope["version"] = version
        valid_path.write_text(json.dumps(envelope, separators=(",", ":")))
        with pytest.raises(UnsupportedFormat):
            Wallet.open(valid_path, PASSWORD)


def test_lock_background_and_inactivity_invalidate_session(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create(path, PASSWORD, PASSWORD, {}, inactivity_minutes=1)
    assert wallet.is_unlocked
    wallet.background()
    assert not wallet.is_unlocked
    with pytest.raises(WalletLockedError):
        wallet.update_payload({})

    wallet = Wallet.open(path, PASSWORD, inactivity_minutes=1)
    assert wallet.check_inactivity(now=wallet.last_activity + 60.1)
    assert not wallet.is_unlocked


def test_password_rewrap_preserves_encrypted_payload(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    before = json.loads(path.read_text())

    wallet = Wallet.open(path, PASSWORD)
    wallet.change_password(NEW_PASSWORD, NEW_PASSWORD)
    after = json.loads(path.read_text())

    assert after["payload"] == before["payload"]
    assert after["kdf"] != before["kdf"]
    assert after["wrap"] != before["wrap"]
    with pytest.raises(UnlockFailed):
        Wallet.open(path, PASSWORD)
    Wallet.open(path, NEW_PASSWORD)


def test_failed_write_preserves_previous_valid_container(tmp_path: Path, monkeypatch):
    path = tmp_path / "wallet.dw"
    Wallet.create(path, PASSWORD, PASSWORD, {"revision": 1})
    before = path.read_bytes()

    def fail(_path, _data):
        raise StorageFailure()

    monkeypatch.setattr(container_module, "_atomic_write", fail)
    wallet = Wallet.open(path, PASSWORD)
    with pytest.raises(StorageFailure):
        wallet.update_payload({"revision": 2})
    assert path.read_bytes() == before
    assert Wallet.open(path, PASSWORD).is_unlocked


def test_directory_sync_failure_restores_previous_container(tmp_path: Path, monkeypatch):
    path = tmp_path / "wallet.dw"
    Wallet.create(path, PASSWORD, PASSWORD, {"revision": 1})
    before = path.read_bytes()

    def fail(_directory):
        raise OSError("simulated directory sync failure")

    monkeypatch.setattr(container_module, "_fsync_directory", fail)
    wallet = Wallet.open(path, PASSWORD)
    with pytest.raises(StorageFailure):
        wallet.update_payload({"revision": 2})
    assert path.read_bytes() == before
    assert list(tmp_path.glob(".decent-wallet-*")) == []


def test_unlock_failures_use_bounded_progressive_delay(tmp_path: Path, monkeypatch):
    path = tmp_path / "wallet.dw"
    Wallet.create(path, PASSWORD, PASSWORD, {})
    delays: list[float] = []
    monkeypatch.setattr(container_module.time, "sleep", delays.append)

    with pytest.raises(UnlockFailed):
        Wallet.open(path, "wrong password that is long")
    with pytest.raises(UnlockFailed):
        Wallet.open(path, "wrong password that is long")
    assert delays == [0.05, 0.1]


def test_password_policy_and_confirmation(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    with pytest.raises(PasswordPolicyError):
        Wallet.create(path, "too short", "too short", {})
    with pytest.raises(PasswordPolicyError):
        Wallet.create(path, PASSWORD, NEW_PASSWORD, {})


def test_generic_wallet_payload_cannot_inject_dispatch_intent(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    with pytest.raises(InvalidContainer):
        Wallet.create(
            path,
            PASSWORD,
            PASSWORD,
            {"rotation_dispatch_intent": {}},
        )
    assert not path.exists()


def test_initialization_does_not_overwrite_an_existing_container(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    Wallet.create(path, PASSWORD, PASSWORD, {"owner": "alice"})
    before = path.read_bytes()
    with pytest.raises(StorageFailure):
        Wallet.create(path, PASSWORD, PASSWORD, {"owner": "bob"})
    assert path.read_bytes() == before
    assert Wallet.open(path, PASSWORD).is_unlocked


def test_export_container_returns_exact_encrypted_bytes(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    public_key = wallet.public_key
    wallet.lock()

    raw = json.dumps(json.loads(path.read_bytes()), indent=2).encode("utf-8")
    path.write_bytes(raw)
    wallet = Wallet.open(path, PASSWORD)
    exported = wallet.export_container()

    assert exported == raw
    assert b"private_seed" not in exported
    assert wallet.public_key == public_key
    wallet.lock()
    with pytest.raises(WalletLockedError):
        wallet.export_container()


def test_import_container_preserves_exact_ciphertext_and_signing_identity(tmp_path: Path):
    source = tmp_path / "source.dw"
    destination = tmp_path / "imported.dw"
    original = Wallet.create_with_generated_key(source, PASSWORD, PASSWORD)
    original_public_key = original.public_key
    original_bytes = original.export_container()

    imported = Wallet.import_container(destination, original_bytes, PASSWORD)

    assert destination.read_bytes() == original_bytes
    assert source.read_bytes() == original_bytes
    assert list(tmp_path.glob(".decent-wallet-*")) == []
    assert imported.is_unlocked
    assert imported.public_key == original_public_key
    signer = imported.create_signer()
    assert signer.public_key == original_public_key
    signer.invalidate()
    assert destination.stat().st_mode & 0o777 == 0o600
    original.lock()
    imported.lock()


def test_import_container_rejects_bad_password_and_malformed_bytes(tmp_path: Path):
    source = tmp_path / "source.dw"
    destination = tmp_path / "imported.dw"
    original = Wallet.create_with_generated_key(source, PASSWORD, PASSWORD)
    container = original.export_container()
    original.lock()

    with pytest.raises(UnlockFailed):
        Wallet.import_container(destination, container, "wrong password that is long")
    assert not destination.exists()

    with pytest.raises(InvalidContainer):
        Wallet.import_container(destination, b"not a wallet container", PASSWORD)
    assert not destination.exists()


def test_import_container_never_overwrites_initialized_wallet(tmp_path: Path):
    source = tmp_path / "source.dw"
    destination = tmp_path / "destination.dw"
    original = Wallet.create_with_generated_key(source, PASSWORD, PASSWORD)
    imported_bytes = original.export_container()
    original.lock()

    destination_wallet = Wallet.create(destination, PASSWORD, PASSWORD, {"owner": "existing"})
    before = destination.read_bytes()
    destination_wallet.lock()

    with pytest.raises(StorageFailure):
        Wallet.import_container(destination, imported_bytes, PASSWORD)

    assert destination.read_bytes() == before
    reopened = Wallet.open(destination, PASSWORD)
    assert reopened.is_unlocked
    reopened.lock()


def test_import_container_rejects_unsupported_version_without_creating_target(tmp_path: Path):
    source = tmp_path / "source.dw"
    destination = tmp_path / "imported.dw"
    original = Wallet.create(source, PASSWORD, PASSWORD, {"owner": "alice"})
    envelope = json.loads(original.export_container())
    original.lock()
    envelope["version"] = 1

    with pytest.raises(UnsupportedFormat):
        Wallet.import_container(
            destination,
            json.dumps(envelope, separators=(",", ":")).encode("utf-8"),
            PASSWORD,
        )
    assert not destination.exists()


def test_export_container_rejects_external_replacement(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create(path, PASSWORD, PASSWORD, {"owner": "alice"})
    other_path = tmp_path / "other.dw"
    other = Wallet.create(other_path, PASSWORD, PASSWORD, {"owner": "bob"})
    path.write_bytes(other.export_container())

    with pytest.raises(InvalidContainer):
        wallet.export_container()

    wallet.lock()
    other.lock()


def test_import_directory_sync_failure_removes_new_container_and_temp_file(
    tmp_path: Path, monkeypatch
):
    source = tmp_path / "source.dw"
    destination = tmp_path / "imported.dw"
    original = Wallet.create(source, PASSWORD, PASSWORD, {"owner": "alice"})
    container = original.export_container()
    original.lock()

    def fail_directory_sync(_directory):
        raise OSError("simulated directory sync failure")

    monkeypatch.setattr(container_module, "_fsync_directory", fail_directory_sync)
    with pytest.raises(StorageFailure):
        Wallet.import_container(destination, container, PASSWORD)

    assert not destination.exists()
    assert list(tmp_path.glob(".decent-wallet-*")) == []


def test_import_staging_unlink_failure_rolls_back_linked_destination(
    tmp_path: Path, monkeypatch
):
    source = tmp_path / "source.dw"
    destination = tmp_path / "imported.dw"
    original = Wallet.create(source, PASSWORD, PASSWORD, {"owner": "alice"})
    container = original.export_container()
    original.lock()

    real_unlink = Path.unlink
    failed_once = False

    def fail_once_for_staging(path, *args, **kwargs):
        nonlocal failed_once
        if path.name.startswith(".decent-wallet-") and not failed_once:
            failed_once = True
            raise OSError("simulated staging unlink failure")
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", fail_once_for_staging)
    with pytest.raises(StorageFailure):
        Wallet.import_container(destination, container, PASSWORD)

    assert failed_once
    assert not destination.exists()
    assert list(tmp_path.glob(".decent-wallet-*")) == []


def test_pending_key_rotation_persists_encrypted_successor_without_changing_active_key(
    tmp_path: Path,
):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    active_public_key = wallet.public_key

    active_signer = wallet.create_signer()
    pending_public_key = wallet.prepare_signing_key_rotation()

    assert pending_public_key != active_public_key
    assert wallet.pending_signing_public_key == pending_public_key
    assert wallet.public_key == active_public_key
    assert not active_signer.is_active
    assert wallet.create_signer().public_key == active_public_key
    raw = wallet.export_container()
    assert b"pending_private_seed" not in raw
    assert b"pending_public_key" not in raw
    assert base64.b64encode(pending_public_key) not in raw
    wallet.lock()

    reopened = Wallet.open(path, PASSWORD)
    assert reopened.public_key == active_public_key
    assert reopened.pending_signing_public_key == pending_public_key
    reopened.lock()


def test_pending_key_rotation_is_idempotent_until_cancelled(tmp_path: Path):
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)

    first = wallet.prepare_signing_key_rotation()
    second = wallet.prepare_signing_key_rotation()

    assert second == first
    assert wallet.pending_signing_public_key == first
    wallet.lock()


def test_cancel_pending_key_rotation_preserves_active_key_across_reopen(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    active_public_key = wallet.public_key
    pending_public_key = wallet.prepare_signing_key_rotation()
    assert pending_public_key != active_public_key
    wallet.lock()

    reopened = Wallet.open(path, PASSWORD)
    reopened.cancel_signing_key_rotation()
    assert reopened.pending_signing_public_key is None
    assert reopened.public_key == active_public_key
    reopened.lock()

    reopened = Wallet.open(path, PASSWORD)
    assert reopened.pending_signing_public_key is None
    assert reopened.public_key == active_public_key
    reopened.lock()


def test_failed_pending_key_rotation_write_leaves_no_staged_key(tmp_path: Path, monkeypatch):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    active_public_key = wallet.public_key
    before = path.read_bytes()

    def fail(_path, _data, *, replace=True):
        raise StorageFailure()

    monkeypatch.setattr(container_module, "_atomic_write", fail)
    with pytest.raises(StorageFailure):
        wallet.prepare_signing_key_rotation()

    assert path.read_bytes() == before
    assert wallet.pending_signing_public_key is None
    assert wallet.public_key == active_public_key
    wallet.lock()


def test_public_payload_apis_reject_internal_rotation_material(tmp_path: Path):
    with pytest.raises(InvalidContainer):
        Wallet.create(
            tmp_path / "create.dw",
            PASSWORD,
            PASSWORD,
            {"pending_private_seed": bytes(32)},
        )

    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    with pytest.raises(InvalidContainer):
        wallet.update_payload({"pending_public_key": bytes(32)})
    with pytest.raises(InvalidContainer):
        wallet.update_payload({"pending_private_seed": bytes(32)})
    wallet.lock()


def test_payload_update_and_import_preserve_pending_key_rotation(tmp_path: Path):
    source = tmp_path / "source.dw"
    destination = tmp_path / "imported.dw"
    wallet = Wallet.create_with_generated_key(source, PASSWORD, PASSWORD)
    active_public_key = wallet.public_key
    pending_public_key = wallet.prepare_signing_key_rotation()

    wallet.update_payload({"owner": "alice"})
    exported = wallet.export_container()
    wallet.lock()

    imported = Wallet.import_container(destination, exported, PASSWORD)
    assert destination.read_bytes() == exported
    assert imported.public_key == active_public_key
    assert imported.pending_signing_public_key == pending_public_key
    imported.lock()


def test_failed_cancel_write_keeps_pending_key_rotation(tmp_path: Path, monkeypatch):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    active_public_key = wallet.public_key
    pending_public_key = wallet.prepare_signing_key_rotation()
    before = path.read_bytes()

    def fail(_path, _data, *, replace=True):
        raise StorageFailure()

    monkeypatch.setattr(container_module, "_atomic_write", fail)
    with pytest.raises(StorageFailure):
        wallet.cancel_signing_key_rotation()

    assert path.read_bytes() == before
    assert wallet.pending_signing_public_key == pending_public_key
    assert wallet.public_key == active_public_key
    wallet.lock()


def test_pending_key_rotation_rejects_csrng_provider_replacement(
    tmp_path: Path, monkeypatch
):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    before = path.read_bytes()
    calls: list[int] = []

    def replacement(size: int) -> bytes:
        calls.append(size)
        return b"x" * size

    monkeypatch.setattr(signer_module.secrets, "token_bytes", replacement)
    with pytest.raises(KeyGenerationError):
        wallet.prepare_signing_key_rotation()

    assert calls == []
    assert path.read_bytes() == before
    assert wallet.pending_signing_public_key is None
    wallet.lock()


def test_concurrent_rotation_preparation_persists_one_pending_key(
    tmp_path: Path, monkeypatch
):
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    generation_barrier = Barrier(2)
    generated_seeds: list[bytearray] = []

    def synchronized_seed() -> bytearray:
        seed = bytearray(bytes([len(generated_seeds) + 1]) * 32)
        generated_seeds.append(seed)
        try:
            generation_barrier.wait(timeout=1)
        except BrokenBarrierError:
            pass
        return seed

    monkeypatch.setattr(signer_module, "_generate_seed", synchronized_seed)
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(wallet.prepare_signing_key_rotation)
            for _ in range(2)
        ]
        results = [future.result(timeout=5) for future in futures]

    assert len(generated_seeds) == 1
    assert results[0] == results[1]
    assert wallet.pending_signing_public_key == results[0]
    wallet.lock()

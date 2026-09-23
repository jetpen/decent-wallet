import json
from pathlib import Path

import pytest

from decent_wallet import (
    InvalidContainer,
    PasswordPolicyError,
    StorageFailure,
    UnlockFailed,
    UnsupportedFormat,
    Wallet,
    WalletLockedError,
)
import decent_wallet.container as container_module


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
    assert envelope["version"] == 1
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
    envelope["version"] = 99
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
    envelope["version"] = 2

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

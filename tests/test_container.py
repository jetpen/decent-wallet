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

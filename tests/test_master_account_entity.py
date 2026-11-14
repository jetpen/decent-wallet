from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from decent_wallet import StorageFailure, Wallet, WalletLockedError
import decent_wallet.container as container_module


PASSWORD = "correct horse battery staple"
ENTITY = {
    "display_name": "Ada Lovelace",
    "locale": "en-GB",
    "preferences": {"newsletter": False, "topics": ["math", "computing"]},
}


def test_master_account_entity_source_ownership_stays_in_wallet_container_and_core():
    repo = Path(__file__).resolve().parents[1]
    production_roots = (
        repo / "src" / "decent_wallet",
        repo / "platforms" / "android-wallet" / "src" / "main",
        repo / "apps" / "android-wallet-client" / "src" / "main",
    )
    entity_markers = ("master_account_entity", "MasterAccountEntity", "Master Account Entity")
    references = set()
    for root in production_roots:
        for source in root.rglob("*"):
            if source.suffix not in {".py", ".kt", ".java"}:
                continue
            text = source.read_text(encoding="utf-8")
            if any(marker.lower() in text.lower() for marker in entity_markers):
                references.add(source.relative_to(repo).as_posix())

    # These are the only production owners of the entity state/API. This source
    # inventory is bounded to checked-in Python and Android production sources;
    # it does not prove absence of indirect calls or runtime behavior.
    assert references == {
        "src/decent_wallet/container.py",
        "platforms/android-wallet/src/main/kotlin/org/decentwallet/wallet/android/AndroidWallet.kt",
    }


def test_master_account_entity_is_local_encrypted_v2_state_and_survives_reopen_import(tmp_path: Path):
    source = tmp_path / "source.dw"
    imported_path = tmp_path / "imported.dw"
    wallet = Wallet.create_with_generated_key(source, PASSWORD, PASSWORD)

    assert callable(getattr(wallet, "set_master_account_entity", None)), "wallet is missing the local entity write interface"
    assert callable(getattr(wallet, "get_master_account_entity", None)), "wallet is missing the local entity read interface"
    assert wallet.get_master_account_entity() == {}

    wallet.set_master_account_entity(ENTITY)
    returned = wallet.get_master_account_entity()
    assert returned == ENTITY
    returned["preferences"]["topics"].append("mutated by caller")
    assert wallet.get_master_account_entity() == ENTITY

    raw = wallet.export_container()
    outer = json.loads(raw)
    assert set(outer) == {"format", "version", "kdf", "wrap", "payload"}
    assert outer["format"] == "decent-wallet"
    assert outer["version"] == 2
    assert set(outer["kdf"]) == {"algorithm", "memory_kib", "time_cost", "parallelism", "salt"}
    assert set(outer["wrap"]) == {"algorithm", "nonce", "ciphertext", "tag"}
    assert set(outer["payload"]) == {"algorithm", "nonce", "ciphertext", "tag"}
    # Entity data is available only through the authenticated payload after unlock.
    # Ciphertext is opaque; do not infer privacy from plaintext substring absence.
    import inspect
    getter_signature = inspect.signature(Wallet.get_master_account_entity)
    setter_signature = inspect.signature(Wallet.set_master_account_entity)
    assert tuple(getter_signature.parameters) == ("self",)
    assert tuple(setter_signature.parameters) == ("self", "entity")
    assert all(
        parameter.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD
        and parameter.default is inspect.Parameter.empty
        for signature in (getter_signature, setter_signature)
        for parameter in signature.parameters.values()
    )
    public_master_api = {name for name in dir(Wallet) if "master" in name.casefold()}
    assert public_master_api == {"get_master_account_entity", "set_master_account_entity"}
    persisted_before_lock = source.read_bytes()
    wallet.lock()
    with pytest.raises(WalletLockedError):
        wallet.get_master_account_entity()
    with pytest.raises(WalletLockedError):
        wallet.set_master_account_entity({"display_name": "locked-write-marker"})
    assert source.read_bytes() == persisted_before_lock

    reopened = Wallet.open(source, PASSWORD)
    assert reopened.get_master_account_entity() == ENTITY
    reopened.set_master_account_entity({"display_name": "Ada Byron", "locale": "en"})
    exported = reopened.export_container()
    reopened.lock()

    imported = Wallet.import_container(imported_path, exported, PASSWORD)
    assert imported.get_master_account_entity() == {"display_name": "Ada Byron", "locale": "en"}
    assert imported_path.read_bytes() == exported
    imported.lock()


def test_failed_master_account_entity_write_preserves_previous_encrypted_state(tmp_path: Path, monkeypatch):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    wallet.set_master_account_entity(ENTITY)
    before = path.read_bytes()

    def fail(_path, _data, *, replace=True):
        raise StorageFailure()

    monkeypatch.setattr(container_module, "_atomic_write", fail)
    with pytest.raises(StorageFailure):
        wallet.set_master_account_entity({"display_name": "uncommitted"})

    assert path.read_bytes() == before
    assert wallet.get_master_account_entity() == ENTITY
    wallet.lock()


def test_generic_payload_updates_preserve_entity_and_cannot_replace_it(tmp_path: Path):
    wallet = Wallet.create_with_generated_key(tmp_path / "wallet.dw", PASSWORD, PASSWORD)
    wallet.set_master_account_entity(ENTITY)

    wallet.update_payload({"owner_note": "ordinary wallet metadata"})
    assert wallet.get_master_account_entity() == ENTITY
    with pytest.raises(container_module.InvalidContainer):
        wallet.update_payload({"master_account_entity": {"display_name": "injected"}})
    assert wallet.get_master_account_entity() == ENTITY
    wallet.lock()


def test_entity_values_must_be_json_compatible_and_rejected_updates_are_atomic(tmp_path: Path):
    path = tmp_path / "wallet.dw"
    wallet = Wallet.create_with_generated_key(path, PASSWORD, PASSWORD)
    wallet.set_master_account_entity(ENTITY)
    before = path.read_bytes()
    recursive: list[object] = []
    recursive.append(recursive)
    too_deep: object = "value"
    for _ in range(65):
        too_deep = [too_deep]
    invalid_values = (
        {1: "numeric key"},
        {"raw_bytes": b"not JSON"},
        {"float": 1.5},
        {"surrogate": "\ud800"},
        {"recursive": recursive},
        {"deep": too_deep},
    )
    for value in invalid_values:
        with pytest.raises(container_module.InvalidContainer):
            wallet.set_master_account_entity(cast(Any, value))
        assert path.read_bytes() == before
        assert wallet.get_master_account_entity() == ENTITY
    wallet.lock()


def test_create_copies_initial_entity_and_rejects_invalid_shape(tmp_path: Path):
    initial = {"display_name": "Ada", "nested": {"enabled": True}}
    wallet = Wallet.create(
        tmp_path / "wallet.dw", PASSWORD, PASSWORD,
        {"master_account_entity": initial},
    )
    initial["nested"]["enabled"] = False
    assert wallet.get_master_account_entity() == {
        "display_name": "Ada", "nested": {"enabled": True}
    }
    wallet.lock()

    with pytest.raises(container_module.InvalidContainer):
        Wallet.create(
            tmp_path / "invalid.dw", PASSWORD, PASSWORD,
            {"master_account_entity": ["not an object"]},
        )

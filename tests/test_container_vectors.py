import base64
import json
from pathlib import Path
from typing import Any

import pytest

from decent_wallet import UnlockFailed, UnsupportedFormat, Wallet
import decent_wallet.container as container_module


VECTOR_PATH = Path(__file__).parent / "vectors" / "wallet-container-v2.json"


def _read_vector() -> dict[str, Any]:
    return json.loads(VECTOR_PATH.read_text(encoding="utf-8"))


def _decode_fixture_value(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"$bytes_hex"}:
            return bytes.fromhex(value["$bytes_hex"])
        return {key: _decode_fixture_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_decode_fixture_value(item) for item in value]
    return value


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_v2_known_answer_matches_kdf_aad_payload_and_envelope(monkeypatch):
    vector = _read_vector()
    _require(vector.get("schema") == "decent-wallet-container-v2-kat", "vector schema mismatch")
    _require(vector.get("schema_version") == 1, "vector schema version mismatch")
    _require(vector.get("test_only") is True, "fixture is not marked test-only")
    notice = vector.get("notice")
    _require(
        isinstance(notice, str)
        and "public synthetic" in notice
        and "Never use with a real wallet" in notice,
        "fixture lacks its public synthetic test-only warning",
    )

    inputs = vector["input"]
    expected = vector["expected"]
    password = inputs["password"]
    salt = bytes.fromhex(inputs["salt_hex"])
    dek = bytes.fromhex(inputs["dek_hex"])
    wrap_nonce = bytes.fromhex(inputs["wrap_nonce_hex"])
    payload_nonce = bytes.fromhex(inputs["payload_nonce_hex"])
    payload = _decode_fixture_value(inputs["payload"])
    _require(isinstance(payload, dict), "fixture payload is not a map")

    kdf = container_module._kdf_header(salt)
    kek = container_module._derive_kek(password, salt)
    try:
        _require(kek.hex() == expected["kek_hex"], "Argon2id output mismatch")
        wrap_aad = container_module._wrap_aad(kdf)
        payload_info = {
            "algorithm": "xchacha20-poly1305",
            "nonce": base64.b64encode(payload_nonce).decode("ascii"),
        }
        payload_aad = container_module._payload_aad(payload_info)
        _require(
            wrap_aad.hex() == expected["wrap_aad_utf8_hex"],
            "DEK-wrap AAD mismatch",
        )
        _require(
            payload_aad.hex() == expected["payload_aad_utf8_hex"],
            "payload AAD mismatch",
        )
    finally:
        container_module._wipe(kek)

    typed_payload = container_module._canonical_json(
        container_module._encode_value(payload)
    )
    _require(
        typed_payload.hex() == expected["typed_payload_json_utf8_hex"],
        "typed payload encoding mismatch",
    )

    nonces = iter((wrap_nonce, payload_nonce))

    def fixed_nonce(length: int) -> bytes:
        nonce = next(nonces)
        _require(len(nonce) == length, "fixture nonce length mismatch")
        return nonce

    monkeypatch.setattr(container_module.secrets, "token_bytes", fixed_nonce)
    envelope = container_module._build_v2_envelope(password, dek, kdf, payload)
    envelope_bytes = container_module._canonical_json(envelope)
    _require(
        envelope_bytes.hex() == expected["container_json_utf8_hex"],
        "canonical container output mismatch",
    )
    _require(envelope == expected["container"], "container fields differ from vector")
    _require(
        envelope["wrap"]["ciphertext"] == expected["wrap_ciphertext_base64"],
        "wrapped DEK ciphertext mismatch",
    )
    _require(envelope["wrap"]["tag"] == expected["wrap_tag_base64"], "wrapped DEK tag mismatch")
    _require(
        envelope["payload"]["ciphertext"] == expected["payload_ciphertext_base64"],
        "payload ciphertext mismatch",
    )
    _require(
        envelope["payload"]["tag"] == expected["payload_tag_base64"],
        "payload tag mismatch",
    )
    _require(envelope_bytes == bytes.fromhex(expected["container_json_utf8_hex"]), "envelope bytes mismatch")


def test_v2_known_answer_opens_with_expected_wallet_semantics(tmp_path: Path):
    vector = _read_vector()
    inputs = vector["input"]
    expected = vector["expected"]
    container_bytes = bytes.fromhex(expected["container_json_utf8_hex"])
    source = tmp_path / "wallet.dw"
    source.write_bytes(container_bytes)

    wallet = Wallet.open(source, inputs["password"])
    try:
        _require(wallet.is_unlocked, "known-answer wallet did not unlock")
        _require(
            wallet.public_key.hex() == expected["public_key_hex"],
            "known-answer public key mismatch",
        )
        expected_payload = _decode_fixture_value(inputs["payload"])
        expected_payload.pop("private_seed")
        _require(wallet._payload == expected_payload, "decoded wallet payload mismatch")
    finally:
        wallet.lock()


def test_v2_known_answer_rejects_tampering_and_downgrade(tmp_path: Path):
    vector = _read_vector()
    inputs = vector["input"]
    expected = vector["expected"]
    envelope = json.loads(bytes.fromhex(expected["container_json_utf8_hex"]))

    tampered = dict(envelope)
    tampered["payload"] = dict(envelope["payload"])
    nonce = base64.b64decode(tampered["payload"]["nonce"])
    tampered["payload"]["nonce"] = base64.b64encode(
        bytes([nonce[0] ^ 1]) + nonce[1:]
    ).decode("ascii")
    tampered_path = tmp_path / "tampered.dw"
    tampered_path.write_bytes(container_module._canonical_json(tampered))
    with pytest.raises(UnlockFailed):
        Wallet.open(tampered_path, inputs["password"])

    downgraded = dict(envelope)
    downgraded["version"] = 1
    downgraded_bytes = container_module._canonical_json(downgraded)
    downgraded_path = tmp_path / "downgraded.dw"
    downgraded_path.write_bytes(downgraded_bytes)
    with pytest.raises(UnsupportedFormat):
        Wallet.open(downgraded_path, inputs["password"])

    parsed_as_v1 = container_module._parse_container(
        downgraded_bytes, expected_version=1
    )
    with pytest.raises(UnlockFailed):
        container_module._unlock_envelope(parsed_as_v1, inputs["password"], version=1)

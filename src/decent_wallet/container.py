"""Versioned encrypted wallet storage with a small, deep interface.

The module keeps wallet content inside authenticated ciphertext and exposes
only public metadata. Secret lifetime in a managed runtime is best effort:
mutable buffers are wiped where practical, while callers must not retain or
copy secret-bearing values supplied to the wallet.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import secrets
import stat
import sys
import tempfile
import time
import weakref
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from threading import Lock, RLock
from pathlib import Path
from typing import TYPE_CHECKING, Any

from argon2 import Type
from argon2.low_level import hash_secret_raw
from Crypto.Cipher import ChaCha20_Poly1305

if TYPE_CHECKING:
    from .identity import (
        IdentityBundle,
        IdentityDraft,
        RotationConfirmation,
        RotationDispatchRejection,
        RotationPublication,
    )


CURRENT_FORMAT_VERSION = 2
_FORMAT = "decent-wallet"
_KDF_MEMORY_KIB = 64 * 1024
_KDF_TIME_COST = 3
_KDF_PARALLELISM = 4
_ARGON2_VERSION = 19
_KEY_LENGTH = 32
_SALT_LENGTH = 16
_NONCE_LENGTH = 24
_TAG_LENGTH = 16
_MAX_CONTAINER_BYTES = 16 * 1024 * 1024
_MIN_PASSWORD_LENGTH = 16
_MAX_AUTH_DELAY_SECONDS = 0.5
_AUTH_FAILURES: dict[str, int] = {}
_AUTH_FAILURES_LOCK = Lock()
_WALLET_SECRETS: dict[object, bytearray] = {}
_PENDING_WALLET_SECRETS: dict[object, bytearray] = {}
_PENDING_PRIVATE_SEED = "pending_private_seed"
_PENDING_PUBLIC_KEY = "pending_public_key"
_ROTATION_DISPATCH_INTENT = "rotation_dispatch_intent"
_MASTER_ACCOUNT_ENTITY = "master_account_entity"
_PENDING_ACCOUNT_DISCLOSURE = "pending_account_disclosure_v1"
_DISCLOSURE_CLAIM_KEYS = {
    "urn:decent:account:v1:given_name": "given_name",
    "urn:decent:account:v1:family_name": "family_name",
    "urn:decent:account:v1:email": "email",
    "urn:decent:account:v1:phone": "phone",
    "urn:decent:account:v1:locale": "locale",
}
_SIGNING_FIELDS = {
    "private_seed",
    "public_key",
    _PENDING_PRIVATE_SEED,
    _PENDING_PUBLIC_KEY,
    _ROTATION_DISPATCH_INTENT,
}


class WalletError(Exception):
    """Base class for stable, value-free wallet failures."""

    code = "wallet-error"
    message = "wallet operation failed"

    def __init__(self) -> None:
        super().__init__(self.message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


class WalletLockedError(WalletError):
    code = "wallet-locked"
    message = "wallet is locked"


class PasswordPolicyError(WalletError):
    code = "password-policy"
    message = "password policy rejected"


class UnlockFailed(WalletError):
    code = "unlock-failed"
    message = "wallet unlock failed"


class InvalidContainer(WalletError):
    code = "invalid-container"
    message = "wallet container is invalid"


class UnsupportedFormat(WalletError):
    code = "unsupported-format"
    message = "wallet format is unsupported"


class StorageFailure(WalletError):
    code = "storage-failure"
    message = "wallet storage operation failed"


class StorageOutcomeUnknown(WalletError):
    code = "storage-outcome-unknown"
    message = "wallet storage outcome is unknown"


class RotationInProgress(WalletError):
    code = "rotation-in-progress"
    message = "signing-key rotation dispatch is unresolved"


def valid_registry_environment(value: Any) -> bool:
    """Exact public realm ID: valid Unicode, 1..256 UTF-16 units, not White_Space-only."""
    if type(value) is not str:
        return False
    try:
        length = len(value.encode("utf-16-le")) // 2
    except UnicodeEncodeError:
        return False
    whitespace = "\t\n\v\f\r \u0085\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
    return 1 <= length <= 256 and any(c not in whitespace for c in value)


@dataclass(frozen=True, slots=True)
class RotationDispatchIntent:
    """Public, non-secret binding for a possibly dispatched owner-key rotation."""

    owner_name: bytes
    predecessor_owner_public_key: bytes
    successor_owner_public_key: bytes
    predecessor_state_hash: bytes
    sequence: int
    envelope_hash: bytes
    environment: str | None = None

    def __post_init__(self) -> None:
        if self.environment is not None and not valid_registry_environment(self.environment):
            raise InvalidContainer()
        if type(self.owner_name) is not bytes or not 1 <= len(self.owner_name) <= 1024 * 1024:
            raise InvalidContainer()
        try:
            self.owner_name.decode("utf-8")
        except UnicodeDecodeError:
            raise InvalidContainer() from None
        for value in (
            self.predecessor_owner_public_key,
            self.successor_owner_public_key,
            self.predecessor_state_hash,
            self.envelope_hash,
        ):
            if type(value) is not bytes or len(value) != _KEY_LENGTH:
                raise InvalidContainer()
        if type(self.sequence) is not int or self.sequence < 1:
            raise InvalidContainer()

    def _to_payload(self) -> dict[str, Any]:
        value = {
            "owner_name": self.owner_name,
            "predecessor_owner_public_key": self.predecessor_owner_public_key,
            "successor_owner_public_key": self.successor_owner_public_key,
            "predecessor_state_hash": self.predecessor_state_hash,
            "sequence": self.sequence,
            "envelope_hash": self.envelope_hash,
        }
        if self.environment is not None:
            value["environment"] = self.environment
        return value

    @classmethod
    def _from_payload(cls, value: Any) -> "RotationDispatchIntent":
        keys = {
            "owner_name",
            "predecessor_owner_public_key",
            "successor_owner_public_key",
            "predecessor_state_hash",
            "sequence",
            "envelope_hash",
        }
        if not isinstance(value, dict) or set(value) not in (keys, keys | {"environment"}):
            raise InvalidContainer()
        if "environment" in value and not valid_registry_environment(value["environment"]):
            raise InvalidContainer()
        try:
            return cls(**value)
        except (TypeError, ValueError):
            raise InvalidContainer() from None


_ROTATION_PERMIT_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class RotationDispatchPermit:
    """Ephemeral proof that the caller's exact dispatch intent was durably latched."""

    intent: RotationDispatchIntent
    _seal: object

    def __init__(self, *, intent: RotationDispatchIntent, seal: object) -> None:
        if seal is not _ROTATION_PERMIT_SEAL:
            raise InvalidContainer()
        object.__setattr__(self, "intent", intent)
        object.__setattr__(self, "_seal", seal)

    def _authentic(self) -> bool:
        return (
            getattr(self, "_seal", None) is _ROTATION_PERMIT_SEAL
            and isinstance(getattr(self, "intent", None), RotationDispatchIntent)
        )

    def __repr__(self) -> str:
        return "RotationDispatchPermit(latched=True)"

    def __reduce_ex__(self, _protocol: Any) -> Any:
        raise TypeError("rotation dispatch permits are process-local")


def _wipe(buffer: bytearray | None) -> None:
    if buffer is not None:
        buffer[:] = b"\x00" * len(buffer)


def _validate_seed_public_key_pair(seed: Any, public_key: Any) -> None:
    from .signer import _public_key_from_seed

    if type(seed) is not bytes or len(seed) != _KEY_LENGTH:
        raise InvalidContainer()
    if type(public_key) is not bytes or len(public_key) != _KEY_LENGTH:
        raise InvalidContainer()
    try:
        derived_public_key = _public_key_from_seed(seed)
    except Exception:
        raise InvalidContainer() from None
    if public_key != derived_public_key:
        raise InvalidContainer()


def _public_key_for_secret(seed: bytearray | None, stored_public_key: Any) -> bytes:
    from .signer import SignerUnavailable, _public_key_from_seed

    if type(seed) is not bytearray or len(seed) != _KEY_LENGTH:
        raise SignerUnavailable()
    if type(stored_public_key) is not bytes or len(stored_public_key) != _KEY_LENGTH:
        raise SignerUnavailable()
    try:
        derived_public_key = _public_key_from_seed(bytes(seed))
    except Exception:
        raise SignerUnavailable() from None
    if stored_public_key != derived_public_key:
        raise SignerUnavailable()
    return derived_public_key


def _finalize_wallet_secret(handle: object) -> None:
    seed = _WALLET_SECRETS.pop(handle, None)
    if seed is not None:
        _wipe(seed)
    pending_seed = _PENDING_WALLET_SECRETS.pop(handle, None)
    if pending_seed is not None:
        _wipe(pending_seed)


def _b64_encode(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64_decode(value: Any, expected_length: int | None = None) -> bytes:
    if not isinstance(value, str):
        raise InvalidContainer()
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError):
        raise InvalidContainer() from None
    if expected_length is not None and len(decoded) != expected_length:
        raise InvalidContainer()
    return decoded


def _canonical_json(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise InvalidContainer() from None


def _encode_value(value: Any) -> dict[str, Any]:
    """Encode payload values with explicit types and no executable decoding."""
    if value is None:
        return {"t": "null"}
    if isinstance(value, bool):
        return {"t": "bool", "v": value}
    if isinstance(value, str):
        return {"t": "str", "v": value}
    if isinstance(value, int):
        return {"t": "int", "v": value}
    if isinstance(value, bytes):
        return {"t": "bytes", "v": _b64_encode(value)}
    if isinstance(value, list):
        return {"t": "list", "v": [_encode_value(item) for item in value]}
    if isinstance(value, Mapping):
        items: list[list[Any]] = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidContainer()
            items.append([key, _encode_value(item)])
        items.sort(key=lambda pair: pair[0])
        return {"t": "map", "v": items}
    raise InvalidContainer()


def _copy_master_account_entity(value: Any) -> dict[str, Any]:
    """Copy schema-open JSON values into the existing encrypted wallet payload."""
    active: set[int] = set()

    def copy_json(item: Any, depth: int) -> Any:
        if depth > 64:
            raise InvalidContainer()
        if item is None or type(item) in (bool, int):
            return item
        if type(item) is str:
            try:
                item.encode("utf-8")
            except UnicodeEncodeError:
                raise InvalidContainer() from None
            return item
        if isinstance(item, list):
            marker = id(item)
            if marker in active:
                raise InvalidContainer()
            active.add(marker)
            try:
                return [copy_json(child, depth + 1) for child in item]
            finally:
                active.remove(marker)
        if isinstance(item, Mapping):
            marker = id(item)
            if marker in active:
                raise InvalidContainer()
            active.add(marker)
            try:
                result: dict[str, Any] = {}
                for key, child in item.items():
                    if type(key) is not str:
                        raise InvalidContainer()
                    try:
                        key.encode("utf-8")
                    except UnicodeEncodeError:
                        raise InvalidContainer() from None
                    result[key] = copy_json(child, depth + 1)
                return result
            finally:
                active.remove(marker)
        raise InvalidContainer()

    if not isinstance(value, Mapping):
        raise InvalidContainer()
    try:
        copied = copy_json(value, 0)
    except RecursionError:
        raise InvalidContainer() from None
    if type(copied) is not dict:
        raise InvalidContainer()
    return copied


def _decode_value(value: Any) -> Any:
    if not isinstance(value, dict) or set(value) - {"t", "v"} or "t" not in value:
        raise InvalidContainer()
    kind = value["t"]
    if kind == "null":
        if set(value) != {"t"}:
            raise InvalidContainer()
        return None
    if "v" not in value:
        raise InvalidContainer()
    raw = value["v"]
    if kind == "bool" and type(raw) is bool:
        return raw
    if kind == "str" and isinstance(raw, str):
        return raw
    if kind == "int" and type(raw) is int:
        return raw
    if kind == "bytes":
        return _b64_decode(raw)
    if kind == "list" and isinstance(raw, list):
        return [_decode_value(item) for item in raw]
    if kind == "map" and isinstance(raw, list):
        result: dict[str, Any] = {}
        previous: str | None = None
        for item in raw:
            if not isinstance(item, list) or len(item) != 2 or not isinstance(item[0], str):
                raise InvalidContainer()
            key = item[0]
            if previous is not None and key <= previous:
                raise InvalidContainer()
            previous = key
            result[key] = _decode_value(item[1])
        return result
    raise InvalidContainer()


def _validate_password(password: str, confirmation: str | None = None) -> None:
    if not isinstance(password, str) or len(password) < _MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError()
    if confirmation is not None and (not isinstance(confirmation, str) or password != confirmation):
        raise PasswordPolicyError()


def _record_unlock_failure(path: Path) -> None:
    key = os.fspath(path)
    with _AUTH_FAILURES_LOCK:
        count = _AUTH_FAILURES.get(key, 0) + 1
        _AUTH_FAILURES[key] = min(count, 32)
    delay = min(0.05 * (2 ** min(count - 1, 4)), _MAX_AUTH_DELAY_SECONDS)
    time.sleep(delay)


def _clear_unlock_failures(path: Path) -> None:
    with _AUTH_FAILURES_LOCK:
        _AUTH_FAILURES.pop(os.fspath(path), None)


def _derive_kek(password: str, salt: bytes) -> bytearray:
    try:
        password_bytes = bytearray(password.encode("utf-8"))
        try:
            derived = hash_secret_raw(
                secret=bytes(password_bytes),
                salt=salt,
                time_cost=_KDF_TIME_COST,
                memory_cost=_KDF_MEMORY_KIB,
                parallelism=_KDF_PARALLELISM,
                hash_len=_KEY_LENGTH,
                type=Type.ID,
                version=_ARGON2_VERSION,
            )
        finally:
            _wipe(password_bytes)
    except Exception:
        raise UnlockFailed() from None
    return bytearray(derived)


def _kdf_header(salt: bytes) -> dict[str, Any]:
    return {
        "algorithm": "argon2id",
        "memory_kib": _KDF_MEMORY_KIB,
        "time_cost": _KDF_TIME_COST,
        "parallelism": _KDF_PARALLELISM,
        "salt": _b64_encode(salt),
    }


def _wrap_aad(
    kdf: dict[str, Any], *, version: int = CURRENT_FORMAT_VERSION
) -> bytes:
    return _canonical_json({"format": _FORMAT, "version": version, "kdf": kdf})


def _payload_aad(
    payload_info: dict[str, Any], *, version: int = CURRENT_FORMAT_VERSION
) -> bytes:
    return _canonical_json({"format": _FORMAT, "version": version, "payload": payload_info})


def _seal(key: bytes, plaintext: bytes, aad: bytes, nonce: bytes | None = None) -> tuple[dict[str, str], bytes, bytes]:
    nonce = secrets.token_bytes(_NONCE_LENGTH) if nonce is None else nonce
    try:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(aad)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    except Exception:
        raise StorageFailure() from None
    return {"algorithm": "xchacha20-poly1305", "nonce": _b64_encode(nonce)}, ciphertext, tag


def _open(key: bytes, ciphertext: bytes, tag: bytes, info: dict[str, Any], aad: bytes) -> bytes:
    if info.get("algorithm") != "xchacha20-poly1305":
        raise InvalidContainer()
    nonce = _b64_decode(info.get("nonce"), _NONCE_LENGTH)
    try:
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        cipher.update(aad)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except Exception:
        raise UnlockFailed() from None


def _make_payload(
    dek: bytes,
    payload: Mapping[str, Any],
    *,
    version: int = CURRENT_FORMAT_VERSION,
) -> tuple[dict[str, str], bytes, bytes]:
    encoded = _canonical_json(_encode_value(dict(payload)))
    info = {"algorithm": "xchacha20-poly1305", "nonce": _b64_encode(secrets.token_bytes(_NONCE_LENGTH))}
    nonce = _b64_decode(info["nonce"], _NONCE_LENGTH)
    try:
        cipher = ChaCha20_Poly1305.new(key=dek, nonce=nonce)
        cipher.update(_payload_aad(info, version=version))
        ciphertext, tag = cipher.encrypt_and_digest(encoded)
    except Exception:
        raise StorageFailure() from None
    return info, ciphertext, tag


def _wrap_dek(
    kek: bytes,
    dek: bytes,
    kdf: dict[str, Any],
    *,
    version: int = CURRENT_FORMAT_VERSION,
) -> tuple[dict[str, str], bytes, bytes]:
    return _seal(kek, dek, _wrap_aad(kdf, version=version))


def _fsync_directory(directory: Path) -> None:
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _stage_file(
    path: Path, data: bytes, *, replace: bool
) -> tuple[int, int]:
    directory = path.parent
    temporary_path: Path | None = None
    fd: int | None = None
    linked_target = False
    staged_identity: tuple[int, int] | None = None
    try:
        fd, name = tempfile.mkstemp(prefix=".decent-wallet-", dir=directory)
        temporary_path = Path(name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
            staged_stat = os.fstat(handle.fileno())
            staged_identity = (staged_stat.st_dev, staged_stat.st_ino)
        if staged_identity is None:
            raise StorageFailure()
        if replace:
            os.replace(temporary_path, path)
            temporary_path = None
        else:
            os.link(temporary_path, path)
            linked_target = True
            temporary_path.unlink()
            temporary_path = None
            linked_target = False
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if temporary_path is not None:
            if linked_target:
                # Roll back only our own no-replace link, not a pre-existing target.
                try:
                    if temporary_path.samefile(path):
                        path.unlink()
                except OSError:
                    pass
            try:
                temporary_path.unlink()
            except OSError:
                pass
    return staged_identity


def _restore_previous_after_failed_sync(
    path: Path,
    previous_data: bytes | None,
    installed_identity: tuple[int, int],
) -> bool:
    try:
        installed_stat = path.lstat()
    except FileNotFoundError:
        if previous_data is not None:
            return False
    except OSError:
        return False
    else:
        if (installed_stat.st_dev, installed_stat.st_ino) != installed_identity:
            return False
        try:
            if previous_data is None:
                path.unlink()
            else:
                _stage_file(path, previous_data, replace=True)
        except FileNotFoundError:
            if previous_data is not None:
                return False
        except (OSError, ValueError, WalletError):
            pass

    try:
        current_data = path.read_bytes()
    except FileNotFoundError:
        current_data = None
    except OSError:
        return False
    if current_data != previous_data:
        return False
    try:
        _fsync_directory(path.parent)
    except OSError:
        return False
    try:
        current_data = path.read_bytes()
    except FileNotFoundError:
        current_data = None
    except OSError:
        return False
    return current_data == previous_data


def _atomic_write(path: Path, data: bytes, *, replace: bool = True) -> None:
    previous_data: bytes | None = None
    if replace and path.exists():
        try:
            previous_data = path.read_bytes()
        except OSError:
            raise StorageFailure() from None
    try:
        installed_identity = _stage_file(path, data, replace=replace)
        try:
            _fsync_directory(path.parent)
        except OSError:
            if not _restore_previous_after_failed_sync(
                path, previous_data, installed_identity
            ):
                raise StorageOutcomeUnknown() from None
            raise StorageFailure() from None
    except WalletError:
        raise
    except (OSError, ValueError):
        raise StorageFailure() from None


def _write_verified(path: Path, data: bytes, *, replace: bool = True) -> None:
    """An acknowledgement alone cannot release a durable-state artifact."""
    # Preserve the established two-argument call shape for writer adapters and
    # fault-injection seams; only creation needs the explicit no-replace mode.
    if replace:
        _atomic_write(path, data)
    else:
        _atomic_write(path, data, replace=False)
    try:
        if _read(path) != data:
            raise StorageOutcomeUnknown()
    except Exception:
        raise StorageOutcomeUnknown() from None


def _serialize(envelope: dict[str, Any]) -> bytes:
    return _canonical_json(envelope)


def _parse_container(
    raw: bytes, *, expected_version: int = CURRENT_FORMAT_VERSION
) -> dict[str, Any]:
    if len(raw) > _MAX_CONTAINER_BYTES:
        raise InvalidContainer()
    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise InvalidContainer() from None
    if not isinstance(decoded, dict) or set(decoded) != {"format", "version", "kdf", "wrap", "payload"}:
        raise InvalidContainer()
    if decoded.get("format") != _FORMAT or type(decoded.get("version")) is not int:
        raise InvalidContainer()
    version = decoded["version"]
    if version != expected_version:
        raise UnsupportedFormat()
    kdf = decoded["kdf"]
    if not isinstance(kdf, dict) or set(kdf) != {"algorithm", "memory_kib", "time_cost", "parallelism", "salt"}:
        raise InvalidContainer()
    if (
        kdf.get("algorithm") != "argon2id"
        or kdf.get("memory_kib") != _KDF_MEMORY_KIB
        or kdf.get("time_cost") != _KDF_TIME_COST
        or kdf.get("parallelism") != _KDF_PARALLELISM
    ):
        raise UnsupportedFormat()
    _b64_decode(kdf.get("salt"), _SALT_LENGTH)
    for name in ("wrap", "payload"):
        value = decoded[name]
        if not isinstance(value, dict) or set(value) != {"algorithm", "nonce", "ciphertext", "tag"}:
            raise InvalidContainer()
        if value["algorithm"] != "xchacha20-poly1305":
            raise UnsupportedFormat()
        _b64_decode(value["nonce"], _NONCE_LENGTH)
        _b64_decode(value["ciphertext"])
        _b64_decode(value["tag"], _TAG_LENGTH)
    return decoded


def _read(path: Path) -> bytes:
    try:
        with path.open("rb") as handle:
            raw = handle.read(_MAX_CONTAINER_BYTES + 1)
    except OSError:
        raise StorageFailure() from None
    return raw


def _decode_payload(
    envelope: dict[str, Any],
    dek: bytes,
    *,
    version: int = CURRENT_FORMAT_VERSION,
) -> dict[str, Any]:
    payload = envelope["payload"]
    info = {"algorithm": payload["algorithm"], "nonce": payload["nonce"]}
    ciphertext = _b64_decode(payload["ciphertext"])
    tag = _b64_decode(payload["tag"], _TAG_LENGTH)
    plaintext = bytearray(
        _open(dek, ciphertext, tag, info, _payload_aad(info, version=version))
    )
    try:
        try:
            decoded = json.loads(bytes(plaintext).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise UnlockFailed() from None
        result = _decode_value(decoded)
        if not isinstance(result, dict):
            raise UnlockFailed()
        return result
    finally:
        _wipe(plaintext)


def _unlock_envelope(
    envelope: dict[str, Any],
    password: str,
    *,
    version: int = CURRENT_FORMAT_VERSION,
) -> tuple[bytearray, dict[str, Any]]:
    salt = _b64_decode(envelope["kdf"]["salt"], _SALT_LENGTH)
    kek = _derive_kek(password, salt)
    dek: bytearray | None = None
    try:
        wrap = envelope["wrap"]
        wrap_info = {"algorithm": wrap["algorithm"], "nonce": wrap["nonce"]}
        dek_bytes = _open(
            bytes(kek),
            _b64_decode(wrap["ciphertext"]),
            _b64_decode(wrap["tag"], _TAG_LENGTH),
            wrap_info,
            _wrap_aad(envelope["kdf"], version=version),
        )
        dek = bytearray(dek_bytes)
        if len(dek) != _KEY_LENGTH:
            raise UnlockFailed()
        payload = _decode_payload(envelope, bytes(dek), version=version)
        return dek, payload
    except Exception:
        _wipe(dek)
        raise
    finally:
        _wipe(kek)


def _build_v2_envelope(
    password: str,
    dek: bytes,
    kdf: dict[str, Any],
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    salt = _b64_decode(kdf["salt"], _SALT_LENGTH)
    kek = _derive_kek(password, salt)
    try:
        wrapped = _wrap_dek(bytes(kek), dek, kdf)
    finally:
        _wipe(kek)
    payload_info, ciphertext, tag = _make_payload(dek, payload)
    return {
        "format": _FORMAT,
        "version": CURRENT_FORMAT_VERSION,
        "kdf": kdf,
        "wrap": {
            **wrapped[0],
            "ciphertext": _b64_encode(wrapped[1]),
            "tag": _b64_encode(wrapped[2]),
        },
        "payload": {
            **payload_info,
            "ciphertext": _b64_encode(ciphertext),
            "tag": _b64_encode(tag),
        },
    }


def _is_active_disclosure_record(record: Any, now: int) -> bool:
    return (type(record) is dict and type(record.get("expires_at")) is int
            and _disclosure_expiry(record) > now)


def _disclosure_expiry(record: dict[str, Any]) -> int:
    submission = record.get("submission")
    if type(submission) is dict:
        return min(record["expires_at"], submission["expires_at"])
    return record["expires_at"]


def _validate_disclosure_record(record: Any) -> None:
    fields = {"version", "state", "handle",              "handle_digest", "context", "identity_id", "owner_public_key",
              "approved_claim_ids", "approved_values", "created_at", "expires_at",
              "proof_issued", "proof_challenge", "submission"}
    if type(record) is not dict or set(record) != fields or record.get("version") != 1:
        raise InvalidContainer()
    if record.get("state") not in {"approved", "prepared", "ambiguous"}:
        raise InvalidContainer()
    if type(record.get("handle")) is not str or type(record.get("handle_digest")) is not str:
        raise InvalidContainer()
    try:
        _decode_disclosure_handle(record["handle"])
    except Exception:
        raise InvalidContainer() from None
    context = record.get("context")
    context_fields = {"keycloak_issuer", "rp_client_id", "rp_display_name", "rp_origin", "action", "request_id",
                      "transaction_id", "oidc_nonce", "purpose", "claims", "expires_at"}
    if type(context) is not dict or set(context) != context_fields:
        raise InvalidContainer()
    if type(record.get("approved_claim_ids")) is not list or type(record.get("approved_values")) is not dict:
        raise InvalidContainer()
    if set(record["approved_values"]) != set(record["approved_claim_ids"]):
        raise InvalidContainer()
    if type(record.get("owner_public_key")) is not bytes or len(record["owner_public_key"]) != 32:
        raise InvalidContainer()
    if type(record.get("proof_issued")) is not bool or type(record.get("created_at")) is not int or type(record.get("expires_at")) is not int:
        raise InvalidContainer()
    submission = record.get("submission")
    if submission is not None and (type(submission) is not dict or set(submission) != {"response_uri", "state", "presentation_jws", "body", "expires_at"}
                                   or type(submission.get("expires_at")) is not int
                                   or not record["created_at"] < submission["expires_at"] <= record["expires_at"]):
        raise InvalidContainer()


def _strict_disclosure_json(raw: bytes) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result
    if type(raw) is not bytes or not raw or len(raw) > 16 * 1024:
        raise ValueError
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))


def _is_json_media_type(value: Any) -> bool:
    """Accept only application/json with syntactically valid MIME parameters."""
    import re

    if type(value) is not str or not value.isascii():
        return False
    token = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
    quoted = r'"(?:[\t !#-\[\]-~]|\\[\t -~])*"'
    pattern = rf"[ \t]*application/json[ \t]*(?:;[ \t]*{token}[ \t]*=[ \t]*(?:{token}|{quoted})[ \t]*)*"
    return re.fullmatch(pattern, value, flags=re.IGNORECASE) is not None


def _sign_account_jws(header: dict[str, Any], payload: dict[str, Any], seed: bytes, jcs: Callable[[Any], bytes]) -> str:
    private = __import__("cryptography.hazmat.primitives.asymmetric.ed25519", fromlist=["Ed25519PrivateKey"]).Ed25519PrivateKey.from_private_bytes(seed)
    protected = _b64url_encode(jcs(header))
    body = _b64url_encode(jcs(payload))
    signing_input = (protected + "." + body).encode("ascii")
    return protected + "." + body + "." + _b64url_encode(private.sign(signing_input))


def _read_envelope(path: Path) -> dict[str, Any]:
    return _parse_container(_read(path))


def _container_path(path: str | os.PathLike[str]) -> Path:
    # Resolve directory aliases, never a wallet symlink (which atomic replace
    # would otherwise split into two independently locked container names).
    target = Path(path)
    return target.parent.resolve() / target.name


def _windows_owned_by_current_user(path: Path | int) -> bool:
    """Compare a Windows path/descriptor owner SID with the process user."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityInfo.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.EqualSid.restype = wintypes.BOOL
    advapi32.EqualSid.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.OpenProcessToken.restype = wintypes.BOOL
    kernel32.OpenProcessToken.argtypes = (wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE))
    kernel32.GetTokenInformation.restype = wintypes.BOOL
    kernel32.GetTokenInformation.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    owner = ctypes.c_void_p()
    security_descriptor = ctypes.c_void_p()
    token = wintypes.HANDLE()
    token_user_size = wintypes.DWORD()
    try:
        if isinstance(path, int):
            result = advapi32.GetSecurityInfo(
                wintypes.HANDLE(path), 1, 1, ctypes.byref(owner), None, None, None,
                ctypes.byref(security_descriptor),
            )
        else:
            result = advapi32.GetNamedSecurityInfoW(
                str(path), 1, 1, ctypes.byref(owner), None, None, None,
                ctypes.byref(security_descriptor),
            )
        if result != 0:
            return False
        if not kernel32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            return False
        kernel32.GetTokenInformation(token, 1, None, 0, ctypes.byref(token_user_size))
        if token_user_size.value == 0:
            return False
        token_user = ctypes.create_string_buffer(token_user_size.value)
        if not kernel32.GetTokenInformation(
            token, 1, token_user, token_user_size, ctypes.byref(token_user_size)
        ):
            return False
        user_sid = ctypes.cast(token_user, ctypes.POINTER(ctypes.c_void_p))[0]
        return bool(advapi32.EqualSid(owner, user_sid))
    except (AttributeError, OSError):
        return False
    finally:
        if token:
            kernel32.CloseHandle(token)
        if security_descriptor:
            kernel32.LocalFree(security_descriptor)


def _windows_acl_entries_are_safe(
    aces: Any,
    trusted_sids: set[str],
    *,
    dacl_present: bool = True,
    query_succeeded: bool = True,
) -> bool:
    """Pure fail-closed decision for normalized Windows DACL entries."""
    if not query_succeeded or not dacl_present or not trusted_sids:
        return False
    try:
        for ace_type, sid in aces:
            if ace_type not in ("allow", "deny") or not isinstance(sid, str):
                return False
            if sid not in trusted_sids:
                return False
        return True
    except (TypeError, ValueError):
        return False


def _windows_acl_is_safe(path: Path | int) -> bool:
    """Conservatively reject ACLs that could let an untrusted SID replace a lock."""
    import ctypes
    from ctypes import wintypes

    class _AclSizeInformation(ctypes.Structure):
        _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD),
                    ("AclBytesFree", wintypes.DWORD)]

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetNamedSecurityInfoW.argtypes = (
        wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityInfo.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = (
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD
    )
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = (ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p))
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = (ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR))
    advapi32.CreateWellKnownSid.restype = wintypes.BOOL
    advapi32.CreateWellKnownSid.argtypes = (
        wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)
    )
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.OpenProcessToken.restype = wintypes.BOOL
    kernel32.OpenProcessToken.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    )
    kernel32.GetTokenInformation.restype = wintypes.BOOL
    kernel32.GetTokenInformation.argtypes = (
        wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
    )
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    descriptor = ctypes.c_void_p()
    owner = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    token = wintypes.HANDLE()
    try:
        if isinstance(path, int):
            result = advapi32.GetSecurityInfo(wintypes.HANDLE(path), 1, 5,
                ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
        else:
            result = advapi32.GetNamedSecurityInfoW(str(path), 1, 5,
                ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor))
        if result != 0 or not dacl.value:
            return False
        size = _AclSizeInformation()
        if not advapi32.GetAclInformation(dacl, ctypes.byref(size), ctypes.sizeof(size), 2):
            return False
        if not kernel32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            return False
        needed = wintypes.DWORD()
        kernel32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not needed.value:
            return False
        token_user = ctypes.create_string_buffer(needed.value)
        if not kernel32.GetTokenInformation(token, 1, token_user, needed, ctypes.byref(needed)):
            return False
        user_sid = ctypes.cast(token_user, ctypes.POINTER(ctypes.c_void_p))[0]
        if not owner.value:
            return False
        trusted_sids = set()

        def sid_string(sid):
            value = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(value)):
                raise OSError("SID conversion failed")
            try:
                return value.value
            finally:
                kernel32.LocalFree(ctypes.cast(value, ctypes.c_void_p))

        trusted_sids.add(sid_string(owner))
        trusted_sids.add(sid_string(user_sid))
        well_known_sid_buffers = []
        for kind in (22, 26):
            sid_buffer = ctypes.create_string_buffer(68)
            sid_size = wintypes.DWORD(len(sid_buffer))
            if not advapi32.CreateWellKnownSid(
                kind, None, sid_buffer, ctypes.byref(sid_size)
            ):
                return False
            well_known_sid_buffers.append(sid_buffer)
            trusted_sids.add(sid_string(ctypes.addressof(sid_buffer)))
        normalized_aces = []
        for index in range(size.AceCount):
            ace = ctypes.c_void_p()
            if not advapi32.GetAce(dacl, index, ctypes.byref(ace)):
                return False
            header = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte * 8)).contents
            ace_type = header[0]
            if ace_type not in (0, 1):  # standard allow/deny only
                normalized_aces.append((f"type-{ace_type}", None))
                continue
            sid = ctypes.c_void_p(ctypes.addressof(header) + 8)
            normalized_aces.append(("allow" if ace_type == 0 else "deny", sid_string(sid)))
        return _windows_acl_entries_are_safe(normalized_aces, trusted_sids)
    except (AttributeError, OSError, TypeError, ValueError):
        return False
    finally:
        if token:
            kernel32.CloseHandle(token)
        if descriptor:
            kernel32.LocalFree(descriptor)


@contextmanager
def _windows_container_guard(path: Path):
    """Bounded Windows byte-range lock on a stable, empty per-wallet sidecar."""
    import errno

    descriptor = None
    locked = False
    lock_path = path.with_name("." + path.name + ".lock")
    try:
        import msvcrt
        if not _windows_owned_by_current_user(path.parent) or not _windows_acl_is_safe(path.parent):
            raise StorageFailure()

        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOINHERIT", 0)
        descriptor = os.open(lock_path, flags, 0o600)
        lock_handle = msvcrt.get_osfhandle(descriptor)
        if not _windows_owned_by_current_user(lock_handle) or not _windows_acl_is_safe(lock_handle):
            raise StorageFailure()
        info = os.fstat(descriptor)
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        attributes = getattr(info, "st_file_attributes", 0)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != 0
                or attributes & reparse):
            raise StorageFailure()
        current = os.lstat(lock_path)
        if ((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                or getattr(current, "st_file_attributes", 0) & reparse):
            raise StorageFailure()
        deadline = time.monotonic() + 5.0
        while True:
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
                locked = True
                break
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EAGAIN, errno.EDEADLK):
                    raise
                if time.monotonic() >= deadline:
                    raise StorageFailure() from None
                time.sleep(0.01)
        current = os.lstat(lock_path)
        if ((current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
                or getattr(current, "st_file_attributes", 0) & reparse):
            raise StorageFailure()
        try:
            target = os.lstat(path)
        except FileNotFoundError:
            target = None
        if target is not None and (
            not stat.S_ISREG(target.st_mode) or target.st_nlink != 1
            or getattr(target, "st_file_attributes", 0) & reparse
        ):
            raise StorageFailure()
    except (ImportError, AttributeError, OSError):
        if locked:
            try:
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
        if descriptor is not None:
            os.close(descriptor)
        raise StorageFailure() from None
    except BaseException:
        if locked:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        if descriptor is not None:
            os.close(descriptor)
        raise
    try:
        yield
    finally:
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
        except OSError:
            try:
                os.close(descriptor)
            finally:
                raise StorageOutcomeUnknown() from None
        try:
            os.close(descriptor)
        except OSError:
            raise StorageOutcomeUnknown() from None


@contextmanager
def _posix_container_guard(path: Path):
    """Bounded POSIX inter-process lock, unchanged across atomic replacement."""
    descriptor = None
    try:
        import fcntl
        parent = path.parent.stat()
        if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o022:
            raise StorageFailure()
        flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        lock_path = path.with_name("." + path.name + ".lock")
        descriptor = os.open(lock_path, flags, 0o600)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or info.st_size != 0):
            raise StorageFailure()
        deadline = time.monotonic() + 5.0
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise StorageFailure() from None
                time.sleep(0.01)
        current = lock_path.lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise StorageFailure()
        try:
            target = path.lstat()
        except FileNotFoundError:
            target = None
        if target is not None and (not stat.S_ISREG(target.st_mode) or target.st_nlink != 1):
            raise StorageFailure()
    except (ImportError, AttributeError, OSError):
        if descriptor is not None:
            os.close(descriptor)
        raise StorageFailure() from None
    except BaseException:
        if descriptor is not None:
            os.close(descriptor)
        raise
    try:
        yield
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise StorageOutcomeUnknown() from None


@contextmanager
def _container_guard(path: Path):
    """Serialize cooperating local processes using a platform-native lock."""
    if sys.platform == "win32":
        with _windows_container_guard(path):
            yield
    else:
        with _posix_container_guard(path):
            yield


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_disclosure_handle(handle: str) -> bytes:
    if type(handle) is not str or len(handle) != 43:
        raise ValueError
    raw = base64.urlsafe_b64decode(handle + "=")
    if len(raw) != 32 or _b64url_encode(raw) != handle:
        raise ValueError
    return raw


def _decode_b64url_exact(value: str, size: int) -> bytes:
    if type(value) is not str or not value or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-" for c in value):
        raise ValueError
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if len(raw) != size or _b64url_encode(raw) != value:
        raise ValueError
    return raw


def _disclosure_context_payload(context: Any) -> dict[str, Any]:
    return {
        "keycloak_issuer": context.keycloak_issuer, "rp_client_id": context.rp_client_id,
        "rp_display_name": context.rp_display_name, "rp_origin": context.rp_origin,
        "action": context.action, "request_id": context.request_id,
        "transaction_id": context.transaction_id, "oidc_nonce": context.oidc_nonce,
        "purpose": context.purpose,
        "claims": [{"id": item.claim_id, "required": item.required} for item in context.claims],
        "expires_at": context.expires_at,
    }


def _entity_digest(entity: Mapping[str, Any]) -> str:
    return hashlib.sha256(json.dumps(entity, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":")).encode("utf-8")).hexdigest()


def _review_fingerprint(review: Any) -> bytes:
    return hashlib.sha256(_canonical_json(_encode_value({
        "context": _disclosure_context_payload(review.context),
        "handle_digest": review.handle_digest, "identity_id": review.identity_id,
        "owner_public_key": review.owner_public_key, "entity_digest": review.entity_digest,
        "values": [list(pair) for pair in review.values], "expires_at": review.expires_at,
    }))).digest()


class Wallet:
    """An unlocked wallet session backed by one versioned container."""

    def __init__(
        self,
        path: Path,
        dek: bytearray,
        payload: dict[str, Any],
        envelope: dict[str, Any],
        inactivity_minutes: int,
    ) -> None:
        self._path = path
        self._rotation_lock = RLock()
        self._dek = dek
        self._secret_handle = object()
        self._secret_finalizer = weakref.finalize(
            self,
            _finalize_wallet_secret,
            self._secret_handle,
        )
        self._payload = dict(payload)
        if _PENDING_ACCOUNT_DISCLOSURE in self._payload:
            _validate_disclosure_record(self._payload[_PENDING_ACCOUNT_DISCLOSURE])
        self._install_secret_material()
        self._envelope = envelope
        self._capabilities: set[Any] = set()
        self._disclosure_epoch = 0
        self._disclosure_review: Any = None
        self._disclosure_review_fingerprint: bytes | None = None
        self._inactivity_seconds = inactivity_minutes * 60
        self._last_activity = time.monotonic()

    @classmethod
    def create(
        cls,
        path: str | os.PathLike[str],
        password: str,
        confirmation: str,
        payload: Mapping[str, Any],
        *,
        inactivity_minutes: int = 5,
    ) -> "Wallet":
        if not isinstance(payload, Mapping) or _SIGNING_FIELDS.intersection(payload):
            raise InvalidContainer()
        normalized_payload = dict(payload)
        if _PENDING_ACCOUNT_DISCLOSURE in normalized_payload:
            raise InvalidContainer()
        if _MASTER_ACCOUNT_ENTITY in normalized_payload:
            normalized_payload[_MASTER_ACCOUNT_ENTITY] = _copy_master_account_entity(
                normalized_payload[_MASTER_ACCOUNT_ENTITY]
            )
        return cls._create_storage(
            path,
            password,
            confirmation,
            normalized_payload,
            inactivity_minutes=inactivity_minutes,
        )

    @classmethod
    def _create_storage(
        cls,
        path: str | os.PathLike[str],
        password: str,
        confirmation: str,
        payload: Mapping[str, Any],
        *,
        inactivity_minutes: int = 5,
    ) -> "Wallet":
        _validate_password(password, confirmation)
        _validate_inactivity(inactivity_minutes)
        if not isinstance(payload, Mapping):
            raise InvalidContainer()
        target = _container_path(path)
        with _container_guard(target):
            created = False
            dek = bytearray()
            try:
                dek = bytearray(secrets.token_bytes(_KEY_LENGTH))
                salt = secrets.token_bytes(_SALT_LENGTH)
                kdf = _kdf_header(salt)
                envelope = _build_v2_envelope(password, bytes(dek), kdf, payload)
                _write_verified(target, _serialize(envelope), replace=False)
                created = True
                return cls(target, dek, dict(payload), envelope, inactivity_minutes)
            except WalletError:
                if created:
                    try:
                        target.unlink()
                    except OSError:
                        pass
                _wipe(dek)
                raise
            except Exception:
                if created:
                    try:
                        target.unlink()
                    except OSError:
                        pass
                _wipe(dek)
                raise StorageFailure() from None

    @classmethod
    def create_with_generated_key(
        cls,
        path: str | os.PathLike[str],
        password: str,
        confirmation: str,
        *,
        inactivity_minutes: int = 5,
    ) -> "Wallet":
        from .signer import _generate_seed, _public_key_from_seed

        seed = _generate_seed()
        try:
            public_key = _public_key_from_seed(bytes(seed))
            return cls._create_storage(
                path,
                password,
                confirmation,
                {"private_seed": bytes(seed), "public_key": public_key},
                inactivity_minutes=inactivity_minutes,
            )
        finally:
            _wipe(seed)

    @classmethod
    def open(
        cls,
        path: str | os.PathLike[str],
        password: str,
        *,
        inactivity_minutes: int = 5,
    ) -> "Wallet":
        _validate_password(password)
        _validate_inactivity(inactivity_minutes)
        target = _container_path(path)
        with _container_guard(target):
            envelope = _read_envelope(target)
            try:
                dek, payload = _unlock_envelope(envelope, password)
            except UnlockFailed:
                _record_unlock_failure(target)
                raise
            _clear_unlock_failures(target)
            return cls(target, dek, payload, envelope, inactivity_minutes)

    @classmethod
    def migrate_container(
        cls,
        path: str | os.PathLike[str],
        password: str,
        *,
        inactivity_minutes: int = 5,
    ) -> "Wallet":
        """Authenticate and migrate one version-1 container in place to v2."""
        _validate_password(password)
        _validate_inactivity(inactivity_minutes)
        target = _container_path(path)
        with _container_guard(target):
            envelope = _parse_container(_read(target), expected_version=1)
            wallet: Wallet | None = None
            dek: bytearray | None = None
            try:
                try:
                    dek, payload = _unlock_envelope(envelope, password, version=1)
                except UnlockFailed:
                    _record_unlock_failure(target)
                    raise
                _clear_unlock_failures(target)
                migrated_envelope = _build_v2_envelope(
                    password,
                    bytes(dek),
                    envelope["kdf"],
                    payload,
                )
                wallet = cls(
                    target,
                    dek,
                    payload,
                    migrated_envelope,
                    inactivity_minutes,
                )
                _write_verified(target, _serialize(migrated_envelope))
                return wallet
            except Exception as error:
                if wallet is not None:
                    wallet.lock()
                elif dek is not None:
                    _wipe(dek)
                if isinstance(error, WalletError):
                    raise
                raise StorageFailure() from None

    @classmethod
    def import_container(
        cls,
        path: str | os.PathLike[str],
        data: bytes,
        password: str,
        *,
        inactivity_minutes: int = 5,
    ) -> "Wallet":
        """Authenticate and atomically import exact encrypted-container bytes."""
        _validate_password(password)
        _validate_inactivity(inactivity_minutes)
        if type(data) is not bytes:
            raise InvalidContainer()
        target = _container_path(path)
        with _container_guard(target):
            envelope = _parse_container(data)
            wallet: Wallet | None = None
            dek: bytearray | None = None
            try:
                try:
                    dek, payload = _unlock_envelope(envelope, password)
                except UnlockFailed:
                    _record_unlock_failure(target)
                    raise
                record = payload.get(_PENDING_ACCOUNT_DISCLOSURE)
                if _is_active_disclosure_record(record, int(time.time())):
                    _wipe(dek)
                    raise InvalidContainer()
                _clear_unlock_failures(target)
                wallet = cls(target, dek, payload, envelope, inactivity_minutes)
                _write_verified(target, data, replace=False)
                return wallet
            except Exception as error:
                if wallet is not None:
                    wallet.lock()
                elif dek is not None:
                    _wipe(dek)
                if isinstance(error, WalletError):
                    raise
                raise StorageFailure() from None

    def _install_secret_material(self) -> None:
        seed = self._payload.pop("private_seed", None)
        pending_seed = self._payload.pop(_PENDING_PRIVATE_SEED, None)
        public_key = self._payload.get("public_key")
        pending_public_key = self._payload.get(_PENDING_PUBLIC_KEY)
        has_dispatch_intent = _ROTATION_DISPATCH_INTENT in self._payload

        if seed is None:
            if (
                public_key is not None
                or pending_seed is not None
                or pending_public_key is not None
                or has_dispatch_intent
            ):
                raise InvalidContainer()
            return
        _validate_seed_public_key_pair(seed, public_key)

        if pending_seed is None:
            if pending_public_key is not None:
                raise InvalidContainer()
        else:
            _validate_seed_public_key_pair(pending_seed, pending_public_key)
            if pending_public_key == public_key:
                raise InvalidContainer()

        if has_dispatch_intent:
            if pending_public_key is None:
                raise InvalidContainer()
            intent = RotationDispatchIntent._from_payload(
                self._payload[_ROTATION_DISPATCH_INTENT]
            )
            if (
                intent.predecessor_owner_public_key != public_key
                or intent.successor_owner_public_key != pending_public_key
            ):
                raise InvalidContainer()

        pending_secret = bytearray(pending_seed) if pending_seed is not None else None
        _WALLET_SECRETS[self._secret_handle] = bytearray(seed)
        if pending_secret is not None:
            _PENDING_WALLET_SECRETS[self._secret_handle] = pending_secret

    @property
    def is_unlocked(self) -> bool:
        return self._dek is not None

    @property
    def public_key(self) -> bytes:
        self._touch()
        seed = _WALLET_SECRETS.get(self._secret_handle)
        stored_public_key = self._payload.get("public_key")
        return _public_key_for_secret(seed, stored_public_key)

    def create_signer(self, *, timeout_seconds: float = 60.0) -> Any:
        from .signer import SignerUnavailable, _create_capability_from_seed

        with self._rotation_lock:
            self._touch()
            self._ensure_rotation_dispatch_not_latched()
            seed = _WALLET_SECRETS.get(self._secret_handle)
            stored_public_key = self._payload.get("public_key")
            if seed is None or type(stored_public_key) is not bytes:
                raise SignerUnavailable()
            if len(seed) != _KEY_LENGTH or len(stored_public_key) != _KEY_LENGTH:
                raise SignerUnavailable()
            try:
                capability = _create_capability_from_seed(
                    bytes(seed),
                    timeout_seconds=timeout_seconds,
                    on_invalidate=self._capabilities.discard,
                )
            except Exception:
                raise SignerUnavailable() from None
            if capability.public_key != stored_public_key:
                capability.invalidate()
                raise SignerUnavailable()
            self._capabilities.add(capability)
            return capability

    @property
    def signing_key_rotation_dispatch_intent(self) -> RotationDispatchIntent | None:
        with self._rotation_lock:
            self._touch()
            if _ROTATION_DISPATCH_INTENT not in self._payload:
                return None
            return RotationDispatchIntent._from_payload(
                self._payload[_ROTATION_DISPATCH_INTENT]
            )

    @property
    def pending_signing_public_key(self) -> bytes | None:
        """Return the staged successor's public key, if one is persisted."""
        from .signer import SignerUnavailable

        with self._rotation_lock:
            self._touch()
            seed = _PENDING_WALLET_SECRETS.get(self._secret_handle)
            stored_public_key = self._payload.get(_PENDING_PUBLIC_KEY)
            if seed is None:
                if stored_public_key is not None:
                    raise SignerUnavailable()
                return None
            return _public_key_for_secret(seed, stored_public_key)

    def prepare_signing_key_rotation(self) -> bytes:
        """Persist one encrypted successor while leaving the active key unchanged."""
        with self._rotation_lock:
            return self._prepare_signing_key_rotation()

    def _prepare_signing_key_rotation(self) -> bytes:
        from .signer import (
            KeyGenerationError,
            SignerUnavailable,
            _generate_seed,
            _public_key_from_seed,
        )

        self._touch()
        self._ensure_rotation_dispatch_not_latched()
        existing_pending_seed = _PENDING_WALLET_SECRETS.get(self._secret_handle)
        if existing_pending_seed is not None:
            pending_public_key = self.pending_signing_public_key
            if pending_public_key is None:
                raise SignerUnavailable()
            return pending_public_key

        active_seed = _WALLET_SECRETS.get(self._secret_handle)
        active_public_key = self._payload.get("public_key")
        if active_seed is None or type(active_public_key) is not bytes:
            raise SignerUnavailable()
        pending_seed = _generate_seed()
        persisted = False
        try:
            try:
                pending_public_key = _public_key_from_seed(bytes(pending_seed))
            except Exception:
                raise KeyGenerationError() from None
            if pending_public_key == active_public_key:
                raise KeyGenerationError()

            updated_payload = dict(self._payload)
            updated_payload[_PENDING_PUBLIC_KEY] = pending_public_key
            envelope = self._build_envelope(
                updated_payload,
                pending_seed_override=pending_seed,
            )
            self._persist_envelope(envelope)
            persisted = True
            _PENDING_WALLET_SECRETS[self._secret_handle] = pending_seed
            self._payload = updated_payload
            self._envelope = envelope
            self._invalidate_capabilities()
            return pending_public_key
        finally:
            if not persisted:
                _wipe(pending_seed)

    def prove_pending_signing_key_rotation(self, draft: IdentityDraft) -> None:
        """Locally prove possession of the staged successor for one draft.

        The signature is verified against the pending public key and discarded;
        it is never returned, persisted, logged, or added to the public bundle.
        """
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )

        from .identity import (
            IdentityDraft,
            InvalidIdentityRequest,
        )
        from .signer import SignerUnavailable

        with self._rotation_lock:
            self._touch()
            self._ensure_rotation_dispatch_not_latched()
            pending_seed = _PENDING_WALLET_SECRETS.get(self._secret_handle)
            active_seed = _WALLET_SECRETS.get(self._secret_handle)
            pending_public_key = self._payload.get(_PENDING_PUBLIC_KEY)
            active_public_key = self._payload.get("public_key")
            if (
                pending_seed is None
                or active_seed is None
                or type(pending_public_key) is not bytes
                or type(active_public_key) is not bytes
            ):
                raise SignerUnavailable()

            if not isinstance(draft, IdentityDraft):
                raise InvalidIdentityRequest()
            derived_active = _public_key_for_secret(active_seed, active_public_key)
            derived_pending = _public_key_for_secret(pending_seed, pending_public_key)
            try:
                validated_draft = IdentityDraft(
                    signed_update_bytes=draft.signed_update_bytes,
                    previous_state_envelope=draft.previous_state_envelope,
                    previous_state_history=draft.previous_state_history,
                )
                validated_draft.validate_owner_key_rotation_binding(
                    predecessor_owner_public_key=derived_active,
                    successor_owner_public_key=derived_pending,
                )
            except Exception:
                raise InvalidIdentityRequest() from None

            signature: bytes | None = None
            try:
                digest = hashlib.sha256(validated_draft.signed_update_bytes).digest()
                private_key = Ed25519PrivateKey.from_private_bytes(bytes(pending_seed))
                signature = private_key.sign(digest)
                Ed25519PublicKey.from_public_bytes(derived_pending).verify(
                    signature, digest
                )
            except InvalidSignature:
                raise SignerUnavailable() from None
            except Exception:
                raise SignerUnavailable() from None
            finally:
                signature = None

    def latch_signing_key_rotation_dispatch_intent(
        self,
        bundle: "IdentityBundle",
        publication: "RotationPublication",
    ) -> RotationDispatchPermit:
        """Persist the authorized operation-5 artifact before its one-use dispatch."""
        from .identity import (
            IdentityBundle,
            InvalidIdentityRequest,
            RotationPublication,
        )
        from .signer import SignerUnavailable

        with self._rotation_lock:
            self._touch()
            self._ensure_rotation_dispatch_not_latched()
            if not isinstance(bundle, IdentityBundle):
                raise InvalidIdentityRequest()
            try:
                validated_bundle = IdentityBundle.from_cbor(bundle.to_cbor())
                finalized_envelope = validated_bundle.finalize()
            except InvalidIdentityRequest:
                raise
            except Exception:
                raise InvalidIdentityRequest() from None
            if (
                not isinstance(publication, RotationPublication)
                or publication.expires_at <= int(time.time())
                or not publication._matches_bundle(validated_bundle)
            ):
                raise InvalidIdentityRequest()

            draft = validated_bundle.draft
            authorization = draft.authorization
            if authorization is None or authorization[3] != 5:
                raise InvalidIdentityRequest()
            self.prove_pending_signing_key_rotation(draft)
            active_public_key = self.public_key
            successor_public_key = self.pending_signing_public_key
            if successor_public_key is None:
                raise SignerUnavailable()
            intent = RotationDispatchIntent(
                owner_name=draft.owner_name,
                predecessor_owner_public_key=active_public_key,
                successor_owner_public_key=successor_public_key,
                predecessor_state_hash=authorization[7],
                sequence=draft.sequence,
                envelope_hash=hashlib.sha256(finalized_envelope).digest(),
                environment=publication.environment,
            )

            with publication._owner_lock(intent):
                if publication._owner_is_latched():
                    raise InvalidIdentityRequest()
                self._invalidate_capabilities()
                updated_payload = dict(self._payload)
                updated_payload[_ROTATION_DISPATCH_INTENT] = intent._to_payload()
                envelope = self._build_envelope(updated_payload)
                self._persist_envelope(envelope)
                self._payload = updated_payload
                self._envelope = envelope
                if not publication._mark_latched(intent):
                    raise InvalidIdentityRequest()
                return RotationDispatchPermit(
                    intent=intent,
                    seal=_ROTATION_PERMIT_SEAL,
                )

    def bind_legacy_rotation_dispatch_environment(
        self, environment: str, *, consent: Callable[[RotationDispatchIntent, str], bool]
    ) -> RotationDispatchIntent:
        """Explicit local-only six-to-seven field recovery; never creates dispatch authority."""
        from dataclasses import replace

        from .identity import InvalidIdentityRequest

        with self._rotation_lock:
            self._touch()
            intent = self.signing_key_rotation_dispatch_intent
            if (intent is None or intent.environment is not None
                or not valid_registry_environment(environment) or not callable(consent)):
                raise InvalidIdentityRequest()
            try:
                approved = consent(intent, environment) is True
            except Exception:
                raise InvalidIdentityRequest() from None
            self._touch()
            if not approved or self.signing_key_rotation_dispatch_intent != intent:
                raise InvalidIdentityRequest()
            bound = replace(intent, environment=environment)
            updated = dict(self._payload)
            updated[_ROTATION_DISPATCH_INTENT] = bound._to_payload()
            envelope = self._build_envelope(updated)
            self._invalidate_capabilities()
            self._persist_envelope(envelope)
            self._payload = updated
            self._envelope = envelope
            return bound

    def finalize_signing_key_rotation(
        self, confirmation: "RotationConfirmation"
    ) -> bytes:
        """Promote the pending seed only after adapter-issued remote confirmation."""
        from .identity import InvalidIdentityRequest, RotationConfirmation
        from .signer import SignerUnavailable

        with self._rotation_lock:
            self._touch()
            if not isinstance(confirmation, RotationConfirmation):
                raise InvalidIdentityRequest()
            raw_intent = self._payload.get(_ROTATION_DISPATCH_INTENT)
            if raw_intent is None:
                raise InvalidIdentityRequest()
            intent = RotationDispatchIntent._from_payload(raw_intent)
            if not confirmation._matches_intent(intent):
                raise InvalidIdentityRequest()

            active_seed = _WALLET_SECRETS.get(self._secret_handle)
            pending_seed = _PENDING_WALLET_SECRETS.get(self._secret_handle)
            active_public_key = self._payload.get("public_key")
            pending_public_key = self._payload.get(_PENDING_PUBLIC_KEY)
            if (
                active_seed is None
                or pending_seed is None
                or type(active_public_key) is not bytes
                or type(pending_public_key) is not bytes
                or active_public_key != intent.predecessor_owner_public_key
                or pending_public_key != intent.successor_owner_public_key
            ):
                raise SignerUnavailable()
            _public_key_for_secret(active_seed, active_public_key)
            successor_public_key = _public_key_for_secret(
                pending_seed, pending_public_key
            )
            if successor_public_key != confirmation.successor_owner_public_key:
                raise SignerUnavailable()

            if not confirmation._is_latched(intent):
                raise InvalidIdentityRequest()
            with confirmation._owner_lock(intent):
                if not confirmation._is_latched(intent):
                    raise InvalidIdentityRequest()
                updated_payload = dict(self._payload)
                updated_payload["public_key"] = successor_public_key
                updated_payload.pop(_PENDING_PUBLIC_KEY, None)
                updated_payload.pop(_ROTATION_DISPATCH_INTENT, None)
                self._invalidate_capabilities()
                envelope = self._build_envelope(
                    updated_payload,
                    active_seed_override=pending_seed,
                    include_pending=False,
                )
                self._persist_envelope(envelope)
                _WALLET_SECRETS[self._secret_handle] = pending_seed
                _PENDING_WALLET_SECRETS.pop(self._secret_handle, None)
                self._payload = updated_payload
                self._envelope = envelope
                _wipe(active_seed)
                if not confirmation._clear_latch(intent):
                    raise InvalidIdentityRequest()
                return successor_public_key

    def resolve_signing_key_rotation_rejection(
        self, rejection: "RotationDispatchRejection"
    ) -> None:
        """Clear a dispatch latch only from a one-use, adapter-issued expiry rejection."""
        from .identity import InvalidIdentityRequest, PublishStatus, RotationDispatchRejection
        from .signer import SignerUnavailable

        with self._rotation_lock:
            self._touch()
            if (
                not isinstance(rejection, RotationDispatchRejection)
                or rejection.status is not PublishStatus.EXPIRED
            ):
                raise InvalidIdentityRequest()
            raw_intent = self._payload.get(_ROTATION_DISPATCH_INTENT)
            if raw_intent is None:
                raise InvalidIdentityRequest()
            intent = RotationDispatchIntent._from_payload(raw_intent)
            if not rejection._matches_intent(intent):
                raise InvalidIdentityRequest()
            active_seed = _WALLET_SECRETS.get(self._secret_handle)
            pending_seed = _PENDING_WALLET_SECRETS.get(self._secret_handle)
            active_public_key = self._payload.get("public_key")
            pending_public_key = self._payload.get(_PENDING_PUBLIC_KEY)
            if (
                active_seed is None
                or pending_seed is None
                or type(active_public_key) is not bytes
                or type(pending_public_key) is not bytes
                or active_public_key != intent.predecessor_owner_public_key
                or pending_public_key != intent.successor_owner_public_key
            ):
                raise SignerUnavailable()
            _public_key_for_secret(active_seed, active_public_key)
            _public_key_for_secret(pending_seed, pending_public_key)
            with rejection._owner_lock(intent):
                if not rejection._is_latched(intent) or not rejection._claim():
                    raise InvalidIdentityRequest()
                updated_payload = dict(self._payload)
                updated_payload.pop(_ROTATION_DISPATCH_INTENT, None)
                try:
                    envelope = self._build_envelope(updated_payload)
                    self._persist_envelope(envelope)
                except Exception:
                    rejection._release()
                    raise
                self._payload = updated_payload
                self._envelope = envelope
                self._invalidate_capabilities()
                rejection._clear_latch(intent)

    def cancel_signing_key_rotation(self) -> None:
        """Remove an unfinalized successor without changing the active key."""
        with self._rotation_lock:
            self._cancel_signing_key_rotation()

    def _cancel_signing_key_rotation(self) -> None:
        self._touch()
        self._ensure_rotation_dispatch_not_latched()
        pending_seed = _PENDING_WALLET_SECRETS.get(self._secret_handle)
        if pending_seed is None:
            if self._payload.get(_PENDING_PUBLIC_KEY) is not None:
                from .signer import SignerUnavailable

                raise SignerUnavailable()
            return

        updated_payload = dict(self._payload)
        updated_payload.pop(_PENDING_PUBLIC_KEY, None)
        envelope = self._build_envelope(updated_payload, include_pending=False)
        self._persist_envelope(envelope)
        self._payload = updated_payload
        self._envelope = envelope
        _PENDING_WALLET_SECRETS.pop(self._secret_handle, None)
        _wipe(pending_seed)
        self._invalidate_capabilities()

    @property
    def last_activity(self) -> float:
        self._require_unlocked()
        return self._last_activity

    def set_master_account_entity(self, entity: Mapping[str, Any]) -> None:
        """Atomically replace owner-held entity values inside the v2 payload."""
        with self._rotation_lock:
            self._touch()
            copied_entity = _copy_master_account_entity(entity)
            updated_payload = dict(self._payload)
            updated_payload[_MASTER_ACCOUNT_ENTITY] = copied_entity
            envelope = self._build_envelope(updated_payload)
            self._persist_envelope(envelope)
            self._payload = updated_payload
            self._envelope = envelope
            self._invalidate_capabilities()

    def get_master_account_entity(self) -> dict[str, Any]:
        """Return an isolated snapshot of local entity values while unlocked."""
        with self._rotation_lock:
            self._touch()
            return _copy_master_account_entity(
                self._payload.get(_MASTER_ACCOUNT_ENTITY, {})
            )

    def review_account_disclosure(self, context: Any, handle: str, identity_id: str) -> Any:
        """Create an immutable value snapshot for the trusted consent UI."""
        from .account_disclosure import WalletAccountDisclosureContext, parse_wallet_account_disclosure_context
        from .account_issuance import AccountDisclosureError, AccountDisclosureReview

        try:
            if not isinstance(context, WalletAccountDisclosureContext):
                raise AccountDisclosureError()
            context = parse_wallet_account_disclosure_context(
                json.dumps({"profile": "decent-account-disclosure-v1", **_disclosure_context_payload(context)}).encode(),
                expected_keycloak_issuer=context.keycloak_issuer,
            )
            raw_handle = _decode_disclosure_handle(handle)
            derived = _b64url_encode(hashlib.sha256(handle.encode("ascii")).digest())
            if context.transaction_id != derived or type(identity_id) is not str or not identity_id:
                raise AccountDisclosureError()
            identity_id.encode("utf-8", "strict")
            with self._rotation_lock:
                self._touch()
                self._clear_expired_disclosure(int(time.time()))
                entity = _copy_master_account_entity(self._payload.get(_MASTER_ACCOUNT_ENTITY, {}))
                values = []
                for claim in context.claims:
                    key = _DISCLOSURE_CLAIM_KEYS.get(claim.claim_id)
                    if key is None:
                        raise AccountDisclosureError()
                    value = entity.get(key)
                    if value is not None:
                        if type(value) is not str or not value or len(value.encode("utf-8", "strict")) > 1024:
                            raise AccountDisclosureError()
                    if claim.required and value is None:
                        raise AccountDisclosureError()
                    values.append((claim.claim_id, value))
                owner_public_key = self._payload.get("public_key")
                if type(owner_public_key) is not bytes or len(owner_public_key) != 32:
                    raise AccountDisclosureError()
                review = AccountDisclosureReview(
                    context=context, handle_digest=hashlib.sha256(raw_handle).hexdigest(),
                    identity_id=identity_id, owner_public_key=owner_public_key,
                    entity_digest=_entity_digest(entity),
                    values=tuple(values), expires_at=context.expires_at,
                )
                self._disclosure_review = review
                self._disclosure_review_fingerprint = _review_fingerprint(review)
                return review
        except AccountDisclosureError:
            raise
        except Exception:
            raise AccountDisclosureError() from None

    def approve_account_disclosure(self, review: Any, approved_claim_ids: Any, *, consent: Callable[[Any], bool]) -> Any:
        """Persist one approval after an unlocked, re-entrant consent callback."""
        from .account_issuance import AccountDisclosureError, AccountDisclosureReview, PendingAccountApproval

        try:
            if not isinstance(review, AccountDisclosureReview) or not callable(consent):
                raise AccountDisclosureError()
            instant = int(time.time())
            if type(instant) is not int:
                raise AccountDisclosureError()
            approved = tuple(approved_claim_ids)
            requested = tuple(claim_id for claim_id, _ in review.values)
            required = {claim.claim_id for claim in review.context.claims if claim.required}
            if (len(set(approved)) != len(approved) or not required <= set(approved)
                    or not set(approved) <= set(requested) or not approved):
                raise AccountDisclosureError()
            snapshot_values = dict(review.values)
            if any(snapshot_values[cid] is None for cid in approved):
                raise AccountDisclosureError()
            with self._rotation_lock:
                self._touch()
                self._clear_expired_disclosure(instant)
                if review is not self._disclosure_review or _review_fingerprint(review) != self._disclosure_review_fingerprint:
                    raise AccountDisclosureError()
                if _PENDING_ACCOUNT_DISCLOSURE in self._payload:
                    raise AccountDisclosureError()
                epoch = self._disclosure_epoch
                entity = _copy_master_account_entity(self._payload.get(_MASTER_ACCOUNT_ENTITY, {}))
                digest = _entity_digest(entity)
                if digest != review.entity_digest or self._payload.get("public_key") != review.owner_public_key or review.expires_at <= instant:
                    raise AccountDisclosureError()
                for claim in review.context.claims:
                    entity_key = _DISCLOSURE_CLAIM_KEYS.get(claim.claim_id)
                    if entity_key is None or snapshot_values.get(claim.claim_id) != entity.get(entity_key):
                        raise AccountDisclosureError()
            try:
                consented = consent(review) is True
            except Exception:
                raise AccountDisclosureError() from None
            if not consented:
                raise AccountDisclosureError()
            with self._rotation_lock:
                self._touch()
                recheck_time = int(time.time())
                if type(recheck_time) is not int:
                    raise AccountDisclosureError()
                self._clear_expired_disclosure(recheck_time)
                if (epoch != self._disclosure_epoch or review.expires_at <= recheck_time
                        or review is not self._disclosure_review
                        or _review_fingerprint(review) != self._disclosure_review_fingerprint):
                    raise AccountDisclosureError()
                entity = _copy_master_account_entity(self._payload.get(_MASTER_ACCOUNT_ENTITY, {}))
                digest = _entity_digest(entity)
                if digest != review.entity_digest or self._payload.get("public_key") != review.owner_public_key or _PENDING_ACCOUNT_DISCLOSURE in self._payload:
                    raise AccountDisclosureError()
                created = recheck_time
                expiry = min(review.expires_at, created + 300)
                record = {
                    "version": 1, "state": "approved", "handle": _b64url_encode(secrets.token_bytes(32)),
                    "handle_digest": review.handle_digest, "context": _disclosure_context_payload(review.context),
                    "identity_id": review.identity_id, "owner_public_key": review.owner_public_key,
                    "approved_claim_ids": list(approved),
                    "approved_values": {cid: snapshot_values[cid] for cid in approved},
                    "created_at": created, "expires_at": expiry, "proof_issued": False,
                    "proof_challenge": None, "submission": None,
                }
                updated = dict(self._payload)
                updated[_PENDING_ACCOUNT_DISCLOSURE] = record
                envelope = self._build_envelope(updated)
                commit_time = int(time.time())
                if type(commit_time) is not int or commit_time < created or commit_time >= expiry:
                    raise AccountDisclosureError()
                self._persist_envelope(envelope)
                self._payload, self._envelope = updated, envelope
                self._disclosure_review = None
                self._disclosure_review_fingerprint = None
                release_time = int(time.time())
                if type(release_time) is not int or release_time < commit_time or release_time >= expiry:
                    try:
                        self._discard_disclosure(PendingAccountApproval(record["handle"], expiry))
                    except Exception:
                        self.lock()
                        raise AccountDisclosureError() from None
                    raise AccountDisclosureError()
                return PendingAccountApproval(record["handle"], expiry)
        except AccountDisclosureError:
            raise
        except WalletError:
            raise
        except Exception:
            raise AccountDisclosureError() from None

    def create_account_login_proof(self, pending: Any, *, challenge: str) -> Any:
        """Issue the unchanged four-member wallet-login proof exactly once."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from .account_issuance import AccountDisclosureError, PendingAccountApproval, WalletLoginProofRequest
        from .account_presentation import _jcs

        try:
            if not isinstance(pending, PendingAccountApproval):
                raise AccountDisclosureError()
            _decode_b64url_exact(challenge, 32)
            with self._rotation_lock:
                self._touch()
                self._ensure_rotation_dispatch_not_latched()
                instant = int(time.time())
                if type(instant) is not int:
                    raise AccountDisclosureError()
                self._clear_expired_disclosure(instant)
                record = self._disclosure_record(pending)
                if record["expires_at"] <= instant or record["state"] != "approved" or record["proof_issued"]:
                    raise AccountDisclosureError()
                seed = _WALLET_SECRETS.get(self._secret_handle)
                if seed is None or self._payload.get("public_key") != record["owner_public_key"]:
                    self._discard_disclosure(pending)
                    raise AccountDisclosureError()
                proof_body = {"profile": "decent-wallet-login-v1", "challenge": challenge, "identity_id": record["identity_id"]}
                signature = Ed25519PrivateKey.from_private_bytes(bytes(seed)).sign(_jcs(proof_body))
                proof = {**proof_body, "signature": _b64url_encode(signature)}
                updated_record = dict(record)
                updated_record["proof_issued"] = True
                updated_record["proof_challenge"] = challenge
                updated = dict(self._payload)
                updated[_PENDING_ACCOUNT_DISCLOSURE] = updated_record
                envelope = self._build_envelope(updated)
                commit_time = int(time.time())
                if type(commit_time) is not int or commit_time < instant or commit_time >= record["expires_at"]:
                    try:
                        self._discard_disclosure(pending)
                    except Exception:
                        self.lock()
                        raise AccountDisclosureError() from None
                    raise AccountDisclosureError()
                self._persist_envelope(envelope)
                self._payload, self._envelope = updated, envelope
                release_time = int(time.time())
                if type(release_time) is not int or release_time < commit_time or release_time >= record["expires_at"]:
                    try:
                        self._discard_disclosure(pending)
                    except Exception:
                        self.lock()
                        raise AccountDisclosureError() from None
                    raise AccountDisclosureError()
                return WalletLoginProofRequest(proof)
        except AccountDisclosureError:
            raise
        except WalletError:
            raise
        except Exception:
            raise AccountDisclosureError() from None

    def prepare_account_presentation(self, pending: Any, *, binding_jws: str, keycloak_jwks: dict[str, Any], outer_request: dict[str, Any], request_object: str, registration: Any) -> Any:
        """Re-verify raw OIDC binding and signed RP request, then persist exact dual JWS bytes."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from .account_disclosure import WalletAccountDisclosureContext, RequestedAccountClaim, verify_owner_key_binding
        from .account_issuance import AccountDisclosureError, AccountPresentationSubmission, PendingAccountApproval
        from .oid4vp_request import TrustedRPRegistration, verify_oid4vp_authorization_request
        from .account_presentation import _jcs

        invalidate_pending = True
        try:
            if not isinstance(pending, PendingAccountApproval) or not isinstance(registration, TrustedRPRegistration):
                raise AccountDisclosureError()
            instant = int(time.time())
            with self._rotation_lock:
                self._touch()
                self._ensure_rotation_dispatch_not_latched()
                record = self._disclosure_record(pending)
                if record["expires_at"] <= instant:
                    self._clear_expired_disclosure(instant)
                    raise AccountDisclosureError()
                if record["state"] != "approved" or not record["proof_issued"]:
                    invalidate_pending = False
                    raise AccountDisclosureError()
                context_raw = record["context"]
                context = WalletAccountDisclosureContext(
                    context_raw["keycloak_issuer"], context_raw["rp_client_id"], context_raw["rp_display_name"],
                    context_raw["rp_origin"], context_raw["action"], context_raw["request_id"],
                    context_raw["transaction_id"], context_raw["oidc_nonce"], context_raw["purpose"],
                    tuple(RequestedAccountClaim(c["id"], c["required"]) for c in context_raw["claims"]),
                    context_raw["expires_at"],
                )
                identity = record["identity_id"]
                binding = verify_owner_key_binding(binding_jws, keycloak_jwks, context, expected_identity_id=identity, now=instant)
                seed = _WALLET_SECRETS.get(self._secret_handle)
                pub = self._payload.get("public_key")
                if seed is None:
                    raise AccountDisclosureError()
                derived_pub = Ed25519PrivateKey.from_private_bytes(bytes(seed)).public_key().public_bytes(
                    serialization.Encoding.Raw, serialization.PublicFormat.Raw
                )
                binding_pub = base64.urlsafe_b64decode(binding.owner_key.x + "=" * (-len(binding.owner_key.x) % 4))
                if pub != derived_pub or pub != record["owner_public_key"] or binding_pub != derived_pub:
                    raise AccountDisclosureError()
                request = verify_oid4vp_authorization_request(
                    outer_request, request_object=request_object, registration=registration,
                    context=context, owner_key_binding_jws=binding_jws, verified_binding=binding, now=instant,
                )
                claims = dict(record["approved_values"])
                if set(claims) != set(record["approved_claim_ids"]):
                    raise AccountDisclosureError()
                for requested in context.claims:
                    if requested.required and requested.claim_id not in claims:
                        raise AccountDisclosureError()
                issued_at = instant
                expires_at = min(record["expires_at"], binding.expires_at, request.expires_at, issued_at + 300)
                if expires_at <= issued_at:
                    raise AccountDisclosureError()
                thumb = binding.owner_key_thumbprint
                credential = {
                    "profile": "decent-account-disclosure-v1", "credential_type": "decent_account_assertion_v1",
                    "iss": identity, "sub": identity, "iat": issued_at, "exp": expires_at,
                    "jti": _b64url_encode(secrets.token_bytes(32)), "action": context.action,
                    "rp_oidc_client_id": context.rp_client_id, "request_id": context.request_id,
                    "transaction_id": context.transaction_id, "purpose": context.purpose,
                    "owner_key_thumbprint": thumb, "owner_binding_jti": binding.jti, "claims": claims,
                }
                cred_header = {"alg": "EdDSA", "kid": thumb, "typ": "decent-account-credential+jwt"}
                credential_jws = _sign_account_jws(cred_header, credential, bytes(seed), _jcs)
                vp = {
                    "profile": "decent-account-disclosure-v1", "iss": identity, "sub": identity,
                    "aud": request.client_id, "nonce": request.nonce, "iat": issued_at,
                    "exp": expires_at, "jti": _b64url_encode(secrets.token_bytes(32)),
                    "vp": {"type": ["decent_account_presentation_v1"], "verifiableCredential": [credential_jws]},
                }
                vp_header = {"alg": "EdDSA", "kid": thumb, "typ": "decent-account-presentation+jwt"}
                presentation_jws = _sign_account_jws(vp_header, vp, bytes(seed), _jcs)
                if len(presentation_jws.encode("utf-8")) > 16 * 1024:
                    raise AccountDisclosureError()
                from .account_presentation import verify_account_presentation
                verify_account_presentation(
                    presentation_jws, context=context, binding=binding, request=request,
                    approved_claim_ids=record["approved_claim_ids"], approval_expires_at=record["expires_at"], now=instant,
                )
                import urllib.parse
                vp_token_json = json.dumps({"account": [presentation_jws]}, ensure_ascii=False, separators=(",", ":"))
                submission_body = urllib.parse.urlencode((
                    ("state", request.state), ("vp_token", vp_token_json),
                )).encode("ascii")
                submission = {"response_uri": request.response_uri, "state": request.state,
                              "presentation_jws": presentation_jws, "body": submission_body.decode("ascii"),
                              "expires_at": expires_at}
                updated_record = dict(record)
                updated_record["state"] = "prepared"
                updated_record["submission"] = submission
                updated = dict(self._payload)
                updated[_PENDING_ACCOUNT_DISCLOSURE] = updated_record
                envelope = self._build_envelope(updated)
                commit_time = int(time.time())
                if type(commit_time) is not int or commit_time < instant or commit_time >= expires_at:
                    raise AccountDisclosureError()
                self._persist_envelope(envelope)
                self._payload, self._envelope = updated, envelope
                release_time = int(time.time())
                if type(release_time) is not int or release_time < commit_time or release_time >= expires_at:
                    raise AccountDisclosureError()
                return AccountPresentationSubmission(pending, request.response_uri, request.state, presentation_jws, submission_body)
        except AccountDisclosureError:
            with self._rotation_lock:
                try:
                    if invalidate_pending and self.is_unlocked and isinstance(pending, PendingAccountApproval):
                        self._discard_disclosure(pending)
                except Exception:
                    self.lock()
            raise
        except WalletError:
            raise
        except Exception:
            with self._rotation_lock:
                try:
                    if invalidate_pending and self.is_unlocked and isinstance(pending, PendingAccountApproval):
                        self._discard_disclosure(pending)
                except Exception:
                    self.lock()
            raise AccountDisclosureError() from None

    def recover_account_presentation_retry(self) -> Any:
        """Explicitly classify an interrupted prepared send as ambiguous.

        Unlock plus this invocation authorizes recovery of *only* the already
        committed exact submission, even if the host lost its pending handle.
        It never recovers a login proof or creates a second presentation.
        """
        from .account_issuance import AccountDisclosureError, PendingAccountApproval, PresentationDeliveryOutcome

        with self._rotation_lock:
            self._touch()
            self._ensure_rotation_dispatch_not_latched()
            self._clear_expired_disclosure(int(time.time()))
            record = self._payload.get(_PENDING_ACCOUNT_DISCLOSURE)
            if type(record) is not dict or record["state"] not in {"prepared", "ambiguous"}:
                raise AccountDisclosureError()
            pending = PendingAccountApproval(record["handle"], record["expires_at"])
            if self.public_key != record["owner_public_key"]:
                self._discard_disclosure(pending)
                raise AccountDisclosureError()
            # Persist/validate the conservative transition before any retry bytes
            # escape. No file guard is held here: finish/get acquire it in order.
            self.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
            return self.get_account_presentation_retry(pending)

    def get_account_presentation_retry(self, pending: Any) -> Any:
        """Return only the immutable exact submission after an ambiguous send."""
        from .account_issuance import AccountDisclosureError, AccountPresentationSubmission, PendingAccountApproval
        try:
            with self._rotation_lock:
                self._touch()
                self._ensure_rotation_dispatch_not_latched()
                self._clear_expired_disclosure(int(time.time()))
                record = self._disclosure_record(pending)
                if self.public_key != record["owner_public_key"]:
                    self._discard_disclosure(pending)
                    raise AccountDisclosureError()
                try:
                    with _container_guard(self._path):
                        self._assert_disk_current()
                        record = self._disclosure_record(pending)
                        if _disclosure_expiry(record) <= int(time.time()) or record["state"] != "ambiguous" or not record["submission"]:
                            raise AccountDisclosureError()
                        if self.public_key != record["owner_public_key"]:
                            raise AccountDisclosureError()
                        saved = record["submission"]
                        return AccountPresentationSubmission(pending, saved["response_uri"], saved["state"], saved["presentation_jws"], saved["body"].encode("ascii"))
                except WalletError:
                    self.lock()
                    raise
        except (AccountDisclosureError, WalletError):
            raise
        except Exception:
            raise AccountDisclosureError() from None

    def finish_account_presentation(self, pending: Any, outcome: Any, *, status_code: int | None = None, content_type: str | None = None, response_body: bytes | None = None) -> None:
        """Finalize, retain exact bytes only for ambiguous sends, or consume accepted result."""
        import json
        from .account_issuance import AccountDisclosureError, PresentationDeliveryOutcome
        try:
            outcome = PresentationDeliveryOutcome(outcome)
            with self._rotation_lock:
                self._touch()
                self._clear_expired_disclosure(int(time.time()))
                record = self._disclosure_record(pending)
                if record["state"] not in {"prepared", "ambiguous"} or record["expires_at"] <= int(time.time()):
                    raise AccountDisclosureError()
                if outcome is PresentationDeliveryOutcome.ACCEPTED:
                    if type(status_code) is not int or status_code != 200 or not _is_json_media_type(content_type) or type(response_body) is not bytes:
                        raise AccountDisclosureError()
                    response = _strict_disclosure_json(response_body)
                    uri = response.get("redirect_uri") if type(response) is dict else None
                    if type(uri) is not str or not uri:
                        raise AccountDisclosureError()
                    record_context = record["context"]
                    parsed = __import__("urllib.parse", fromlist=["urlsplit", "parse_qs"]).urlsplit(uri)
                    parse_qs = __import__("urllib.parse", fromlist=["parse_qs"]).parse_qs
                    fragment = parse_qs(parsed.fragment, keep_blank_values=True, strict_parsing=True)
                    origin = f"{parsed.scheme}://{parsed.netloc}"
                    if (origin != record_context["rp_origin"] or parsed.query or set(fragment) != {"response_code"}
                            or len(fragment["response_code"]) != 1):
                        raise AccountDisclosureError()
                    _decode_b64url_exact(fragment["response_code"][0], 32)
                updated = dict(self._payload)
                if outcome is PresentationDeliveryOutcome.AMBIGUOUS:
                    changed = dict(record)
                    changed["state"] = "ambiguous"
                    updated[_PENDING_ACCOUNT_DISCLOSURE] = changed
                else:
                    updated.pop(_PENDING_ACCOUNT_DISCLOSURE, None)
                envelope = self._build_envelope(updated)
                try:
                    self._persist_envelope(envelope)
                except WalletError:
                    self.lock()
                    raise
                self._payload, self._envelope = updated, envelope
        except (AccountDisclosureError, WalletError):
            raise
        except Exception:
            raise AccountDisclosureError() from None

    def cancel_account_disclosure(self, pending: Any) -> None:
        from .account_issuance import AccountDisclosureError
        with self._rotation_lock:
            self._touch()
            try:
                self._disclosure_record(pending)
            except Exception:
                raise AccountDisclosureError() from None
            try:
                self._discard_disclosure(pending)
            except Exception:
                self.lock()
                raise AccountDisclosureError() from None

    def _discard_disclosure(self, pending: Any) -> None:
        self._disclosure_record(pending)
        updated = dict(self._payload)
        updated.pop(_PENDING_ACCOUNT_DISCLOSURE, None)
        envelope = self._build_envelope(updated)
        self._persist_envelope(envelope)
        self._payload, self._envelope = updated, envelope

    def _disclosure_record(self, pending: Any) -> dict[str, Any]:
        record = self._payload.get(_PENDING_ACCOUNT_DISCLOSURE)
        if (type(record) is not dict or record.get("handle") != getattr(pending, "handle", None)
                or record.get("expires_at") != getattr(pending, "expires_at", None)):
            raise ValueError
        return record

    def _clear_expired_disclosure(self, now: int) -> None:
        record = self._payload.get(_PENDING_ACCOUNT_DISCLOSURE)
        if type(record) is dict and type(record.get("expires_at")) is int and _disclosure_expiry(record) <= now:
            try:
                updated = dict(self._payload)
                updated.pop(_PENDING_ACCOUNT_DISCLOSURE, None)
                envelope = self._build_envelope(updated)
                self._persist_envelope(envelope)
                self._payload, self._envelope = updated, envelope
            except Exception:
                # A failed expiry invalidation must not leave the expired approval
                # usable if this process's wall clock later moves backward.
                self.lock()
                raise

    def update_payload(self, payload: Mapping[str, Any]) -> None:
        """Replace wallet-local content and atomically persist it."""
        with self._rotation_lock:
            self._update_payload(payload)

    def _update_payload(self, payload: Mapping[str, Any]) -> None:
        self._touch()
        if (
            not isinstance(payload, Mapping)
            or _SIGNING_FIELDS.intersection(payload)
            or _MASTER_ACCOUNT_ENTITY in payload
            or _PENDING_ACCOUNT_DISCLOSURE in payload
        ):
            raise InvalidContainer()
        updated_payload = dict(payload)
        if _MASTER_ACCOUNT_ENTITY in self._payload:
            updated_payload[_MASTER_ACCOUNT_ENTITY] = self._payload[
                _MASTER_ACCOUNT_ENTITY
            ]
        if _PENDING_ACCOUNT_DISCLOSURE in self._payload:
            updated_payload[_PENDING_ACCOUNT_DISCLOSURE] = self._payload[_PENDING_ACCOUNT_DISCLOSURE]
        if self._secret_handle in _WALLET_SECRETS:
            updated_payload["public_key"] = self._payload["public_key"]
        if self._secret_handle in _PENDING_WALLET_SECRETS:
            updated_payload[_PENDING_PUBLIC_KEY] = self._payload[_PENDING_PUBLIC_KEY]
        if _ROTATION_DISPATCH_INTENT in self._payload:
            updated_payload[_ROTATION_DISPATCH_INTENT] = self._payload[
                _ROTATION_DISPATCH_INTENT
            ]
        envelope = self._build_envelope(updated_payload)
        self._persist_envelope(envelope)
        self._payload = updated_payload
        self._envelope = envelope
        self._invalidate_capabilities()

    def export_container(self) -> bytes:
        """Return the exact encrypted container bytes for explicit transfer."""
        with self._rotation_lock:
            return self._export_container()

    def _export_container(self) -> bytes:
        self._touch()
        self._clear_expired_disclosure(int(time.time()))
        if _is_active_disclosure_record(self._payload.get(_PENDING_ACCOUNT_DISCLOSURE), int(time.time())):
            from .account_issuance import AccountDisclosureError
            raise AccountDisclosureError()
        raw = _read(self._path)
        envelope = _parse_container(raw)
        if envelope != self._envelope:
            raise InvalidContainer()
        return raw

    def change_password(self, password: str, confirmation: str) -> None:
        """Rewrap the DEK without re-encrypting the authenticated payload."""
        with self._rotation_lock:
            self._change_password(password, confirmation)

    def _change_password(self, password: str, confirmation: str) -> None:
        self._touch()
        _validate_password(password, confirmation)
        salt = secrets.token_bytes(_SALT_LENGTH)
        kdf = _kdf_header(salt)
        kek = _derive_kek(password, salt)
        try:
            dek = self._dek
            if dek is None:
                raise WalletLockedError()
            wrapped = _wrap_dek(bytes(kek), bytes(dek), kdf)
        finally:
            _wipe(kek)
        current_payload = self._envelope["payload"]
        envelope = {
            "format": _FORMAT,
            "version": CURRENT_FORMAT_VERSION,
            "kdf": kdf,
            "wrap": {
                **wrapped[0],
                "ciphertext": _b64_encode(wrapped[1]),
                "tag": _b64_encode(wrapped[2]),
            },
            "payload": current_payload,
        }
        self._persist_envelope(envelope)
        self._envelope = envelope

    def _persist_envelope(self, envelope: dict[str, Any]) -> None:
        known_failure = False
        try:
            with _container_guard(self._path):
                self._assert_disk_current()
                data = _serialize(envelope)
                try:
                    _write_verified(self._path, data)
                except StorageFailure:
                    known_failure = True
                    raise
        except WalletError:
            if not known_failure:
                self.lock()
            raise

    def _assert_disk_current(self) -> None:
        """Call only while holding the stable container guard."""
        try:
            if _read_envelope(self._path) != self._envelope:
                raise StorageFailure()
        except Exception:
            self.lock()
            raise StorageFailure() from None

    def _invalidate_capabilities(self) -> None:
        for capability in tuple(self._capabilities):
            capability.invalidate()
        self._capabilities.clear()

    def lock(self) -> None:
        with self._rotation_lock:
            self._lock()

    def _lock(self) -> None:
        self._disclosure_epoch += 1
        self._disclosure_review = None
        self._disclosure_review_fingerprint = None
        self._invalidate_capabilities()
        self._secret_finalizer.detach()
        seed = _WALLET_SECRETS.pop(self._secret_handle, None)
        if seed is not None:
            _wipe(seed)
        pending_seed = _PENDING_WALLET_SECRETS.pop(self._secret_handle, None)
        if pending_seed is not None:
            _wipe(pending_seed)
        _wipe(self._dek)
        self._dek = None
        self._payload = {}
        self._envelope = {}

    def background(self) -> None:
        self.lock()

    def check_inactivity(self, *, now: float | None = None) -> bool:
        if not self.is_unlocked:
            return True
        current = time.monotonic() if now is None else now
        if current - self._last_activity >= self._inactivity_seconds:
            self.lock()
            return True
        return False

    def __repr__(self) -> str:
        return f"Wallet(unlocked={self.is_unlocked})"

    def _touch(self) -> None:
        self._require_unlocked()
        if self.check_inactivity():
            raise WalletLockedError()
        self._last_activity = time.monotonic()

    def _require_unlocked(self) -> None:
        if self._dek is None:
            raise WalletLockedError()

    def _ensure_rotation_dispatch_not_latched(self) -> None:
        if _ROTATION_DISPATCH_INTENT in self._payload:
            raise RotationInProgress()

    def _build_envelope(
        self,
        payload: Mapping[str, Any],
        *,
        pending_seed_override: bytearray | None = None,
        active_seed_override: bytearray | None = None,
        include_pending: bool = True,
    ) -> dict[str, Any]:
        self._require_unlocked()
        salt = _b64_decode(self._envelope["kdf"]["salt"], _SALT_LENGTH)
        kdf = _kdf_header(salt)
        wrap = self._envelope["wrap"]
        dek = self._dek
        if dek is None:
            raise WalletLockedError()
        payload_for_storage = dict(payload)
        seed = (
            active_seed_override
            if active_seed_override is not None
            else _WALLET_SECRETS.get(self._secret_handle)
        )
        if seed is not None:
            payload_for_storage["private_seed"] = bytes(seed)
            if active_seed_override is None:
                payload_for_storage["public_key"] = self._payload["public_key"]
        if include_pending:
            pending_seed = (
                pending_seed_override
                if pending_seed_override is not None
                else _PENDING_WALLET_SECRETS.get(self._secret_handle)
            )
            if pending_seed is not None:
                pending_public_key = payload_for_storage.get(_PENDING_PUBLIC_KEY)
                if type(pending_public_key) is not bytes or len(pending_public_key) != _KEY_LENGTH:
                    raise InvalidContainer()
                payload_for_storage[_PENDING_PRIVATE_SEED] = bytes(pending_seed)
                payload_for_storage[_PENDING_PUBLIC_KEY] = pending_public_key
        else:
            payload_for_storage.pop(_PENDING_PRIVATE_SEED, None)
            payload_for_storage.pop(_PENDING_PUBLIC_KEY, None)
        payload_info, ciphertext, tag = _make_payload(bytes(dek), payload_for_storage)
        return {
            "format": _FORMAT,
            "version": CURRENT_FORMAT_VERSION,
            "kdf": kdf,
            "wrap": wrap,
            "payload": {
                **payload_info,
                "ciphertext": _b64_encode(ciphertext),
                "tag": _b64_encode(tag),
            },
        }


def _validate_inactivity(minutes: int) -> None:
    if type(minutes) is not int or not 1 <= minutes <= 15:
        raise InvalidContainer()

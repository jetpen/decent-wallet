"""Versioned encrypted wallet storage with a small, deep interface.

The module keeps wallet content inside authenticated ciphertext and exposes
only public metadata. Secret lifetime in a managed runtime is best effort:
mutable buffers are wiped where practical, while callers must not retain or
copy secret-bearing values supplied to the wallet.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import secrets
import tempfile
import time
import weakref
from collections.abc import Mapping
from threading import Lock
from pathlib import Path
from typing import Any

from argon2 import Type
from argon2.low_level import hash_secret_raw
from Crypto.Cipher import ChaCha20_Poly1305


CURRENT_FORMAT_VERSION = 1
_FORMAT = "decent-wallet"
_KDF_MEMORY_KIB = 64 * 1024
_KDF_TIME_COST = 3
_KDF_PARALLELISM = 4
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
_SIGNING_FIELDS = {"private_seed", "public_key"}


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


def _wipe(buffer: bytearray | None) -> None:
    if buffer is not None:
        buffer[:] = b"\x00" * len(buffer)


def _finalize_wallet_secret(handle: object) -> None:
    seed = _WALLET_SECRETS.pop(handle, None)
    if seed is not None:
        _wipe(seed)


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


def _wrap_aad(kdf: dict[str, Any]) -> bytes:
    return _canonical_json({"format": _FORMAT, "version": CURRENT_FORMAT_VERSION, "kdf": kdf})


def _payload_aad(payload_info: dict[str, Any]) -> bytes:
    return _canonical_json({"format": _FORMAT, "version": CURRENT_FORMAT_VERSION, "payload": payload_info})


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


def _make_payload(dek: bytes, payload: Mapping[str, Any]) -> tuple[dict[str, str], bytes, bytes]:
    encoded = _canonical_json(_encode_value(dict(payload)))
    info = {"algorithm": "xchacha20-poly1305", "nonce": _b64_encode(secrets.token_bytes(_NONCE_LENGTH))}
    nonce = _b64_decode(info["nonce"], _NONCE_LENGTH)
    try:
        cipher = ChaCha20_Poly1305.new(key=dek, nonce=nonce)
        cipher.update(_payload_aad(info))
        ciphertext, tag = cipher.encrypt_and_digest(encoded)
    except Exception:
        raise StorageFailure() from None
    return info, ciphertext, tag


def _wrap_dek(kek: bytes, dek: bytes, kdf: dict[str, Any]) -> tuple[dict[str, str], bytes, bytes]:
    return _seal(kek, dek, _wrap_aad(kdf))


def _fsync_directory(directory: Path) -> None:
    directory_fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _stage_file(path: Path, data: bytes, *, replace: bool) -> None:
    directory = path.parent
    temporary_path: Path | None = None
    fd: int | None = None
    linked_target = False
    try:
        fd, name = tempfile.mkstemp(prefix=".decent-wallet-", dir=directory)
        temporary_path = Path(name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            fd = None
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
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


def _atomic_write(path: Path, data: bytes, *, replace: bool = True) -> None:
    previous_data: bytes | None = None
    if replace and path.exists():
        try:
            previous_data = path.read_bytes()
        except OSError:
            raise StorageFailure() from None
    try:
        _stage_file(path, data, replace=replace)
        try:
            _fsync_directory(path.parent)
        except OSError:
            # A directory fsync can fail after the rename has succeeded. Put
            # the last valid bytes back before reporting storage failure.
            if previous_data is not None:
                try:
                    _stage_file(path, previous_data, replace=True)
                except OSError:
                    pass
            else:
                try:
                    path.unlink()
                except OSError:
                    pass
            raise StorageFailure() from None
    except WalletError:
        raise
    except (OSError, ValueError):
        raise StorageFailure() from None


def _serialize(envelope: dict[str, Any]) -> bytes:
    return _canonical_json(envelope)


def _parse_container(raw: bytes) -> dict[str, Any]:
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
    if version != CURRENT_FORMAT_VERSION:
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


def _decode_payload(envelope: dict[str, Any], dek: bytes) -> dict[str, Any]:
    payload = envelope["payload"]
    info = {"algorithm": payload["algorithm"], "nonce": payload["nonce"]}
    ciphertext = _b64_decode(payload["ciphertext"])
    tag = _b64_decode(payload["tag"], _TAG_LENGTH)
    plaintext = bytearray(_open(dek, ciphertext, tag, info, _payload_aad(info)))
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


def _unlock_envelope(envelope: dict[str, Any], password: str) -> tuple[bytearray, dict[str, Any]]:
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
            _wrap_aad(envelope["kdf"]),
        )
        dek = bytearray(dek_bytes)
        if len(dek) != _KEY_LENGTH:
            raise UnlockFailed()
        payload = _decode_payload(envelope, bytes(dek))
        return dek, payload
    except Exception:
        _wipe(dek)
        raise
    finally:
        _wipe(kek)


def _read_envelope(path: Path) -> dict[str, Any]:
    return _parse_container(_read(path))


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
        self._dek = dek
        self._secret_handle = object()
        self._secret_finalizer = weakref.finalize(
            self,
            _finalize_wallet_secret,
            self._secret_handle,
        )
        self._payload = dict(payload)
        self._install_secret_material()
        self._envelope = envelope
        self._capabilities: set[Any] = set()
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
        return cls._create_storage(
            path,
            password,
            confirmation,
            payload,
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
        target = Path(path)
        created = False
        dek = bytearray()
        try:
            dek = bytearray(secrets.token_bytes(_KEY_LENGTH))
            salt = secrets.token_bytes(_SALT_LENGTH)
            kdf = _kdf_header(salt)
            kek = _derive_kek(password, salt)
            try:
                wrapped = _wrap_dek(bytes(kek), bytes(dek), kdf)
            finally:
                _wipe(kek)
            payload_info, ciphertext, tag = _make_payload(bytes(dek), payload)
            envelope = {
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
            _atomic_write(target, _serialize(envelope), replace=False)
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
        target = Path(path)
        envelope = _read_envelope(target)
        try:
            dek, payload = _unlock_envelope(envelope, password)
        except UnlockFailed:
            _record_unlock_failure(target)
            raise
        _clear_unlock_failures(target)
        return cls(target, dek, payload, envelope, inactivity_minutes)

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
        target = Path(path)
        envelope = _parse_container(data)
        wallet: Wallet | None = None
        dek: bytearray | None = None
        try:
            try:
                dek, payload = _unlock_envelope(envelope, password)
            except UnlockFailed:
                _record_unlock_failure(target)
                raise
            _clear_unlock_failures(target)
            wallet = cls(target, dek, payload, envelope, inactivity_minutes)
            _atomic_write(target, data, replace=False)
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
        if seed is None:
            return
        from .signer import _public_key_from_seed

        public_key = self._payload.get("public_key")
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
        _WALLET_SECRETS[self._secret_handle] = bytearray(seed)

    @property
    def is_unlocked(self) -> bool:
        return self._dek is not None

    @property
    def public_key(self) -> bytes:
        from .signer import SignerUnavailable, _public_key_from_seed

        self._touch()
        seed = _WALLET_SECRETS.get(self._secret_handle)
        stored_public_key = self._payload.get("public_key")
        if seed is None or type(stored_public_key) is not bytes:
            raise SignerUnavailable()
        if len(seed) != _KEY_LENGTH or len(stored_public_key) != _KEY_LENGTH:
            raise SignerUnavailable()
        try:
            derived_public_key = _public_key_from_seed(bytes(seed))
        except Exception:
            raise SignerUnavailable() from None
        if stored_public_key != derived_public_key:
            raise SignerUnavailable()
        return derived_public_key

    def create_signer(self, *, timeout_seconds: float = 60.0) -> Any:
        from .signer import SignerUnavailable, _create_capability_from_seed

        self._touch()
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
    def last_activity(self) -> float:
        self._require_unlocked()
        return self._last_activity

    def update_payload(self, payload: Mapping[str, Any]) -> None:
        """Replace wallet-local content and atomically persist it."""
        self._touch()
        if not isinstance(payload, Mapping) or _SIGNING_FIELDS.intersection(payload):
            raise InvalidContainer()
        updated_payload = dict(payload)
        if self._secret_handle in _WALLET_SECRETS:
            updated_payload["public_key"] = self._payload["public_key"]
        envelope = self._build_envelope(updated_payload)
        _atomic_write(self._path, _serialize(envelope))
        self._payload = updated_payload
        self._envelope = envelope
        self._invalidate_capabilities()

    def export_container(self) -> bytes:
        """Return the exact encrypted container bytes for explicit transfer."""
        self._touch()
        raw = _read(self._path)
        envelope = _parse_container(raw)
        if envelope != self._envelope:
            raise InvalidContainer()
        return raw

    def change_password(self, password: str, confirmation: str) -> None:
        """Rewrap the DEK without re-encrypting the authenticated payload."""
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
        _atomic_write(self._path, _serialize(envelope))
        self._envelope = envelope

    def _invalidate_capabilities(self) -> None:
        for capability in tuple(self._capabilities):
            capability.invalidate()
        self._capabilities.clear()

    def lock(self) -> None:
        self._invalidate_capabilities()
        self._secret_finalizer.detach()
        seed = _WALLET_SECRETS.pop(self._secret_handle, None)
        if seed is not None:
            _wipe(seed)
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

    def _build_envelope(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._require_unlocked()
        salt = _b64_decode(self._envelope["kdf"]["salt"], _SALT_LENGTH)
        kdf = _kdf_header(salt)
        wrap = self._envelope["wrap"]
        dek = self._dek
        if dek is None:
            raise WalletLockedError()
        payload_for_storage = dict(payload)
        seed = _WALLET_SECRETS.get(self._secret_handle)
        if seed is not None:
            payload_for_storage["private_seed"] = bytes(seed)
            payload_for_storage["public_key"] = self._payload["public_key"]
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

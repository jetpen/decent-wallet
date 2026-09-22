"""CSRNG-only Ed25519 generation and one-operation Identity signing."""

from __future__ import annotations

import hashlib
import secrets
import time
from collections.abc import Callable
from threading import RLock, Timer
from typing import Any

import cbor2
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


_KEY_LENGTH = 32
_SIGNATURE_LENGTH = 64
_DEFAULT_TIMEOUT_SECONDS = 60.0
_APPROVED_CSRNG = secrets.token_bytes
_CONSTRUCTOR_TOKEN = object()
_AUTHORIZATION_KEYS = set(range(1, 8))
_SIGNER_ENTRY_KEYS = {1, 2}
_OPERATION_VALUES = {1, 2, 3, 4}
_SIGNER_ID_MAX_BYTES = 256
_ZERO_STATE_HASH_LENGTH = 32
_PRIVATE_KEYS: dict[object, Ed25519PrivateKey] = {}


class SignerError(Exception):
    """Base class for stable, value-free signing failures."""

    message = "signing operation failed"

    def __init__(self) -> None:
        super().__init__(self.message)

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


class KeyGenerationError(SignerError):
    message = "key generation failed"


class SignerUnavailable(SignerError):
    message = "signer unavailable"


class InvalidSigningInput(SignerError):
    message = "signing input rejected"


def _generate_seed() -> bytearray:
    """Get exactly one 32-byte seed through the approved CSRNG seam."""
    if secrets.token_bytes is not _APPROVED_CSRNG:
        raise KeyGenerationError()
    try:
        seed = secrets.token_bytes(_KEY_LENGTH)
    except Exception:
        raise KeyGenerationError() from None
    if type(seed) is not bytes or len(seed) != _KEY_LENGTH:
        raise KeyGenerationError()
    return bytearray(seed)


def _public_key_from_seed(seed: bytes) -> bytes:
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        return private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except Exception:
        raise KeyGenerationError() from None


def _require_exact_int_keys(value: Any, expected: set[int]) -> None:
    if not isinstance(value, dict):
        raise InvalidSigningInput()
    keys = list(value.keys())
    if any(type(key) is not int for key in keys) or set(keys) != expected:
        raise InvalidSigningInput()


def _require_uint(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidSigningInput()
    return value


def _validate_authorization(authorization: Any, signer_public_key: bytes) -> None:
    _require_exact_int_keys(authorization, _AUTHORIZATION_KEYS)
    if _require_uint(authorization[1]) != 1 or _require_uint(authorization[2]) != 1:
        raise InvalidSigningInput()
    if _require_uint(authorization[3]) not in _OPERATION_VALUES:
        raise InvalidSigningInput()
    _require_uint(authorization[4])
    threshold = _require_uint(authorization[5])
    entries = authorization[6]
    if not isinstance(entries, list) or not entries:
        raise InvalidSigningInput()
    seen_ids: set[str] = set()
    seen_keys: set[bytes] = set()
    previous_id: bytes | None = None
    signer_keys: set[bytes] = set()
    for entry in entries:
        _require_exact_int_keys(entry, _SIGNER_ENTRY_KEYS)
        signer_id = entry[1]
        public_key = entry[2]
        if not isinstance(signer_id, str) or not signer_id:
            raise InvalidSigningInput()
        signer_id_bytes = signer_id.encode("utf-8")
        if len(signer_id_bytes) > _SIGNER_ID_MAX_BYTES:
            raise InvalidSigningInput()
        if previous_id is not None and signer_id_bytes <= previous_id:
            raise InvalidSigningInput()
        previous_id = signer_id_bytes
        if type(public_key) is not bytes or len(public_key) != _KEY_LENGTH:
            raise InvalidSigningInput()
        if signer_id in seen_ids or public_key in seen_keys:
            raise InvalidSigningInput()
        seen_ids.add(signer_id)
        seen_keys.add(public_key)
        signer_keys.add(public_key)
    if threshold < 1 or threshold > len(entries):
        raise InvalidSigningInput()
    predecessor = authorization[7]
    if type(predecessor) is not bytes or len(predecessor) != _ZERO_STATE_HASH_LENGTH:
        raise InvalidSigningInput()
    # Replacement proofs are authorized by the predecessor signer set; the
    # successor set may intentionally remove the signer performing this call.
    if signer_public_key not in signer_keys and authorization[3] != 3:
        raise InvalidSigningInput()


def _validate_identity_update(data: bytes, signer_public_key: bytes) -> None:
    if type(data) is not bytes or not data:
        raise InvalidSigningInput()
    try:
        decoded = cbor2.loads(data)
        if cbor2.dumps(decoded, canonical=True) != data:
            raise InvalidSigningInput()
    except InvalidSigningInput:
        raise
    except Exception:
        raise InvalidSigningInput() from None
    if not isinstance(decoded, dict):
        raise InvalidSigningInput()
    decoded_keys = set(decoded.keys())
    if any(type(key) is not int for key in decoded.keys()) or decoded_keys not in ({1, 2, 3}, {1, 2, 3, 4}):
        raise InvalidSigningInput()
    record = decoded.get(1)
    if not isinstance(record, dict):
        raise InvalidSigningInput()
    _require_exact_int_keys(record, {1, 2})
    if type(record.get(1)) is not bytes or not record[1]:
        raise InvalidSigningInput()
    if type(record.get(2)) is not bytes or len(record[2]) != _KEY_LENGTH:
        raise InvalidSigningInput()
    if decoded.get(2) != {} or _require_uint(decoded.get(3)) < 0:
        raise InvalidSigningInput()
    if 4 in decoded:
        _validate_authorization(decoded[4], signer_public_key)
    elif record[2] != signer_public_key:
        raise InvalidSigningInput()


def _wipe(buffer: bytearray) -> None:
    buffer[:] = b"\x00" * len(buffer)


class SignerCapability:
    """Wallet-owned, one-operation Ed25519 capability.

    The capability accepts only canonical Identity SignedUpdate bytes. It
    exposes the raw public key and signature, never the private key or seed.
    """

    __slots__ = (
        "_handle",
        "_public_key",
        "_expires_at",
        "_active",
        "_on_invalidate",
        "_timeout_timer",
        "_use_lock",
    )

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        public_key: bytes,
        timeout_seconds: float,
        on_invalidate: Callable[["SignerCapability"], None] | None,
        *,
        _token: object | None = None,
    ) -> None:
        if _token is not _CONSTRUCTOR_TOKEN:
            raise SignerUnavailable()
        self._handle = object()
        _PRIVATE_KEYS[self._handle] = private_key
        self._public_key = public_key
        self._use_lock = RLock()
        self._expires_at = time.monotonic() + timeout_seconds
        self._active = True
        self._on_invalidate = on_invalidate
        self._timeout_timer = Timer(timeout_seconds, self.invalidate)
        self._timeout_timer.daemon = True
        self._timeout_timer.start()

    @property
    def public_key(self) -> bytes:
        return self._public_key

    @property
    def is_active(self) -> bool:
        with self._use_lock:
            if self._active and time.monotonic() >= self._expires_at:
                self._invalidate_unlocked()
            return self._active

    def sign_identity_update(self, canonical_update: bytes) -> bytes:
        with self._use_lock:
            self._assert_active()
            try:
                _validate_identity_update(canonical_update, self._public_key)
                digest = hashlib.sha256(canonical_update).digest()
                key = _PRIVATE_KEYS.get(self._handle)
                if key is None:
                    raise SignerUnavailable()
                signature = key.sign(digest)
                if type(signature) is not bytes or len(signature) != _SIGNATURE_LENGTH:
                    raise SignerError()
                return signature
            except InvalidSigningInput:
                raise
            except SignerError:
                raise
            except Exception:
                raise SignerError() from None
            finally:
                self._invalidate_unlocked()

    def cancel(self) -> None:
        self.invalidate()

    def invalidate(self) -> None:
        with self._use_lock:
            self._invalidate_unlocked()

    def _invalidate_unlocked(self) -> None:
        if not self._active and self._handle is None:
            return
        self._active = False
        self._expires_at = 0.0
        _PRIVATE_KEYS.pop(self._handle, None)
        self._handle = None
        timer = self._timeout_timer
        self._timeout_timer = None
        if timer is not None:
            timer.cancel()
        callback = self._on_invalidate
        self._on_invalidate = None
        if callback is not None:
            callback(self)

    def __getstate__(self) -> dict[str, Any]:
        raise TypeError("signer capabilities are not serializable")

    def __reduce__(self) -> Any:
        raise TypeError("signer capabilities are not serializable")

    def __repr__(self) -> str:
        return f"SignerCapability(active={self.is_active})"

    def _assert_active(self) -> None:
        if not self._active:
            raise SignerUnavailable()
        if time.monotonic() >= self._expires_at:
            self.invalidate()
            raise SignerUnavailable()
        if self._handle is None or self._handle not in _PRIVATE_KEYS:
            raise SignerUnavailable()


def _create_capability_from_seed(
    seed: bytes,
    *,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    on_invalidate: Callable[[SignerCapability], None] | None = None,
) -> SignerCapability:
    if type(seed) is not bytes or len(seed) != _KEY_LENGTH:
        raise SignerUnavailable()
    if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 900:
        raise SignerUnavailable()
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(seed)
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except Exception:
        raise SignerUnavailable() from None
    return SignerCapability(
        private_key,
        public_key,
        float(timeout_seconds),
        on_invalidate,
        _token=_CONSTRUCTOR_TOKEN,
    )

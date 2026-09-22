from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock
from typing import Any, Callable, Mapping, Protocol, TYPE_CHECKING

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if TYPE_CHECKING:
    from .signer import SignerCapability


_KEY_LENGTH = 32
_SIGNATURE_LENGTH = 64
_AUTHORIZATION_KEYS = set(range(1, 8))
_SIGNER_ENTRY_KEYS = {1, 2}
_OPERATION_VALUES = {1, 2, 3, 4}
_OPERATION_NAMES = {
    1: "genesis",
    2: "ordinary-update",
    3: "replace-signers",
    4: "upgrade",
}


class IdentityAdapterError(Exception):
    """Base class for privacy-safe Identity adapter failures."""


class InvalidIdentityState(IdentityAdapterError):
    """The Registry returned malformed or unverifiable public state."""


class InvalidIdentityRequest(IdentityAdapterError):
    """The requested public Identity transition is invalid."""


class TransportFailure(IdentityAdapterError):
    """The public transport failed without exposing provider details."""


class StalePublication(IdentityAdapterError):
    """The transport rejected a conditional write against changed state."""


class ExpiredPublication(IdentityAdapterError):
    """The transport rejected a write whose consent deadline elapsed."""


class ConsentDecision(StrEnum):
    APPROVED = "approved"
    DENIED = "denied"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    FAILED = "failed"


class PublishStatus(StrEnum):
    CONFIRMED = "confirmed"
    PROOF_READY = "proof-ready"
    UNKNOWN = "unknown"
    FAILED = "failed"
    STALE = "stale"
    DENIED = "denied"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class DispatchUnknown(Exception):
    """The transport cannot determine whether publication was accepted."""


class IdentityTransport(Protocol):
    """Public-only transport boundary for Identity envelopes.

    A conditional write with ``expected_state_hash=None`` means that the
    lookup key must still be absent. The transport must enforce this
    precondition atomically with publication. It must also reject the write
    atomically when ``expires_at`` has elapsed, before accepting the envelope.
    """

    def get_identity_envelope(self, *, owner_name_hex: str) -> bytes | None:
        ...

    def put_identity_envelope(
        self,
        *,
        owner_name_hex: str,
        envelope_cbor: bytes,
        expected_state_hash: bytes | None,
        expires_at: int,
    ) -> None:
        ...


class ReplayNonceStore(Protocol):
    """Atomic replay-nonce consumption boundary.

    Applications can provide a durable implementation to preserve replay
    protection across adapter restarts.
    """

    def consume(self, key: bytes) -> bool:
        ...


class InMemoryReplayNonceStore:
    """Thread-safe process-local replay store for isolated applications/tests."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._consumed: set[bytes] = set()

    def consume(self, key: bytes) -> bool:
        with self._lock:
            if key in self._consumed:
                return False
            self._consumed.add(key)
            return True


ConsentHandler = Callable[["ConsentTranscript"], ConsentDecision | str]
SignerFactory = Callable[[], "SignerCapability"]


@dataclass(frozen=True, slots=True)
class ConsentTranscript:
    """Immutable, non-secret description of one consent item."""

    authenticated_origin: str
    environment: str
    operation: str
    payload_hash: bytes
    purpose: str
    capability: str
    expires_at: int
    replay_nonce: bytes
    sequence: int
    generation: int | None
    signer_id: str | None = None
    signer_public_key: bytes | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.authenticated_origin, str) or not self.authenticated_origin:
            raise InvalidIdentityRequest()
        if not isinstance(self.environment, str) or not self.environment:
            raise InvalidIdentityRequest()
        if not isinstance(self.operation, str) or not self.operation:
            raise InvalidIdentityRequest()
        if not isinstance(self.purpose, str) or not self.purpose:
            raise InvalidIdentityRequest()
        if not isinstance(self.capability, str) or not self.capability:
            raise InvalidIdentityRequest()
        _require_uint(self.expires_at)
        _require_uint(self.sequence)
        _require_bytes(self.payload_hash, length=_KEY_LENGTH)
        _require_bytes(self.replay_nonce, nonempty=True)
        if self.generation is not None:
            _require_uint(self.generation)
        if self.signer_id is not None:
            if not isinstance(self.signer_id, str) or not self.signer_id:
                raise InvalidIdentityRequest()
        if self.signer_public_key is not None:
            _require_bytes(self.signer_public_key, length=_KEY_LENGTH)
        elif self.signer_id is not None:
            raise InvalidIdentityRequest()

    def canonical_bytes(self) -> bytes:
        value: dict[int, Any] = {
            1: self.authenticated_origin,
            2: self.environment,
            3: self.operation,
            4: self.payload_hash,
            5: self.purpose,
            6: self.capability,
            7: self.expires_at,
            8: self.replay_nonce,
            9: self.sequence,
        }
        if self.generation is not None:
            value[10] = self.generation
        if self.signer_id is not None:
            value[11] = self.signer_id
        if self.signer_public_key is not None:
            value[12] = self.signer_public_key
        return cbor2.dumps(value, canonical=True)

    @property
    def digest(self) -> bytes:
        return hashlib.sha256(self.canonical_bytes()).digest()


@dataclass(frozen=True, slots=True)
class IdentityState:
    """Verified public state read from a finalized Identity envelope."""

    owner_name: bytes
    owner_public_key: bytes
    sequence: int
    signed_update_bytes: bytes
    envelope_bytes: bytes
    state_hash: bytes
    generation: int | None
    threshold: int | None
    signer_set: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    status: PublishStatus
    transcript: ConsentTranscript
    envelope_bytes: bytes | None = None
    signed_update_bytes: bytes | None = None
    proof_bytes: bytes | None = None
    accepted_state: IdentityState | None = None
    reason: str | None = None


def _require_uint(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise InvalidIdentityRequest()
    return value


def _require_bytes(
    value: Any, *, length: int | None = None, nonempty: bool = False
) -> bytes:
    if not isinstance(value, bytes):
        raise InvalidIdentityRequest()
    if length is not None and len(value) != length:
        raise InvalidIdentityRequest()
    if nonempty and not value:
        raise InvalidIdentityRequest()
    return value


def _require_exact_keys(value: Any, expected: set[int]) -> dict[int, Any]:
    if not isinstance(value, dict):
        raise InvalidIdentityState()
    if any(type(key) is not int for key in value) or set(value) != expected:
        raise InvalidIdentityState()
    return value


def _validate_owner_name(value: Any) -> bytes:
    if not isinstance(value, bytes) or not value:
        raise InvalidIdentityRequest()
    try:
        value.decode("utf-8")
    except UnicodeDecodeError:
        raise InvalidIdentityRequest() from None
    return value


def _canonical(data: Any) -> bytes:
    return cbor2.dumps(data, canonical=True)


def _require_canonical(data: bytes) -> Any:
    if not isinstance(data, bytes) or not data:
        raise InvalidIdentityState()
    try:
        decoded = cbor2.loads(data)
        if _canonical(decoded) != data:
            raise InvalidIdentityState()
        return decoded
    except InvalidIdentityState:
        raise
    except Exception:
        raise InvalidIdentityState() from None


def _validate_authorization(value: Any) -> dict[int, Any]:
    auth = _require_exact_keys(value, _AUTHORIZATION_KEYS)
    if _require_uint(auth[1]) != 1 or _require_uint(auth[2]) != 1:
        raise InvalidIdentityState()
    operation = _require_uint(auth[3])
    if operation not in _OPERATION_VALUES:
        raise InvalidIdentityState()
    epoch = _require_uint(auth[4])
    threshold = _require_uint(auth[5])
    signer_set = auth[6]
    if not isinstance(signer_set, list) or not signer_set:
        raise InvalidIdentityState()

    normalized: list[dict[int, Any]] = []
    seen_ids: set[str] = set()
    seen_keys: set[bytes] = set()
    for entry in signer_set:
        entry = _require_exact_keys(entry, _SIGNER_ENTRY_KEYS)
        signer_id = entry[1]
        public_key = _require_bytes(entry[2], length=_KEY_LENGTH)
        if not isinstance(signer_id, str) or not signer_id:
            raise InvalidIdentityState()
        try:
            signer_id_bytes = signer_id.encode("utf-8")
        except UnicodeEncodeError:
            raise InvalidIdentityState() from None
        if len(signer_id_bytes) > 256:
            raise InvalidIdentityState()
        if signer_id in seen_ids or public_key in seen_keys:
            raise InvalidIdentityState()
        seen_ids.add(signer_id)
        seen_keys.add(public_key)
        normalized.append({1: signer_id, 2: public_key})

    ordered = sorted(normalized, key=lambda entry: entry[1].encode("utf-8"))
    if normalized != ordered or not 1 <= threshold <= len(normalized):
        raise InvalidIdentityState()
    predecessor = _require_bytes(auth[7], length=_KEY_LENGTH)
    return {
        1: 1,
        2: 1,
        3: operation,
        4: epoch,
        5: threshold,
        6: normalized,
        7: predecessor,
    }


def _decode_signed_update(
    signed_update_bytes: bytes,
) -> tuple[dict[int, Any], dict[int, Any], int, dict[int, Any] | None]:
    decoded = _require_canonical(signed_update_bytes)
    if not isinstance(decoded, dict):
        raise InvalidIdentityState()
    if any(type(key) is not int for key in decoded):
        raise InvalidIdentityState()
    if set(decoded) not in ({1, 2, 3}, {1, 2, 3, 4}):
        raise InvalidIdentityState()
    record = _require_exact_keys(decoded[1], {1, 2})
    payload = _require_exact_keys(decoded[2], set())
    sequence = _require_uint(decoded[3])
    authorization = None
    if 4 in decoded:
        authorization = _validate_authorization(decoded[4])
    return record, payload, sequence, authorization


def build_identity_update(
    *,
    owner_name: bytes,
    owner_public_key: bytes,
    sequence: int,
    authorization: Mapping[int, Any] | None = None,
) -> bytes:
    """Build exact canonical legacy or version-1 Identity SignedUpdate bytes."""
    owner_name = _validate_owner_name(owner_name)
    _require_bytes(owner_public_key, length=_KEY_LENGTH)
    _require_uint(sequence)
    record = {1: owner_name, 2: owner_public_key}
    value: dict[int, Any] = {1: record, 2: {}, 3: sequence}
    if authorization is not None:
        auth = _validate_authorization(dict(authorization))
        value[4] = auth
    return _canonical(value)


def _verify_signature(public_key: bytes, update: bytes, signature: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, hashlib.sha256(update).digest()
        )
    except (InvalidSignature, ValueError):
        raise InvalidIdentityState() from None


def _parse_identity_envelope(
    *,
    owner_name: bytes,
    envelope_bytes: bytes,
    previous_state: IdentityState | None = None,
) -> IdentityState:
    outer = _require_canonical(envelope_bytes)
    if not isinstance(outer, dict):
        raise InvalidIdentityState()
    if any(type(key) is not int for key in outer):
        raise InvalidIdentityState()

    if set(outer) == {1, 2}:
        update_bytes = _require_bytes(outer[1])
        signature = _require_bytes(outer[2], length=_SIGNATURE_LENGTH)
        record, payload, sequence, authorization = _decode_signed_update(update_bytes)
        if authorization is not None or payload or record[1] != owner_name:
            raise InvalidIdentityState()
        public_key = _require_bytes(record[2], length=_KEY_LENGTH)
        _verify_signature(public_key, update_bytes, signature)
        return IdentityState(
            owner_name=owner_name,
            owner_public_key=public_key,
            sequence=sequence,
            signed_update_bytes=update_bytes,
            envelope_bytes=envelope_bytes,
            state_hash=hashlib.sha256(update_bytes).digest(),
            generation=None,
            threshold=None,
            signer_set=(),
        )

    if set(outer) != {1, 2, 3} or type(outer[1]) is not int or outer[1] != 1:
        raise InvalidIdentityState()
    update_bytes = _require_bytes(outer[2])
    proofs = outer[3]
    record, payload, sequence, authorization = _decode_signed_update(update_bytes)
    if authorization is None or payload or record[1] != owner_name:
        raise InvalidIdentityState()
    signer_entries = authorization[6]
    operation = authorization[3]
    if operation == 1:
        if authorization[4] != 1 or authorization[7] != bytes(_KEY_LENGTH):
            raise InvalidIdentityState()
        if authorization[5] != 2 or len(signer_entries) != 3:
            raise InvalidIdentityState()
    elif operation == 4:
        if authorization[4] != 1 or authorization[5] != 2 or len(signer_entries) != 3:
            raise InvalidIdentityState()
    elif operation == 3:
        if authorization[5] != 2 or len(signer_entries) != 3:
            raise InvalidIdentityState()
    elif operation != 2:
        raise InvalidIdentityState()
    proof_list = _validate_proof_list(proofs)
    if operation == 4 and len(proof_list) != 1:
        raise InvalidIdentityState()
    candidate_keys = {entry[1]: entry[2] for entry in signer_entries}
    previous_keys = dict(previous_state.signer_set) if previous_state is not None else {}
    verification_keys = previous_keys if operation == 3 and previous_keys else candidate_keys
    valid_signers: set[str] = set()
    for proof in proof_list:
        signer_id = proof[1]
        public_key = verification_keys.get(signer_id)
        if public_key is None:
            if operation != 3 or previous_state is not None:
                raise InvalidIdentityState()
            continue
        _verify_signature(public_key, update_bytes, proof[2])
        valid_signers.add(signer_id)
    if operation != 3 and len(valid_signers) < authorization[5]:
        raise InvalidIdentityState()
    if operation == 3 and len(proof_list) < authorization[5]:
        raise InvalidIdentityState()
    public_key = _require_bytes(record[2], length=_KEY_LENGTH)
    return IdentityState(
        owner_name=owner_name,
        owner_public_key=public_key,
        sequence=sequence,
        signed_update_bytes=update_bytes,
        envelope_bytes=envelope_bytes,
        state_hash=hashlib.sha256(update_bytes).digest(),
        generation=authorization[4],
        threshold=authorization[5],
        signer_set=tuple((entry[1], entry[2]) for entry in signer_entries),
    )


def _validate_proof_list(proofs: Any) -> list[dict[int, Any]]:
    if not isinstance(proofs, list):
        raise InvalidIdentityState()
    normalized: list[dict[int, Any]] = []
    seen: set[str] = set()
    for proof in proofs:
        proof = _require_exact_keys(proof, {1, 2})
        signer_id = proof[1]
        if not isinstance(signer_id, str) or not signer_id:
            raise InvalidIdentityState()
        signature = _require_bytes(proof[2], length=_SIGNATURE_LENGTH)
        try:
            signer_id.encode("utf-8")
        except UnicodeEncodeError:
            raise InvalidIdentityState() from None
        if signer_id in seen:
            raise InvalidIdentityState()
        seen.add(signer_id)
        normalized.append({1: signer_id, 2: signature})
    if normalized != sorted(normalized, key=lambda item: item[1].encode("utf-8")):
        raise InvalidIdentityState()
    return normalized


def _legacy_envelope(update: bytes, signature: bytes) -> bytes:
    return _canonical({1: update, 2: signature})


def _versioned_envelope(update: bytes, signer_id: str, signature: bytes) -> bytes:
    return _canonical({1: 1, 2: update, 3: [{1: signer_id, 2: signature}]})


def _normalize_consent(value: ConsentDecision | str) -> ConsentDecision:
    try:
        return ConsentDecision(value)
    except (TypeError, ValueError):
        return ConsentDecision.FAILED


def _require_complete_2_of_3(auth: dict[int, Any]) -> None:
    if auth[5] != 2 or len(auth[6]) != 3:
        raise InvalidIdentityRequest()


def _signer_map(entries: list[dict[int, Any]]) -> dict[str, bytes]:
    return {entry[1]: entry[2] for entry in entries}


def _validate_transition(
    *,
    current: IdentityState | None,
    auth: dict[int, Any],
    signer_id: str,
    signer_public_key: bytes,
) -> None:
    operation = auth[3]
    predecessor = auth[7]
    if current is None:
        if operation != 1 or auth[4] != 1 or predecessor != bytes(_KEY_LENGTH):
            raise InvalidIdentityRequest()
        _require_complete_2_of_3(auth)
        if _signer_map(auth[6]).get(signer_id) != signer_public_key:
            raise InvalidIdentityRequest()
        return

    if not current.signer_set:
        if operation != 4 or auth[4] != 1 or predecessor != current.state_hash:
            raise InvalidIdentityRequest()
        _require_complete_2_of_3(auth)
        if signer_public_key != current.owner_public_key:
            raise InvalidIdentityRequest()
        if _signer_map(auth[6]).get(signer_id) != signer_public_key:
            raise InvalidIdentityRequest()
        return

    current_signers = dict(current.signer_set)
    if operation == 2:
        if auth[4] != current.generation or auth[5] != current.threshold:
            raise InvalidIdentityRequest()
        if tuple((entry[1], entry[2]) for entry in auth[6]) != current.signer_set:
            raise InvalidIdentityRequest()
        if current_signers.get(signer_id) != signer_public_key:
            raise InvalidIdentityRequest()
        return
    if operation == 3:
        if auth[4] <= (current.generation or 0):
            raise InvalidIdentityRequest()
        _require_complete_2_of_3(auth)
        if tuple((entry[1], entry[2]) for entry in auth[6]) == current.signer_set:
            raise InvalidIdentityRequest()
        if current_signers.get(signer_id) != signer_public_key:
            raise InvalidIdentityRequest()
        return
    raise InvalidIdentityRequest()


class RegistryAdapter:
    """Build, consent-gate, sign, and publish Identity envelopes.

    The transport receives only owner-name hex, canonical public envelopes, and
    no wallet object or private material. It must implement independent readback
    for confirmation after publication.
    """

    def __init__(
        self,
        transport: IdentityTransport,
        replay_store: ReplayNonceStore | None = None,
    ) -> None:
        self._transport = transport
        self._replay_store = replay_store or InMemoryReplayNonceStore()

    def read_state(self, *, owner_name: bytes) -> IdentityState | None:
        owner_name = _validate_owner_name(owner_name)
        try:
            envelope = self._transport.get_identity_envelope(
                owner_name_hex=owner_name.hex()
            )
        except Exception:
            raise TransportFailure() from None
        if envelope is None:
            return None
        return _parse_identity_envelope(owner_name=owner_name, envelope_bytes=envelope)

    def _reserve_replay_nonce(
        self,
        *,
        owner_name: bytes,
        authenticated_origin: str,
        environment: str,
        replay_nonce: bytes,
    ) -> bool:
        key = hashlib.sha256(
            _canonical(
                {
                    1: owner_name,
                    2: authenticated_origin,
                    3: environment,
                    4: replay_nonce,
                }
            )
        ).digest()
        return self._replay_store.consume(key)

    def submit_identity(
        self,
        *,
        owner_name: bytes,
        owner_public_key: bytes,
        signer_public_key: bytes,
        signer_factory: SignerFactory,
        consent: ConsentHandler,
        authenticated_origin: str,
        environment: str,
        operation: str,
        purpose: str,
        capability: str,
        expires_at: int,
        replay_nonce: bytes,
        authorization: Mapping[int, Any] | None = None,
        signer_id: str | None = None,
    ) -> SubmissionResult:
        """Submit one explicitly consented Identity update without auto-retry."""
        _require_bytes(owner_public_key, length=_KEY_LENGTH)
        _require_bytes(signer_public_key, length=_KEY_LENGTH)
        current = self.read_state(owner_name=owner_name)
        sequence = 1 if current is None else current.sequence + 1
        authorization_epoch: int | None = None
        auth: dict[int, Any] | None = None

        if current is not None and current.owner_public_key != owner_public_key:
            raise InvalidIdentityRequest()
        if authorization is None and current is not None and current.signer_set:
            raise InvalidIdentityRequest()
        if authorization is None and signer_public_key != owner_public_key:
            raise InvalidIdentityRequest()
        record_public_key = owner_public_key
        if authorization is not None:
            auth = _validate_authorization(dict(authorization))
            if operation != _OPERATION_NAMES[auth[3]]:
                raise InvalidIdentityRequest()
            authorization_epoch = auth[4]
            if current is not None and auth[7] != current.state_hash:
                raise InvalidIdentityRequest()
            if current is None and auth[7] != bytes(_KEY_LENGTH):
                raise InvalidIdentityRequest()
            if signer_id is None or not isinstance(signer_id, str) or not signer_id:
                raise InvalidIdentityRequest()
            _validate_transition(
                current=current,
                auth=auth,
                signer_id=signer_id,
                signer_public_key=signer_public_key,
            )
            update = build_identity_update(
                owner_name=owner_name,
                owner_public_key=record_public_key,
                sequence=sequence,
                authorization=auth,
            )
        else:
            if signer_id is not None:
                raise InvalidIdentityRequest()
            update = build_identity_update(
                owner_name=owner_name,
                owner_public_key=record_public_key,
                sequence=sequence,
            )

        transcript = ConsentTranscript(
            authenticated_origin=authenticated_origin,
            environment=environment,
            operation=operation,
            payload_hash=hashlib.sha256(update).digest(),
            purpose=purpose,
            capability=capability,
            expires_at=expires_at,
            replay_nonce=replay_nonce,
            sequence=sequence,
            generation=(authorization_epoch if authorization is not None else (current.generation if current else None)),
            signer_id=signer_id,
            signer_public_key=signer_public_key,
        )
        try:
            replay_available = self._reserve_replay_nonce(
                owner_name=owner_name,
                authenticated_origin=authenticated_origin,
                environment=environment,
                replay_nonce=replay_nonce,
            )
        except Exception:
            return SubmissionResult(
                status=PublishStatus.FAILED,
                transcript=transcript,
                reason="replay protection unavailable",
            )
        if not replay_available:
            return SubmissionResult(
                status=PublishStatus.FAILED,
                transcript=transcript,
                reason="replay rejected",
            )
        if expires_at <= int(time.time()):
            return SubmissionResult(
                status=PublishStatus.EXPIRED,
                transcript=transcript,
                reason="consent expired",
            )
        try:
            decision = _normalize_consent(consent(transcript))
        except Exception:
            decision = ConsentDecision.FAILED
        if decision is not ConsentDecision.APPROVED:
            status = {
                ConsentDecision.DENIED: PublishStatus.DENIED,
                ConsentDecision.CANCELLED: PublishStatus.CANCELLED,
                ConsentDecision.EXPIRED: PublishStatus.EXPIRED,
            }.get(decision, PublishStatus.FAILED)
            return SubmissionResult(status=status, transcript=transcript, reason=decision.value)
        if expires_at <= int(time.time()):
            return SubmissionResult(
                status=PublishStatus.EXPIRED,
                transcript=transcript,
                reason="consent expired",
            )

        latest = self.read_state(owner_name=owner_name)
        if not _same_state(current, latest):
            return SubmissionResult(
                status=PublishStatus.STALE,
                transcript=transcript,
                reason="accepted state changed before signing",
            )
        if expires_at <= int(time.time()):
            return SubmissionResult(
                status=PublishStatus.EXPIRED,
                transcript=transcript,
                reason="consent expired",
            )

        signer = None
        try:
            signer = signer_factory()
            if signer.public_key != signer_public_key:
                raise InvalidIdentityRequest()
            if expires_at <= int(time.time()) or not getattr(signer, "is_active", True):
                signer.invalidate()
                return SubmissionResult(
                    status=PublishStatus.EXPIRED,
                    transcript=transcript,
                    reason="consent expired",
                )
            signature = signer.sign_identity_update(update)
            if type(signature) is not bytes or len(signature) != _SIGNATURE_LENGTH:
                raise InvalidIdentityRequest()
            _verify_signature(signer_public_key, update, signature)
        except InvalidIdentityRequest:
            if signer is not None:
                signer.invalidate()
            return SubmissionResult(
                status=PublishStatus.FAILED,
                transcript=transcript,
                reason="signing failed",
            )
        except Exception:
            if signer is not None:
                signer.invalidate()
            return SubmissionResult(
                status=PublishStatus.FAILED,
                transcript=transcript,
                reason="signing failed",
            )

        latest = self.read_state(owner_name=owner_name)
        if not _same_state(current, latest):
            return SubmissionResult(
                status=PublishStatus.STALE,
                transcript=transcript,
                signed_update_bytes=update,
                reason="accepted state changed before publication",
            )
        if expires_at <= int(time.time()):
            return SubmissionResult(
                status=PublishStatus.EXPIRED,
                transcript=transcript,
                signed_update_bytes=update,
                reason="consent expired",
            )

        if auth is not None and auth[5] > 1:
            if signer_id is None:
                raise InvalidIdentityRequest()
            proof = _canonical({1: signer_id, 2: signature})
            return SubmissionResult(
                status=PublishStatus.PROOF_READY,
                transcript=transcript,
                signed_update_bytes=update,
                proof_bytes=proof,
                reason="threshold bundle required",
            )

        if authorization is None:
            envelope = _legacy_envelope(update, signature)
        else:
            if signer_id is None:
                raise InvalidIdentityRequest()
            envelope = _versioned_envelope(update, signer_id, signature)

        owner_name_hex = owner_name.hex()
        expected_state_hash = current.state_hash if current is not None else None
        try:
            self._transport.put_identity_envelope(
                owner_name_hex=owner_name_hex,
                envelope_cbor=envelope,
                expected_state_hash=expected_state_hash,
                expires_at=expires_at,
            )
        except StalePublication:
            return SubmissionResult(
                status=PublishStatus.STALE,
                transcript=transcript,
                envelope_bytes=envelope,
                reason="conditional publication rejected",
            )
        except ExpiredPublication:
            return SubmissionResult(
                status=PublishStatus.EXPIRED,
                transcript=transcript,
                envelope_bytes=envelope,
                reason="consent expired",
            )
        except Exception:
            accepted = self._confirm(
                owner_name=owner_name,
                envelope=envelope,
                previous_state=current,
            )
            return SubmissionResult(
                status=PublishStatus.CONFIRMED if accepted else PublishStatus.UNKNOWN,
                transcript=transcript,
                envelope_bytes=envelope,
                accepted_state=accepted,
                reason="independent readback required",
            )

        accepted = self._confirm(
            owner_name=owner_name,
            envelope=envelope,
            previous_state=current,
        )
        return SubmissionResult(
            status=PublishStatus.CONFIRMED if accepted else PublishStatus.UNKNOWN,
            transcript=transcript,
            envelope_bytes=envelope,
            accepted_state=accepted,
            reason=None if accepted else "readback did not confirm exact envelope",
        )

    def _confirm(
        self,
        *,
        owner_name: bytes,
        envelope: bytes,
        previous_state: IdentityState | None,
    ) -> IdentityState | None:
        owner_name = _validate_owner_name(owner_name)
        try:
            candidate = self._transport.get_identity_envelope(
                owner_name_hex=owner_name.hex()
            )
            if candidate is None:
                return None
            state = _parse_identity_envelope(
                owner_name=owner_name,
                envelope_bytes=candidate,
                previous_state=previous_state,
            )
        except Exception:
            return None
        if state.envelope_bytes == envelope:
            return state
        return None


def _same_state(left: IdentityState | None, right: IdentityState | None) -> bool:
    if left is None or right is None:
        return left is right
    return left.state_hash == right.state_hash and left.envelope_bytes == right.envelope_bytes

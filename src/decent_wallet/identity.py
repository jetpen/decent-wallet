from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from enum import StrEnum
from threading import Lock, RLock
from typing import Any, Callable, Mapping, Protocol, TYPE_CHECKING

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if TYPE_CHECKING:
    from .container import RotationDispatchIntent, RotationDispatchPermit
    from .signer import SignerCapability


_KEY_LENGTH = 32
_SIGNATURE_LENGTH = 64
_MAX_PREDECESSOR_DEPTH = 1024
_AUTHORIZATION_KEYS = set(range(1, 8))
_SIGNER_ENTRY_KEYS = {1, 2}
_OPERATION_VALUES = {1, 2, 3, 4, 5}
_OPERATION_NAMES = {
    1: "genesis",
    2: "ordinary-update",
    3: "replace-signers",
    4: "upgrade",
    5: "owner-key-rotation",
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
    READY = "ready"
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
    Every non-genesis version-1 state requires retained predecessor lookup by
    state hash back to its signed anchor; incomplete history is rejected.
    ``supports_owner_key_rotation`` must be true only when this adapter targets
    a Registry deployment that validates operation 5 and implements the fresh
    remote read method below.
    """

    supports_owner_key_rotation: bool

    def get_identity_envelope(self, *, owner_name_hex: str) -> bytes | None:
        ...

    def get_identity_envelope_by_hash(
        self,
        *,
        owner_name_hex: str,
        state_hash: bytes,
    ) -> bytes | None:
        """Return a retained public predecessor envelope for transition checks."""
        ...

    def get_remote_identity_envelope(self, *, owner_name_hex: str) -> bytes | None:
        """Read from a fresh remote source, bypassing local and write-through caches.

        The result is evidence from one remote DHT response, not proof of
        network-wide replication. Owner-key promotion requires this read path.
        """
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
    review_payload: bytes
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
        _require_bytes(self.review_payload, nonempty=True)
        if hashlib.sha256(self.review_payload).digest() != self.payload_hash:
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
        value[13] = self.review_payload
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
    predecessor_envelopes: tuple[bytes, ...] = ()


def _parse_previous_state_chain(
    *,
    owner_name: bytes,
    envelope: bytes | None,
    history: tuple[bytes, ...],
) -> IdentityState | None:
    if envelope is None:
        if history:
            raise InvalidIdentityRequest()
        return None
    previous = None
    for predecessor_envelope in reversed(history):
        previous = _parse_identity_envelope(
            owner_name=owner_name,
            envelope_bytes=predecessor_envelope,
            previous_state=previous,
        )
    return _parse_identity_envelope(
        owner_name=owner_name,
        envelope_bytes=envelope,
        previous_state=previous,
    )


@dataclass(frozen=True, slots=True)
class IdentityDraft:
    """Immutable public Identity update draft, optionally bound to prior state."""

    signed_update_bytes: bytes
    previous_state_envelope: bytes | None = None
    previous_state_history: tuple[bytes, ...] = ()

    def __post_init__(self) -> None:
        record, payload, sequence, authorization = _decode_signed_update(
            self.signed_update_bytes
        )
        if (
            payload
            or not isinstance(self.previous_state_history, tuple)
            or len(self.previous_state_history) > _MAX_PREDECESSOR_DEPTH
        ):
            raise InvalidIdentityRequest()
        if any(type(envelope) is not bytes for envelope in self.previous_state_history):
            raise InvalidIdentityRequest()
        owner_name = _validate_owner_name(record[1])
        owner_public_key = _require_bytes(record[2], length=_KEY_LENGTH)
        previous = _parse_previous_state_chain(
            owner_name=owner_name,
            envelope=self.previous_state_envelope,
            history=self.previous_state_history,
        )
        _validate_draft_transition(
            owner_name=owner_name,
            owner_public_key=owner_public_key,
            sequence=sequence,
            authorization=authorization,
            previous_state=previous,
        )

    @classmethod
    def create(
        cls,
        *,
        owner_name: bytes,
        owner_public_key: bytes,
        sequence: int,
        authorization: Mapping[int, Any] | None = None,
        previous_state_envelope: bytes | None = None,
        previous_state_history: tuple[bytes, ...] = (),
    ) -> "IdentityDraft":
        return cls(
            signed_update_bytes=build_identity_update(
                owner_name=owner_name,
                owner_public_key=owner_public_key,
                sequence=sequence,
                authorization=authorization,
            ),
            previous_state_envelope=previous_state_envelope,
            previous_state_history=previous_state_history,
        )

    @property
    def owner_name(self) -> bytes:
        return _decode_signed_update(self.signed_update_bytes)[0][1]

    @property
    def owner_public_key(self) -> bytes:
        return _decode_signed_update(self.signed_update_bytes)[0][2]

    @property
    def sequence(self) -> int:
        return _decode_signed_update(self.signed_update_bytes)[2]

    @property
    def authorization(self) -> dict[int, Any] | None:
        authorization = _decode_signed_update(self.signed_update_bytes)[3]
        return authorization

    def validate_owner_key_rotation_binding(
        self,
        *,
        predecessor_owner_public_key: bytes,
        successor_owner_public_key: bytes,
    ) -> None:
        """Require this draft to rotate between the supplied public keys."""
        if (
            type(predecessor_owner_public_key) is not bytes
            or len(predecessor_owner_public_key) != _KEY_LENGTH
            or type(successor_owner_public_key) is not bytes
            or len(successor_owner_public_key) != _KEY_LENGTH
        ):
            raise InvalidIdentityRequest()
        authorization = self.authorization
        previous = _draft_previous_state(self)
        if (
            authorization is None
            or authorization[3] != 5
            or previous is None
            or previous.owner_public_key != predecessor_owner_public_key
            or self.owner_public_key != successor_owner_public_key
        ):
            raise InvalidIdentityRequest()

    def to_cbor(self) -> bytes:
        return _canonical(
            {
                1: 2,
                2: self.signed_update_bytes,
                3: self.previous_state_envelope,
                4: list(self.previous_state_history),
            }
        )

    @classmethod
    def from_cbor(cls, data: bytes) -> "IdentityDraft":
        try:
            value = _require_canonical(data)
            value = _require_exact_keys(value, {1, 2, 3, 4})
            if type(value[1]) is not int or value[1] not in (1, 2):
                raise InvalidIdentityRequest()
            if value[3] is not None and type(value[3]) is not bytes:
                raise InvalidIdentityRequest()
            if value[1] == 1:
                if value[4] is None:
                    history = ()
                elif type(value[4]) is bytes:
                    history = (value[4],)
                else:
                    raise InvalidIdentityRequest()
            else:
                if not isinstance(value[4], list) or any(
                    type(item) is not bytes for item in value[4]
                ):
                    raise InvalidIdentityRequest()
                history = tuple(value[4])
            return cls(value[2], value[3], history)
        except InvalidIdentityRequest:
            raise
        except Exception:
            raise InvalidIdentityRequest() from None


def _draft_previous_state(draft: IdentityDraft) -> IdentityState | None:
    return _parse_previous_state_chain(
        owner_name=draft.owner_name,
        envelope=draft.previous_state_envelope,
        history=draft.previous_state_history,
    )


@dataclass(frozen=True, slots=True)
class IdentityProof:
    """Detached public proof bound to its declared signer identity."""

    signer_id: str | None
    signer_public_key: bytes
    signature: bytes

    def __post_init__(self) -> None:
        if self.signer_id is not None:
            if not isinstance(self.signer_id, str) or not self.signer_id:
                raise InvalidIdentityRequest()
            try:
                signer_id_bytes = self.signer_id.encode("utf-8")
            except UnicodeEncodeError:
                raise InvalidIdentityRequest() from None
            if len(signer_id_bytes) > 256:
                raise InvalidIdentityRequest()
        _require_bytes(self.signer_public_key, length=_KEY_LENGTH)
        _require_bytes(self.signature, length=_SIGNATURE_LENGTH)


@dataclass(frozen=True, slots=True)
class SubmissionResult:
    status: PublishStatus
    transcript: ConsentTranscript
    envelope_bytes: bytes | None = None
    signed_update_bytes: bytes | None = None
    proof_bytes: bytes | None = None
    accepted_state: IdentityState | None = None
    reason: str | None = None
    draft: IdentityDraft | None = None
    identity_proof: IdentityProof | None = None


@dataclass(frozen=True, slots=True)
class PublicationResult:
    status: PublishStatus
    envelope_bytes: bytes | None = None
    accepted_state: IdentityState | None = None
    reason: str | None = None
    publication: RotationPublication | None = None


@dataclass(frozen=True, slots=True)
class IdentityBundle:
    """Public draft and detached proofs exchanged outside Registry state."""

    draft: IdentityDraft
    proofs: tuple[IdentityProof, ...] = ()

    def __post_init__(self) -> None:
        if (
            not isinstance(self.draft, IdentityDraft)
            or not isinstance(self.proofs, tuple)
            or any(not isinstance(proof, IdentityProof) for proof in self.proofs)
        ):
            raise InvalidIdentityRequest()
        if self.proofs != tuple(sorted(self.proofs, key=_proof_order)):
            raise InvalidIdentityRequest()
        signer_ids = [proof.signer_id for proof in self.proofs]
        if len(signer_ids) != len(set(signer_ids)):
            raise InvalidIdentityRequest()

    @classmethod
    def from_submission(cls, result: SubmissionResult) -> "IdentityBundle":
        if (
            result.status is not PublishStatus.PROOF_READY
            or result.draft is None
            or result.identity_proof is None
        ):
            raise InvalidIdentityRequest()
        return cls(result.draft, (result.identity_proof,))

    def merge(self, other: "IdentityBundle") -> "IdentityBundle":
        if not isinstance(other, IdentityBundle) or self.draft != other.draft:
            raise InvalidIdentityRequest()
        combined = self.proofs + other.proofs
        signer_ids = [proof.signer_id for proof in combined]
        if len(signer_ids) != len(set(signer_ids)):
            raise InvalidIdentityRequest()
        return IdentityBundle(self.draft, tuple(sorted(combined, key=_proof_order)))

    def to_cbor(self) -> bytes:
        return _canonical(
            {
                1: 2,
                2: self.draft.to_cbor(),
                3: [
                    {
                        1: proof.signer_id,
                        2: proof.signer_public_key,
                        3: proof.signature,
                    }
                    for proof in self.proofs
                ],
            }
        )

    @classmethod
    def from_cbor(cls, data: bytes) -> "IdentityBundle":
        try:
            value = _require_canonical(data)
            value = _require_exact_keys(value, {1, 2, 3})
            if type(value[1]) is not int or value[1] not in (1, 2) or type(value[2]) is not bytes:
                raise InvalidIdentityRequest()
            if not isinstance(value[3], list):
                raise InvalidIdentityRequest()
            proofs = tuple(
                IdentityProof(
                    signer_id=_require_exact_keys(item, {1, 2, 3})[1],
                    signer_public_key=item[2],
                    signature=item[3],
                )
                for item in value[3]
            )
            if proofs != tuple(sorted(proofs, key=_proof_order)):
                raise InvalidIdentityRequest()
            return cls(IdentityDraft.from_cbor(value[2]), proofs)
        except InvalidIdentityRequest:
            raise
        except Exception:
            raise InvalidIdentityRequest() from None

    def finalize(self) -> bytes:
        previous_state = _draft_previous_state(self.draft)
        if not self.proofs:
            raise InvalidIdentityRequest()
        record, payload, _sequence, authorization = _decode_signed_update(
            self.draft.signed_update_bytes
        )
        if payload:
            raise InvalidIdentityRequest()
        if authorization is None:
            if len(self.proofs) != 1:
                raise InvalidIdentityRequest()
            proof = self.proofs[0]
            if proof.signer_id is not None or proof.signer_public_key != record[2]:
                raise InvalidIdentityRequest()
            _verify_bundle_signature(
                proof.signer_public_key,
                self.draft.signed_update_bytes,
                proof.signature,
            )
            envelope = _legacy_envelope(self.draft.signed_update_bytes, proof.signature)
        else:
            operation = authorization[3]
            rotation_predecessor_owner_key = (
                previous_state.owner_public_key
                if operation == 5
                and previous_state is not None
                and not previous_state.signer_set
                else None
            )
            rotation_from_legacy = rotation_predecessor_owner_key is not None
            if operation == 3 or (operation == 5 and not rotation_from_legacy):
                if previous_state is None or not previous_state.signer_set:
                    raise InvalidIdentityRequest()
                authorized_keys = dict(previous_state.signer_set)
            elif rotation_from_legacy:
                if previous_state is None:
                    raise InvalidIdentityRequest()
                authorized_keys = {}
            else:
                authorized_keys = _signer_map(authorization[6])
            valid_signers: set[str] = set()
            proof_values: list[dict[int, Any]] = []
            for proof in self.proofs:
                if rotation_from_legacy:
                    if rotation_predecessor_owner_key is None:
                        raise InvalidIdentityRequest()
                    if (
                        proof.signer_id is not None
                        or proof.signer_public_key != rotation_predecessor_owner_key
                    ):
                        raise InvalidIdentityRequest()
                    _verify_bundle_signature(
                        proof.signer_public_key,
                        self.draft.signed_update_bytes,
                        proof.signature,
                    )
                    proof_values.append({1: None, 2: proof.signature})
                    continue
                if proof.signer_id is None:
                    raise InvalidIdentityRequest()
                expected_key = authorized_keys.get(proof.signer_id)
                if expected_key is None or expected_key != proof.signer_public_key:
                    raise InvalidIdentityRequest()
                _verify_bundle_signature(
                    expected_key,
                    self.draft.signed_update_bytes,
                    proof.signature,
                )
                valid_signers.add(proof.signer_id)
                proof_values.append({1: proof.signer_id, 2: proof.signature})
            if operation == 4:
                if (
                    len(self.proofs) != 1
                    or len(valid_signers) != 1
                    or self.proofs[0].signer_public_key != record[2]
                ):
                    raise InvalidIdentityRequest()
            elif rotation_from_legacy:
                if len(self.proofs) != 1:
                    raise InvalidIdentityRequest()
            elif len(valid_signers) < authorization[5]:
                raise InvalidIdentityRequest()
            envelope = _canonical({1: 1, 2: self.draft.signed_update_bytes, 3: proof_values})
        try:
            _parse_identity_envelope(
                owner_name=self.draft.owner_name,
                envelope_bytes=envelope,
                previous_state=previous_state,
            )
        except InvalidIdentityState:
            raise InvalidIdentityRequest() from None
        return envelope


@dataclass(frozen=True, slots=True)
class _RotationBinding:
    owner_name: bytes
    predecessor_owner_public_key: bytes
    successor_owner_public_key: bytes
    predecessor_state_hash: bytes
    sequence: int
    envelope_hash: bytes


def _rotation_binding(value: Any) -> _RotationBinding | None:
    owner_name = getattr(value, "owner_name", None)
    predecessor_owner_public_key = getattr(
        value, "predecessor_owner_public_key", None
    )
    successor_owner_public_key = getattr(value, "successor_owner_public_key", None)
    predecessor_state_hash = getattr(value, "predecessor_state_hash", None)
    sequence = getattr(value, "sequence", None)
    envelope_hash = getattr(value, "envelope_hash", None)
    if (
        type(owner_name) is not bytes
        or not owner_name
        or type(predecessor_owner_public_key) is not bytes
        or len(predecessor_owner_public_key) != _KEY_LENGTH
        or type(successor_owner_public_key) is not bytes
        or len(successor_owner_public_key) != _KEY_LENGTH
        or type(predecessor_state_hash) is not bytes
        or len(predecessor_state_hash) != _KEY_LENGTH
        or type(sequence) is not int
        or sequence <= 0
        or type(envelope_hash) is not bytes
        or len(envelope_hash) != _KEY_LENGTH
    ):
        return None
    return _RotationBinding(
        owner_name=owner_name,
        predecessor_owner_public_key=predecessor_owner_public_key,
        successor_owner_public_key=successor_owner_public_key,
        predecessor_state_hash=predecessor_state_hash,
        sequence=sequence,
        envelope_hash=envelope_hash,
    )


class _RotationLatchRegistry:
    """Serialize normal writes against locally persisted unresolved rotations."""

    def __init__(self) -> None:
        self._guard = Lock()
        self._owner_locks: dict[bytes, RLock] = {}
        self._bindings: dict[bytes, tuple[_RotationBinding, bool]] = {}

    def owner_lock(self, owner_name: bytes) -> RLock:
        with self._guard:
            lock = self._owner_locks.get(owner_name)
            if lock is None:
                lock = RLock()
                self._owner_locks[owner_name] = lock
            return lock

    def is_owner_latched(self, owner_name: bytes) -> bool:
        with self._guard:
            return owner_name in self._bindings

    def is_latched(self, value: Any) -> bool:
        binding = _rotation_binding(value)
        if binding is None:
            return False
        with self._guard:
            current = self._bindings.get(binding.owner_name)
            return current is not None and current[0] == binding

    def is_dispatch_ready(self, value: Any) -> bool:
        binding = _rotation_binding(value)
        if binding is None:
            return False
        with self._guard:
            current = self._bindings.get(binding.owner_name)
            return current is not None and current == (binding, True)

    def register(self, value: Any, *, dispatch_ready: bool = False) -> bool:
        binding = _rotation_binding(value)
        if binding is None:
            return False
        with self.owner_lock(binding.owner_name):
            with self._guard:
                current = self._bindings.get(binding.owner_name)
                if current is not None and current[0] != binding:
                    return False
                ready = dispatch_ready or (current is not None and current[1])
                self._bindings[binding.owner_name] = (binding, ready)
                return True

    def clear(self, value: Any) -> bool:
        binding = _rotation_binding(value)
        if binding is None:
            return False
        with self.owner_lock(binding.owner_name):
            with self._guard:
                current = self._bindings.get(binding.owner_name)
                if current is None or current[0] != binding:
                    return False
                del self._bindings[binding.owner_name]
                return True


_ROTATION_CAPABILITY_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class RotationPublication:
    """One-use public capability prepared after rotation consent and state checks."""

    _bundle: IdentityBundle
    _envelope_bytes: bytes
    _previous_state: IdentityState
    expires_at: int
    _adapter_token: object
    _latch_registry: _RotationLatchRegistry
    _consumption: list[bool]
    _lock: Lock

    def __init__(
        self,
        *,
        seal: object,
        bundle: IdentityBundle,
        envelope_bytes: bytes,
        previous_state: IdentityState,
        expires_at: int,
        adapter_token: object,
        latch_registry: _RotationLatchRegistry,
    ) -> None:
        if seal is not _ROTATION_CAPABILITY_SEAL:
            raise InvalidIdentityRequest()
        object.__setattr__(self, "_bundle", bundle)
        object.__setattr__(self, "_envelope_bytes", envelope_bytes)
        object.__setattr__(self, "_previous_state", previous_state)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "_adapter_token", adapter_token)
        object.__setattr__(self, "_latch_registry", latch_registry)
        object.__setattr__(self, "_consumption", [False])
        object.__setattr__(self, "_lock", Lock())

    @property
    def envelope_bytes(self) -> bytes:
        return self._envelope_bytes

    @property
    def owner_name(self) -> bytes:
        return self._bundle.draft.owner_name

    @property
    def predecessor_owner_public_key(self) -> bytes:
        return self._previous_state.owner_public_key

    @property
    def successor_owner_public_key(self) -> bytes:
        return self._bundle.draft.owner_public_key

    @property
    def predecessor_state_hash(self) -> bytes:
        return self._previous_state.state_hash

    @property
    def sequence(self) -> int:
        return self._bundle.draft.sequence

    @property
    def envelope_hash(self) -> bytes:
        return hashlib.sha256(self._envelope_bytes).digest()

    def _matches_bundle(self, bundle: IdentityBundle) -> bool:
        if not isinstance(bundle, IdentityBundle) or bundle != self._bundle:
            return False
        try:
            if bundle.finalize() != self._envelope_bytes:
                return False
            previous = _draft_previous_state(bundle.draft)
        except Exception:
            return False
        return (
            previous == self._previous_state
            and bundle.draft.owner_name == self.owner_name
            and bundle.draft.owner_public_key == self.successor_owner_public_key
            and bundle.draft.sequence == self.sequence
            and bundle.draft.authorization is not None
            and bundle.draft.authorization[3] == 5
        )

    def _matches_intent(self, intent: Any) -> bool:
        return _rotation_binding(self) == _rotation_binding(intent)

    def _owner_lock(self, intent: Any) -> RLock:
        if not self._matches_intent(intent):
            raise InvalidIdentityRequest()
        return self._latch_registry.owner_lock(self.owner_name)

    def _owner_is_latched(self) -> bool:
        return self._latch_registry.is_owner_latched(self.owner_name)

    def _mark_latched(self, intent: Any) -> bool:
        return self._matches_intent(intent) and self._latch_registry.register(
            intent, dispatch_ready=True
        )

    def _clear_latch(self, intent: Any) -> bool:
        return self._matches_intent(intent) and self._latch_registry.clear(intent)

    def _latch_registry_contains(self, intent: Any) -> bool:
        return self._latch_registry.is_latched(intent)

    def _consume_for(self, adapter_token: object) -> bool:
        with self._lock:
            if self._adapter_token is not adapter_token or self._consumption[0]:
                return False
            self._consumption[0] = True
            return True

    def __repr__(self) -> str:
        return "RotationPublication(ready=True)"


@dataclass(frozen=True, slots=True, init=False)
class RotationConfirmation:
    owner_name: bytes
    predecessor_owner_public_key: bytes
    successor_owner_public_key: bytes
    predecessor_state_hash: bytes
    sequence: int
    envelope_hash: bytes
    state_hash: bytes
    _seal: object
    _latch_registry: _RotationLatchRegistry

    def __init__(
        self,
        *,
        seal: object,
        owner_name: bytes,
        predecessor_owner_public_key: bytes,
        successor_owner_public_key: bytes,
        predecessor_state_hash: bytes,
        sequence: int,
        envelope_hash: bytes,
        state_hash: bytes,
        latch_registry: _RotationLatchRegistry,
    ) -> None:
        if seal is not _ROTATION_CAPABILITY_SEAL:
            raise InvalidIdentityRequest()
        for name, value in (
            ("owner_name", owner_name),
            ("predecessor_owner_public_key", predecessor_owner_public_key),
            ("successor_owner_public_key", successor_owner_public_key),
            ("predecessor_state_hash", predecessor_state_hash),
            ("envelope_hash", envelope_hash),
            ("state_hash", state_hash),
        ):
            object.__setattr__(self, name, value)
        object.__setattr__(self, "sequence", sequence)
        object.__setattr__(self, "_seal", seal)
        object.__setattr__(self, "_latch_registry", latch_registry)

    def _matches_intent(self, intent: Any) -> bool:
        return (
            self._seal is _ROTATION_CAPABILITY_SEAL
            and _rotation_binding(self) == _rotation_binding(intent)
        )

    def _owner_lock(self, intent: Any) -> RLock:
        if not self._matches_intent(intent):
            raise InvalidIdentityRequest()
        return self._latch_registry.owner_lock(self.owner_name)

    def _is_latched(self, intent: Any) -> bool:
        return self._matches_intent(intent) and self._latch_registry.is_latched(intent)

    def _clear_latch(self, intent: Any) -> bool:
        return self._matches_intent(intent) and self._latch_registry.clear(intent)

    def __repr__(self) -> str:
        return "RotationConfirmation(verified=True)"


@dataclass(frozen=True, slots=True, init=False)
class RotationDispatchRejection:
    status: PublishStatus
    owner_name: bytes
    predecessor_owner_public_key: bytes
    successor_owner_public_key: bytes
    predecessor_state_hash: bytes
    sequence: int
    envelope_hash: bytes
    _seal: object
    _publication: RotationPublication
    _consumption: list[bool]
    _lock: Lock

    def __init__(
        self,
        *,
        seal: object,
        status: PublishStatus,
        publication: RotationPublication,
    ) -> None:
        if seal is not _ROTATION_CAPABILITY_SEAL or status not in {
            PublishStatus.FAILED,
            PublishStatus.STALE,
            PublishStatus.EXPIRED,
        }:
            raise InvalidIdentityRequest()
        object.__setattr__(self, "status", status)
        for name in (
            "owner_name",
            "predecessor_owner_public_key",
            "successor_owner_public_key",
            "predecessor_state_hash",
            "sequence",
            "envelope_hash",
        ):
            object.__setattr__(self, name, getattr(publication, name))
        object.__setattr__(self, "_seal", seal)
        object.__setattr__(self, "_publication", publication)
        object.__setattr__(self, "_consumption", [False])
        object.__setattr__(self, "_lock", Lock())

    def _matches_intent(self, intent: Any) -> bool:
        return (
            self._seal is _ROTATION_CAPABILITY_SEAL
            and _rotation_binding(self) == _rotation_binding(intent)
        )

    def _owner_lock(self, intent: Any) -> RLock:
        if not self._matches_intent(intent):
            raise InvalidIdentityRequest()
        return self._publication._owner_lock(intent)

    def _is_latched(self, intent: Any) -> bool:
        return self._matches_intent(intent) and self._publication._latch_registry_contains(intent)

    def _clear_latch(self, intent: Any) -> bool:
        return self._matches_intent(intent) and self._publication._clear_latch(intent)

    def _claim(self) -> bool:
        with self._lock:
            if self._consumption[0]:
                return False
            self._consumption[0] = True
            return True

    def _release(self) -> None:
        with self._lock:
            self._consumption[0] = False


@dataclass(frozen=True, slots=True)
class RotationDispatchResult:
    status: PublishStatus
    confirmation: RotationConfirmation | None = None
    rejection: RotationDispatchRejection | None = None
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


def _verify_bundle_signature(public_key: bytes, update: bytes, signature: bytes) -> None:
    try:
        _verify_signature(public_key, update, signature)
    except InvalidIdentityState:
        raise InvalidIdentityRequest() from None


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
        if (
            previous_state is not None
            or sequence != 1
            or authorization[4] != 1
            or authorization[7] != bytes(_KEY_LENGTH)
        ):
            raise InvalidIdentityState()
        if authorization[5] != 2 or len(signer_entries) != 3:
            raise InvalidIdentityState()
    elif operation == 4:
        if authorization[4] != 1 or authorization[5] != 2 or len(signer_entries) != 3:
            raise InvalidIdentityState()
    elif operation == 2:
        if (
            previous_state is None
            or not previous_state.signer_set
            or previous_state.owner_name != owner_name
            or previous_state.owner_public_key != record[2]
            or previous_state.state_hash != authorization[7]
            or sequence != previous_state.sequence + 1
            or authorization[4] != previous_state.generation
            or authorization[5] != previous_state.threshold
            or tuple((entry[1], entry[2]) for entry in signer_entries)
            != previous_state.signer_set
        ):
            raise InvalidIdentityState()
    elif operation == 3:
        if authorization[5] != 2 or len(signer_entries) != 3:
            raise InvalidIdentityState()
        if (
            previous_state is None
            or not previous_state.signer_set
            or previous_state.owner_name != owner_name
            or previous_state.owner_public_key != record[2]
            or previous_state.state_hash != authorization[7]
            or sequence != previous_state.sequence + 1
            or authorization[4] <= (previous_state.generation or 0)
            or tuple((entry[1], entry[2]) for entry in signer_entries)
            == previous_state.signer_set
        ):
            raise InvalidIdentityState()
    elif operation == 5:
        if (
            previous_state is None
            or previous_state.owner_name != owner_name
            or previous_state.owner_public_key == record[2]
            or previous_state.state_hash != authorization[7]
            or sequence != previous_state.sequence + 1
        ):
            raise InvalidIdentityState()
        candidate_signers = tuple((entry[1], entry[2]) for entry in signer_entries)
        if previous_state.signer_set:
            if (
                authorization[4] != previous_state.generation
                or authorization[5] != previous_state.threshold
                or candidate_signers != previous_state.signer_set
            ):
                raise InvalidIdentityState()
        elif (
            authorization[4] != 1
            or authorization[5] != 2
            or len(signer_entries) != 3
            or record[2] not in {entry[2] for entry in signer_entries}
        ):
            raise InvalidIdentityState()
    elif operation != 2:
        raise InvalidIdentityState()
    proof_list = _validate_proof_list(proofs)
    candidate_keys = {entry[1]: entry[2] for entry in signer_entries}
    if operation == 4:
        if (
            len(proof_list) != 1
            or candidate_keys.get(proof_list[0][1]) != record[2]
            or previous_state is None
            or previous_state.signer_set
            or previous_state.owner_public_key != record[2]
            or previous_state.state_hash != authorization[7]
            or sequence != previous_state.sequence + 1
        ):
            raise InvalidIdentityState()
    rotation_from_legacy = (
        operation == 5
        and previous_state is not None
        and not previous_state.signer_set
    )
    if rotation_from_legacy:
        if previous_state is None:
            raise InvalidIdentityState()
        if (
            len(proof_list) != 1
            or proof_list[0][1] is not None
        ):
            raise InvalidIdentityState()
        _verify_signature(
            previous_state.owner_public_key,
            update_bytes,
            proof_list[0][2],
        )
        valid_signers: set[str] = set()
    else:
        previous_keys = dict(previous_state.signer_set) if previous_state is not None else {}
        verification_keys = previous_keys if operation in (2, 3, 5) else candidate_keys
        valid_signers = set()
        for proof in proof_list:
            signer_id = proof[1]
            if signer_id is None:
                raise InvalidIdentityState()
            public_key = verification_keys.get(signer_id)
            if public_key is None:
                raise InvalidIdentityState()
            _verify_signature(public_key, update_bytes, proof[2])
            valid_signers.add(signer_id)
    if operation == 3:
        if len(valid_signers) < authorization[5]:
            raise InvalidIdentityState()
    elif operation == 4:
        if len(valid_signers) != 1:
            raise InvalidIdentityState()
    elif rotation_from_legacy:
        if len(proof_list) != 1:
            raise InvalidIdentityState()
    elif len(valid_signers) < authorization[5]:
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
        predecessor_envelopes=(
            (previous_state.envelope_bytes, *previous_state.predecessor_envelopes)
            if operation in (2, 3, 4, 5) and previous_state is not None
            else ()
        ),
    )


def _validate_proof_list(proofs: Any) -> list[dict[int, Any]]:
    if not isinstance(proofs, list):
        raise InvalidIdentityState()
    normalized: list[dict[int, Any]] = []
    seen: set[str | None] = set()
    for proof in proofs:
        proof = _require_exact_keys(proof, {1, 2})
        signer_id = proof[1]
        if signer_id is not None and (
            not isinstance(signer_id, str) or not signer_id
        ):
            raise InvalidIdentityState()
        signature = _require_bytes(proof[2], length=_SIGNATURE_LENGTH)
        if signer_id is not None:
            try:
                signer_id.encode("utf-8")
            except UnicodeEncodeError:
                raise InvalidIdentityState() from None
        if signer_id in seen:
            raise InvalidIdentityState()
        seen.add(signer_id)
        normalized.append({1: signer_id, 2: signature})
    if normalized != sorted(
        normalized,
        key=lambda item: b"" if item[1] is None else item[1].encode("utf-8"),
    ):
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


def _proof_order(proof: IdentityProof) -> bytes:
    if proof.signer_id is None:
        return b""
    try:
        return proof.signer_id.encode("utf-8")
    except UnicodeEncodeError:
        raise InvalidIdentityRequest() from None


def _validate_draft_transition(
    *,
    owner_name: bytes,
    owner_public_key: bytes,
    sequence: int,
    authorization: dict[int, Any] | None,
    previous_state: IdentityState | None,
) -> None:
    if previous_state is None:
        if sequence != 1:
            raise InvalidIdentityRequest()
        if authorization is None:
            return
        if (
            authorization[3] != 1
            or authorization[4] != 1
            or authorization[7] != bytes(_KEY_LENGTH)
        ):
            raise InvalidIdentityRequest()
        _require_complete_2_of_3(authorization)
        return

    if owner_name != previous_state.owner_name or sequence != previous_state.sequence + 1:
        raise InvalidIdentityRequest()
    if authorization is None:
        if previous_state.signer_set or owner_public_key != previous_state.owner_public_key:
            raise InvalidIdentityRequest()
        return
    if authorization[7] != previous_state.state_hash:
        raise InvalidIdentityRequest()

    if authorization[3] == 5:
        if owner_public_key == previous_state.owner_public_key:
            raise InvalidIdentityRequest()
        candidate = tuple((entry[1], entry[2]) for entry in authorization[6])
        if not previous_state.signer_set:
            if (
                authorization[4] != 1
                or authorization[5] != 2
                or len(candidate) != 3
                or owner_public_key not in {key for _signer_id, key in candidate}
            ):
                raise InvalidIdentityRequest()
        elif (
            authorization[4] != previous_state.generation
            or authorization[5] != previous_state.threshold
            or candidate != previous_state.signer_set
        ):
            raise InvalidIdentityRequest()
        return

    if owner_public_key != previous_state.owner_public_key:
        raise InvalidIdentityRequest()

    candidate = tuple((entry[1], entry[2]) for entry in authorization[6])
    if not previous_state.signer_set:
        if authorization[3] != 4 or authorization[4] != 1:
            raise InvalidIdentityRequest()
        _require_complete_2_of_3(authorization)
        if previous_state.owner_public_key not in _signer_map(authorization[6]).values():
            raise InvalidIdentityRequest()
        return

    if authorization[3] == 2:
        if (
            authorization[4] != previous_state.generation
            or authorization[5] != previous_state.threshold
            or candidate != previous_state.signer_set
        ):
            raise InvalidIdentityRequest()
        return
    if authorization[3] == 3:
        if authorization[4] <= (previous_state.generation or 0):
            raise InvalidIdentityRequest()
        _require_complete_2_of_3(authorization)
        if candidate == previous_state.signer_set:
            raise InvalidIdentityRequest()
        return
    raise InvalidIdentityRequest()


def _validate_transition(
    *,
    current: IdentityState | None,
    auth: dict[int, Any],
    signer_id: str | None,
    signer_public_key: bytes,
) -> None:
    operation = auth[3]
    predecessor = auth[7]
    if current is None:
        if operation != 1 or auth[4] != 1 or predecessor != bytes(_KEY_LENGTH):
            raise InvalidIdentityRequest()
        _require_complete_2_of_3(auth)
        if signer_id is None or _signer_map(auth[6]).get(signer_id) != signer_public_key:
            raise InvalidIdentityRequest()
        return

    if operation == 5:
        if not current.signer_set:
            if (
                auth[4] != 1
                or auth[5] != 2
                or len(auth[6]) != 3
                or signer_id is not None
                or signer_public_key != current.owner_public_key
            ):
                raise InvalidIdentityRequest()
            return
        current_signers = dict(current.signer_set)
        if (
            auth[4] != current.generation
            or auth[5] != current.threshold
            or tuple((entry[1], entry[2]) for entry in auth[6])
            != current.signer_set
            or signer_id is None
            or current_signers.get(signer_id) != signer_public_key
        ):
            raise InvalidIdentityRequest()
        return

    if not current.signer_set:
        if operation != 4 or auth[4] != 1 or predecessor != current.state_hash:
            raise InvalidIdentityRequest()
        _require_complete_2_of_3(auth)
        if signer_public_key != current.owner_public_key:
            raise InvalidIdentityRequest()
        if signer_id is None or _signer_map(auth[6]).get(signer_id) != signer_public_key:
            raise InvalidIdentityRequest()
        return

    current_signers = dict(current.signer_set)
    if signer_id is None:
        raise InvalidIdentityRequest()
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
        self._rotation_token = object()
        self._rotation_latches = _RotationLatchRegistry()

    @staticmethod
    def _rotation_transport_available(transport: IdentityTransport) -> bool:
        try:
            return (
                getattr(transport, "supports_owner_key_rotation", False) is True
                and callable(getattr(transport, "get_remote_identity_envelope", None))
            )
        except Exception:
            return False

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
        return self._parse_state_with_history(owner_name=owner_name, envelope=envelope)

    def _parse_state_with_history(
        self,
        *,
        owner_name: bytes,
        envelope: bytes,
    ) -> IdentityState:
        chain: list[bytes] = []
        current_envelope = envelope
        while True:
            value = _require_canonical(current_envelope)
            authorization = None
            if (
                isinstance(value, dict)
                and type(value.get(1)) is int
                and value[1] == 1
                and type(value.get(2)) is bytes
            ):
                _, _, _, authorization = _decode_signed_update(value[2])
            if authorization is None or authorization[3] not in (2, 3, 4, 5):
                state = _parse_identity_envelope(
                    owner_name=owner_name,
                    envelope_bytes=current_envelope,
                )
                break
            if len(chain) >= _MAX_PREDECESSOR_DEPTH:
                raise InvalidIdentityState()
            try:
                predecessor_envelope = self._transport.get_identity_envelope_by_hash(
                    owner_name_hex=owner_name.hex(),
                    state_hash=authorization[7],
                )
            except Exception:
                raise TransportFailure() from None
            if predecessor_envelope is None:
                raise InvalidIdentityState()
            chain.append(current_envelope)
            current_envelope = predecessor_envelope
        for current_envelope in reversed(chain):
            state = _parse_identity_envelope(
                owner_name=owner_name,
                envelope_bytes=current_envelope,
                previous_state=state,
            )
        return state

    def create_draft(
        self,
        *,
        owner_name: bytes,
        owner_public_key: bytes,
        authorization: Mapping[int, Any] | None = None,
    ) -> IdentityDraft:
        owner_name = _validate_owner_name(owner_name)
        _require_bytes(owner_public_key, length=_KEY_LENGTH)
        current = self.read_state(owner_name=owner_name)
        if current is not None and current.owner_public_key != owner_public_key:
            raise InvalidIdentityRequest()
        sequence = 1 if current is None else current.sequence + 1
        return IdentityDraft.create(
            owner_name=owner_name,
            owner_public_key=owner_public_key,
            sequence=sequence,
            authorization=authorization,
            previous_state_envelope=(current.envelope_bytes if current is not None else None),
            previous_state_history=(
                current.predecessor_envelopes if current is not None else ()
            ),
        )

    def create_owner_key_rotation_draft(
        self,
        *,
        owner_name: bytes,
        successor_owner_public_key: bytes,
        successor_signer_set: list[dict[int, Any]] | None = None,
    ) -> IdentityDraft:
        """Build a local operation-5 draft from the verified accepted state.

        Legacy predecessors require the complete successor 2-of-3 signer set.
        Version-1 predecessors preserve their existing signer governance and do
        not accept a caller-supplied replacement set.
        """
        owner_name = _validate_owner_name(owner_name)
        if self._rotation_latches.is_owner_latched(owner_name):
            raise InvalidIdentityRequest()
        successor_owner_public_key = _require_bytes(
            successor_owner_public_key, length=_KEY_LENGTH
        )
        previous = self.read_state(owner_name=owner_name)
        if previous is None or successor_owner_public_key == previous.owner_public_key:
            raise InvalidIdentityRequest()

        if previous.signer_set:
            if successor_signer_set is not None:
                raise InvalidIdentityRequest()
            epoch = previous.generation
            threshold = previous.threshold
            signer_entries = [
                {1: signer_id, 2: public_key}
                for signer_id, public_key in previous.signer_set
            ]
        else:
            if not isinstance(successor_signer_set, list):
                raise InvalidIdentityRequest()
            try:
                signer_entries = sorted(
                    successor_signer_set,
                    key=lambda entry: entry[1].encode("utf-8"),
                )
            except Exception:
                raise InvalidIdentityRequest() from None
            epoch = 1
            threshold = 2

        authorization = {
            1: 1,
            2: 1,
            3: 5,
            4: epoch,
            5: threshold,
            6: signer_entries,
            7: previous.state_hash,
        }
        return IdentityDraft.create(
            owner_name=owner_name,
            owner_public_key=successor_owner_public_key,
            sequence=previous.sequence + 1,
            authorization=authorization,
            previous_state_envelope=previous.envelope_bytes,
            previous_state_history=previous.predecessor_envelopes,
        )

    def sign_draft(
        self,
        *,
        draft: IdentityDraft,
        signer_public_key: bytes,
        signer_factory: SignerFactory,
        consent: ConsentHandler,
        authenticated_origin: str,
        environment: str,
        purpose: str,
        capability: str,
        expires_at: int,
        replay_nonce: bytes,
        signer_id: str | None = None,
    ) -> SubmissionResult:
        if not isinstance(draft, IdentityDraft):
            raise InvalidIdentityRequest()
        if self._rotation_latches.is_owner_latched(draft.owner_name):
            raise InvalidIdentityRequest()
        authorization = draft.authorization
        operation = (
            _OPERATION_NAMES[authorization[3]]
            if authorization is not None
            else "identity.update"
        )
        return self.submit_identity(
            owner_name=draft.owner_name,
            owner_public_key=draft.owner_public_key,
            signer_public_key=signer_public_key,
            signer_factory=signer_factory,
            consent=consent,
            authenticated_origin=authenticated_origin,
            environment=environment,
            operation=operation,
            purpose=purpose,
            capability=capability,
            expires_at=expires_at,
            replay_nonce=replay_nonce,
            authorization=authorization,
            signer_id=signer_id,
            draft=draft,
        )

    def publish_bundle(
        self,
        bundle: IdentityBundle,
        *,
        consent: ConsentHandler,
        authenticated_origin: str,
        environment: str,
        purpose: str,
        capability: str,
        expires_at: int,
        replay_nonce: bytes,
    ) -> PublicationResult:
        if not isinstance(bundle, IdentityBundle) or not bundle.proofs:
            raise InvalidIdentityRequest()
        if bundle.draft.authorization is not None and bundle.draft.authorization[3] == 5:
            raise InvalidIdentityRequest()
        envelope = bundle.finalize()
        owner_name = bundle.draft.owner_name
        if self._rotation_latches.is_owner_latched(owner_name):
            return PublicationResult(
                status=PublishStatus.FAILED,
                envelope_bytes=envelope,
                reason="owner-key rotation is unresolved",
            )
        previous_state = _draft_previous_state(bundle.draft)
        current = self.read_state(owner_name=owner_name)
        if not _same_state(previous_state, current):
            return PublicationResult(
                status=PublishStatus.STALE,
                envelope_bytes=envelope,
                reason="accepted state changed before publication",
            )

        authorization = bundle.draft.authorization
        operation = (
            _OPERATION_NAMES[authorization[3]]
            if authorization is not None
            else "identity.update"
        )
        transcript = ConsentTranscript(
            authenticated_origin=authenticated_origin,
            environment=environment,
            operation=operation,
            payload_hash=hashlib.sha256(envelope).digest(),
            purpose=purpose,
            capability=capability,
            expires_at=expires_at,
            replay_nonce=replay_nonce,
            sequence=bundle.draft.sequence,
            generation=(
                authorization[4]
                if authorization is not None
                else (previous_state.generation if previous_state is not None else None)
            ),
            review_payload=envelope,
        )
        consent_failure = self._consent_gate(
            owner_name=owner_name,
            transcript=transcript,
            consent=consent,
        )
        if consent_failure is not None:
            status, reason = consent_failure
            return PublicationResult(
                status=status,
                envelope_bytes=envelope,
                reason=reason,
            )

        # Re-read after consent so a state change during the approval step is stale.
        current = self.read_state(owner_name=owner_name)
        if not _same_state(previous_state, current):
            return PublicationResult(
                status=PublishStatus.STALE,
                envelope_bytes=envelope,
                reason="accepted state changed before publication",
            )
        if expires_at <= int(time.time()):
            return PublicationResult(
                status=PublishStatus.EXPIRED,
                envelope_bytes=envelope,
                reason="consent expired",
            )
        try:
            with self._rotation_latches.owner_lock(owner_name):
                if self._rotation_latches.is_owner_latched(owner_name):
                    return PublicationResult(
                        status=PublishStatus.FAILED,
                        envelope_bytes=envelope,
                        reason="owner-key rotation is unresolved",
                    )
                self._transport.put_identity_envelope(
                    owner_name_hex=owner_name.hex(),
                    envelope_cbor=envelope,
                    expected_state_hash=(current.state_hash if current is not None else None),
                    expires_at=expires_at,
                )
        except StalePublication:
            return PublicationResult(
                status=PublishStatus.STALE,
                envelope_bytes=envelope,
                reason="conditional publication rejected",
            )
        except ExpiredPublication:
            return PublicationResult(
                status=PublishStatus.EXPIRED,
                envelope_bytes=envelope,
                reason="consent expired",
            )
        except Exception:
            return self._confirm_publication(
                owner_name=owner_name,
                envelope=envelope,
                previous_state=previous_state,
                failure_reason="independent readback did not confirm dispatch",
            )
        return self._confirm_publication(
            owner_name=owner_name,
            envelope=envelope,
            previous_state=previous_state,
            failure_reason="readback did not confirm exact envelope",
        )

    def confirm_bundle(self, bundle: IdentityBundle) -> PublicationResult:
        if not isinstance(bundle, IdentityBundle):
            raise InvalidIdentityRequest()
        if bundle.draft.authorization is not None and bundle.draft.authorization[3] == 5:
            raise InvalidIdentityRequest()
        envelope = bundle.finalize()
        previous_state = _draft_previous_state(bundle.draft)
        return self._confirm_publication(
            owner_name=bundle.draft.owner_name,
            envelope=envelope,
            previous_state=previous_state,
            failure_reason="readback did not confirm exact envelope",
        )

    def prepare_owner_key_rotation_publication(
        self,
        bundle: IdentityBundle,
        *,
        consent: ConsentHandler,
        authenticated_origin: str,
        environment: str,
        purpose: str,
        capability: str,
        expires_at: int,
        replay_nonce: bytes,
    ) -> PublicationResult:
        """Obtain fresh consent and prepare a one-use operation-5 dispatch."""
        if not isinstance(bundle, IdentityBundle):
            raise InvalidIdentityRequest()
        if self._rotation_latches.is_owner_latched(bundle.draft.owner_name):
            return PublicationResult(
                status=PublishStatus.FAILED,
                reason="owner-key rotation is unresolved",
            )
        authorization = bundle.draft.authorization
        if authorization is None or authorization[3] != 5:
            raise InvalidIdentityRequest()
        if not self._rotation_transport_available(self._transport):
            return PublicationResult(
                status=PublishStatus.FAILED,
                reason="rotation transport capability unavailable",
            )
        envelope = bundle.finalize()
        previous_state = _draft_previous_state(bundle.draft)
        if previous_state is None:
            raise InvalidIdentityRequest()
        current = self.read_state(owner_name=bundle.draft.owner_name)
        if not _same_state(previous_state, current):
            return PublicationResult(
                status=PublishStatus.STALE,
                envelope_bytes=envelope,
                reason="accepted state changed before publication",
            )

        transcript = ConsentTranscript(
            authenticated_origin=authenticated_origin,
            environment=environment,
            operation="owner-key-rotation",
            payload_hash=hashlib.sha256(envelope).digest(),
            purpose=purpose,
            capability=capability,
            expires_at=expires_at,
            replay_nonce=replay_nonce,
            sequence=bundle.draft.sequence,
            generation=authorization[4],
            review_payload=envelope,
        )
        consent_failure = self._consent_gate(
            owner_name=bundle.draft.owner_name,
            transcript=transcript,
            consent=consent,
        )
        if consent_failure is not None:
            status, reason = consent_failure
            return PublicationResult(
                status=status,
                envelope_bytes=envelope,
                reason=reason,
            )

        current = self.read_state(owner_name=bundle.draft.owner_name)
        if not _same_state(previous_state, current):
            return PublicationResult(
                status=PublishStatus.STALE,
                envelope_bytes=envelope,
                reason="accepted state changed before publication",
            )
        if expires_at <= int(time.time()):
            return PublicationResult(
                status=PublishStatus.EXPIRED,
                envelope_bytes=envelope,
                reason="consent expired",
            )
        publication = RotationPublication(
            seal=_ROTATION_CAPABILITY_SEAL,
            bundle=bundle,
            envelope_bytes=envelope,
            previous_state=previous_state,
            expires_at=expires_at,
            adapter_token=self._rotation_token,
            latch_registry=self._rotation_latches,
        )
        return PublicationResult(
            status=PublishStatus.READY,
            envelope_bytes=envelope,
            publication=publication,
        )

    def dispatch_owner_key_rotation(
        self,
        publication: RotationPublication,
        permit: RotationDispatchPermit,
    ) -> RotationDispatchResult:
        """Dispatch only with an ephemeral permit minted after durable wallet latching."""
        from .container import RotationDispatchPermit

        if (
            not isinstance(publication, RotationPublication)
            or not isinstance(permit, RotationDispatchPermit)
            or not permit._authentic()
            or not publication._matches_intent(permit.intent)
            or not self._rotation_latches.is_dispatch_ready(permit.intent)
            or not publication._consume_for(self._rotation_token)
        ):
            raise InvalidIdentityRequest()
        intent = permit.intent

        def make_rejection(status: PublishStatus) -> RotationDispatchRejection:
            return RotationDispatchRejection(
                seal=_ROTATION_CAPABILITY_SEAL,
                status=status,
                publication=publication,
            )

        with self._rotation_latches.owner_lock(publication.owner_name):
            if not self._rotation_latches.is_latched(intent):
                raise InvalidIdentityRequest()
            if not self._rotation_transport_available(self._transport):
                rejection = make_rejection(PublishStatus.FAILED)
                return RotationDispatchResult(
                    status=PublishStatus.FAILED,
                    rejection=rejection,
                    reason="rotation transport capability unavailable",
                )
            try:
                current = self.read_state(owner_name=publication.owner_name)
            except IdentityAdapterError:
                rejection = make_rejection(PublishStatus.FAILED)
                return RotationDispatchResult(
                    status=PublishStatus.FAILED,
                    rejection=rejection,
                    reason="pre-write state validation failed",
                )
            if not _same_state(publication._previous_state, current):
                rejection = make_rejection(PublishStatus.STALE)
                return RotationDispatchResult(
                    status=PublishStatus.STALE,
                    rejection=rejection,
                    reason="accepted state changed before publication",
                )
            if publication.expires_at <= int(time.time()):
                rejection = make_rejection(PublishStatus.EXPIRED)
                return RotationDispatchResult(
                    status=PublishStatus.EXPIRED,
                    rejection=rejection,
                    reason="consent expired",
                )

            try:
                self._transport.put_identity_envelope(
                    owner_name_hex=publication.owner_name.hex(),
                    envelope_cbor=publication.envelope_bytes,
                    expected_state_hash=publication._previous_state.state_hash,
                    expires_at=publication.expires_at,
                )
            except StalePublication:
                rejection = make_rejection(PublishStatus.STALE)
                return RotationDispatchResult(
                    status=PublishStatus.STALE,
                    rejection=rejection,
                    reason="conditional publication rejected",
                )
            except ExpiredPublication:
                rejection = make_rejection(PublishStatus.EXPIRED)
                return RotationDispatchResult(
                    status=PublishStatus.EXPIRED,
                    rejection=rejection,
                    reason="consent expired",
                )
            except Exception:
                confirmation = self.confirm_owner_key_rotation(intent)
                if confirmation is not None:
                    return RotationDispatchResult(
                        status=PublishStatus.CONFIRMED,
                        confirmation=confirmation,
                    )
                return RotationDispatchResult(
                    status=PublishStatus.UNKNOWN,
                    reason="independent readback did not confirm dispatch",
                )

            confirmation = self.confirm_owner_key_rotation(intent)
            if confirmation is not None:
                return RotationDispatchResult(
                    status=PublishStatus.CONFIRMED,
                    confirmation=confirmation,
                )
            return RotationDispatchResult(
                status=PublishStatus.UNKNOWN,
                reason="readback did not confirm exact envelope",
            )

    def confirm_owner_key_rotation(
        self, intent: RotationDispatchIntent
    ) -> RotationConfirmation | None:
        """Mint confirmation only from a fresh remote envelope and verified history."""
        from .container import RotationDispatchIntent

        if (
            not isinstance(intent, RotationDispatchIntent)
            or not self._rotation_latches.register(intent)
        ):
            raise InvalidIdentityRequest()
        try:
            remote_envelope = self._transport.get_remote_identity_envelope(
                owner_name_hex=intent.owner_name.hex()
            )
        except Exception:
            return None
        if type(remote_envelope) is not bytes:
            return None
        if hashlib.sha256(remote_envelope).digest() != intent.envelope_hash:
            return None

        try:
            state = self._parse_state_with_history(
                owner_name=intent.owner_name,
                envelope=remote_envelope,
            )
            _record, _payload, sequence, authorization = _decode_signed_update(
                state.signed_update_bytes
            )
            if (
                authorization is None
                or authorization[3] != 5
                or authorization[7] != intent.predecessor_state_hash
                or state.owner_name != intent.owner_name
                or state.owner_public_key != intent.successor_owner_public_key
                or sequence != intent.sequence
            ):
                return None
            predecessor_envelope = self._transport.get_identity_envelope_by_hash(
                owner_name_hex=intent.owner_name.hex(),
                state_hash=intent.predecessor_state_hash,
            )
            if type(predecessor_envelope) is not bytes:
                return None
            predecessor = self._parse_state_with_history(
                owner_name=intent.owner_name,
                envelope=predecessor_envelope,
            )
            if (
                predecessor.owner_public_key != intent.predecessor_owner_public_key
                or predecessor.state_hash != intent.predecessor_state_hash
                or state.sequence != predecessor.sequence + 1
            ):
                return None
        except Exception:
            return None
        return RotationConfirmation(
            seal=_ROTATION_CAPABILITY_SEAL,
            owner_name=intent.owner_name,
            predecessor_owner_public_key=intent.predecessor_owner_public_key,
            successor_owner_public_key=intent.successor_owner_public_key,
            predecessor_state_hash=intent.predecessor_state_hash,
            sequence=intent.sequence,
            envelope_hash=intent.envelope_hash,
            state_hash=state.state_hash,
            latch_registry=self._rotation_latches,
        )

    def _confirm_publication(
        self,
        *,
        owner_name: bytes,
        envelope: bytes,
        previous_state: IdentityState | None,
        failure_reason: str,
    ) -> PublicationResult:
        accepted = self._confirm(
            owner_name=owner_name,
            envelope=envelope,
            previous_state=previous_state,
        )
        return PublicationResult(
            status=PublishStatus.CONFIRMED if accepted else PublishStatus.UNKNOWN,
            envelope_bytes=envelope,
            accepted_state=accepted,
            reason=None if accepted else failure_reason,
        )

    def _consent_gate(
        self,
        *,
        owner_name: bytes,
        transcript: ConsentTranscript,
        consent: ConsentHandler,
    ) -> tuple[PublishStatus, str] | None:
        try:
            replay_available = self._reserve_replay_nonce(
                owner_name=owner_name,
                authenticated_origin=transcript.authenticated_origin,
                environment=transcript.environment,
                replay_nonce=transcript.replay_nonce,
            )
        except Exception:
            return PublishStatus.FAILED, "replay protection unavailable"
        if not replay_available:
            return PublishStatus.FAILED, "replay rejected"
        if transcript.expires_at <= int(time.time()):
            return PublishStatus.EXPIRED, "consent expired"
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
            return status, decision.value
        if transcript.expires_at <= int(time.time()):
            return PublishStatus.EXPIRED, "consent expired"
        return None

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
        draft: IdentityDraft | None = None,
    ) -> SubmissionResult:
        """Submit one explicitly consented Identity update without auto-retry."""
        owner_name = _validate_owner_name(owner_name)
        if self._rotation_latches.is_owner_latched(owner_name):
            raise InvalidIdentityRequest()
        _require_bytes(owner_public_key, length=_KEY_LENGTH)
        _require_bytes(signer_public_key, length=_KEY_LENGTH)
        current = self.read_state(owner_name=owner_name)
        if draft is not None:
            if not isinstance(draft, IdentityDraft):
                raise InvalidIdentityRequest()
            if draft.previous_state_envelope != (current.envelope_bytes if current else None):
                raise InvalidIdentityRequest()
            if draft.previous_state_history != (
                current.predecessor_envelopes if current else ()
            ):
                raise InvalidIdentityRequest()
            if draft.owner_name != owner_name or draft.owner_public_key != owner_public_key:
                raise InvalidIdentityRequest()
            if draft.authorization != (dict(authorization) if authorization is not None else None):
                raise InvalidIdentityRequest()
            if draft.sequence != (1 if current is None else current.sequence + 1):
                raise InvalidIdentityRequest()
        sequence = 1 if current is None else current.sequence + 1
        authorization_epoch: int | None = None
        auth: dict[int, Any] | None = None

        record_public_key = owner_public_key
        if authorization is not None:
            auth = _validate_authorization(dict(authorization))
            if operation != _OPERATION_NAMES[auth[3]]:
                raise InvalidIdentityRequest()
            if (
                current is not None
                and current.owner_public_key != owner_public_key
                and auth[3] != 5
            ):
                raise InvalidIdentityRequest()
            if auth[3] == 5 and draft is None:
                raise InvalidIdentityRequest()
            authorization_epoch = auth[4]
            if current is not None and auth[7] != current.state_hash:
                raise InvalidIdentityRequest()
            if current is None and auth[7] != bytes(_KEY_LENGTH):
                raise InvalidIdentityRequest()
            legacy_owner_rotation_proof = (
                auth[3] == 5
                and current is not None
                and not current.signer_set
            )
            if not legacy_owner_rotation_proof and (
                signer_id is None
                or not isinstance(signer_id, str)
                or not signer_id
            ):
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
            if current is not None and current.owner_public_key != owner_public_key:
                raise InvalidIdentityRequest()
            if current is not None and current.signer_set:
                raise InvalidIdentityRequest()
            if signer_public_key != owner_public_key:
                raise InvalidIdentityRequest()
            if signer_id is not None:
                raise InvalidIdentityRequest()
            update = build_identity_update(
                owner_name=owner_name,
                owner_public_key=record_public_key,
                sequence=sequence,
            )

        if draft is not None and update != draft.signed_update_bytes:
            raise InvalidIdentityRequest()

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
            review_payload=update,
        )
        consent_failure = self._consent_gate(
            owner_name=owner_name,
            transcript=transcript,
            consent=consent,
        )
        if consent_failure is not None:
            status, reason = consent_failure
            return SubmissionResult(status=status, transcript=transcript, reason=reason)

        def complete_submission() -> SubmissionResult:
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

            if draft is not None:
                identity_proof = IdentityProof(
                    signer_id=signer_id,
                    signer_public_key=signer_public_key,
                    signature=signature,
                )
                proof_bytes = (
                    signature
                    if signer_id is None
                    else _canonical({1: signer_id, 2: signature})
                )
                return SubmissionResult(
                    status=PublishStatus.PROOF_READY,
                    transcript=transcript,
                    signed_update_bytes=update,
                    proof_bytes=proof_bytes,
                    reason="draft proof ready",
                    draft=draft,
                    identity_proof=identity_proof,
                )

            if auth is not None and auth[5] > 1:
                if signer_id is None:
                    raise InvalidIdentityRequest()
                proof = _canonical({1: signer_id, 2: signature})
                proof_draft = IdentityDraft(
                    signed_update_bytes=update,
                    previous_state_envelope=(current.envelope_bytes if current else None),
                    previous_state_history=(
                        current.predecessor_envelopes if current else ()
                    ),
                )
                return SubmissionResult(
                    status=PublishStatus.PROOF_READY,
                    transcript=transcript,
                    signed_update_bytes=update,
                    proof_bytes=proof,
                    reason="threshold bundle required",
                    draft=proof_draft,
                    identity_proof=IdentityProof(
                        signer_id=signer_id,
                        signer_public_key=signer_public_key,
                        signature=signature,
                    ),
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

        with self._rotation_latches.owner_lock(owner_name):
            if self._rotation_latches.is_owner_latched(owner_name):
                return SubmissionResult(
                    status=PublishStatus.FAILED,
                    transcript=transcript,
                    reason="owner-key rotation is unresolved",
                )
            return complete_submission()

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

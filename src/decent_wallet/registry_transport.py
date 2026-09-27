"""Synchronous, direct-DHT adapter for the optional decent-registry package.

The Registry and libp2p dependencies are imported only when a transport is
constructed, so importing the wallet core does not require the Registry extra.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Awaitable, Callable, Sequence, TypeVar

from .identity import ExpiredPublication, StalePublication


_Result = TypeVar("_Result")


class RegistryTransport:
    """Bridge the wallet's synchronous Identity protocol to Registry's DHT API.

    ``store_path`` is an LMDB path retained across calls. At least one complete
    bootstrap multiaddr (including ``/p2p/<peer-id>``) is required. This adapter
    does not use an HTTP coordinator and never receives private keys.
    ``supports_owner_key_rotation`` is a trusted operator assertion, not a
    network handshake, and defaults to false. Enable it only when every
    configured Registry peer is pinned to a compatible operation-5 validator.
    """

    def __init__(
        self,
        *,
        bootstrap_peers: Sequence[str],
        store_path: str | Path,
        supports_owner_key_rotation: bool = False,
    ) -> None:
        if type(supports_owner_key_rotation) is not bool:
            raise TypeError("supports_owner_key_rotation must be a bool")
        if isinstance(bootstrap_peers, (str, bytes)):
            raise TypeError("bootstrap_peers must be a sequence of peer multiaddrs")
        peers = tuple(bootstrap_peers)
        if not peers or any(
            not isinstance(peer, str) or not peer for peer in peers
        ):
            raise ValueError(
                "at least one non-empty bootstrap peer multiaddr is required"
            )
        if any("/p2p/" not in peer for peer in peers):
            raise ValueError("bootstrap peers must include /p2p/<peer-id>")
        if store_path is None or not str(store_path):
            raise ValueError("a persistent Registry store_path is required")

        # Keep the optional Registry/libp2p dependency out of wallet-core imports.
        try:
            from decent_registry.dht.libp2p_dht import DHTMode, Libp2pKadDHT
            from decent_registry.durable_store import LMDBDatastore
            from decent_registry.exceptions import (
                IdentityPublicationExpired,
                IdentityStatePreconditionFailed,
            )
            from decent_registry.registry_service import RegistryService
        except ImportError as exc:
            raise ImportError(
                "RegistryTransport requires the optional decent-registry package"
            ) from exc

        self._bootstrap_peers = peers
        self._store_path = Path(store_path)
        self.supports_owner_key_rotation = supports_owner_key_rotation
        self._dht_mode = DHTMode.CLIENT
        self._dht_type = Libp2pKadDHT
        self._datastore_type = LMDBDatastore
        self._registry_service_type = RegistryService
        self._precondition_failed_type = IdentityStatePreconditionFailed
        self._publication_expired_type = IdentityPublicationExpired

    async def _execute(
        self, operation: Callable[..., Awaitable[_Result]]
    ) -> _Result:
        store = self._datastore_type(path=self._store_path)
        async with self._dht_type(
            listen="/ip4/127.0.0.1/tcp/0",
            durable_store=store,
            dht_mode=self._dht_mode,
        ) as dht:
            connected = False
            last_error: Exception | None = None
            for peer in self._bootstrap_peers:
                try:
                    await dht.bootstrap(peer)
                except Exception as exc:
                    last_error = exc
                    continue
                connected = True
            if not connected:
                raise ConnectionError(
                    "could not connect to any configured Registry bootstrap peer"
                ) from last_error
            service = self._registry_service_type(dht)
            return await operation(service, dht)

    def _run(self, operation: Callable[..., Awaitable[_Result]]) -> _Result:
        """Run one Registry operation in a fresh Trio runtime."""
        import trio

        return trio.run(self._execute, operation)

    def get_identity_envelope(self, *, owner_name_hex: str) -> bytes | None:
        async def get(service, _dht):
            return await service.get_identity_envelope(owner_name_hex=owner_name_hex)

        return self._run(get)

    def get_identity_envelope_by_hash(
        self, *, owner_name_hex: str, state_hash: bytes
    ) -> bytes | None:
        async def get(service, _dht):
            return await service.get_identity_envelope_by_hash(
                owner_name_hex=owner_name_hex,
                state_hash=state_hash,
            )

        return self._run(get)

    def get_remote_identity_envelope(self, *, owner_name_hex: str) -> bytes | None:
        async def get(_service, dht):
            try:
                owner_name = bytes.fromhex(owner_name_hex)
            except ValueError:
                raise ValueError("owner_name must be valid hex") from None
            object_key_hex = hashlib.sha256(owner_name).hexdigest()
            return await dht.read_remote_identity_envelope(object_key_hex)

        return self._run(get)

    def put_identity_envelope(
        self,
        *,
        owner_name_hex: str,
        envelope_cbor: bytes,
        expected_state_hash: bytes | None,
        expires_at: int,
    ) -> None:
        if expected_state_hash is None:
            raise StalePublication()

        async def put(service, _dht):
            await service.put_identity_envelope_if_current(
                owner_name_hex=owner_name_hex,
                envelope_cbor=envelope_cbor,
                expected_state_hash=expected_state_hash,
                expires_at=expires_at,
            )

        try:
            self._run(put)
        except self._precondition_failed_type as exc:
            raise StalePublication() from exc
        except self._publication_expired_type as exc:
            raise ExpiredPublication() from exc

"""Narrow value objects for wallet-owned account-disclosure issuance."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AccountDisclosureError(ValueError):
    """Value-free disclosure lifecycle failure."""

    def __init__(self) -> None:
        super().__init__("account disclosure operation rejected")

    def __repr__(self) -> str:
        return "AccountDisclosureError()"


@dataclass(frozen=True, slots=True, repr=False)
class AccountDisclosureReview:
    context: Any = field(repr=False)
    handle_digest: str = field(repr=False)
    identity_id: str = field(repr=False)
    owner_public_key: bytes = field(repr=False)
    entity_digest: str = field(repr=False)
    values: tuple[tuple[str, str | None], ...] = field(repr=False)
    expires_at: int

    def __repr__(self) -> str:
        return f"AccountDisclosureReview(claim_count={len(self.values)}, expires_at={self.expires_at})"


@dataclass(frozen=True, slots=True, repr=False)
class PendingAccountApproval:
    handle: str = field(repr=False)
    expires_at: int

    def __repr__(self) -> str:
        return f"PendingAccountApproval(expires_at={self.expires_at})"


@dataclass(frozen=True, slots=True, repr=False)
class WalletLoginProofRequest:
    proof: dict[str, str] = field(repr=False)

    def __repr__(self) -> str:
        return "WalletLoginProofRequest()"


@dataclass(frozen=True, slots=True, repr=False)
class AccountPresentationSubmission:
    pending: PendingAccountApproval = field(repr=False)
    response_uri: str = field(repr=False)
    state: str = field(repr=False)
    presentation_jws: str = field(repr=False)
    body: bytes = field(repr=False)

    @property
    def vp_token(self) -> bytes:
        import json
        return json.dumps({"account": [self.presentation_jws]}, separators=(",", ":")).encode("utf-8")

    def __repr__(self) -> str:
        return "AccountPresentationSubmission()"


class PresentationDeliveryOutcome(str, Enum):
    AMBIGUOUS = "ambiguous"
    ACCEPTED = "accepted"
    DEFINITIVE_FAILURE = "definitive_failure"
    CANCELLED = "cancelled"

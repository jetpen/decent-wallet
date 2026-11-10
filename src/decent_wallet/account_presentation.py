"""Verifier for the Account Disclosure v1 credential and presentation JWSs.

This module verifies artifacts only. It neither creates signatures nor owns approval
state, replay protection, networking, or transport.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from decent_wallet.account_disclosure import (
    CLAIM_IDS,
    WalletAccountDisclosureContext,
    VerifiedOwnerKeyBinding,
)
from decent_wallet.oid4vp_request import VerifiedOID4VPRequest

_PROFILE = "decent-account-disclosure-v1"
_CREDENTIAL = "decent_account_assertion_v1"
_PRESENTATION = "decent_account_presentation_v1"
_CRED_TYP = "decent-account-credential+jwt"
_VP_TYP = "decent-account-presentation+jwt"
_B64 = re.compile(r"^[A-Za-z0-9_-]+$")
_CRED_KEYS = frozenset({"profile", "credential_type", "iss", "sub", "iat", "exp", "jti", "action", "rp_oidc_client_id", "request_id", "transaction_id", "purpose", "owner_key_thumbprint", "owner_binding_jti", "claims"})
_VP_KEYS = frozenset({"profile", "iss", "sub", "aud", "nonce", "iat", "exp", "jti", "vp"})


class AccountPresentationError(ValueError):
    """Value-free invalid-credential/presentation error."""
    def __init__(self) -> None:
        super().__init__("account presentation rejected")
    def __repr__(self) -> str:
        return "AccountPresentationError()"


@dataclass(frozen=True, slots=True)
class VerifiedAccountPresentation:
    identity_id: str
    claims: dict[str, str]
    credential_jti: str
    presentation_jti: str
    issued_at: int
    expires_at: int


def _bad() -> None:
    raise AccountPresentationError()


def _pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in items:
        if key in result:
            _bad()
        result[key] = value
    return result


def _parse_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        _bad()
    return value


def _jcs(value: Any) -> bytes:
    """RFC 8785 serialization for parsed JSON data (I-JSON values only)."""
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if type(value) is str:
        try:
            value.encode("utf-8", "strict")
        except UnicodeEncodeError:
            _bad()
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if type(value) is int:
        if abs(value) > (1 << 53) - 1:
            _bad()
        return str(value).encode("ascii")
    if type(value) is float:
        if not math.isfinite(value):
            _bad()
        # ECMAScript's shortest-roundtrip representation, with its exponent cutovers.
        if value == 0:
            return b"0"
        text = repr(value).lower()
        negative = text.startswith("-")
        magnitude = text[1:] if negative else text
        if "e" in magnitude:
            mantissa, exponent = magnitude.split("e")
            exp = int(exponent)
        else:
            mantissa, exp = magnitude, 0
        before, dot, after = mantissa.partition(".")
        digits = before + after
        decimal_position = len(before) + exp
        while len(digits) > 1 and digits[0] == "0":
            digits = digits[1:]
            decimal_position -= 1
        while len(digits) > 1 and digits[-1] == "0":
            digits = digits[:-1]
        if 0 < decimal_position <= 21:
            if decimal_position >= len(digits):
                result = digits + "0" * (decimal_position - len(digits))
            else:
                result = digits[:decimal_position] + "." + digits[decimal_position:]
        elif -6 < decimal_position <= 0:
            result = "0." + "0" * (-decimal_position) + digits
        else:
            exponent_out = decimal_position - 1
            result = digits[0] + ("." + digits[1:] if len(digits) > 1 else "")
            result += "e" + ("+" if exponent_out >= 0 else "") + str(exponent_out)
        return ("-" if negative else "").encode("ascii") + result.encode("ascii")
    if type(value) is list:
        return b"[" + b",".join(_jcs(item) for item in value) + b"]"
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            _bad()
        try:
            keys = sorted(value, key=lambda key: key.encode("utf-16-be", "strict"))
        except UnicodeEncodeError:
            _bad()
        members = []
        for key in keys:
            members.append(_jcs(key) + b":" + _jcs(value[key]))
        return b"{" + b",".join(members) + b"}"
    _bad()


def _json(raw: bytes) -> Any:
    try:
        parsed = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_pairs,
                            parse_float=_parse_float, parse_constant=lambda _: _bad())
        # Recurse all strings/keys and ensure invalid surrogate code points are rejected.
        _jcs(parsed)
        if _jcs(parsed) != raw:
            _bad()
        return parsed
    except AccountPresentationError:
        raise
    except Exception:
        _bad()


def _decode(segment: str) -> bytes:
    if type(segment) is not str or not segment or not _B64.fullmatch(segment):
        _bad()
    try:
        decoded = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except Exception:
        _bad()
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        _bad()
    return decoded


def _compact(token: str, *, max_bytes: int | None = None):
    try:
        raw = token.encode("utf-8", "strict") if type(token) is str else b""
    except UnicodeEncodeError:
        _bad()
    if not raw or (max_bytes is not None and len(raw) > max_bytes):
        _bad()
    parts = token.split(".")
    if len(parts) != 3:
        _bad()
    header, payload, signature = _json(_decode(parts[0])), _json(_decode(parts[1])), _decode(parts[2])
    if type(header) is not dict or type(payload) is not dict:
        _bad()
    return header, payload, signature, (parts[0] + "." + parts[1]).encode("ascii")


def _text(value: Any) -> bool:
    if type(value) is not str or not value:
        return False
    try:
        value.encode("utf-8", "strict")
        return True
    except UnicodeEncodeError:
        return False


def _jti(value: Any) -> bool:
    if not _text(value):
        return False
    try:
        raw = _decode(value)
    except AccountPresentationError:
        return False
    return len(raw) == 32


def _verify_signature(token: str, expected_typ: str, binding: VerifiedOwnerKeyBinding, *, max_bytes: int | None = None):
    header, payload, signature, signed = _compact(token, max_bytes=max_bytes)
    if type(header) is not dict or set(header) != {"alg", "kid", "typ"}:
        _bad()
    if header != {"alg": "EdDSA", "kid": binding.owner_key_thumbprint, "typ": expected_typ}:
        _bad()
    try:
        pub = _decode(binding.owner_key.x)
        if len(pub) != 32 or len(signature) != 64:
            _bad()
        Ed25519PublicKey.from_public_bytes(pub).verify(signature, signed)
    except AccountPresentationError:
        raise
    except Exception:
        _bad()
    return payload


def verify_account_presentation(
    presentation_jws: str,
    *,
    context: WalletAccountDisclosureContext,
    binding: VerifiedOwnerKeyBinding,
    request: VerifiedOID4VPRequest,
    approved_claim_ids: list[str] | tuple[str, ...],
    approval_expires_at: int,
    now: int,
) -> VerifiedAccountPresentation:
    """Verify both nested signatures and their exact transaction/claim bindings."""
    try:
        if not isinstance(context, WalletAccountDisclosureContext) or not isinstance(binding, VerifiedOwnerKeyBinding) or not isinstance(request, VerifiedOID4VPRequest):
            _bad()
        if type(now) is not int or type(approval_expires_at) is not int:
            _bad()
        if not (0 < approval_expires_at <= context.expires_at):
            _bad()
        if (binding.issuer, binding.audience, binding.action, binding.transaction_id, binding.request_id, binding.oidc_nonce) != (context.keycloak_issuer, context.rp_client_id, context.action, context.transaction_id, context.request_id, context.oidc_nonce):
            _bad()
        if (request.action, request.transaction_id, request.request_id, request.purpose) != (context.action, context.transaction_id, context.request_id, context.purpose):
            _bad()
        if request.client_id == "" or request.nonce == "" or request.expires_at <= now:
            _bad()
        approved = tuple(approved_claim_ids)
        if any(type(cid) is not str for cid in approved) or len(set(approved)) != len(approved):
            _bad()
        requested = tuple(claim.claim_id for claim in context.claims)
        required = {claim.claim_id for claim in context.claims if claim.required}
        if not required <= set(approved) or not set(approved) <= set(requested) or not approved:
            _bad()
        query_cred = request.dcql_query["credentials"][0]
        selected_short = {cid.rsplit(":", 1)[-1] for cid in approved}
        if not any(set(choice) == selected_short for choice in query_cred["claim_sets"]):
            _bad()

        vp = _verify_signature(presentation_jws, _VP_TYP, binding, max_bytes=16 * 1024)
        if set(vp) != _VP_KEYS or vp.get("profile") != _PROFILE:
            _bad()
        if vp.get("iss") != binding.identity_id or vp.get("sub") != binding.identity_id:
            _bad()
        if vp.get("aud") != request.client_id or vp.get("nonce") != request.nonce:
            _bad()
        vp_iat, vp_exp = vp.get("iat"), vp.get("exp")
        if type(vp_iat) is not int or type(vp_exp) is not int or vp_iat < 1 or vp_exp < 1 or vp_iat > now + 60 or vp_exp <= now or vp_exp <= vp_iat:
            _bad()
        if not _jti(vp.get("jti")):
            _bad()
        vp_obj = vp.get("vp")
        if type(vp_obj) is not dict or set(vp_obj) != {"type", "verifiableCredential"} or vp_obj.get("type") != [_PRESENTATION] or type(vp_obj.get("verifiableCredential")) is not list or len(vp_obj["verifiableCredential"]) != 1:
            _bad()
        credential_token = vp_obj["verifiableCredential"][0]
        if not _text(credential_token):
            _bad()
        cred = _verify_signature(credential_token, _CRED_TYP, binding)
        if set(cred) != _CRED_KEYS or cred.get("profile") != _PROFILE or cred.get("credential_type") != _CREDENTIAL:
            _bad()
        if cred.get("iss") != binding.identity_id or cred.get("sub") != binding.identity_id or vp.get("iss") != cred.get("iss") or vp.get("sub") != cred.get("sub"):
            _bad()
        if (cred.get("action"), cred.get("rp_oidc_client_id"), cred.get("request_id"), cred.get("transaction_id"), cred.get("purpose"), cred.get("owner_key_thumbprint"), cred.get("owner_binding_jti")) != (context.action, context.rp_client_id, context.request_id, context.transaction_id, context.purpose, binding.owner_key_thumbprint, binding.jti):
            _bad()
        ciat, cexp = cred.get("iat"), cred.get("exp")
        if type(ciat) is not int or type(cexp) is not int or ciat < 1 or cexp < 1 or ciat > now + 60 or cexp <= now or cexp <= ciat or cexp - ciat > 300 or cexp > approval_expires_at or cexp > binding.expires_at:
            _bad()
        if not _jti(cred.get("jti")) or cred.get("jti") == vp.get("jti"):
            _bad()
        if vp_exp > min(cexp, binding.expires_at, approval_expires_at, request.expires_at):
            _bad()
        claims = cred.get("claims")
        if type(claims) is not dict or not set(claims) == set(approved) or not set(claims) <= set(CLAIM_IDS):
            _bad()
        for claim_id, value in claims.items():
            if claim_id not in requested or not _text(value) or len(value.encode("utf-8", "strict")) > 1024:
                _bad()
        if not required <= set(claims) or not set(claims) <= set(approved):
            _bad()
        return VerifiedAccountPresentation(binding.identity_id, dict(claims), cred["jti"], vp["jti"], vp_iat, vp_exp)
    except AccountPresentationError:
        raise
    except Exception:
        _bad()

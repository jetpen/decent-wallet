"""Strict consumer-side parsing for the adopted Account Disclosure v1 context."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


PROFILE_ID = "decent-account-disclosure-v1"
CLAIM_IDS = frozenset(
    {
        "urn:decent:account:v1:given_name",
        "urn:decent:account:v1:family_name",
        "urn:decent:account:v1:email",
        "urn:decent:account:v1:phone",
        "urn:decent:account:v1:locale",
    }
)
_CONTEXT_KEYS = frozenset(
    {
        "profile",
        "keycloak_issuer",
        "rp_client_id",
        "rp_display_name",
        "rp_origin",
        "action",
        "request_id",
        "transaction_id",
        "oidc_nonce",
        "purpose",
        "claims",
        "expires_at",
    }
)
_B64URL = re.compile(r"^[A-Za-z0-9_-]+$")
_DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_BIDI_CONTROLS = frozenset(
    {0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)}
)


class WalletDisclosureRequestError(ValueError):
    """Stable, value-free error for invalid Account Disclosure request context."""

    def __init__(self) -> None:
        super().__init__("wallet disclosure request rejected")

    def __repr__(self) -> str:
        return "WalletDisclosureRequestError()"


@dataclass(frozen=True, slots=True)
class RequestedAccountClaim:
    claim_id: str
    required: bool


@dataclass(frozen=True, slots=True)
class WalletAccountDisclosureContext:
    keycloak_issuer: str
    rp_client_id: str
    rp_display_name: str
    rp_origin: str
    action: str
    request_id: str
    transaction_id: str
    oidc_nonce: str
    purpose: str
    claims: tuple[RequestedAccountClaim, ...]
    expires_at: int
    decent_native_continuation: bool = False


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise WalletDisclosureRequestError()
        result[key] = value
    return result


def _parse_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise WalletDisclosureRequestError()
    return number


def _reject_constant(_value: str) -> Any:
    raise WalletDisclosureRequestError()


def _decode_context_json(raw: bytes) -> Any:
    if type(raw) is not bytes or not raw or len(raw) > 64 * 1024:
        raise WalletDisclosureRequestError()
    try:
        text = raw.decode("utf-8", errors="strict")
        if text.startswith("\ufeff"):
            raise WalletDisclosureRequestError()
        return json.loads(
            text,
            object_pairs_hook=_reject_duplicate_members,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except WalletDisclosureRequestError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise WalletDisclosureRequestError() from None


def _text(value: Any, *, minimum: int = 1, maximum: int = 4096) -> str:
    if type(value) is not str or not minimum <= len(value) <= maximum:
        raise WalletDisclosureRequestError()
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError:
        raise WalletDisclosureRequestError() from None
    return value


def _decode_b64url(value: Any, *, minimum_bytes: int, maximum_bytes: int) -> bytes:
    text = _text(value, minimum=1, maximum=128)
    if not _B64URL.fullmatch(text):
        raise WalletDisclosureRequestError()
    try:
        decoded = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, binascii.Error):
        raise WalletDisclosureRequestError() from None
    if not minimum_bytes <= len(decoded) <= maximum_bytes:
        raise WalletDisclosureRequestError()
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != text:
        raise WalletDisclosureRequestError()
    return decoded


def _validate_https_origin(value: str) -> None:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise WalletDisclosureRequestError() from None
    if (
        parsed.scheme != "https"
        or host is None
        or host != host.lower()
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or "?" in value
        or "#" in value
        or value.endswith("/")
    ):
        raise WalletDisclosureRequestError()
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        raise WalletDisclosureRequestError() from None
    if len(host) > 253 or host.endswith("."):
        raise WalletDisclosureRequestError()
    labels = host.split(".")
    if not labels or any(not _DNS_LABEL.fullmatch(label) for label in labels):
        raise WalletDisclosureRequestError()
    if port is not None and (not 1 <= port <= 65535 or port == 443):
        raise WalletDisclosureRequestError()
    expected_netloc = host if port is None else f"{host}:{port}"
    if parsed.netloc != expected_netloc:
        raise WalletDisclosureRequestError()


def _validate_purpose(value: Any) -> str:
    purpose = _text(value, minimum=1, maximum=160)
    if not any(not char.isspace() for char in purpose):
        raise WalletDisclosureRequestError()
    for char in purpose:
        point = ord(char)
        if point <= 0x1F or 0x7F <= point <= 0x9F or point in _BIDI_CONTROLS:
            raise WalletDisclosureRequestError()
    return purpose


def _parse_claims(value: Any) -> tuple[RequestedAccountClaim, ...]:
    if type(value) is not list or not 1 <= len(value) <= 16:
        raise WalletDisclosureRequestError()
    parsed: list[RequestedAccountClaim] = []
    seen: set[str] = set()
    required_count = 0
    optional_count = 0
    for item in value:
        if type(item) is not dict or set(item) != {"id", "required"}:
            raise WalletDisclosureRequestError()
        claim_id = _text(item["id"], maximum=128)
        required = item["required"]
        if claim_id not in CLAIM_IDS or claim_id in seen or type(required) is not bool:
            raise WalletDisclosureRequestError()
        seen.add(claim_id)
        required_count += int(required)
        optional_count += int(not required)
        parsed.append(RequestedAccountClaim(claim_id, required))
    if required_count < 1 or optional_count > 4:
        raise WalletDisclosureRequestError()
    return tuple(parsed)


def parse_wallet_account_disclosure_context(
    raw: bytes,
    *,
    expected_keycloak_issuer: str,
) -> WalletAccountDisclosureContext:
    """Parse the closed context object; caller must fetch it from trusted HTTPS Keycloak."""
    context = _decode_context_json(raw)
    if type(context) is not dict or set(context) not in (_CONTEXT_KEYS, _CONTEXT_KEYS | {"decent_native_continuation"}):
        raise WalletDisclosureRequestError()
    native_marker = context.get("decent_native_continuation", False)
    if type(native_marker) is not bool or ("decent_native_continuation" in context and native_marker is not True):
        raise WalletDisclosureRequestError()
    if context["profile"] != PROFILE_ID:
        raise WalletDisclosureRequestError()

    issuer = _text(context["keycloak_issuer"], maximum=2048)
    expected_issuer = _text(expected_keycloak_issuer, maximum=2048)
    if issuer != expected_issuer:
        raise WalletDisclosureRequestError()
    try:
        issuer_url = urlsplit(issuer)
        if (
            issuer_url.scheme != "https"
            or issuer_url.hostname is None
            or issuer_url.hostname != issuer_url.hostname.lower()
            or issuer_url.username is not None
            or issuer_url.password is not None
            or issuer_url.query
            or issuer_url.fragment
            or "?" in issuer
            or "#" in issuer
        ):
            raise WalletDisclosureRequestError()
    except ValueError:
        raise WalletDisclosureRequestError() from None

    client_id = _text(context["rp_client_id"], maximum=256)
    display_name = _text(context["rp_display_name"], maximum=128)
    rp_origin = _text(context["rp_origin"], maximum=2048)
    _validate_https_origin(rp_origin)

    action = context["action"]
    if type(action) is not str or action not in {"signup", "signup_recovery"}:
        raise WalletDisclosureRequestError()
    request_id = context["request_id"]
    if len(_decode_b64url(request_id, minimum_bytes=16, maximum_bytes=16)) != 16:
        raise WalletDisclosureRequestError()
    transaction_id = context["transaction_id"]
    if len(_decode_b64url(transaction_id, minimum_bytes=32, maximum_bytes=32)) != 32:
        raise WalletDisclosureRequestError()
    oidc_nonce = context["oidc_nonce"]
    _decode_b64url(oidc_nonce, minimum_bytes=16, maximum_bytes=96)
    purpose = _validate_purpose(context["purpose"])
    claims = _parse_claims(context["claims"])
    expires_at = context["expires_at"]
    if type(expires_at) is not int or expires_at < 1:
        raise WalletDisclosureRequestError()

    return WalletAccountDisclosureContext(
        keycloak_issuer=issuer,
        rp_client_id=client_id,
        rp_display_name=display_name,
        rp_origin=rp_origin,
        action=action,
        request_id=request_id,
        transaction_id=transaction_id,
        oidc_nonce=oidc_nonce,
        purpose=purpose,
        claims=claims,
        expires_at=expires_at,
        decent_native_continuation=native_marker,
    )


@dataclass(frozen=True, slots=True)
class Ed25519OwnerPublicKey:
    kty: str
    crv: str
    x: str


@dataclass(frozen=True, slots=True)
class VerifiedOwnerKeyBinding:
    issuer: str
    audience: str
    subject: str
    identity_id: str
    owner_key: Ed25519OwnerPublicKey
    owner_key_thumbprint: str
    action: str
    transaction_id: str
    request_id: str
    oidc_nonce: str
    issued_at: int
    expires_at: int
    jti: str
    compact_jws_sha256: str
    continuation_capability_hash: str | None = None


_BINDING_KEYS = frozenset({"v", "iss", "aud", "sub", "identity_id", "owner_key", "owner_key_thumbprint", "action", "transaction_id", "request_id", "oidc_nonce", "iat", "exp", "jti"})
_BINDING_TYP = "decent-owner-key-binding+jwt"
_MAX_ISSUER_JWKS_KEYS = 64


def _decode_segment(segment: str, *, maximum: int = 16_384) -> bytes:
    if not isinstance(segment, str) or not segment or len(segment) > maximum or not _B64URL.fullmatch(segment):
        raise WalletDisclosureRequestError()
    try:
        raw = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (ValueError, binascii.Error):
        raise WalletDisclosureRequestError() from None
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != segment:
        raise WalletDisclosureRequestError()
    return raw


def _binding_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_reject_duplicate_members,
                          parse_float=_parse_float, parse_constant=_reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        raise WalletDisclosureRequestError() from None


def _thumbprint(owner: dict[str, Any]) -> str:
    canonical = json.dumps({"crv": owner["crv"], "kty": owner["kty"], "x": owner["x"]},
                           ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return base64.urlsafe_b64encode(__import__("hashlib").sha256(canonical).digest()).decode("ascii").rstrip("=")


def verify_owner_key_binding(compact_jws: str, issuer_jwks: dict[str, Any], pending_context: WalletAccountDisclosureContext,
                             *, expected_identity_id: str, now: int) -> VerifiedOwnerKeyBinding:
    """Verify the nested Keycloak binding after trusted HTTPS JWKS retrieval and OIDC validation.

    This does not validate the outer ID token, state, code exchange, or PKCE.
    """
    try:
        if type(now) is not int or not isinstance(pending_context, WalletAccountDisclosureContext):
            raise WalletDisclosureRequestError()
        token = _text(compact_jws, maximum=32_768)
        parts = token.split(".")
        if len(parts) != 3:
            raise WalletDisclosureRequestError()
        hraw, praw, sig = (_decode_segment(part) for part in parts)
        header = _binding_json(hraw)
        if type(header) is not dict or set(header) != {"alg", "typ", "kid"}:
            raise WalletDisclosureRequestError()
        kid = _text(header["kid"], maximum=256)
        if header["alg"] != "RS256" or header["typ"] != _BINDING_TYP:
            raise WalletDisclosureRequestError()
        if type(issuer_jwks) is not dict or set(issuer_jwks) != {"keys"} or type(issuer_jwks["keys"]) is not list:
            raise WalletDisclosureRequestError()
        if len(issuer_jwks["keys"]) > _MAX_ISSUER_JWKS_KEYS:
            raise WalletDisclosureRequestError()
        matches = [key for key in issuer_jwks["keys"] if type(key) is dict and key.get("kid") == kid and key.get("kty") == "RSA" and key.get("use") == "sig" and key.get("alg") == "RS256"]
        if len(matches) != 1:
            raise WalletDisclosureRequestError()
        key = matches[0]
        if not {"kid", "kty", "use", "alg", "n", "e"} <= set(key) or set(key) - {"kid", "kty", "use", "alg", "n", "e", "key_ops"}:
            raise WalletDisclosureRequestError()
        if "key_ops" in key and key["key_ops"] != ["verify"]:
            raise WalletDisclosureRequestError()
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding, rsa
        n = int.from_bytes(_decode_segment(key["n"], maximum=2048), "big")
        e = int.from_bytes(_decode_segment(key["e"], maximum=16), "big")
        public_key = rsa.RSAPublicNumbers(e, n).public_key()
        if public_key.key_size < 2048:
            raise WalletDisclosureRequestError()
        public_key.verify(sig, (parts[0] + "." + parts[1]).encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        payload = _binding_json(praw)
        payload_keys = set(payload) if type(payload) is dict else set()
        if (type(payload) is not dict or payload_keys not in (_BINDING_KEYS, _BINDING_KEYS | {"continuation_capability_hash"})
                or type(payload["v"]) is not int or payload["v"] != 1):
            raise WalletDisclosureRequestError()
        capability_hash = None
        if "continuation_capability_hash" in payload:
            if not pending_context.decent_native_continuation:
                raise WalletDisclosureRequestError()
            capability_hash = _text(payload["continuation_capability_hash"], maximum=43)
            if len(_decode_b64url(capability_hash, minimum_bytes=32, maximum_bytes=32)) != 32:
                raise WalletDisclosureRequestError()
        elif pending_context.decent_native_continuation:
            raise WalletDisclosureRequestError()
        owner = payload["owner_key"]
        if type(owner) is not dict or set(owner) != {"kty", "crv", "x"} or owner["kty"] != "OKP" or owner["crv"] != "Ed25519":
            raise WalletDisclosureRequestError()
        x = _text(owner["x"], maximum=64)
        if len(_decode_segment(x, maximum=64)) != 32:
            raise WalletDisclosureRequestError()
        thumb = _text(payload["owner_key_thumbprint"], maximum=64)
        if thumb != _thumbprint(owner):
            raise WalletDisclosureRequestError()
        for field in ("iss", "aud", "sub", "identity_id", "action", "transaction_id", "request_id", "oidc_nonce"):
            _text(payload[field])
        if len(_decode_segment(payload["jti"], maximum=64)) != 32:
            raise WalletDisclosureRequestError()
        if payload["iss"] != pending_context.keycloak_issuer or payload["aud"] != pending_context.rp_client_id:
            raise WalletDisclosureRequestError()
        if any(payload[k] != getattr(pending_context, attr) for k, attr in (("action", "action"), ("transaction_id", "transaction_id"), ("request_id", "request_id"), ("oidc_nonce", "oidc_nonce"))):
            raise WalletDisclosureRequestError()
        if payload["identity_id"] != expected_identity_id:
            raise WalletDisclosureRequestError()
        iat, exp = payload["iat"], payload["exp"]
        if type(iat) is not int or type(exp) is not int or exp <= iat or exp - iat > 300 or iat > now + 60 or now >= exp or exp > pending_context.expires_at:
            raise WalletDisclosureRequestError()
        return VerifiedOwnerKeyBinding(payload["iss"], payload["aud"], payload["sub"], payload["identity_id"], Ed25519OwnerPublicKey("OKP", "Ed25519", x), thumb, payload["action"], payload["transaction_id"], payload["request_id"], payload["oidc_nonce"], iat, exp, payload["jti"], hashlib.sha256(token.encode("utf-8")).hexdigest(), capability_hash)
    except WalletDisclosureRequestError:
        raise
    except Exception:
        raise WalletDisclosureRequestError() from None

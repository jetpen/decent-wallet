"""Offline verifier for the adopted OpenID4VP Authorization Request profile.

The caller must fetch request_uri without redirects, over HTTPS, with no-store and
referrer protections. This module performs no network access or persistence.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from decent_wallet.account_disclosure import (
    WalletAccountDisclosureContext,
    VerifiedOwnerKeyBinding,
)

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

MAX_JWS_BYTES = 65536
FORMAT = "decent_account_jwt_v1"
PROFILE = "decent-account-disclosure-v1"
NAMES = {"given_name", "family_name", "email", "phone", "locale"}
KNOWN_OUTER = {
    "client_id",
    "request_uri",
    "response_type",
    "response_mode",
    "scope",
    "redirect_uri",
    "response_uri",
    "state",
    "nonce",
    "prompt",
    "max_age",
    "login_hint",
    "claims",
    "request",
    "request_uri_method",
    "client_metadata",
    "dcql_query",
    "transaction_data",
    "code_challenge",
    "code_challenge_method",
}


class OID4VPRequestError(ValueError):
    """Value-free protocol rejection."""

    def __init__(self):
        super().__init__("OID4VP authorization request rejected")

    def __repr__(self):
        return "OID4VPRequestError()"


@dataclass(frozen=True, slots=True)
class TrustedRPRegistration:
    client_id: str
    x509_san_dns: str
    origin: str
    response_uri: str
    trust_anchor_sha256: str
    rp_client_id: str = ""


@dataclass(frozen=True, slots=True)
class VerifiedOID4VPRequest:
    client_id: str
    state: str
    nonce: str
    response_uri: str
    dcql_query: dict[str, Any]
    purpose: str
    request_id: str
    transaction_id: str
    action: str
    expires_at: int


def _fail():
    raise OID4VPRequestError()


def _pairs(items):
    d = {}
    for k, v in items:
        if k in d:
            _fail()
        d[k] = v
    return d


def _json(b):
    def pf(s):
        n = float(s)
        if not math.isfinite(n):
            _fail()
        return n

    def bad(_):
        _fail()

    def valid_unicode(value):
        if isinstance(value, str):
            if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
                _fail()
        elif isinstance(value, dict):
            for key, item in value.items():
                valid_unicode(key)
                valid_unicode(item)
        elif isinstance(value, list):
            for item in value:
                valid_unicode(item)

    try:
        value = json.loads(
            b.decode("utf-8", "strict"),
            object_pairs_hook=_pairs,
            parse_float=pf,
            parse_constant=bad,
        )
        valid_unicode(value)
        return value
    except OID4VPRequestError:
        raise
    except Exception:
        _fail()


def _b64(s):
    if type(s) is not str or not re.fullmatch(r"[A-Za-z0-9_-]+", s):
        _fail()
    try:
        b = base64.urlsafe_b64decode(s + "=" * ((-len(s)) % 4))
    except Exception:
        _fail()
    if base64.urlsafe_b64encode(b).rstrip(b"=").decode() != s:
        _fail()
    return b


def _compact(token):
    if type(token) is not str or len(token.encode("utf-8", "strict")) > MAX_JWS_BYTES:
        _fail()
    p = token.split(".")
    if len(p) != 3:
        _fail()
    h = _json(_b64(p[0]))
    payload = _json(_b64(p[1]))
    sig = _b64(p[2])
    if type(h) is not dict or type(payload) is not dict:
        _fail()
    return h, payload, sig, (p[0] + "." + p[1]).encode("ascii")


def _https_origin(uri):
    try:
        p = urlsplit(uri)
        host = p.hostname
        port = p.port
    except Exception:
        _fail()
    if (
        p.scheme != "https"
        or not host
        or host != host.lower()
        or p.username
        or p.password
        or p.fragment
        or p.netloc not in (host, f"{host}:{port}" if port else host)
    ):
        _fail()
    return host


def _dns_from_x5c(value):
    if type(value) is not list or not 1 <= len(value) <= 8:
        _fail()
    try:
        return [
            x509.load_der_x509_certificate(base64.b64decode(x, validate=True))
            for x in value
        ]
    except Exception:
        _fail()


def _verify_certificates(chain, reg, now):
    anchor_fp = reg.trust_anchor_sha256.lower()
    if not re.fullmatch("[0-9a-f]{64}", anchor_fp):
        _fail()
    if not chain or chain[-1].fingerprint(hashes.SHA256()).hex() != anchor_fp:
        _fail()
    leaf = chain[0]
    for cert in chain:
        if (
            now < cert.not_valid_before_utc.timestamp()
            or now > cert.not_valid_after_utc.timestamp()
        ):
            _fail()
    try:
        san = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
    except Exception:
        _fail()
    if (
        reg.x509_san_dns not in san
        or reg.client_id != "x509_san_dns:" + reg.x509_san_dns
    ):
        _fail()
    for i, child in enumerate(chain[:-1]):
        issuer = chain[i + 1]
        if child.issuer != issuer.subject:
            _fail()
        try:
            public_key = issuer.public_key()
            if isinstance(public_key, rsa.RSAPublicKey):
                public_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    child.signature_hash_algorithm,
                )
            elif isinstance(public_key, ec.EllipticCurvePublicKey):
                public_key.verify(
                    child.signature,
                    child.tbs_certificate_bytes,
                    ec.ECDSA(child.signature_hash_algorithm),
                )
            else:
                _fail()
        except Exception:
            _fail()
    # A one-certificate self-signed pinned leaf is valid; otherwise the anchor
    # must be a CA and every intermediate must authorize certificate signing.
    for issuer in chain[1:]:
        try:
            bc = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            ku = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
            if not bc.ca or not ku.key_cert_sign:
                _fail()
        except x509.ExtensionNotFound:
            _fail()


def _verify_sig(head, payload, sig, signed, registration, now):
    if (
        head.get("alg") != "ES256"
        or head.get("typ") != "oauth-authz-req+jwt"
        or "crit" in head
    ):
        _fail()
    cs = _dns_from_x5c(head.get("x5c"))
    _verify_certificates(cs, registration, now)
    key = cs[0].public_key()
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(
        key.curve, ec.SECP256R1
    ):
        _fail()
    if len(sig) != 64:
        _fail()
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

    try:
        key.verify(
            encode_dss_signature(
                int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
            ),
            signed,
            ec.ECDSA(hashes.SHA256()),
        )
    except Exception:
        _fail()


def verify_oid4vp_authorization_request(
    outer: dict[str, Any],
    *,
    request_object: str,
    registration: TrustedRPRegistration,
    context: Any,
    owner_key_binding_jws: str,
    verified_binding: Any = None,
    now: int | None = None,
) -> VerifiedOID4VPRequest:
    try:
        instant = int(time.time()) if now is None else now
        if type(instant) is not int:
            _fail()
        if type(outer) is not dict or set(("client_id", "request_uri")) - set(outer):
            _fail()
        if any(
            k in KNOWN_OUTER
            and k not in ("client_id", "request_uri", "transaction_data")
            for k in outer
        ):
            _fail()
        if "transaction_data" in outer:
            _fail()
        if (
            outer["client_id"] != registration.client_id
            or type(outer["request_uri"]) is not str
        ):
            _fail()
        if (
            registration.client_id != outer["client_id"]
            or registration.rp_client_id != context.rp_client_id
            or registration.origin != context.rp_origin
        ):
            _fail()
        if not isinstance(context, WalletAccountDisclosureContext) or not isinstance(
            verified_binding, VerifiedOwnerKeyBinding
        ):
            _fail()
        if (
            verified_binding.compact_jws_sha256
            != hashlib.sha256(
                owner_key_binding_jws.encode("utf-8", "strict")
            ).hexdigest()
        ):
            _fail()
        if (
            verified_binding.issuer != context.keycloak_issuer
            or verified_binding.audience != context.rp_client_id
            or verified_binding.action != context.action
            or verified_binding.request_id != context.request_id
            or verified_binding.transaction_id != context.transaction_id
            or verified_binding.oidc_nonce != context.oidc_nonce
            or verified_binding.expires_at > context.expires_at
        ):
            _fail()
        u = outer["request_uri"]
        host = _https_origin(u)
        if (
            host != registration.x509_san_dns
            or urlsplit(u).netloc != urlsplit(registration.origin).netloc
        ):
            _fail()
        head, p, sig, signed = _compact(request_object)
        _verify_sig(head, p, sig, signed, registration, instant)
        if type(p) is not dict or "transaction_data" in p:
            _fail()
        if (
            p.get("aud") != "https://self-issued.me/v2"
            or p.get("client_id") != registration.client_id
        ):
            _fail()
        if (
            p.get("response_type") != "vp_token"
            or p.get("response_mode") != "direct_post"
            or p.get("response_uri") != registration.response_uri
        ):
            _fail()
        if _https_origin(registration.origin) != registration.x509_san_dns:
            _fail()
        reused_context_values = {
            context.oidc_nonce,
            context.request_id,
            context.transaction_id,
        }
        if (
            type(p.get("state")) is not str
            or len(_b64(p["state"])) < 16
            or type(p.get("nonce")) is not str
            or len(_b64(p["nonce"])) < 32
            or p["state"] == p["nonce"]
            or p["state"] in reused_context_values
            or p["nonce"] in reused_context_values
        ):
            _fail()
        iat, exp = p.get("iat"), p.get("exp")
        if (
            type(iat) is not int
            or type(exp) is not int
            or iat > instant + 60
            or exp <= instant
            or exp <= iat
            or exp - iat > 300
            or exp > context.expires_at
            or exp > verified_binding.expires_at
            or type(p.get("jti")) is not str
            or not p["jti"]
        ):
            _fail()
        if "iss" in p:
            pass
        md = p.get("client_metadata")
        if (
            type(md) is not dict
            or type(md.get("vp_formats_supported")) is not dict
            or type(md["vp_formats_supported"].get(FORMAT)) is not dict
            or md["vp_formats_supported"][FORMAT].get("alg_values") != ["EdDSA"]
        ):
            _fail()
        ext = p.get("decent_account")
        if type(ext) is not dict or set(ext) != {
            "profile",
            "rp_oidc_client_id",
            "action",
            "request_id",
            "transaction_id",
            "purpose",
            "owner_key_binding",
            "claims",
        }:
            _fail()
        if (
            ext["profile"] != PROFILE
            or ext["rp_oidc_client_id"] != context.rp_client_id
            or ext["action"] != context.action
            or ext["request_id"] != context.request_id
            or ext["transaction_id"] != context.transaction_id
            or ext["purpose"] != context.purpose
            or ext["owner_key_binding"] != owner_key_binding_jws
            or ext["claims"]
            != [{"id": c.claim_id, "required": c.required} for c in context.claims]
        ):
            _fail()
        q = p.get("dcql_query")
        if (
            type(q) is not dict
            or type(q.get("credentials")) is not list
            or len(q["credentials"]) != 1
        ):
            _fail()
        cred = q["credentials"][0]
        if (
            type(cred) is not dict
            or cred.get("id") != "account"
            or cred.get("format") != FORMAT
            or cred.get("multiple") is not False
            or type(cred.get("meta")) is not dict
            or cred.get("require_cryptographic_holder_binding") is not True
        ):
            _fail()
        if "credential_sets" in q or "trusted_authorities" in cred:
            _fail()
        claims = cred.get("claims")
        requested = [c.claim_id.rsplit(":", 1)[-1] for c in context.claims]
        if type(claims) is not list or len(claims) != len(requested):
            _fail()
        ids = []
        normalized_claims = []
        for cl in claims:
            if (
                type(cl) is not dict
                or "id" not in cl
                or "path" not in cl
                or any(k in cl for k in ("values", "intent_to_retain"))
                or cl["id"] not in NAMES
                or cl["path"] != ["claims", "urn:decent:account:v1:" + cl["id"]]
            ):
                _fail()
            ids.append(cl["id"])
            normalized_claims.append({"id": cl["id"], "path": list(cl["path"])})
        if ids != requested:
            _fail()
        required = [c.claim_id.rsplit(":", 1)[-1] for c in context.claims if c.required]
        optional = [
            c.claim_id.rsplit(":", 1)[-1] for c in context.claims if not c.required
        ]
        if not required or len(optional) > 4:
            _fail()
        expected = []
        for n in range(len(optional) + 1):
            for mask in range(1 << len(optional)):
                chosen = required + [x for i, x in enumerate(optional) if mask >> i & 1]
                if len(chosen) == len(required) + n:
                    expected.append([x for x in ids if x in chosen])
        # Sort stable by count then original request ordering; all generated sets unique.
        expected = sorted(expected, key=lambda x: (len(x), [ids.index(y) for y in x]))
        if cred.get("claim_sets") != expected:
            _fail()
        normalized_cred = {
            "id": "account",
            "format": FORMAT,
            "multiple": False,
            "meta": {},
            "require_cryptographic_holder_binding": True,
            "claims": normalized_claims,
            "claim_sets": expected,
        }
        normalized_q = {"credentials": [normalized_cred]}
        return VerifiedOID4VPRequest(
            registration.client_id,
            p["state"],
            p["nonce"],
            registration.response_uri,
            normalized_q,
            context.purpose,
            context.request_id,
            context.transaction_id,
            context.action,
            exp,
        )
    except OID4VPRequestError:
        raise
    except Exception:
        _fail()

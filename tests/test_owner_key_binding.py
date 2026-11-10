from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from decent_wallet import WalletDisclosureRequestError, parse_wallet_account_disclosure_context, verify_owner_key_binding

VECTORS = Path(__file__).parent / "vectors" / "wallet-account-disclosure-v1" / "vectors"
ISSUER = "https://login.example.test/realms/site"


def _vector():
    return json.loads((VECTORS / "valid-signup.json").read_text())


def _verify(vector, token=None, *, jwks=None, context=None, identity="mailto:ada@example.test", now=1800000001):
    pending = parse_wallet_account_disclosure_context(
        json.dumps(context or vector["keycloak_context"]).encode(), expected_keycloak_issuer=ISSUER
    )
    return verify_owner_key_binding(
        token or vector["owner_key_binding_jws"], jwks or vector["keycloak_jwks"], pending,
        expected_identity_id=identity, now=now,
    )


def _signed(payload):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()
    b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    encint = lambda value: b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))
    header = b64(b'{"alg":"RS256","kid":"test-key","typ":"decent-owner-key-binding+jwt"}')
    body = b64(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header}.{body}".encode()
    signature = private.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    jwks = {"keys": [{"kty": "RSA", "n": encint(public.n), "e": encint(public.e), "kid": "test-key", "use": "sig", "alg": "RS256"}]}
    return f"{header}.{body}.{b64(signature)}", jwks


def test_verifies_shared_signed_binding_and_returns_typed_public_owner_key():
    result = _verify(_vector())
    assert result.issuer == ISSUER
    assert result.subject == "kc-subject-9f2a"
    assert result.identity_id == "mailto:ada@example.test"
    assert result.action == "signup"
    assert result.owner_key.kty == "OKP"
    assert result.owner_key.crv == "Ed25519"
    assert result.owner_key_thumbprint == "p-GGO8M2jfl0NV7PEz-ysaXEQtvajbpiTd9-pcOkGLQ"
    assert result.compact_jws_sha256 == __import__("hashlib").sha256(_vector()["owner_key_binding_jws"].encode()).hexdigest()


def test_rejects_tampered_signature_bad_header_and_duplicate_payload_members():
    v = _vector(); token = v["owner_key_binding_jws"]
    a, b, c = token.split(".")
    with pytest.raises(WalletDisclosureRequestError): _verify(v, token=f"{a}.{b}.{c[:-1]}{'A' if c[-1] != 'A' else 'B'}")
    with pytest.raises(WalletDisclosureRequestError): _verify(v, token=f"eyJhbGciOiJub25lIn0.{b}.{c}")
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = private.public_key().public_numbers()
    b64 = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    encint = lambda value: b64(value.to_bytes((value.bit_length() + 7) // 8, "big"))
    header = b64(b'{"alg":"RS256","kid":"test-key","typ":"decent-owner-key-binding+jwt"}')
    duplicate_payload = b64(b'{"v":1,"v":1}')
    signed = f"{header}.{duplicate_payload}"
    signature = b64(private.sign(signed.encode(), padding.PKCS1v15(), hashes.SHA256()))
    jwks = {"keys": [{"kty": "RSA", "n": encint(public.n), "e": encint(public.e), "kid": "test-key", "use": "sig", "alg": "RS256"}]}
    with pytest.raises(WalletDisclosureRequestError): _verify(v, token=f"{signed}.{signature}", jwks=jwks)


@pytest.mark.parametrize("field,value", [
    ("iss", "https://wrong.example"), ("aud", "other-client"), ("oidc_nonce", "wrong"),
    ("action", "signup_recovery"), ("transaction_id", "wrong"), ("request_id", "wrong"),
    ("identity_id", "mailto:other@example.test"),
])
def test_rejects_signed_binding_mismatches(field, value):
    v = _vector()
    original = json.loads(base64.urlsafe_b64decode(v["owner_key_binding_jws"].split(".")[1] + "=="))
    original[field] = value
    token, jwks = _signed(original)
    with pytest.raises(WalletDisclosureRequestError): _verify(v, token=token, jwks=jwks)


def test_accepts_and_returns_signed_subject_without_wallet_expected_subject():
    v = _vector()
    payload = json.loads(base64.urlsafe_b64decode(v["owner_key_binding_jws"].split(".")[1] + "=="))
    payload["sub"] = "different-but-well-formed-subject"
    token, jwks = _signed(payload)
    result = _verify(v, token=token, jwks=jwks)
    assert result.subject == "different-but-well-formed-subject"


@pytest.mark.parametrize("subject", ["", 7, None])
def test_rejects_missing_or_invalid_signed_subject(subject):
    v = _vector()
    payload = json.loads(base64.urlsafe_b64decode(v["owner_key_binding_jws"].split(".")[1] + "=="))
    payload["sub"] = subject
    token, jwks = _signed(payload)
    with pytest.raises(WalletDisclosureRequestError):
        _verify(v, token=token, jwks=jwks)


def test_rejects_wrong_identity_and_expired_or_stale_statement():
    v = _vector()
    with pytest.raises(WalletDisclosureRequestError): _verify(v, identity="mailto:other@example.test")
    with pytest.raises(WalletDisclosureRequestError): _verify(v, now=1800000300)
    with pytest.raises(WalletDisclosureRequestError): _verify(v, now=1800000000 - 61)


def test_issuer_jwks_key_count_is_bounded_without_rejecting_the_limit():
    vector = _vector()
    key = vector["keycloak_jwks"]["keys"][0]
    unrelated = [
        {"kid": f"unrelated-{index}", "kty": "RSA", "use": "enc", "alg": "RS256"}
        for index in range(64)
    ]
    within_limit = {"keys": [key, *unrelated[:63]]}
    above_limit = {"keys": [key, *unrelated]}

    assert _verify(vector, jwks=within_limit).subject == "kc-subject-9f2a"
    with pytest.raises(WalletDisclosureRequestError):
        _verify(vector, jwks=above_limit)


def test_rejects_ambiguous_or_ineligible_jwks_and_private_or_malformed_owner_jwk():
    v = _vector(); key = v["keycloak_jwks"]["keys"][0]
    with pytest.raises(WalletDisclosureRequestError): _verify(v, jwks={"keys": [key, dict(key)]})
    with pytest.raises(WalletDisclosureRequestError): _verify(v, jwks={"keys": []})
    owner_mutations = (
        {"kty": "OKP", "crv": "Ed25519", "x": "bad"},
        {"kty": "OKP", "crv": "Ed25519", "x": "dPZCzkywe4AnlUjmnR_cSlCdKlk6rfaxs4S5jTma9wk", "d": "private"},
    )
    original = json.loads(base64.urlsafe_b64decode(v["owner_key_binding_jws"].split(".")[1] + "=="))
    for owner in owner_mutations:
        changed = dict(original, owner_key=owner)
        token, jwks = _signed(changed)
        with pytest.raises(WalletDisclosureRequestError): _verify(v, token=token, jwks=jwks)

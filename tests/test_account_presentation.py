from __future__ import annotations

import base64
import copy
import json
from pathlib import Path
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from decent_wallet.account_disclosure import Ed25519OwnerPublicKey
from decent_wallet.account_presentation import _jcs

from decent_wallet.account_disclosure import (
    parse_wallet_account_disclosure_context,
    verify_owner_key_binding,
)
from decent_wallet.oid4vp_request import TrustedRPRegistration, verify_oid4vp_authorization_request
from decent_wallet.account_presentation import verify_account_presentation

VECTORS = Path(__file__).parent / "vectors/wallet-account-disclosure-v1/vectors"
ISSUER = "https://login.example.test/realms/site"


def vector(name):
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def verified(v):
    context = parse_wallet_account_disclosure_context(
        json.dumps(v["keycloak_context"]).encode(), expected_keycloak_issuer=ISSUER
    )
    binding = verify_owner_key_binding(
        v["owner_key_binding_jws"], v["keycloak_jwks"], context,
        expected_identity_id="mailto:ada@example.test", now=v["validation_time"],
    )
    registration = TrustedRPRegistration(
        v["oid4vp_client_id"], "site.example.test", context.rp_origin,
        "https://site.example.test/oid4vp/response",
        v["rp_certificate"]["trust_anchor_sha256"], context.rp_client_id,
    )
    request = verify_oid4vp_authorization_request(
        outer=v["oid4vp_authorization_parameters"],
        request_object=v["oid4vp_request_jws"], registration=registration,
        context=context, owner_key_binding_jws=v["owner_key_binding_jws"],
        verified_binding=binding, now=v["validation_time"],
    )
    return context, binding, request


@pytest.mark.parametrize("filename", sorted(p.name for p in VECTORS.glob("valid-*.json")))
def test_accepts_unchanged_positive_presentation_vectors(filename):
    v = vector(filename)
    context, binding, request = verified(v)
    result = verify_account_presentation(
        v["presentation_jws"], context=context, binding=binding, request=request,
        approved_claim_ids=v["wallet_approved_claim_ids"], approval_expires_at=context.expires_at,
        now=v["validation_time"],
    )
    assert result.identity_id == "mailto:ada@example.test"
    assert set(result.claims) == set(v["wallet_approved_claim_ids"])


def test_rejects_a_changed_outer_signature():
    v = vector("valid-signup.json")
    context, binding, request = verified(v)
    parts = v["presentation_jws"].split(".")
    changed = parts[0] + "." + parts[1] + "." + ("A" if parts[2][0] != "A" else "B") + parts[2][1:]
    with pytest.raises(ValueError):
        verify_account_presentation(changed, context=context, binding=binding, request=request,
            approved_claim_ids=v["wallet_approved_claim_ids"], approval_expires_at=context.expires_at,
            now=v["validation_time"])


def _enc(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _dec(segment):
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _unpack(token):
    return json.loads(_dec(token.split(".")[1]))


def _signed(token_header, payload, private_key):
    protected = _enc(_jcs(token_header))
    body = _enc(_jcs(payload))
    signed = (protected + "." + body).encode("ascii")
    return protected + "." + body + "." + _enc(private_key.sign(signed))


def _test_signed_presentation(v, *, vp_change=None, credential_change=None, corrupt_inner=False):
    context, binding, request = verified(v)
    private = Ed25519PrivateKey.generate()
    raw_public = private.public_key().public_bytes_raw()
    owner = {"kty": "OKP", "crv": "Ed25519", "x": _enc(raw_public)}
    thumb = _enc(__import__("hashlib").sha256(_jcs(owner)).digest())
    test_binding = replace(binding, owner_key=Ed25519OwnerPublicKey("OKP", "Ed25519", owner["x"]), owner_key_thumbprint=thumb)
    parts = v["presentation_jws"].split(".")
    vp = json.loads(_dec(parts[1]))
    inner = vp["vp"]["verifiableCredential"][0]
    cred_parts = inner.split(".")
    credential = json.loads(_dec(cred_parts[1]))
    credential["owner_key_thumbprint"] = thumb
    if credential_change:
        credential_change(credential)
    cred_header = {"alg": "EdDSA", "kid": thumb, "typ": "decent-account-credential+jwt"}
    new_inner = _signed(cred_header, credential, private)
    if corrupt_inner:
        inner_parts = new_inner.split(".")
        new_inner = ".".join(inner_parts[:2] + [_enc(bytes([_dec(inner_parts[2])[0] ^ 1]) + _dec(inner_parts[2])[1:])])
    vp["vp"]["verifiableCredential"] = [new_inner]
    if vp_change:
        vp_change(vp)
    vp_header = {"alg": "EdDSA", "kid": thumb, "typ": "decent-account-presentation+jwt"}
    token = _signed(vp_header, vp, private)
    return token, context, test_binding, request


@pytest.mark.parametrize("mutate", [
    lambda vp: vp.__setitem__("aud", "x509_san_dns:attacker.example"),
    lambda vp: vp.__setitem__("nonce", "wrong-request-nonce-value"),
    lambda vp: vp.__setitem__("unexpected", True),
])
def test_rejects_validly_signed_presentation_semantic_mutations(mutate):
    v = vector("valid-signup.json")
    token, context, binding, request = _test_signed_presentation(v, vp_change=mutate)
    with pytest.raises(ValueError):
        verify_account_presentation(token, context=context, binding=binding, request=request,
            approved_claim_ids=v["wallet_approved_claim_ids"], approval_expires_at=context.expires_at,
            now=v["validation_time"])


def test_rejects_validly_signed_credential_semantic_mutations():
    v = vector("valid-signup.json")
    def wrong_action(credential):
        credential["action"] = "signup_recovery"
    token, context, binding, request = _test_signed_presentation(v, credential_change=wrong_action)
    with pytest.raises(ValueError):
        verify_account_presentation(token, context=context, binding=binding, request=request,
            approved_claim_ids=v["wallet_approved_claim_ids"], approval_expires_at=context.expires_at,
            now=v["validation_time"])


@pytest.mark.parametrize("mutate", [
    lambda credential: credential.__setitem__("iat", 1800000062),
    lambda credential: credential.__setitem__("exp", credential["iat"] + 301),
    lambda credential: credential["claims"].__setitem__("urn:decent:account:v1:email", "é" * 513),
    lambda credential: credential["claims"].__setitem__("urn:decent:account:v1:email", ""),
])
def test_rejects_validly_signed_invalid_credential_times_and_values(mutate):
    v = vector("valid-signup.json")
    token, context, binding, request = _test_signed_presentation(v, credential_change=mutate)
    with pytest.raises(ValueError):
        verify_account_presentation(token, context=context, binding=binding, request=request,
            approved_claim_ids=v["wallet_approved_claim_ids"], approval_expires_at=context.expires_at,
            now=v["validation_time"])


def test_rejects_credential_expiry_beyond_approval_and_request_boundaries():
    from dataclasses import replace
    v = vector("valid-signup.json")
    token, context, binding, request = _test_signed_presentation(v)
    with pytest.raises(ValueError):
        verify_account_presentation(token, context=context, binding=binding, request=request,
            approved_claim_ids=v["wallet_approved_claim_ids"], approval_expires_at=1800000200,
            now=v["validation_time"])
    with pytest.raises(ValueError):
        verify_account_presentation(token, context=context, binding=binding,
            request=replace(request, expires_at=1800000239),
            approved_claim_ids=v["wallet_approved_claim_ids"], approval_expires_at=context.expires_at,
            now=v["validation_time"])


def test_rejects_invalid_approved_claim_sets():
    v = vector("valid-signup-optional-omitted.json")
    context, binding, request = verified(v)
    for approved in [[], ["urn:decent:account:v1:email"], ["urn:decent:account:v1:given_name", "urn:decent:account:v1:given_name"], ["urn:decent:account:v1:given_name", "urn:decent:account:v1:locale"]]:
        with pytest.raises(ValueError):
            verify_account_presentation(v["presentation_jws"], context=context, binding=binding,
                request=request, approved_claim_ids=approved, approval_expires_at=context.expires_at,
                now=v["validation_time"])


def test_rejects_bad_inner_signature_with_valid_outer_signature():
    v = vector("valid-signup.json")
    token, context, binding, request = _test_signed_presentation(v, corrupt_inner=True)
    with pytest.raises(ValueError):
        verify_account_presentation(token, context=context, binding=binding, request=request,
            approved_claim_ids=v["wallet_approved_claim_ids"], approval_expires_at=context.expires_at,
            now=v["validation_time"])


def test_rejects_badly_encoded_json_and_noncanonical_jcs_payloads():
    v = vector("valid-signup.json")
    context, binding, request = verified(v)
    parts = v["presentation_jws"].split(".")
    payload = _dec(parts[1])
    noncanonical = _enc(b" " + payload)
    changed = parts[0] + "." + noncanonical + "." + parts[2]
    malformed_payloads = [
        b'{"profile":"decent-account-disclosure-v1","profile":"duplicate"}',
        b'{"value":1e400}',
        b'{"value":"\\ud800"}',
        b'{"value":NaN}',
        b'\\xff',
    ]
    for bad_payload in [changed, *(parts[0] + "." + _enc(raw) + "." + parts[2] for raw in malformed_payloads)]:
        with pytest.raises(ValueError):
            verify_account_presentation(bad_payload, context=context, binding=binding, request=request,
                approved_claim_ids=v["wallet_approved_claim_ids"], approval_expires_at=context.expires_at,
                now=v["validation_time"])


def test_jcs_number_serialization_uses_ecmascript_thresholds():
    from decent_wallet.account_presentation import _jcs
    assert _jcs([1e-6, 1e-7, 1e20, 1e21, -0.0]) == b"[0.000001,1e-7,100000000000000000000,1e+21,0]"


PRESENTATION_NEGATIVE_IDS = (
    "presentation-wrong-nonce", "presentation-extra-claim", "claim-value-utf8-byte-limit",
    "presentation-expired", "presentation-expiry-after-credential", "presentation-owner-binding-mismatch",
    "presentation-invalid-signature", "credential-invalid-signature", "presentation-duplicate-json-member",
    "required-claim-omitted", "presentation-request-id-mismatch", "presentation-total-size-limit",
    "presentation-invalid-unicode-scalar",
)


@pytest.mark.parametrize("case_id", PRESENTATION_NEGATIVE_IDS)
def test_rejects_shared_presentation_stage_negative_vectors(case_id):
    negatives = json.loads((VECTORS / "negative.json").read_text(encoding="utf-8"))["vectors"]
    case = next(item for item in negatives if item["id"] == case_id)
    bundle = case["bundle"]
    context, binding, request = verified(bundle)
    with pytest.raises(ValueError):
        verify_account_presentation(bundle["presentation_jws"], context=context, binding=binding,
            request=request, approved_claim_ids=bundle["wallet_approved_claim_ids"],
            approval_expires_at=context.expires_at, now=bundle["validation_time"])

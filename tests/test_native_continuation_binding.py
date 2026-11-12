from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path

import pytest

from decent_wallet import Wallet
from decent_wallet.account_disclosure import parse_wallet_account_disclosure_context
from test_account_disclosure_lifecycle import (
    ISSUER,
    _approved_wallet,
    continuation_artifacts,
    context_for_handle,
)

NATIVE_VECTORS = Path(__file__).parent / "vectors/native-continuation/continuation_vectors.native.json"
NATIVE_VECTORS_SHA256 = "edb30ca38740c06df8342c7f928e30422e9478dc1ef8ff82b3edf00b050bf2f3"
NATIVE_VECTORS_SIZE = 1395928
NATIVE_PROVENANCE = Path(__file__).parent / "vectors/native-continuation/provenance.json"
CHALLENGE = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")


def test_unchanged_upstream_native_vectors_are_pinned_and_wallet_asserts_core_cases():
    raw = NATIVE_VECTORS.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == NATIVE_VECTORS_SHA256
    assert len(raw) == NATIVE_VECTORS_SIZE
    provenance = json.loads(NATIVE_PROVENANCE.read_text())
    assert provenance == {
        "upstream_repository": "https://github.com/jetpen/decent-ecosystem",
        "upstream_commit": "4545d5de8856a576828fb00c17413e9b49d1ad1f",
        "source_path": "docs/protocol/wallet-account-disclosure/v1/vectors/continuation_vectors.native.json",
        "local_path": "tests/vectors/native-continuation/continuation_vectors.native.json",
        "sha256": NATIVE_VECTORS_SHA256,
        "size_bytes": NATIVE_VECTORS_SIZE,
    }
    vectors = json.loads(raw)
    positive = vectors["positive"]
    capability = base64.urlsafe_b64decode(positive["capability_bytes_test_only"] + "==")
    digest = base64.urlsafe_b64encode(hashlib.sha256(capability).digest()).decode().rstrip("=")
    assert positive["context"]["decent_native_continuation"] is True
    assert positive["binding"]["continuation_capability_hash"] == digest
    negative_ids = {item["id"] for item in vectors["negative"]}
    assert {"context-opt-in-false", "binding-capability-hash-mismatch",
            "capability-expiry-mismatch", "request-exceeds-binding-only",
            "request-object-signed-expiry-too-late"} <= negative_ids
    # Exercise the original native context and signed binding/JWKS through wallet code.
    native_context = parse_wallet_account_disclosure_context(
        json.dumps(positive["context"]).encode(), expected_keycloak_issuer=ISSUER,
    )
    bundle = positive["bundle"]
    from decent_wallet.account_disclosure import verify_owner_key_binding
    verified = verify_owner_key_binding(
        bundle["owner_key_binding_jws"], bundle["keycloak_jwks"], native_context,
        expected_identity_id=positive["binding"]["identity_id"],
        now=positive["validation_time"],
    )
    assert native_context.decent_native_continuation is True
    assert native_context.expires_at == positive["context"]["expires_at"]
    assert verified.continuation_capability_hash == positive["capability_sha256_b64url"]
    assert verified.expires_at == positive["binding"]["exp"]
    assert verified.owner_key.x == positive["binding"]["owner_key"]["x"]
    # Then pass the original signed Request Object through its wallet verifier.
    from decent_wallet.oid4vp_request import TrustedRPRegistration, verify_oid4vp_authorization_request
    registration = TrustedRPRegistration(
        client_id=bundle["oid4vp_client_id"],
        x509_san_dns="site.example.test",
        origin=native_context.rp_origin,
        response_uri="https://site.example.test/oid4vp/response",
        trust_anchor_sha256=bundle["rp_certificate"]["trust_anchor_sha256"],
        rp_client_id=native_context.rp_client_id,
    )
    request = verify_oid4vp_authorization_request(
        bundle["oid4vp_authorization_parameters"],
        request_object=bundle["oid4vp_request_jws"], registration=registration,
        context=native_context, owner_key_binding_jws=bundle["owner_key_binding_jws"],
        verified_binding=verified, now=positive["validation_time"],
    )
    assert request.expires_at == positive["request_object_expires_at"]
    assert request.expires_at == verified.expires_at
    assert request.client_id == registration.client_id
    from copy import deepcopy
    from decent_wallet.account_disclosure import WalletDisclosureRequestError
    browser_vector_context = deepcopy(positive["context"])
    browser_vector_context["decent_native_continuation"] = False
    with pytest.raises(WalletDisclosureRequestError):
        parse_wallet_account_disclosure_context(
            json.dumps(browser_vector_context).encode(), expected_keycloak_issuer=ISSUER,
        )


@pytest.mark.parametrize("marker", [False, None, 1, "true"])
def test_context_rejects_nonliteral_native_marker(marker):
    from decent_wallet.container import _disclosure_context_payload

    context = context_for_handle()
    value = {"profile": "decent-account-disclosure-v1", **_disclosure_context_payload(context),
             "decent_native_continuation": marker}
    with pytest.raises(ValueError):
        parse_wallet_account_disclosure_context(json.dumps(value).encode(), expected_keycloak_issuer=ISSUER)


def test_browser_context_rejects_native_binding_claim_but_remains_acceptable(tmp_path):
    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    cap_hash = base64.urlsafe_b64encode(hashlib.sha256(b"browser claim rejected" * 2).digest()).decode().rstrip("=")
    binding, jwks, outer, request, registration = continuation_artifacts(
        context, wallet.public_key, 1_800_000_001, capability_hash=cap_hash,
    )
    with pytest.raises(ValueError):
        wallet.prepare_account_presentation(pending, binding_jws=binding, keycloak_jwks=jwks,
            outer_request=outer, request_object=request, registration=registration)
    wallet.lock()


def test_native_binding_hash_mismatch_invalidates_approval_and_reopen(tmp_path):
    wallet, pending, context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    capability = bytes(range(32))
    encoded = base64.urlsafe_b64encode(capability).decode().rstrip("=")
    wallet.install_native_continuation_capability(pending, encoded, pending.expires_at)
    wrong = "A" * 43  # unchanged binding-capability-hash-mismatch vector claim
    binding, jwks, outer, request, registration = continuation_artifacts(
        context, wallet.public_key, int(__import__("time").time()), capability_hash=wrong,
    )
    with pytest.raises(ValueError):
        wallet.prepare_account_presentation(pending, binding_jws=binding, keycloak_jwks=jwks,
            outer_request=outer, request_object=request, registration=registration)
    assert "pending_account_disclosure_v1" not in wallet._payload
    wallet.lock()
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    with pytest.raises(ValueError):
        reopened.create_account_login_proof(pending, challenge=CHALLENGE)
    reopened.lock()


def test_missing_native_capability_invalidates_pending_approval(tmp_path):
    wallet, pending, context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    binding, jwks, outer, request, registration = continuation_artifacts(
        context, wallet.public_key, 1_800_000_001,
        capability_hash=base64.urlsafe_b64encode(hashlib.sha256(b"x" * 32).digest()).decode().rstrip("="),
    )
    with pytest.raises(ValueError):
        wallet.prepare_account_presentation(pending, binding_jws=binding, keycloak_jwks=jwks,
            outer_request=outer, request_object=request, registration=registration)
    assert "pending_account_disclosure_v1" not in wallet._payload
    wallet.lock()


def test_native_request_expiry_beyond_capability_is_rejected_and_invalidated_after_reopen(tmp_path):
    wallet, pending, context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    capability = bytes(range(32))
    encoded = base64.urlsafe_b64encode(capability).decode().rstrip("=")
    now = int(__import__("time").time())
    cap_expiry = now + 100
    wallet.install_native_continuation_capability(pending, encoded, cap_expiry)
    cap_hash = base64.urlsafe_b64encode(hashlib.sha256(capability).digest()).decode().rstrip("=")
    binding, jwks, outer, request, registration = continuation_artifacts(
        context, wallet.public_key, now, request_expires_at=now + 150,
        capability_hash=cap_hash,
    )
    with pytest.raises(ValueError):
        wallet.prepare_account_presentation(pending, binding_jws=binding, keycloak_jwks=jwks,
            outer_request=outer, request_object=request, registration=registration)
    assert "pending_account_disclosure_v1" not in wallet._payload
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    with pytest.raises(ValueError):
        reopened.create_account_login_proof(pending, challenge=CHALLENGE)
    reopened.lock()
    wallet.lock()


def test_native_request_at_capability_expiry_boundary_is_accepted(tmp_path):
    wallet, pending, context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    capability = bytes(range(32))
    encoded = base64.urlsafe_b64encode(capability).decode().rstrip("=")
    now = int(__import__("time").time())
    cap_expiry = now + 100
    wallet.install_native_continuation_capability(pending, encoded, cap_expiry)
    cap_hash = base64.urlsafe_b64encode(hashlib.sha256(capability).digest()).decode().rstrip("=")
    binding, jwks, outer, request, registration = continuation_artifacts(
        context, wallet.public_key, now, request_expires_at=cap_expiry,
        capability_hash=cap_hash, binding_expires_at=cap_expiry,
    )
    submission = wallet.prepare_account_presentation(pending, binding_jws=binding, keycloak_jwks=jwks,
        outer_request=outer, request_object=request, registration=registration)
    assert submission.presentation_jws
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    record = reopened._payload["pending_account_disclosure_v1"]
    assert record["state"] == "prepared" and "native_continuation" not in record
    assert record["submission"]["expires_at"] == cap_expiry
    assert capability not in (tmp_path / "wallet.json").read_bytes()
    assert reopened.native_continuation_capability(pending) is None
    reopened.lock()
    wallet.lock()


def test_native_context_rejects_binding_without_capability_hash(tmp_path):
    wallet, pending, context = _approved_wallet(tmp_path, native=True)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    binding, jwks, outer, request, registration = continuation_artifacts(
        context, wallet.public_key, int(__import__("time").time()),
    )
    with pytest.raises(ValueError):
        wallet.prepare_account_presentation(pending, binding_jws=binding, keycloak_jwks=jwks,
            outer_request=outer, request_object=request, registration=registration)
    assert "pending_account_disclosure_v1" not in wallet._payload
    wallet.lock()


def test_browser_context_cannot_install_native_capability(tmp_path):
    wallet, pending, _context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    value = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    with pytest.raises(ValueError):
        wallet.install_native_continuation_capability(pending, value, pending.expires_at)
    wallet.lock()

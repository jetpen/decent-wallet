from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from decent_wallet import InvalidContainer, StorageFailure, StorageOutcomeUnknown, Wallet
from decent_wallet.account_disclosure import parse_wallet_account_disclosure_context

VECTORS = Path(__file__).parent / "vectors/wallet-account-disclosure-v1"
LOGIN_VECTOR = Path(__file__).parent / "vectors/wallet-login-v1/vectors/valid-basic.json"
ISSUER = "https://login.example.test/realms/site"
HANDLE = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
IDENTITY_ID = "mailto:alice@example.org"
GIVEN = "urn:decent:account:v1:given_name"
EMAIL = "urn:decent:account:v1:email"


@pytest.fixture(autouse=True)
def deterministic_clock(monkeypatch):
    monkeypatch.setattr("decent_wallet.container.time.time", lambda: 1_800_000_001)


def context_for_handle(expires_at=1_900_000_000, native=False):
    raw = {
        "profile": "decent-account-disclosure-v1",
        "keycloak_issuer": ISSUER,
        "rp_client_id": "site-client",
        "rp_display_name": "Example Site",
        "rp_origin": "https://site.example.test",
        "action": "signup",
        "request_id": base64.urlsafe_b64encode(b"r" * 16).decode().rstrip("="),
        "transaction_id": base64.urlsafe_b64encode(hashlib.sha256(HANDLE.encode("ascii")).digest()).decode().rstrip("="),
        "oidc_nonce": base64.urlsafe_b64encode(b"n" * 24).decode().rstrip("="),
        "purpose": "Create an account at Example Site",
        "claims": [{"id": GIVEN, "required": True}, {"id": EMAIL, "required": False}],
        "expires_at": expires_at,
    }
    if native:
        raw["decent_native_continuation"] = True
    return parse_wallet_account_disclosure_context(
        json.dumps(raw).encode(), expected_keycloak_issuer=ISSUER
    )


def continuation_artifacts(context, owner_public_key, now, request_expires_at=None, capability_hash=None,
                           binding_expires_at=None):
    from decent_wallet.account_presentation import _jcs
    from decent_wallet.oid4vp_request import TrustedRPRegistration

    enc = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
    owner = {"kty": "OKP", "crv": "Ed25519", "x": enc(owner_public_key)}
    thumb = enc(hashlib.sha256(_jcs(owner)).digest())
    kc_private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = kc_private.public_key().public_numbers()
    encint = lambda n: enc(n.to_bytes((n.bit_length() + 7) // 8, "big"))
    binding_payload = {
        "v": 1, "iss": context.keycloak_issuer, "aud": context.rp_client_id, "sub": "kc-subject",
        "identity_id": IDENTITY_ID, "owner_key": owner, "owner_key_thumbprint": thumb,
        "action": context.action, "transaction_id": context.transaction_id, "request_id": context.request_id,
        "oidc_nonce": context.oidc_nonce, "iat": now,
        "exp": min(context.expires_at, now + 300) if binding_expires_at is None else min(context.expires_at, binding_expires_at),
        "jti": enc(b"b" * 32),
    }
    if capability_hash is not None:
        binding_payload["continuation_capability_hash"] = capability_hash
    h = enc(b'{"alg":"RS256","kid":"kc-key","typ":"decent-owner-key-binding+jwt"}')
    p = enc(json.dumps(binding_payload, separators=(",", ":")).encode())
    signed = f"{h}.{p}".encode()
    binding_jws = f"{h}.{p}.{enc(kc_private.sign(signed, padding.PKCS1v15(), hashes.SHA256()))}"
    jwks = {"keys": [{"kty": "RSA", "n": encint(numbers.n), "e": encint(numbers.e), "kid": "kc-key", "use": "sig", "alg": "RS256"}]}

    host = "site.example.test"
    rp_private = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(rp_private.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(datetime(2020, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2035, 1, 1, tzinfo=timezone.utc))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
            .sign(rp_private, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    response_uri = f"https://{host}/oid4vp/response"
    registration = TrustedRPRegistration(f"x509_san_dns:{host}", host, context.rp_origin,
                                         response_uri, hashlib.sha256(der).hexdigest(), context.rp_client_id)
    short = [claim.claim_id.rsplit(":", 1)[-1] for claim in context.claims]
    required = [claim.claim_id.rsplit(":", 1)[-1] for claim in context.claims if claim.required]
    optional = [claim.claim_id.rsplit(":", 1)[-1] for claim in context.claims if not claim.required]
    claim_sets = [required] + [required + [value] for value in optional]
    payload = {
        "aud": "https://self-issued.me/v2", "client_id": registration.client_id,
        "client_metadata": {"vp_formats_supported": {"decent_account_jwt_v1": {"alg_values": ["EdDSA"]}}},
        "dcql_query": {"credentials": [{"id": "account", "format": "decent_account_jwt_v1", "multiple": False,
                          "meta": {}, "require_cryptographic_holder_binding": True,
                          "claims": [{"id": c, "path": ["claims", f"urn:decent:account:v1:{c}"]} for c in short],
                          "claim_sets": claim_sets}]},
        "decent_account": {"profile": "decent-account-disclosure-v1", "rp_oidc_client_id": context.rp_client_id,
                           "action": context.action, "request_id": context.request_id,
                           "transaction_id": context.transaction_id, "purpose": context.purpose,
                           "owner_key_binding": binding_jws,
                           "claims": [{"id": c.claim_id, "required": c.required} for c in context.claims]},
        "exp": min(context.expires_at, now + 299) if request_expires_at is None else min(context.expires_at, request_expires_at), "iat": now,
        "jti": enc(b"j" * 32), "nonce": enc(b"n" * 32), "state": enc(b"s" * 16),
        "response_mode": "direct_post", "response_type": "vp_token", "response_uri": response_uri,
    }
    header = {"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": [base64.b64encode(der).decode()]}
    hs, ps = enc(_jcs(header)), enc(_jcs(payload))
    signature_der = rp_private.sign(f"{hs}.{ps}".encode(), ec.ECDSA(hashes.SHA256()))
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    r, s = decode_dss_signature(signature_der)
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    request_object = f"{hs}.{ps}.{enc(signature)}"
    outer = {"client_id": registration.client_id, "request_uri": f"https://{host}/oid4vp/requests/opaque"}
    return binding_jws, jwks, outer, request_object, registration


def test_wallet_requires_durable_consent_before_unchanged_login_proof(tmp_path):
    vector = json.loads(LOGIN_VECTOR.read_text())
    entity = {"given_name": "Ada", "email": "ada@example.test"}
    seed = base64.urlsafe_b64decode(vector["test_private_seed_b64url"] + "=")
    public_key = base64.urlsafe_b64decode(vector["public_key_b64url"] + "=")
    wallet = Wallet._create_storage(
        tmp_path / "wallet.json", "correct horse battery", "correct horse battery",
        {"private_seed": seed, "public_key": public_key},
    )
    wallet.set_master_account_entity(entity)
    context = context_for_handle()
    review = wallet.review_account_disclosure(context, HANDLE, IDENTITY_ID)

    with pytest.raises(ValueError):
        wallet.create_account_login_proof(review, challenge=vector["challenge"])

    pending = wallet.approve_account_disclosure(
        review, [GIVEN], consent=lambda _review: True
    )
    proof = wallet.create_account_login_proof(pending, challenge=vector["challenge"])

    assert proof.proof == vector["proof"]
    assert pending.expires_at == min(context.expires_at, 1_800_000_001 + 300)
    wallet.lock()


def test_expired_disclosure_uses_trusted_public_clock(tmp_path, monkeypatch):
    import inspect
    import decent_wallet.container as container_module

    wallet, _pending, _context = _approved_wallet(tmp_path)
    wallet.cancel_account_disclosure(_pending)
    review = wallet.review_account_disclosure(context_for_handle(), HANDLE, IDENTITY_ID)
    monkeypatch.setattr(container_module.time, "time", lambda: 2_000_000_000)
    assert "now" not in inspect.signature(wallet.approve_account_disclosure).parameters
    with pytest.raises(ValueError):
        wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _review: True)


def _approved_wallet(tmp_path, entity=None, native=False):
    vector = json.loads(LOGIN_VECTOR.read_text())
    wallet = Wallet._create_storage(
        tmp_path / "wallet.json", "correct horse battery", "correct horse battery",
        {"private_seed": base64.urlsafe_b64decode(vector["test_private_seed_b64url"] + "="),
         "public_key": base64.urlsafe_b64decode(vector["public_key_b64url"] + "=")},
    )
    wallet.set_master_account_entity(entity if entity is not None else {"given_name": "Ada", "email": "ada@example.test"})
    context = context_for_handle(native=native)
    review = wallet.review_account_disclosure(context, HANDLE, IDENTITY_ID)
    pending = wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _review: True)
    return wallet, pending, context


def test_approved_record_survives_background_reopen_blocks_export_and_active_import(tmp_path):
    private_name = "SYNTHETIC_PRIVATE_NAME_MARKER_FOR_ENCRYPTED_APPROVAL_ONLY_062"
    private_email = "synthetic-private-email-marker-for-encrypted-approval-only@example.test"
    wallet, pending, _context = _approved_wallet(tmp_path, {"given_name": private_name, "email": private_email})
    with pytest.raises(ValueError):
        wallet.export_container()
    active_bytes = (tmp_path / "wallet.json").read_bytes()
    envelope = json.loads(active_bytes)
    assert set(envelope) == {"format", "version", "kdf", "wrap", "payload"}
    assert envelope["format"] == "decent-wallet" and envelope["version"] == 2
    for name in ("wrap", "payload"):
        assert set(envelope[name]) == {"algorithm", "nonce", "ciphertext", "tag"}
        assert envelope[name]["algorithm"] == "xchacha20-poly1305"
        assert len(base64.b64decode(envelope[name]["nonce"])) == 24
        assert len(base64.b64decode(envelope[name]["tag"])) == 16
    for marker in (private_name, private_email, "master_account_entity", "approved_values", GIVEN):
        assert marker.encode() not in active_bytes
        assert marker not in repr(pending)
    with pytest.raises(InvalidContainer):
        Wallet.import_container(tmp_path / "imported.json", active_bytes, "correct horse battery")
    wallet.background()
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    vector = json.loads(LOGIN_VECTOR.read_text())
    assert reopened.create_account_login_proof(pending, challenge=vector["challenge"]).proof == vector["proof"]
    with pytest.raises(ValueError):
        reopened.create_account_login_proof(pending, challenge=vector["challenge"])
    reopened.change_password("new correct horse battery", "new correct horse battery")
    reopened.lock()
    Wallet.open(tmp_path / "wallet.json", "new correct horse battery").lock()


def test_second_approval_is_rejected_and_entity_edit_does_not_change_approved_snapshot(tmp_path):
    from decent_wallet import verify_account_presentation
    from decent_wallet.account_disclosure import verify_owner_key_binding
    from decent_wallet.oid4vp_request import verify_oid4vp_authorization_request
    wallet, pending, context = _approved_wallet(tmp_path)
    review = wallet.review_account_disclosure(context_for_handle(), HANDLE, IDENTITY_ID)
    with pytest.raises(ValueError):
        wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _review: True)
    wallet.set_master_account_entity({"given_name": "Grace", "email": "new@example.test"})
    assert repr(pending) == "PendingAccountApproval(expires_at=1800000301)"
    instant = 1_800_000_001
    wallet.create_account_login_proof(pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("="))
    binding_jws, jwks, outer, request_object, registration = continuation_artifacts(context, wallet.public_key, instant)
    submission = wallet.prepare_account_presentation(
        pending, binding_jws=binding_jws, keycloak_jwks=jwks, outer_request=outer,
        request_object=request_object, registration=registration,
    )
    binding = verify_owner_key_binding(binding_jws, jwks, context, expected_identity_id=IDENTITY_ID, now=instant)
    request = verify_oid4vp_authorization_request(
        outer, request_object=request_object, registration=registration, context=context,
        owner_key_binding_jws=binding_jws, verified_binding=binding, now=instant,
    )
    verified = verify_account_presentation(
        submission.presentation_jws, context=context, binding=binding, request=request,
        approved_claim_ids=[GIVEN], approval_expires_at=pending.expires_at, now=instant,
    )
    assert verified.claims == {GIVEN: "Ada"}
    assert EMAIL not in verified.claims
    assert wallet.get_master_account_entity() == {"given_name": "Grace", "email": "new@example.test"}
    wallet.lock()


def test_consent_callback_is_outside_lock_and_entity_race_aborts_without_approval(tmp_path):
    vector = json.loads(LOGIN_VECTOR.read_text())
    wallet = Wallet._create_storage(
        tmp_path / "wallet.json", "correct horse battery", "correct horse battery",
        {"private_seed": base64.urlsafe_b64decode(vector["test_private_seed_b64url"] + "="),
         "public_key": base64.urlsafe_b64decode(vector["public_key_b64url"] + "=")},
    )
    wallet.set_master_account_entity({"given_name": "Ada"})
    review = wallet.review_account_disclosure(context_for_handle(), HANDLE, IDENTITY_ID)
    def reenter(candidate):
        assert wallet.is_unlocked
        wallet.set_master_account_entity({"given_name": "Grace"})
        return True
    with pytest.raises(ValueError):
        wallet.approve_account_disclosure(review, [GIVEN], consent=reenter)
    wallet.lock()


def test_required_missing_and_invalid_claim_values_fail_closed(tmp_path):
    vector = json.loads(LOGIN_VECTOR.read_text())
    wallet = Wallet._create_storage(
        tmp_path / "wallet.json", "correct horse battery", "correct horse battery",
        {"private_seed": base64.urlsafe_b64decode(vector["test_private_seed_b64url"] + "="),
         "public_key": base64.urlsafe_b64decode(vector["public_key_b64url"] + "=")},
    )
    with pytest.raises(ValueError):
        wallet.review_account_disclosure(context_for_handle(), HANDLE, IDENTITY_ID)
    wallet.set_master_account_entity({"given_name": 7})
    with pytest.raises(ValueError):
        wallet.review_account_disclosure(context_for_handle(), HANDLE, IDENTITY_ID)
    wallet.set_master_account_entity({"given_name": "a" * 1025})
    with pytest.raises(ValueError):
        wallet.review_account_disclosure(context_for_handle(), HANDLE, IDENTITY_ID)
    wallet.set_master_account_entity({"given_name": "Ada"})
    review = wallet.review_account_disclosure(context_for_handle(), HANDLE, IDENTITY_ID)
    with pytest.raises(ValueError):
        wallet.approve_account_disclosure(review, [EMAIL], consent=lambda _review: True)
    wallet.lock()


def test_expiry_clears_pending_before_proof_and_allows_export(tmp_path, monkeypatch):
    vector = json.loads(LOGIN_VECTOR.read_text())
    wallet = Wallet._create_storage(
        tmp_path / "wallet.json", "correct horse battery", "correct horse battery",
        {"private_seed": base64.urlsafe_b64decode(vector["test_private_seed_b64url"] + "="),
         "public_key": base64.urlsafe_b64decode(vector["public_key_b64url"] + "=")},
    )
    wallet.set_master_account_entity({"given_name": "Ada"})
    review = wallet.review_account_disclosure(context_for_handle(1_800_000_050), HANDLE, IDENTITY_ID)
    pending = wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _review: True)
    monkeypatch.setattr("decent_wallet.container.time.time", lambda: 1_800_000_050)
    with pytest.raises(ValueError):
        wallet.create_account_login_proof(pending, challenge=vector["challenge"])
    assert wallet.export_container()
    wallet.lock()


def test_expiry_invalidation_failure_locks_session_and_blocks_clock_rollback_release(tmp_path, monkeypatch):
    import decent_wallet.container as container
    from decent_wallet import WalletLockedError

    vector = json.loads(LOGIN_VECTOR.read_text())
    wallet, pending, _context = _approved_wallet(tmp_path)
    before = (tmp_path / "wallet.json").read_bytes()
    original_atomic_write = container._atomic_write

    def fail_atomic_write(*_args, **_kwargs):
        raise StorageFailure()

    monkeypatch.setattr(container.time, "time", lambda: pending.expires_at)
    monkeypatch.setattr(container, "_atomic_write", fail_atomic_write)
    with pytest.raises(StorageFailure):
        wallet.create_account_login_proof(pending, challenge=vector["challenge"])

    monkeypatch.setattr(container, "_atomic_write", original_atomic_write)
    monkeypatch.setattr(container.time, "time", lambda: 1_800_000_001)
    with pytest.raises(WalletLockedError):
        wallet.create_account_login_proof(pending, challenge=vector["challenge"])
    assert not wallet.is_unlocked
    assert (tmp_path / "wallet.json").read_bytes() == before


def test_explicit_cancel_consumes_approval(tmp_path):
    wallet, pending, _context = _approved_wallet(tmp_path)
    wallet.cancel_account_disclosure(pending)
    assert wallet.export_container()
    with pytest.raises(ValueError):
        wallet.create_account_login_proof(pending, challenge=json.loads(LOGIN_VECTOR.read_text())["challenge"])
    wallet.lock()


def test_wallet_reverifies_raw_continuation_builds_dual_signed_jcs_and_retries_exact_bytes(tmp_path):
    from decent_wallet import PresentationDeliveryOutcome, verify_account_presentation
    from decent_wallet.account_disclosure import verify_owner_key_binding
    from decent_wallet.oid4vp_request import verify_oid4vp_authorization_request

    vector = json.loads(LOGIN_VECTOR.read_text())
    seed = base64.urlsafe_b64decode(vector["test_private_seed_b64url"] + "=")
    public_key = base64.urlsafe_b64decode(vector["public_key_b64url"] + "=")
    wallet = Wallet._create_storage(tmp_path / "wallet.json", "correct horse battery", "correct horse battery",
                                    {"private_seed": seed, "public_key": public_key})
    wallet.set_master_account_entity({"given_name": "Ada", "email": "ada@example.test"})
    context = context_for_handle()
    review = wallet.review_account_disclosure(context, HANDLE, IDENTITY_ID)
    pending = wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _review: True)
    challenge = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    wallet.create_account_login_proof(pending, challenge=challenge)
    artifacts = continuation_artifacts(context, public_key, 1_800_000_001)
    binding_jws, jwks, outer, request_object, registration = artifacts
    barrier = Barrier(2)
    def prepare_once():
        barrier.wait()
        return wallet.prepare_account_presentation(
            pending, binding_jws=binding_jws, keycloak_jwks=jwks, outer_request=outer,
            request_object=request_object, registration=registration,
        )
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(prepare_once) for _ in range(2)]
        completed = []
        for future in futures:
            try:
                completed.append(future.result())
            except ValueError:
                completed.append(None)
    submissions = [item for item in completed if item is not None]
    assert len(submissions) == 1
    submission = submissions[0]
    binding = verify_owner_key_binding(binding_jws, jwks, context, expected_identity_id=IDENTITY_ID, now=1_800_000_001)
    request = verify_oid4vp_authorization_request(
        outer, request_object=request_object, registration=registration, context=context,
        owner_key_binding_jws=binding_jws, verified_binding=binding, now=1_800_000_001,
    )
    result = verify_account_presentation(submission.presentation_jws, context=context, binding=binding,
                                         request=request, approved_claim_ids=[GIVEN],
                                         approval_expires_at=pending.expires_at, now=1_800_000_001)
    assert result.claims == {GIVEN: "Ada"}
    assert len(submission.presentation_jws.encode()) <= 16 * 1024
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    wallet.lock()
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    retry = reopened.get_account_presentation_retry(pending)
    assert retry.presentation_jws == submission.presentation_jws
    assert retry.response_uri == submission.response_uri and retry.state == submission.state
    assert retry.body == submission.body
    reopened.finish_account_presentation(
        pending, PresentationDeliveryOutcome.ACCEPTED, status_code=200,
        content_type="application/json", response_body=b'{"redirect_uri":"https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"}',
    )
    with pytest.raises(ValueError):
        reopened.get_account_presentation_retry(pending)
    reopened.lock()


@pytest.mark.parametrize("status_code", [200.0, True, "200"])
def test_direct_post_acceptance_requires_exact_integer_status_without_consuming_approval(tmp_path, status_code):
    from decent_wallet import PresentationDeliveryOutcome

    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("="))
    binding, jwks, outer, request, registration = continuation_artifacts(context, wallet.public_key, 1_800_000_001)
    submission = wallet.prepare_account_presentation(
        pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
        request_object=request, registration=registration,
    )
    body = b'{"redirect_uri":"https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"}'
    before = (tmp_path / "wallet.json").read_bytes()
    with pytest.raises(ValueError):
        wallet.finish_account_presentation(
            pending, PresentationDeliveryOutcome.ACCEPTED, status_code=status_code,
            content_type="application/json", response_body=body,
        )
    assert (tmp_path / "wallet.json").read_bytes() == before
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    retry = wallet.get_account_presentation_retry(pending)
    assert (retry.body, retry.presentation_jws, retry.response_uri, retry.state) == (
        submission.body, submission.presentation_jws, submission.response_uri, submission.state,
    )
    wallet.lock()


@pytest.mark.parametrize("content_type", ["application/json\\n", "application/json\\r\\n"])
def test_direct_post_acceptance_rejects_crlf_media_type_without_consuming_approval(tmp_path, content_type):
    from decent_wallet import PresentationDeliveryOutcome

    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("="))
    binding, jwks, outer, request, registration = continuation_artifacts(context, wallet.public_key, 1_800_000_001)
    submission = wallet.prepare_account_presentation(
        pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
        request_object=request, registration=registration,
    )
    body = b'{"redirect_uri":"https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"}'
    before = (tmp_path / "wallet.json").read_bytes()
    with pytest.raises(ValueError):
        wallet.finish_account_presentation(
            pending, PresentationDeliveryOutcome.ACCEPTED, status_code=200,
            content_type=content_type, response_body=body,
        )
    assert (tmp_path / "wallet.json").read_bytes() == before
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    retry = wallet.get_account_presentation_retry(pending)
    assert (retry.body, retry.presentation_jws) == (submission.body, submission.presentation_jws)
    wallet.lock()


@pytest.mark.parametrize("content_type", [
    "applıcation/json",  # LATIN SMALL LETTER DOTLESS I
    "applİcation/json",  # LATIN CAPITAL LETTER I WITH DOT ABOVE
    "application/json; charset=é",
])
def test_direct_post_acceptance_rejects_unicode_media_types_without_consuming_approval(tmp_path, content_type):
    from decent_wallet import PresentationDeliveryOutcome

    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("="))
    binding, jwks, outer, request, registration = continuation_artifacts(context, wallet.public_key, 1_800_000_001)
    submission = wallet.prepare_account_presentation(
        pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
        request_object=request, registration=registration,
    )
    body = b'{"redirect_uri":"https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"}'
    before = (tmp_path / "wallet.json").read_bytes()
    with pytest.raises(ValueError):
        wallet.finish_account_presentation(
            pending, PresentationDeliveryOutcome.ACCEPTED, status_code=200,
            content_type=content_type, response_body=body,
        )
    assert (tmp_path / "wallet.json").read_bytes() == before
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    retry = wallet.get_account_presentation_retry(pending)
    assert (retry.body, retry.presentation_jws) == (submission.body, submission.presentation_jws)
    wallet.lock()


def test_direct_post_acceptance_rejects_substring_media_type_without_consuming_approval(tmp_path):
    from decent_wallet import PresentationDeliveryOutcome

    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("="))
    binding, jwks, outer, request, registration = continuation_artifacts(context, wallet.public_key, 1_800_000_001)
    submission = wallet.prepare_account_presentation(
        pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
        request_object=request, registration=registration,
    )
    body = b'{"redirect_uri":"https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"}'
    before = (tmp_path / "wallet.json").read_bytes()
    with pytest.raises(ValueError):
        wallet.finish_account_presentation(
            pending, PresentationDeliveryOutcome.ACCEPTED, status_code=200,
            content_type="text/application/json", response_body=body,
        )
    assert (tmp_path / "wallet.json").read_bytes() == before
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    retry = wallet.get_account_presentation_retry(pending)
    assert (retry.body, retry.presentation_jws, retry.response_uri, retry.state) == (
        submission.body, submission.presentation_jws, submission.response_uri, submission.state,
    )
    wallet.lock()


def test_known_storage_failure_rolls_back_and_unknown_outcome_locks_without_proof(tmp_path, monkeypatch):
    import decent_wallet.container as container
    vector = json.loads(LOGIN_VECTOR.read_text())
    def make_wallet(name):
        wallet = Wallet._create_storage(tmp_path / name, "correct horse battery", "correct horse battery",
            {"private_seed": base64.urlsafe_b64decode(vector["test_private_seed_b64url"] + "="),
             "public_key": base64.urlsafe_b64decode(vector["public_key_b64url"] + "=")})
        wallet.set_master_account_entity({"given_name": "Ada"})
        review = wallet.review_account_disclosure(context_for_handle(), HANDLE, IDENTITY_ID)
        return wallet, review

    wallet, review = make_wallet("known.json")
    monkeypatch.setattr(container, "_atomic_write", lambda *_a, **_kw: (_ for _ in ()).throw(StorageFailure()))
    with pytest.raises(StorageFailure):
        wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _review: True)
    assert wallet.is_unlocked
    with pytest.raises(ValueError):
        wallet.create_account_login_proof(review, challenge=vector["challenge"])
    wallet.lock()

    monkeypatch.undo()
    wallet, review = make_wallet("unknown.json")
    monkeypatch.setattr(container, "_atomic_write", lambda *_a, **_kw: (_ for _ in ()).throw(StorageOutcomeUnknown()))
    with pytest.raises(StorageOutcomeUnknown):
        wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _review: True)
    assert not wallet.is_unlocked
    with pytest.raises(Exception):
        wallet.create_account_login_proof(review, challenge=vector["challenge"])


def test_signed_binding_mismatch_invalidates_durable_approval_and_stale_handle_after_reopen(tmp_path):
    vector = json.loads(LOGIN_VECTOR.read_text())
    wallet, pending, context = _approved_wallet(tmp_path)
    challenge = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")
    wallet.create_account_login_proof(pending, challenge=challenge)
    # A different signed transaction is generated by the same trusted fixture signer.
    mismatched_context = context_for_handle()
    from dataclasses import replace
    mismatched_context = replace(mismatched_context, request_id=base64.urlsafe_b64encode(b"x" * 16).decode().rstrip("="))
    binding_jws, jwks, outer, request, registration = continuation_artifacts(
        mismatched_context, wallet.public_key, 1_800_000_001,
    )
    from decent_wallet.account_disclosure import verify_owner_key_binding
    from decent_wallet.oid4vp_request import verify_oid4vp_authorization_request
    verified_binding = verify_owner_key_binding(
        binding_jws, jwks, mismatched_context, expected_identity_id=IDENTITY_ID, now=1_800_000_001,
    )
    verify_oid4vp_authorization_request(
        outer, request_object=request, registration=registration, context=mismatched_context,
        owner_key_binding_jws=binding_jws, verified_binding=verified_binding, now=1_800_000_001,
    )
    with pytest.raises(ValueError):
        wallet.prepare_account_presentation(pending, binding_jws=binding_jws, keycloak_jwks=jwks,
            outer_request=outer, request_object=request, registration=registration)
    assert wallet.export_container()
    wallet.lock()
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    with pytest.raises(ValueError):
        reopened.create_account_login_proof(pending, challenge=vector["challenge"])
    fresh_review = reopened.review_account_disclosure(context, HANDLE, IDENTITY_ID)
    fresh_pending = reopened.approve_account_disclosure(
        fresh_review, [GIVEN], consent=lambda _review: True,
    )
    reopened.create_account_login_proof(fresh_pending, challenge=challenge)
    binding, jwks, outer, request, registration = continuation_artifacts(context, reopened.public_key, 1_800_000_003)
    submission = reopened.prepare_account_presentation(
        fresh_pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
        request_object=request, registration=registration,
    )
    assert submission.presentation_jws
    reopened.lock()



def test_continuation_expiry_invalidates_pending_before_approval_expiry(tmp_path, monkeypatch):
    wallet, pending, context = _approved_wallet(tmp_path)
    instant = 1_800_000_001
    request_expiry = instant + 5
    assert request_expiry < pending.expires_at
    wallet.create_account_login_proof(
        pending, challenge=json.loads(LOGIN_VECTOR.read_text())["challenge"],
    )
    binding, jwks, outer, request, registration = continuation_artifacts(
        context, wallet.public_key, instant, request_expires_at=request_expiry,
    )
    from decent_wallet.account_disclosure import verify_owner_key_binding
    from decent_wallet.oid4vp_request import verify_oid4vp_authorization_request
    verified_binding = verify_owner_key_binding(
        binding, jwks, context, expected_identity_id=IDENTITY_ID, now=instant,
    )
    verify_oid4vp_authorization_request(
        outer, request_object=request, registration=registration, context=context,
        owner_key_binding_jws=binding, verified_binding=verified_binding, now=instant,
    )
    monkeypatch.setattr("decent_wallet.container.time.time", lambda: request_expiry)
    with pytest.raises(ValueError):
        wallet.prepare_account_presentation(
            pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
            request_object=request, registration=registration,
        )
    wallet.lock()
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    with pytest.raises(ValueError):
        reopened.create_account_login_proof(pending, challenge=json.loads(LOGIN_VECTOR.read_text())["challenge"])
    with pytest.raises(ValueError):
        reopened.get_account_presentation_retry(pending)
    reopened.lock()


def test_public_local_privacy_canary_for_selected_account_disclosure(tmp_path, monkeypatch, caplog, capsys):
    import logging, socket
    from urllib.parse import parse_qsl
    from decent_wallet import verify_account_presentation
    from decent_wallet.account_disclosure import verify_owner_key_binding
    from decent_wallet.oid4vp_request import verify_oid4vp_authorization_request
    caplog.set_level(logging.DEBUG)
    selected = "SELECTED_GIVEN_MARKER_062_" + "s" * 160
    unselected = "OPTIONAL_EMAIL_MARKER_062_" + "o" * 160
    nonrequested = "NONREQUESTED_MARKER_062_" + "n" * 160
    login = json.loads(LOGIN_VECTOR.read_text())
    path = tmp_path / "canary-wallet.json"
    wallet = Wallet._create_storage(path, "correct horse battery", "correct horse battery", {"private_seed": base64.urlsafe_b64decode(login["test_private_seed_b64url"] + "="), "public_key": base64.urlsafe_b64decode(login["public_key_b64url"] + "=")})
    def blocked(*_a, **_kw): raise AssertionError("local flow attempted socket connection")
    monkeypatch.setattr(socket.socket, "connect", blocked)
    wallet.set_master_account_entity({"given_name": selected, "email": unselected, "other": nonrequested})
    context = context_for_handle()
    review = wallet.review_account_disclosure(context, HANDLE, IDENTITY_ID)
    calls = []
    def consent(candidate):
        calls.append(candidate)
        assert candidate == review
        assert {claim.claim_id: claim.required for claim in candidate.context.claims} == {GIVEN: True, EMAIL: False}
        assert dict(candidate.values) == {GIVEN: selected, EMAIL: unselected}
        return True
    with pytest.raises(ValueError) as err:
        wallet.approve_account_disclosure(review, [EMAIL], consent=consent)
    assert str(err.value) == "account disclosure operation rejected"
    assert all(m not in repr(err.value) and m not in str(err.value) for m in (selected, unselected, nonrequested))
    assert calls == [] and "pending_account_disclosure_v1" not in wallet._payload
    # Re-authenticate the persisted container: in-memory absence alone cannot prove no write.
    key = "pending_account_disclosure_v1"
    rejected_reopen = Wallet.open(path, "correct horse battery")
    assert key not in rejected_reopen._payload
    rejected_reopen.lock()
    pending = wallet.approve_account_disclosure(review, [GIVEN], consent=consent)
    assert len(calls) == 1
    # Public pending DTO redacts values; inspect authenticated Wallet.open payload only for this persistence assertion.
    reopened = Wallet.open(path, "correct horse battery")
    key = "pending_account_disclosure_v1"
    assert reopened._payload[key]["approved_values"] == {GIVEN: selected}
    reopened.lock()
    proof = wallet.create_account_login_proof(pending, challenge=login["challenge"])
    assert proof.proof == login["proof"]
    assert set(proof.proof) == {"profile", "challenge", "identity_id", "signature"}
    binding_jws, jwks, outer, request_object, registration = continuation_artifacts(context, wallet.public_key, 1_800_000_001)
    submission = wallet.prepare_account_presentation(pending, binding_jws=binding_jws, keycloak_jwks=jwks, outer_request=outer, request_object=request_object, registration=registration)
    reopened = Wallet.open(path, "correct horse battery")
    prepared_record = reopened._payload[key]
    assert prepared_record["approved_claim_ids"] == [GIVEN]
    assert prepared_record["approved_values"] == {GIVEN: selected}
    assert prepared_record["state"] == "prepared"
    stored_submission = prepared_record["submission"]
    assert stored_submission["body"] == submission.body.decode("ascii")
    assert stored_submission["presentation_jws"] == submission.presentation_jws
    for marker in (unselected, nonrequested):
        assert marker not in repr(prepared_record) and marker not in str(prepared_record)
    reopened.lock()
    for marker in (unselected, nonrequested):
        assert marker not in submission.body.decode("ascii") and marker not in submission.presentation_jws
    fields = parse_qsl(submission.body.decode("ascii"), keep_blank_values=True, strict_parsing=True)
    field_names = [key for key, _ in fields]
    assert sorted(field_names) == ["state", "vp_token"]
    assert field_names.count("state") == 1 and field_names.count("vp_token") == 1
    form = dict(fields)
    assert form["state"] == submission.state
    assert json.loads(form["vp_token"]) == {"account": [submission.presentation_jws]}

    def form_component(value):
        unreserved = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~-"
        return "".join(
            chr(byte) if byte in unreserved else f"%{byte:02X}"
            for byte in value.encode("utf-8")
        )

    # Independently specify application/x-www-form-urlencoded serialization;
    # this checks the core's output bytes, not a Content-Type header or transport.
    compact_vp_token = '{"account":["' + submission.presentation_jws + '"]}'
    expected_body = (
        "state=" + form_component(submission.state)
        + "&vp_token=" + form_component(compact_vp_token)
    ).encode("ascii")
    assert submission.state.isascii()
    assert submission.body == expected_body
    assert submission.body.decode("utf-8").encode("utf-8") == submission.body

    binding = verify_owner_key_binding(binding_jws, jwks, context, expected_identity_id=IDENTITY_ID, now=1_800_000_001)
    request = verify_oid4vp_authorization_request(outer, request_object=request_object, registration=registration, context=context, owner_key_binding_jws=binding_jws, verified_binding=binding, now=1_800_000_001)
    verified = verify_account_presentation(submission.presentation_jws, context=context, binding=binding, request=request, approved_claim_ids=[GIVEN], approval_expires_at=pending.expires_at, now=1_800_000_001)
    assert verified.claims == {GIVEN: selected} and EMAIL not in verified.claims
    objects = (review, pending, proof, submission, wallet)
    for obj in objects:
        assert all(m not in repr(obj) and m not in str(obj) for m in (selected, unselected, nonrequested))
    captured = capsys.readouterr()
    assert all(m not in captured.out and m not in captured.err and m not in caplog.text for m in (selected, unselected, nonrequested))
    encrypted = path.read_bytes()
    assert all(m.encode() not in encrypted for m in (selected, unselected, nonrequested))
    wallet.lock()


def test_approval_rejects_stale_now_without_mutation_then_expires(tmp_path, monkeypatch):
    import copy
    import decent_wallet.container as container_module

    expiry = 1_800_000_010
    wallet = Wallet._create_storage(
        tmp_path / "wallet.json", "correct horse battery", "correct horse battery",
        {"private_seed": base64.urlsafe_b64decode(json.loads(LOGIN_VECTOR.read_text())["test_private_seed_b64url"] + "="),
         "public_key": base64.urlsafe_b64decode(json.loads(LOGIN_VECTOR.read_text())["public_key_b64url"] + "=")},
    )
    wallet.set_master_account_entity({"given_name": "Ada"})
    review = wallet.review_account_disclosure(context_for_handle(expiry), HANDLE, IDENTITY_ID)
    path = tmp_path / "wallet.json"
    before = path.read_bytes()
    payload_before = copy.deepcopy(wallet._payload)
    monkeypatch.setattr(container_module.time, "time", lambda: expiry + 1)
    with pytest.raises(TypeError):
        wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _review: True, now=expiry - 1)
    assert path.read_bytes() == before
    assert wallet._payload == payload_before
    with pytest.raises(ValueError):
        wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _review: True)
    assert path.read_bytes() == before
    assert "pending_account_disclosure_v1" not in wallet._payload
    wallet.lock()


def test_proof_rejects_stale_now_without_mutation_then_expires(tmp_path, monkeypatch):
    import copy
    import decent_wallet.container as container_module

    wallet, pending, _context = _approved_wallet(tmp_path)
    path = tmp_path / "wallet.json"
    before = path.read_bytes()
    payload_before = copy.deepcopy(wallet._payload)
    challenge = json.loads(LOGIN_VECTOR.read_text())["challenge"]
    monkeypatch.setattr(container_module.time, "time", lambda: pending.expires_at + 1)
    with pytest.raises(TypeError):
        wallet.create_account_login_proof(pending, challenge=challenge, now=pending.expires_at - 1)
    assert path.read_bytes() == before
    assert wallet._payload == payload_before
    with pytest.raises(ValueError):
        wallet.create_account_login_proof(pending, challenge=challenge)
    assert "pending_account_disclosure_v1" not in wallet._payload
    assert path.read_bytes() != before
    assert wallet.export_container()
    wallet.lock()


def test_prepare_rejects_stale_now_without_mutation_then_expires_request(tmp_path, monkeypatch):
    import copy
    import decent_wallet.container as container_module
    from decent_wallet.account_disclosure import verify_owner_key_binding
    from decent_wallet.oid4vp_request import verify_oid4vp_authorization_request

    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(
        pending, challenge=json.loads(LOGIN_VECTOR.read_text())["challenge"],
    )
    instant = 1_800_000_001
    request_expiry = instant + 5
    assert request_expiry < pending.expires_at
    binding, jwks, outer, request_object, registration = continuation_artifacts(
        context, wallet.public_key, instant, request_expires_at=request_expiry,
    )
    verified_binding = verify_owner_key_binding(
        binding, jwks, context, expected_identity_id=IDENTITY_ID, now=instant,
    )
    verify_oid4vp_authorization_request(
        outer, request_object=request_object, registration=registration, context=context,
        owner_key_binding_jws=binding, verified_binding=verified_binding, now=request_expiry - 1,
    )
    path = tmp_path / "wallet.json"
    before = path.read_bytes()
    payload_before = copy.deepcopy(wallet._payload)
    monkeypatch.setattr(container_module.time, "time", lambda: request_expiry + 1)
    with pytest.raises(TypeError):
        wallet.prepare_account_presentation(
            pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
            request_object=request_object, registration=registration, now=request_expiry - 1,
        )
    assert path.read_bytes() == before
    assert wallet._payload == payload_before
    with pytest.raises(ValueError):
        wallet.prepare_account_presentation(
            pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
            request_object=request_object, registration=registration,
        )
    assert "pending_account_disclosure_v1" not in wallet._payload
    assert path.read_bytes() != before
    wallet.lock()


def test_prepare_fails_closed_when_request_expires_during_persistence(tmp_path, monkeypatch):
    import decent_wallet.container as container_module
    from decent_wallet.account_disclosure import verify_owner_key_binding
    from decent_wallet.oid4vp_request import verify_oid4vp_authorization_request

    wallet, pending, context = _approved_wallet(tmp_path)
    challenge = json.loads(LOGIN_VECTOR.read_text())["challenge"]
    wallet.create_account_login_proof(pending, challenge=challenge)
    instant = 1_800_000_001
    request_expiry = instant + 5
    assert request_expiry < pending.expires_at
    binding, jwks, outer, request_object, registration = continuation_artifacts(
        context, wallet.public_key, instant, request_expires_at=request_expiry,
    )
    verified_binding = verify_owner_key_binding(
        binding, jwks, context, expected_identity_id=IDENTITY_ID, now=instant,
    )
    verify_oid4vp_authorization_request(
        outer, request_object=request_object, registration=registration, context=context,
        owner_key_binding_jws=binding, verified_binding=verified_binding, now=request_expiry - 1,
    )

    clock = {"now": instant}
    monkeypatch.setattr(container_module.time, "time", lambda: clock["now"])
    original_persist = wallet._persist_envelope
    prepared_writes = []

    def persist_then_expire(envelope):
        original_persist(envelope)
        if not prepared_writes:
            prepared_writes.append(True)
            clock["now"] = request_expiry + 1

    monkeypatch.setattr(wallet, "_persist_envelope", persist_then_expire)
    with pytest.raises(ValueError):
        wallet.prepare_account_presentation(
            pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
            request_object=request_object, registration=registration,
        )

    assert prepared_writes == [True]
    assert "pending_account_disclosure_v1" not in wallet._payload
    wallet.lock()
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    assert "pending_account_disclosure_v1" not in reopened._payload
    with pytest.raises(ValueError):
        reopened.get_account_presentation_retry(pending)
    reopened.lock()


def test_login_proof_fails_closed_when_approval_expires_during_persistence(tmp_path, monkeypatch):
    import decent_wallet.container as container_module

    wallet, pending, _context = _approved_wallet(tmp_path)
    challenge = json.loads(LOGIN_VECTOR.read_text())["challenge"]
    clock = {"now": pending.expires_at - 1}
    monkeypatch.setattr(container_module.time, "time", lambda: clock["now"])
    original_persist = wallet._persist_envelope
    writes = []

    def persist_then_expire(envelope):
        original_persist(envelope)
        if not writes:
            writes.append(True)
            clock["now"] = pending.expires_at + 1

    monkeypatch.setattr(wallet, "_persist_envelope", persist_then_expire)
    with pytest.raises(ValueError):
        wallet.create_account_login_proof(pending, challenge=challenge)

    assert writes == [True]
    assert "pending_account_disclosure_v1" not in wallet._payload
    wallet.lock()
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    assert "pending_account_disclosure_v1" not in reopened._payload
    reopened.lock()


def test_approval_fails_closed_when_context_expires_during_persistence(tmp_path, monkeypatch):
    import decent_wallet.container as container_module

    vector = json.loads(LOGIN_VECTOR.read_text())
    wallet = Wallet._create_storage(
        tmp_path / "wallet.json", "correct horse battery", "correct horse battery",
        {"private_seed": base64.urlsafe_b64decode(vector["test_private_seed_b64url"] + "="),
         "public_key": base64.urlsafe_b64decode(vector["public_key_b64url"] + "=")},
    )
    wallet.set_master_account_entity({"given_name": "Ada", "email": "ada@example.test"})
    expiry = 1_800_000_006
    review = wallet.review_account_disclosure(
        context_for_handle(expires_at=expiry), HANDLE, IDENTITY_ID,
    )
    clock = {"now": 1_800_000_001}
    monkeypatch.setattr(container_module.time, "time", lambda: clock["now"])
    original_persist = wallet._persist_envelope
    writes = []

    def persist_then_expire(envelope):
        original_persist(envelope)
        if not writes:
            writes.append(True)
            clock["now"] = expiry + 1

    monkeypatch.setattr(wallet, "_persist_envelope", persist_then_expire)
    with pytest.raises(ValueError):
        wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _review: True)

    assert writes == [True]
    assert "pending_account_disclosure_v1" not in wallet._payload
    wallet.lock()
    reopened = Wallet.open(tmp_path / "wallet.json", "correct horse battery")
    assert "pending_account_disclosure_v1" not in reopened._payload
    reopened.lock()


def test_wallet_security_boundary_is_local_redacted_and_selection_scoped(tmp_path, monkeypatch, caplog, capsys, request):
    """Security evidence checklist:
    (a) one unchanged encrypted container plus its lock sidecar; no separate key,
    envelope, entity file, media-type field, or network call from this wallet API path;
    (b) safe DTO/error/repr/traceback/log/stdout/stderr and locked public reads;
    (c) persist and independently verify only the approved claim value. This does not
    qualify Keycloak, RP, external Storage/Registry, or device/runtime components.
    """
    import logging
    import socket
    import traceback

    from decent_wallet import WalletLockedError, verify_account_presentation
    from decent_wallet.account_disclosure import verify_owner_key_binding
    from decent_wallet.oid4vp_request import verify_oid4vp_authorization_request

    selected = "SECBOUND_SELECTED_" + "a" * 160
    unselected = "SECBOUND_UNSELECTED_" + "b" * 160
    unrequested = "SECBOUND_UNREQUESTED_" + "c" * 160
    callback_marker = "SECBOUND_CALLBACK_EXCEPTION_" + "d" * 160
    login = json.loads(LOGIN_VECTOR.read_text())
    path = tmp_path / "boundary-wallet.json"
    sessions = []

    def track(session):
        sessions.append(session)
        return session

    def close_sessions():
        for session in sessions:
            if session.is_unlocked:
                session.lock()

    request.addfinalizer(close_sessions)
    wallet = track(Wallet._create_storage(
        path, "correct horse battery", "correct horse battery",
        {"private_seed": base64.urlsafe_b64decode(login["test_private_seed_b64url"] + "="),
         "public_key": base64.urlsafe_b64decode(login["public_key_b64url"] + "=")},
    ))
    caplog.set_level(logging.DEBUG)
    network_calls = []

    def blocked_network(*args, **kwargs):
        network_calls.append((args, kwargs))
        raise AssertionError("wallet disclosure attempted external networking")

    monkeypatch.setattr(socket.socket, "connect", blocked_network)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked_network)
    monkeypatch.setattr(socket.socket, "sendto", blocked_network)
    monkeypatch.setattr(socket, "create_connection", blocked_network)
    wallet.set_master_account_entity(
        {"given_name": selected, "email": unselected, "other": unrequested}
    )
    context = context_for_handle()
    review = wallet.review_account_disclosure(context, HANDLE, IDENTITY_ID)

    def broken_consent(_review):
        raise RuntimeError(callback_marker)

    with pytest.raises(ValueError) as rejected:
        wallet.approve_account_disclosure(review, [GIVEN], consent=broken_consent)
    assert rejected.value.__cause__ is None
    assert rejected.value.__context__ is None
    error_output = "\n".join((str(rejected.value), repr(rejected.value),
        "".join(traceback.format_exception(rejected.value)),
        "".join(traceback.format_exception(rejected.value.__cause__)) if rejected.value.__cause__ else "",
        "".join(traceback.format_exception(rejected.value.__context__)) if rejected.value.__context__ else ""))
    assert callback_marker not in error_output
    assert "pending_account_disclosure_v1" not in wallet._payload
    failed_reopen = track(Wallet.open(path, "correct horse battery"))
    assert "pending_account_disclosure_v1" not in failed_reopen._payload
    failed_reopen.lock()

    pending = wallet.approve_account_disclosure(
        review, [GIVEN], consent=lambda candidate: candidate == review
    )
    assert wallet.get_master_account_entity() == {
        "given_name": selected, "email": unselected, "other": unrequested,
    }
    for obj in (review, pending):
        assert all(marker not in repr(obj) and marker not in str(obj)
                   for marker in (selected, unselected, unrequested, callback_marker))
    reopened = track(Wallet.open(path, "correct horse battery"))
    record = reopened._payload["pending_account_disclosure_v1"]
    assert record["approved_claim_ids"] == [GIVEN]
    assert record["approved_values"] == {GIVEN: selected}
    reopened.lock()

    proof = wallet.create_account_login_proof(pending, challenge=login["challenge"])
    assert proof.proof == login["proof"]
    assert set(proof.proof) == {"profile", "challenge", "identity_id", "signature"}
    binding_jws, jwks, outer, request_object, registration = continuation_artifacts(
        context, wallet.public_key, 1_800_000_001
    )
    submission = wallet.prepare_account_presentation(
        pending, binding_jws=binding_jws, keycloak_jwks=jwks, outer_request=outer,
        request_object=request_object, registration=registration,
    )
    for obj in (review, pending, proof, submission):
        assert all(marker not in repr(obj) and marker not in str(obj)
                   for marker in (selected, unselected, unrequested, callback_marker))
    stored = track(Wallet.open(path, "correct horse battery"))
    prepared = stored._payload["pending_account_disclosure_v1"]
    assert prepared["approved_values"] == {GIVEN: selected}
    assert set(prepared["submission"]) == {
        "response_uri", "state", "body", "presentation_jws", "expires_at",
    }
    assert "content_type" not in prepared["submission"]
    assert prepared["submission"]["body"] == submission.body.decode("ascii")
    assert prepared["submission"]["presentation_jws"] == submission.presentation_jws
    stored.lock()

    binding = verify_owner_key_binding(binding_jws, jwks, context,
        expected_identity_id=IDENTITY_ID, now=1_800_000_001)
    request = verify_oid4vp_authorization_request(outer, request_object=request_object,
        registration=registration, context=context, owner_key_binding_jws=binding_jws,
        verified_binding=binding, now=1_800_000_001)
    verified = verify_account_presentation(submission.presentation_jws, context=context,
        binding=binding, request=request, approved_claim_ids=[GIVEN],
        approval_expires_at=pending.expires_at, now=1_800_000_001)
    assert verified.claims == {GIVEN: selected}
    assert EMAIL not in verified.claims
    for marker in (unselected, unrequested, callback_marker):
        assert marker not in submission.body.decode("ascii")
        assert marker not in submission.presentation_jws

    envelope = json.loads(path.read_bytes())
    assert set(envelope) == {"format", "version", "kdf", "wrap", "payload"}
    assert set(envelope["wrap"]) == {"algorithm", "nonce", "ciphertext", "tag"}
    assert set(envelope["payload"]) == {"algorithm", "nonce", "ciphertext", "tag"}
    assert sorted(item.name for item in tmp_path.iterdir()) == [".boundary-wallet.json.lock", "boundary-wallet.json"]
    wallet.lock()
    locked_bytes = path.read_bytes()
    with pytest.raises(WalletLockedError) as locked:
        wallet.get_master_account_entity()
    with pytest.raises(ValueError) as locked_review:
        wallet.review_account_disclosure(context, HANDLE, IDENTITY_ID)
    with pytest.raises(WalletLockedError) as locked_proof:
        wallet.create_account_login_proof(pending, challenge=login["challenge"])
    locked_output = "\n".join((str(locked.value), repr(locked.value),
        "".join(traceback.format_exception(locked.value)),
        str(locked_review.value), repr(locked_review.value),
        "".join(traceback.format_exception(locked_review.value)),
        str(locked_proof.value), repr(locked_proof.value),
        "".join(traceback.format_exception(locked_proof.value))))
    assert path.read_bytes() == locked_bytes
    assert all(marker not in locked_output
               for marker in (selected, unselected, unrequested, callback_marker))
    assert network_calls == []
    captured = capsys.readouterr()
    for marker in (selected, unselected, unrequested, callback_marker):
        assert marker not in captured.out and marker not in captured.err and marker not in caplog.text
        assert marker.encode() not in path.read_bytes()

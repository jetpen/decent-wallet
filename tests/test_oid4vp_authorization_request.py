from __future__ import annotations
import base64, copy, hashlib, json
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from decent_wallet import (
    WalletDisclosureRequestError,
    parse_wallet_account_disclosure_context,
    verify_owner_key_binding,
)
from decent_wallet.oid4vp_request import (
    OID4VPRequestError,
    TrustedRPRegistration,
    verify_oid4vp_authorization_request,
)

VECTOR_DIR = Path(__file__).parent / "vectors/wallet-account-disclosure-v1/vectors"
ISSUER = "https://login.example.test/realms/site"


def vector(name="valid-signup.json"):
    return json.loads((VECTOR_DIR / name).read_text(encoding="utf-8"))


def b64(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def dec(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _context_binding(v):
    context = parse_wallet_account_disclosure_context(
        json.dumps(v["keycloak_context"]).encode(), expected_keycloak_issuer=ISSUER
    )
    binding = verify_owner_key_binding(
        v["owner_key_binding_jws"],
        v["keycloak_jwks"],
        context,
        expected_identity_id="mailto:ada@example.test",
        now=v["validation_time"],
    )
    return context, binding


def _vector_verify(v):
    context, binding = _context_binding(v)
    registration = TrustedRPRegistration(
        v["oid4vp_client_id"],
        "site.example.test",
        context.rp_origin,
        "https://site.example.test/oid4vp/response",
        v["rp_certificate"]["trust_anchor_sha256"],
        context.rp_client_id,
    )
    return verify_oid4vp_authorization_request(
        outer=v["oid4vp_authorization_parameters"],
        request_object=v["oid4vp_request_jws"],
        registration=registration,
        context=context,
        owner_key_binding_jws=v["owner_key_binding_jws"],
        verified_binding=binding,
        now=v["validation_time"],
    )


@pytest.fixture
def prepared():
    v = vector()
    context, binding = _context_binding(v)
    key = ec.generate_private_key(ec.SECP256R1())
    host = "site.example.test"
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2032, 1, 1, tzinfo=timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    der = cert.public_bytes(serialization.Encoding.DER)
    reg = TrustedRPRegistration(
        v["oid4vp_client_id"],
        host,
        context.rp_origin,
        "https://site.example.test/oid4vp/response",
        hashlib.sha256(der).hexdigest(),
        context.rp_client_id,
    )
    payload = json.loads(dec(v["oid4vp_request_jws"].split(".")[1]))
    payload["decent_account"]["owner_key_binding"] = v["owner_key_binding_jws"]

    def sign_raw(payload_bytes, cert_der=der):
        h = b64(
            json.dumps(
                {
                    "alg": "ES256",
                    "typ": "oauth-authz-req+jwt",
                    "x5c": [base64.b64encode(cert_der).decode()],
                },
                separators=(",", ":"),
            ).encode()
        )
        body = b64(payload_bytes)
        raw = key.sign(f"{h}.{body}".encode(), ec.ECDSA(hashes.SHA256()))
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        r, s = decode_dss_signature(raw)
        return f"{h}.{body}.{b64(r.to_bytes(32,'big')+s.to_bytes(32,'big'))}"

    def sign(p):
        return sign_raw(json.dumps(p, separators=(",", ":")).encode())

    return dict(
        outer=dict(v["oid4vp_authorization_parameters"]),
        request_object=sign(payload),
        registration=reg,
        context=context,
        owner_key_binding_jws=v["owner_key_binding_jws"],
        verified_binding=binding,
        now=v["validation_time"],
        sign=sign,
        sign_raw=sign_raw,
        payload=payload,
        key=key,
    )


def _verify(prepared, **changes):
    args = {
        k: v
        for k, v in prepared.items()
        if k not in {"sign", "sign_raw", "payload", "key"}
    }
    args.update(changes)
    return verify_oid4vp_authorization_request(**args)


def test_all_shared_positive_vectors_use_typed_context_and_binding():
    names = sorted(path.name for path in VECTOR_DIR.glob("valid-*.json"))
    assert len(names) == 5
    assert all(
        _vector_verify(vector(name)).client_id == "x509_san_dns:site.example.test"
        for name in names
    )


def test_registered_oidc_client_mismatch_rejects_validly_signed_request(prepared):
    payload = copy.deepcopy(prepared["payload"])
    payload["decent_account"]["rp_oidc_client_id"] = "another-client"
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, request_object=prepared["sign"](payload))


def test_certificate_san_mismatch_rejects_validly_signed_request(prepared):
    attacker_name = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "attacker.example.test")]
    )
    attacker_cert = (
        x509.CertificateBuilder()
        .subject_name(attacker_name)
        .issuer_name(attacker_name)
        .public_key(prepared["key"].public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime(2032, 1, 1, tzinfo=timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("attacker.example.test")]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(prepared["key"], hashes.SHA256())
    )
    attacker_der = attacker_cert.public_bytes(serialization.Encoding.DER)
    registration = prepared["registration"]
    pinned_registration = TrustedRPRegistration(
        registration.client_id,
        registration.x509_san_dns,
        registration.origin,
        registration.response_uri,
        hashlib.sha256(attacker_der).hexdigest(),
        registration.rp_client_id,
    )
    with pytest.raises(OID4VPRequestError):
        _verify(
            prepared,
            registration=pinned_registration,
            request_object=prepared["sign_raw"](
                json.dumps(prepared["payload"], separators=(",", ":")).encode(),
                cert_der=attacker_der,
            ),
        )


def test_expired_and_not_yet_valid_pinned_leaf_certificates_reject(prepared):
    host = prepared["registration"].x509_san_dns
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    for not_before, not_after in (
        (datetime(2026, 1, 1, tzinfo=timezone.utc), datetime(2026, 12, 31, tzinfo=timezone.utc)),
        (datetime(2028, 1, 1, tzinfo=timezone.utc), datetime(2032, 1, 1, tzinfo=timezone.utc)),
    ):
        certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(prepared["key"].public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(prepared["key"], hashes.SHA256())
        )
        cert_der = certificate.public_bytes(serialization.Encoding.DER)
        registration = prepared["registration"]
        pinned_registration = TrustedRPRegistration(
            registration.client_id,
            registration.x509_san_dns,
            registration.origin,
            registration.response_uri,
            hashlib.sha256(cert_der).hexdigest(),
            registration.rp_client_id,
        )
        with pytest.raises(OID4VPRequestError):
            _verify(
                prepared,
                registration=pinned_registration,
                request_object=prepared["sign_raw"](
                    json.dumps(prepared["payload"], separators=(",", ":")).encode(),
                    cert_der=cert_der,
                ),
                now=prepared["now"],
            )


def test_request_expiry_is_bounded_by_context_and_verified_binding(prepared):
    context_expiry = prepared["context"].expires_at
    binding = prepared["verified_binding"]
    prepared["verified_binding"] = replace(binding, expires_at=context_expiry - 1)

    accepted = copy.deepcopy(prepared["payload"])
    accepted["iat"] = prepared["now"]
    accepted["exp"] = context_expiry - 1
    assert _verify(prepared, request_object=prepared["sign"](accepted))

    for exp in (context_expiry, context_expiry + 1):
        payload = copy.deepcopy(prepared["payload"])
        payload["iat"] = prepared["now"]
        payload["exp"] = exp
        with pytest.raises(OID4VPRequestError):
            _verify(prepared, request_object=prepared["sign"](payload))


def test_registered_oidc_rp_client_mismatch_rejects(prepared):
    registration = prepared["registration"]
    mismatched = TrustedRPRegistration(
        registration.client_id,
        registration.x509_san_dns,
        registration.origin,
        registration.response_uri,
        registration.trust_anchor_sha256,
        "different-registered-rp-client",
    )
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, registration=mismatched)


def test_malformed_x5c_and_wrong_trust_pin_reject(prepared):
    header, body, _signature = prepared["request_object"].split(".")
    header_data = json.loads(dec(header))
    header_data["x5c"] = ["not-base64!"]
    malformed_header = b64(json.dumps(header_data, separators=(",", ":")).encode())
    signed = f"{malformed_header}.{body}".encode()
    raw_signature = prepared["key"].sign(signed, ec.ECDSA(hashes.SHA256()))
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    r, s = decode_dss_signature(raw_signature)
    malformed_token = f"{malformed_header}.{body}.{b64(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, request_object=malformed_token)

    registration = prepared["registration"]
    wrong_pin = TrustedRPRegistration(
        registration.client_id,
        registration.x509_san_dns,
        registration.origin,
        registration.response_uri,
        "00" * 32,
        registration.rp_client_id,
    )
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, registration=wrong_pin)


def test_state_and_nonce_cannot_reuse_context_or_transaction_identifiers(prepared):
    for field, reused in (
        ("state", prepared["context"].request_id),
        ("state", prepared["context"].transaction_id),
        ("nonce", prepared["context"].request_id),
        ("nonce", prepared["context"].transaction_id),
        ("state", prepared["context"].oidc_nonce),
        ("nonce", prepared["context"].oidc_nonce),
    ):
        changed = copy.deepcopy(prepared["payload"])
        changed[field] = reused
        with pytest.raises(OID4VPRequestError):
            _verify(prepared, request_object=prepared["sign"](changed))

    changed = copy.deepcopy(prepared["payload"])
    changed["state"] = changed["nonce"]
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, request_object=prepared["sign"](changed))


STAGE_BY_ID = {
    "request-unsupported-transaction-data": "request",
    "outer-unsupported-transaction-data": "request",
    "recovery-binding-action-mismatch": "binding",
    "context-transaction-mismatch": "binding",
    "login-action-with-disclosure": "context",
    "purpose-bidi-control": "context",
    "binding-wrong-rp-audience": "binding",
    "binding-expired": "binding",
    "request-response-uri-host-mismatch": "request",
    "presentation-wrong-nonce": "presentation",
    "presentation-extra-claim": "presentation",
    "claim-value-utf8-byte-limit": "presentation",
    "presentation-expired": "presentation",
    "presentation-expiry-after-credential": "presentation",
    "presentation-owner-binding-mismatch": "presentation",
    "presentation-invalid-signature": "presentation",
    "credential-invalid-signature": "presentation",
    "presentation-duplicate-json-member": "presentation",
    "required-claim-omitted": "presentation",
    "presentation-request-id-mismatch": "presentation",
    "presentation-total-size-limit": "presentation",
    "oidc-not-validated": "oidc-precondition",
    "oidc-validation-marker-missing": "oidc-precondition",
    "direct-post-state-mismatch": "direct-post",
    "direct-post-vp-token-wrong-shape": "direct-post",
    "presentation-invalid-unicode-scalar": "presentation",
    "request-nonfinite-number-overflow": "request",
    "dcql-missing-required-meta": "request",
    "dcql-claim-sets-incomplete": "request",
}

NEGATIVE_EXPECTED_BY_ID = {
    "request-unsupported-transaction-data": "unsupported-transaction-data",
    "outer-unsupported-transaction-data": "unsupported-transaction-data",
    "recovery-binding-action-mismatch": "binding-context-mismatch",
    "context-transaction-mismatch": "transaction-mismatch",
    "login-action-with-disclosure": "action-mismatch",
    "purpose-bidi-control": "invalid-purpose",
    "binding-wrong-rp-audience": "binding-audience-mismatch",
    "binding-expired": "binding-expired",
    "request-response-uri-host-mismatch": "response-uri-host-mismatch",
    "presentation-wrong-nonce": "presentation-nonce-mismatch",
    "presentation-extra-claim": "unrequested-claim",
    "claim-value-utf8-byte-limit": "invalid-claim-value",
    "presentation-expired": "presentation-expired",
    "presentation-expiry-after-credential": "presentation-expiry-too-late",
    "presentation-owner-binding-mismatch": "owner-binding-mismatch",
    "presentation-invalid-signature": "signature-invalid",
    "credential-invalid-signature": "signature-invalid",
    "presentation-duplicate-json-member": "duplicate-json-member",
    "required-claim-omitted": "required-claim-missing",
    "presentation-request-id-mismatch": "request-id-mismatch",
    "presentation-total-size-limit": "presentation-too-large",
    "oidc-not-validated": "oidc-not-validated",
    "oidc-validation-marker-missing": "oidc-not-validated",
    "direct-post-state-mismatch": "direct-post-response-mismatch",
    "direct-post-vp-token-wrong-shape": "direct-post-response-schema-invalid",
    "presentation-invalid-unicode-scalar": "invalid-unicode-scalar",
    "request-nonfinite-number-overflow": "invalid-json-number",
    "dcql-missing-required-meta": "oid4vp-request-schema-invalid",
    "dcql-claim-sets-incomplete": "dcql-claim-sets-mismatch",
}


def test_all_29_shared_negative_cases_reach_their_owning_stage():
    cases = json.loads((VECTOR_DIR / "negative.json").read_text())["vectors"]
    assert len(cases) == 29
    assert {case["id"] for case in cases} == set(STAGE_BY_ID)
    assert set(STAGE_BY_ID) == set(NEGATIVE_EXPECTED_BY_ID)
    dispositions = {
        "request": "reject",
        "context": "reject",
        "binding": "reject",
        "presentation": "pass-through",
        "direct-post": "pass-through",
        "oidc-precondition": "blocked",
    }
    for case in cases:
        case_id = case["id"]
        bundle = case["bundle"]
        stage = STAGE_BY_ID[case_id]
        assert case["expected"] == NEGATIVE_EXPECTED_BY_ID[case_id]
        assert dispositions[stage] == (
            "blocked"
            if stage == "oidc-precondition"
            else (
                "reject"
                if stage in {"request", "context", "binding"}
                else "pass-through"
            )
        )
        if stage == "oidc-precondition":
            assert bundle.get("oidc_callback_validated") is (
                False if case["id"] == "oidc-not-validated" else None
            )
            continue
        if stage == "context":
            request_payload = json.loads(
                dec(bundle["initial_oidc_request_jws"].split(".")[1])
            )
            malformed_context = dict(bundle["keycloak_context"])
            if case["id"] == "login-action-with-disclosure":
                malformed_context["action"] = request_payload["decent_account_action"]
            else:
                malformed_context["purpose"] = request_payload[
                    "decent_account_request"
                ]["purpose"]
            with pytest.raises(WalletDisclosureRequestError):
                parse_wallet_account_disclosure_context(
                    json.dumps(malformed_context).encode(),
                    expected_keycloak_issuer=ISSUER,
                )
            continue
        try:
            context = parse_wallet_account_disclosure_context(
                json.dumps(bundle["keycloak_context"]).encode(),
                expected_keycloak_issuer=ISSUER,
            )
            binding_payload = json.loads(
                dec(bundle["owner_key_binding_jws"].split(".")[1])
            )
            binding = verify_owner_key_binding(
                bundle["owner_key_binding_jws"],
                bundle["keycloak_jwks"],
                context,
                expected_identity_id=binding_payload["identity_id"],
                now=bundle["validation_time"],
            )
        except WalletDisclosureRequestError:
            assert stage == "binding"
            continue
        reg = TrustedRPRegistration(
            bundle["oid4vp_client_id"],
            "site.example.test",
            context.rp_origin,
            "https://site.example.test/oid4vp/response",
            bundle["rp_certificate"]["trust_anchor_sha256"],
            context.rp_client_id,
        )
        kwargs = dict(
            outer=bundle["oid4vp_authorization_parameters"],
            request_object=bundle["oid4vp_request_jws"],
            registration=reg,
            context=context,
            owner_key_binding_jws=bundle["owner_key_binding_jws"],
            verified_binding=binding,
            now=bundle["validation_time"],
        )
        if stage == "binding":
            # The signed binding and context must agree before Request Object verification.
            with pytest.raises(OID4VPRequestError):
                verify_oid4vp_authorization_request(**kwargs)
        elif stage == "request":
            with pytest.raises(OID4VPRequestError):
                verify_oid4vp_authorization_request(**kwargs)
        else:
            assert (
                verify_oid4vp_authorization_request(**kwargs).client_id
                == bundle["oid4vp_client_id"]
            )


def test_generated_signed_semantic_mutations_and_ignored_extensions(prepared):
    base = prepared["payload"]
    mutations = [
        ("response_type", "code"),
        ("response_mode", "query"),
        ("response_uri", "https://elsewhere.example/response"),
        ("client_id", "x509_san_dns:elsewhere.example"),
        ("aud", "https://wrong.example"),
        ("transaction_data", []),
    ]
    for field, value in mutations:
        changed = copy.deepcopy(base)
        changed[field] = value
        with pytest.raises(OID4VPRequestError):
            _verify(prepared, request_object=prepared["sign"](changed))
    changed = copy.deepcopy(base)
    changed["x-future"] = {"attacker": True}
    changed["future_unicode"] = {"text": "café 🌍"}
    changed["client_metadata"]["future_metadata"] = "ignored"
    changed["dcql_query"]["future_root"] = {"ignored": True}
    changed["dcql_query"]["credentials"][0]["future_credential"] = "ignored"
    changed["dcql_query"]["credentials"][0]["claims"][0]["future_claim"] = ["opaque"]
    changed["dcql_query"]["credentials"][0]["meta"]["future_meta"] = {
        "attacker": "data"
    }
    out = _verify(
        prepared,
        outer={**prepared["outer"], "future_outer": "ignored"},
        request_object=prepared["sign"](changed),
    )
    assert (
        "future_root" not in out.dcql_query
        and "future_claim" not in out.dcql_query["credentials"][0]["claims"][0]
    )


def test_known_unsupported_dcql_fields_and_transaction_data_reject(prepared):
    cases = [
        (("dcql_query",), "credential_sets", []),
        (("dcql_query", "credentials", 0), "trusted_authorities", []),
        (("dcql_query", "credentials", 0, "claims", 0), "values", ["x"]),
        (("dcql_query", "credentials", 0, "claims", 0), "intent_to_retain", True),
    ]
    for path, field, value in cases:
        changed = copy.deepcopy(prepared["payload"])
        obj = changed
        for part in path:
            obj = obj[part]
        obj[field] = value
        with pytest.raises(OID4VPRequestError):
            _verify(prepared, request_object=prepared["sign"](changed))


def test_binding_provenance_and_registration_context_mismatches_reject(prepared):
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, owner_key_binding_jws="other-jws")
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, verified_binding=None)
    registrations = [
        TrustedRPRegistration(
            prepared["registration"].client_id,
            "site.example.test",
            "https://other.example",
            prepared["registration"].response_uri,
            prepared["registration"].trust_anchor_sha256,
            "site-client",
        ),
        TrustedRPRegistration(
            prepared["registration"].client_id,
            "site.example.test",
            prepared["registration"].origin,
            "https://elsewhere.example/response",
            prepared["registration"].trust_anchor_sha256,
            "site-client",
        ),
        TrustedRPRegistration(
            "x509_san_dns:elsewhere.example",
            "elsewhere.example",
            prepared["registration"].origin,
            prepared["registration"].response_uri,
            prepared["registration"].trust_anchor_sha256,
            "site-client",
        ),
        TrustedRPRegistration(
            prepared["registration"].client_id,
            "site.example.test",
            prepared["registration"].origin,
            prepared["registration"].response_uri,
            "00" * 32,
            "site-client",
        ),
    ]
    for registration in registrations:
        with pytest.raises(OID4VPRequestError):
            _verify(prepared, registration=registration)
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, now=2_000_000_000)
    with pytest.raises(OID4VPRequestError):
        _verify(
            prepared,
            outer={**prepared["outer"], "request_uri": "https://evil.example/request"},
        )
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, outer={**prepared["outer"], "client_id": "wrong"})


def test_validly_signed_ignored_extension_rejects_unpaired_surrogate(prepared):
    valid_payload = json.dumps(prepared["payload"], separators=(",", ":")).encode()
    signed_payload = valid_payload[:-1] + b',"future":{"ignored":"\\ud800"}}'
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, request_object=prepared["sign_raw"](signed_payload))


def test_signature_tamper_malformed_and_duplicate_json_reject(prepared):
    h, p, s = prepared["request_object"].split(".")
    with pytest.raises(OID4VPRequestError):
        _verify(
            prepared, request_object=f"{h}.{p}.{s[:-1]}{'A' if s[-1]!='A' else 'B'}"
        )
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, request_object="a.b.c")
    valid_payload = json.dumps(prepared["payload"], separators=(",", ":")).encode()
    duplicate = valid_payload.replace(
        b"{",
        b'{"aud":"https://self-issued.me/v2","aud":"https://self-issued.me/v2",',
        1,
    )
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, request_object=prepared["sign_raw"](duplicate))
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, request_object=prepared["sign_raw"](b'{"truncated":'))


def test_required_request_semantics_reject_signed_mutations(prepared):
    mutations = []
    p = copy.deepcopy(prepared["payload"])
    del p["dcql_query"]["credentials"][0]["meta"]
    mutations.append(p)
    p = copy.deepcopy(prepared["payload"])
    p["dcql_query"]["credentials"][0]["claim_sets"] = []
    mutations.append(p)
    p = copy.deepcopy(prepared["payload"])
    p["state"] = "short"
    mutations.append(p)
    p = copy.deepcopy(prepared["payload"])
    p["nonce"] = "not-base64!"
    mutations.append(p)
    p = copy.deepcopy(prepared["payload"])
    p["exp"] = prepared["now"]
    mutations.append(p)
    p = copy.deepcopy(prepared["payload"])
    p["iat"] = prepared["now"] + 61
    mutations.append(p)
    p = copy.deepcopy(prepared["payload"])
    p["client_metadata"]["vp_formats_supported"]["decent_account_jwt_v1"][
        "alg_values"
    ] = ["ES256"]
    mutations.append(p)
    p = copy.deepcopy(prepared["payload"])
    p["dcql_query"]["credentials"].append(
        copy.deepcopy(p["dcql_query"]["credentials"][0])
    )
    mutations.append(p)
    p = copy.deepcopy(prepared["payload"])
    p["decent_account"]["purpose"] = "altered"
    mutations.append(p)
    for changed in mutations:
        with pytest.raises(OID4VPRequestError):
            _verify(prepared, request_object=prepared["sign"](changed))
    with pytest.raises(OID4VPRequestError):
        _verify(prepared, outer={**prepared["outer"], "response_type": "vp_token"})


def test_unknown_outer_parameters_are_ignored(prepared):
    assert (
        _verify(
            prepared, outer={**prepared["outer"], "x-future": {"nested": 1}}
        ).client_id
        == prepared["registration"].client_id
    )


def test_rejects_bad_outer_shape_without_echoing_input():
    with pytest.raises(OID4VPRequestError) as exc:
        verify_oid4vp_authorization_request(
            {"client_id": ["secret"], "request_uri": "https://rp.example/r"},
            request_object="bad",
            registration=TrustedRPRegistration(
                "x509_san_dns:rp.example",
                "rp.example",
                "https://rp.example",
                "https://rp.example/response",
                "00" * 32,
            ),
            context=None,
            owner_key_binding_jws="binding",
            now=100,
        )
    assert str(exc.value) == "OID4VP authorization request rejected"

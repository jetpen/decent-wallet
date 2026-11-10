from __future__ import annotations

import json
from pathlib import Path

import pytest

from decent_wallet import (
    WalletDisclosureRequestError,
    parse_wallet_account_disclosure_context,
)


FIXTURES = Path(__file__).parent / "vectors" / "wallet-account-disclosure-v1" / "vectors"
EXPECTED_ISSUER = "https://login.example.test/realms/site"


def _positive_contexts():
    for path in sorted(FIXTURES.glob("valid-*.json")):
        vector = json.loads(path.read_text(encoding="utf-8"))
        yield path.name, vector["keycloak_context"]


def test_profile_context_parser_accepts_all_positive_ecosystem_vectors():
    parsed = [
        parse_wallet_account_disclosure_context(
            json.dumps(context, ensure_ascii=False).encode("utf-8"),
            expected_keycloak_issuer=EXPECTED_ISSUER,
        )
        for _, context in _positive_contexts()
    ]
    assert len(parsed) == 5
    assert {context.action for context in parsed} == {"signup", "signup_recovery"}
    assert all(context.rp_origin == "https://site.example.test" for context in parsed)
    assert all(context.claims for context in parsed)
    assert all(any(claim.required for claim in context.claims) for context in parsed)


def test_parser_rejects_duplicate_members_and_extra_context_fields():
    original = next(context for _, context in _positive_contexts())
    raw = json.dumps(original, ensure_ascii=False).encode("utf-8")
    duplicate = raw.replace(b"{\"profile\":", b"{\"profile\":\"duplicate\",\"profile\":", 1)
    with pytest.raises(WalletDisclosureRequestError, match="^wallet disclosure request rejected$"):
        parse_wallet_account_disclosure_context(
            duplicate, expected_keycloak_issuer=EXPECTED_ISSUER
        )

    extra = dict(original, private_data="must not be accepted")
    with pytest.raises(WalletDisclosureRequestError):
        parse_wallet_account_disclosure_context(
            json.dumps(extra).encode(), expected_keycloak_issuer=EXPECTED_ISSUER
        )


def test_parser_rejects_issuer_mismatch_untrusted_origin_and_unregistered_claim():
    _, original = next(_positive_contexts())
    with pytest.raises(WalletDisclosureRequestError):
        parse_wallet_account_disclosure_context(
            json.dumps(original).encode(),
            expected_keycloak_issuer="https://attacker.example.test/realms/site",
        )

    for invalid_origin in (
        "http://site.example.test",
        "https://user@site.example.test",
        "https://site.example.test/path",
        "https://SITE.example.test",
        "https://site.example.test:443",
    ):
        invalid = dict(original, rp_origin=invalid_origin)
        with pytest.raises(WalletDisclosureRequestError):
            parse_wallet_account_disclosure_context(
                json.dumps(invalid).encode(), expected_keycloak_issuer=EXPECTED_ISSUER
            )

    invalid = dict(original, claims=[{"id": "urn:example:unknown", "required": True}])
    with pytest.raises(WalletDisclosureRequestError):
        parse_wallet_account_disclosure_context(
            json.dumps(invalid).encode(), expected_keycloak_issuer=EXPECTED_ISSUER
        )


def test_parser_rejects_noncanonical_ids_unsafe_purpose_and_noninteger_expiry():
    _, original = next(_positive_contexts())
    malformed = (
        dict(original, request_id=original["request_id"] + "="),
        dict(original, transaction_id="A" * 42),
        dict(original, purpose="Look\u202Ehere"),
        dict(original, expires_at=True),
        dict(original, expires_at=1.5),
        dict(original, claims=[{"id": original["claims"][0]["id"], "required": 1}]),
    )
    for item in malformed:
        with pytest.raises(WalletDisclosureRequestError):
            parse_wallet_account_disclosure_context(
                json.dumps(item).encode(), expected_keycloak_issuer=EXPECTED_ISSUER
            )


def test_parser_requires_explicit_trusted_keycloak_issuer_argument():
    _, original = next(_positive_contexts())
    with pytest.raises(WalletDisclosureRequestError):
        parse_wallet_account_disclosure_context(
            json.dumps(original).encode(), expected_keycloak_issuer=""
        )

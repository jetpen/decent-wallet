from __future__ import annotations

import hashlib
import json
from pathlib import Path


FIXTURE_ROOT = Path(__file__).parent / "vectors" / "wallet-account-disclosure-v1"


def _json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def test_wallet_account_disclosure_fixtures_match_pinned_ecosystem_commit():
    manifest = _json(FIXTURE_ROOT / "source-manifest.json")
    assert manifest["source_commit"] == "b861b8c7a088dd21c79e064c8dbb52a0e0e96eb8"
    for relative, expected_digest in manifest["files"].items():
        raw = (FIXTURE_ROOT / relative).read_bytes()
        assert hashlib.sha256(raw).hexdigest() == expected_digest, relative


def test_positive_vectors_cover_signup_recovery_optional_omission_and_receiver_extensions():
    cases = {
        path.name: _json(path)
        for path in (FIXTURE_ROOT / "vectors").glob("valid-*.json")
    }
    assert len(cases) == 5
    assert all(case["expected"] == "accept" for case in cases.values())

    assert cases["valid-signup.json"]["keycloak_context"]["action"] == "signup"
    assert cases["valid-signup-recovery.json"]["keycloak_context"]["action"] == "signup_recovery"
    assert cases["valid-signup-optional-omitted.json"]["wallet_approved_claim_ids"] == [
        "urn:decent:account:v1:given_name"
    ]
    assert cases["valid-request-iss-ignored.json"]["expected"] == "accept"
    assert cases["valid-extensions-ignored.json"]["expected"] == "accept"


def test_negative_vectors_pin_all_29_ecosystem_rejection_cases():
    negative = _json(FIXTURE_ROOT / "vectors" / "negative.json")["vectors"]
    ids = {case["id"] for case in negative}
    assert len(negative) == 29
    assert len(ids) == 29
    assert {
        "oidc-not-validated",
        "oidc-validation-marker-missing",
        "presentation-duplicate-json-member",
        "presentation-invalid-signature",
        "presentation-extra-claim",
        "required-claim-omitted",
        "claim-value-utf8-byte-limit",
        "presentation-total-size-limit",
        "recovery-binding-action-mismatch",
        "context-transaction-mismatch",
    } <= ids


def test_shared_profile_schema_is_draft_2020_12_with_wallet_protocol_shapes():
    schema = _json(FIXTURE_ROOT / "schemas" / "profile.schema.json")
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert {
        "context",
        "binding",
        "oid4vpRequest",
        "accountExtension",
        "accountCredential",
        "presentation",
    } <= set(schema["$defs"])

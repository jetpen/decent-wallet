"""Portable encrypted rotation latch compatibility (synthetic wallets only)."""

import base64
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from test_multisig import (
    EXPIRY,
    PASSWORD,
    approved,
    make_legacy_rotation_bundle,
    prepare_rotation_publication,
)

from decent_wallet import (
    InvalidContainer,
    InvalidIdentityRequest,
    PublishStatus,
    RegistryAdapter,
    RotationDispatchIntent,
    RotationInProgress,
    Wallet,
)


def test_public_preparation_binds_environment_and_confirmation_fails_closed(tmp_path):
    wallets, owner, _, _, bundle, active, pending, _, transport = (
        make_legacy_rotation_bundle(tmp_path)
    )
    adapter = RegistryAdapter(transport, registry_environment="testnet")
    publication = prepare_rotation_publication(adapter, bundle, b"portable")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    assert permit.intent.environment == "testnet"
    raw = owner.export_container()
    imported = Wallet.import_container(tmp_path / "copy.dw", raw, PASSWORD)
    assert imported.export_container() == raw
    assert imported.public_key == active
    assert imported.pending_signing_public_key == pending
    transport.remote_envelope = bundle.finalize()
    for environment in (None, "different"):
        wrong = RegistryAdapter(transport, registry_environment=environment)
        assert wrong.confirm_owner_key_rotation(permit.intent) is None
        with pytest.raises(RotationInProgress):
            imported.cancel_signing_key_rotation()
    confirmation = RegistryAdapter(
        transport, registry_environment="testnet"
    ).confirm_owner_key_rotation(permit.intent)
    assert confirmation is not None
    assert imported.finalize_signing_key_rotation(confirmation) == pending
    assert len(transport.writes) == 1  # fixture genesis only; confirmation is read-only
    for wallet in [*wallets.values(), imported]:
        wallet.lock()


def test_preparation_rejects_missing_or_different_adapter_environment_before_consent(
    tmp_path,
):
    wallets, _, _, _, bundle, _, _, _, transport = make_legacy_rotation_bundle(tmp_path)
    for environment in (None, "different"):
        adapter = RegistryAdapter(transport, registry_environment=environment)
        result = adapter.prepare_owner_key_rotation_publication(
            bundle,
            consent=lambda _: pytest.fail("must not ask consent"),
            authenticated_origin="https://wallet.example",
            environment="testnet",
            purpose="rotation",
            capability="identity.rotate",
            expires_at=EXPIRY,
            replay_nonce=b"wrong-environment",
        )
        assert result.status is PublishStatus.FAILED
    for wallet in wallets.values():
        wallet.lock()


def test_transport_environment_mismatch_stops_preparation_and_dispatch_before_rpc(
    tmp_path,
):
    wallets, owner, _, _, bundle, _, _, adapter, transport = (
        make_legacy_rotation_bundle(tmp_path)
    )
    transport.registry_environment = "other"
    result = adapter.prepare_owner_key_rotation_publication(
        bundle,
        consent=lambda _: pytest.fail("must not ask consent"),
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="rotation",
        capability="identity.rotate",
        expires_at=EXPIRY,
        replay_nonce=b"bad-config",
    )
    assert result.status is PublishStatus.FAILED
    transport.registry_environment = "testnet"
    publication = prepare_rotation_publication(adapter, bundle, b"good-config")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    transport.registry_environment = "other"
    transport.get_identity_envelope = lambda **_: pytest.fail("must not read")
    transport.get_remote_identity_envelope = lambda **_: pytest.fail("must not read")
    assert (
        adapter.dispatch_owner_key_rotation(publication, permit).status
        is PublishStatus.UNKNOWN
    )
    assert adapter.confirm_owner_key_rotation(permit.intent) is None
    assert owner.signing_key_rotation_dispatch_intent == permit.intent
    assert len(transport.writes) == 1
    for wallet in wallets.values():
        wallet.lock()


def test_concrete_transport_has_explicit_environment_configuration(tmp_path):
    pytest.importorskip("decent_registry", reason="optional Registry transport dependency")
    from decent_wallet import RegistryTransport

    transport = RegistryTransport(
        bootstrap_peers=["/ip4/127.0.0.1/tcp/1/p2p/synthetic"],
        store_path=tmp_path / "never-opened.lmdb",
        registry_environment="testnet/é/🌍",
    )
    assert transport.registry_environment == "testnet/é/🌍"
    assert not (tmp_path / "never-opened.lmdb").exists()
    with pytest.raises(ValueError):
        RegistryTransport(
            bootstrap_peers=["/ip4/127.0.0.1/tcp/1/p2p/synthetic"],
            store_path=tmp_path / "never-opened.lmdb",
            registry_environment=" ",
        )


def test_environment_change_during_consent_does_not_prepare_capability(tmp_path):
    wallets, _, _, _, bundle, _, _, adapter, transport = make_legacy_rotation_bundle(
        tmp_path
    )
    transport.registry_environment = "testnet"

    def consent(_):
        transport.registry_environment = "other"
        return approved(_)

    result = adapter.prepare_owner_key_rotation_publication(
        bundle,
        consent=consent,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="rotation",
        capability="identity.rotate",
        expires_at=EXPIRY,
        replay_nonce=b"change-realm",
    )
    assert result.status is PublishStatus.FAILED
    assert result.publication is None
    for wallet in wallets.values():
        wallet.lock()


def test_environment_change_during_dispatch_preflight_cannot_write(tmp_path):
    wallets, owner, _, _, bundle, _, _, adapter, transport = (
        make_legacy_rotation_bundle(tmp_path)
    )
    transport.registry_environment = "testnet"
    publication = prepare_rotation_publication(adapter, bundle, b"preflight-config")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    predecessor = transport.envelope

    def read(**_):
        transport.registry_environment = "other"
        return predecessor

    transport.get_identity_envelope = read
    assert (
        adapter.dispatch_owner_key_rotation(publication, permit).status
        is PublishStatus.UNKNOWN
    )
    assert len(transport.writes) == 1
    assert owner.signing_key_rotation_dispatch_intent == permit.intent
    for wallet in wallets.values():
        wallet.lock()


@pytest.mark.parametrize("read_number", [1, 2])
def test_environment_change_during_preparation_read_cannot_prepare(
    tmp_path, read_number
):
    wallets, _, _, _, bundle, _, _, adapter, transport = make_legacy_rotation_bundle(
        tmp_path
    )
    transport.registry_environment = "testnet"
    predecessor = transport.envelope
    reads = 0

    def read(**_):
        nonlocal reads
        reads += 1
        if reads == read_number:
            transport.registry_environment = "other"
        return predecessor

    transport.get_identity_envelope = read
    result = adapter.prepare_owner_key_rotation_publication(
        bundle,
        consent=approved,
        authenticated_origin="https://wallet.example",
        environment="testnet",
        purpose="rotation",
        capability="identity.rotate",
        expires_at=EXPIRY,
        replay_nonce=b"prepare-config",
    )
    assert result.status is PublishStatus.FAILED
    assert result.publication is None
    for wallet in wallets.values():
        wallet.lock()


@pytest.mark.parametrize("during_history", [False, True])
def test_environment_change_during_confirmation_cannot_mint_authority(
    tmp_path, during_history
):
    wallets, owner, _, _, bundle, _, _, adapter, transport = (
        make_legacy_rotation_bundle(tmp_path)
    )
    transport.registry_environment = "testnet"
    publication = prepare_rotation_publication(adapter, bundle, b"confirm-config")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    transport.history[publication._previous_state.state_hash] = transport.envelope
    transport.remote_envelope = publication.envelope_bytes
    assert adapter.confirm_owner_key_rotation(permit.intent) is not None
    method = (
        transport.get_identity_envelope_by_hash
        if during_history
        else transport.get_remote_identity_envelope
    )

    def read(**kwargs):
        result = method(**kwargs)
        transport.registry_environment = "other"
        return result

    if during_history:
        transport.get_identity_envelope_by_hash = read
    else:
        transport.get_remote_identity_envelope = read
    assert adapter.confirm_owner_key_rotation(permit.intent) is None
    assert owner.signing_key_rotation_dispatch_intent == permit.intent
    assert len(transport.writes) == 1
    for wallet in wallets.values():
        wallet.lock()


@pytest.mark.parametrize("remote_outcome", ["predecessor", "candidate", "missing", "error"])
def test_expired_dispatch_realm_change_during_remote_read_retains_latch(tmp_path, monkeypatch, remote_outcome):
    wallets, owner, _, _, bundle, active, pending, adapter, transport = make_legacy_rotation_bundle(tmp_path)
    transport.registry_environment = "testnet"
    publication = prepare_rotation_publication(adapter, bundle, b"expiry-realm")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    raw = owner.export_container()
    reads = []

    def read(**_):
        reads.append(True)
        transport.registry_environment = "other"
        if remote_outcome == "error":
            raise RuntimeError("synthetic remote failure")
        return {"predecessor": transport.envelope, "candidate": publication.envelope_bytes, "missing": None}[remote_outcome]

    transport.get_remote_identity_envelope = read
    monkeypatch.setattr("decent_wallet.identity.time.time", lambda: EXPIRY)
    result = adapter.dispatch_owner_key_rotation(publication, permit)
    assert result.status is PublishStatus.UNKNOWN
    assert result.rejection is None
    assert result.confirmation is None
    assert owner.public_key == active
    assert owner.pending_signing_public_key == pending
    assert owner.signing_key_rotation_dispatch_intent == permit.intent
    assert owner.export_container() == raw
    assert adapter.confirm_owner_key_rotation(permit.intent) is None
    with pytest.raises(InvalidIdentityRequest):
        adapter.dispatch_owner_key_rotation(publication, permit)
    assert reads == [True]
    assert len(transport.writes) == 1
    for wallet in wallets.values():
        wallet.lock()


@pytest.mark.parametrize("branch", ["stale", "error", "expired"])
@pytest.mark.parametrize("realm", ["other", None])
def test_preflight_mismatch_branches_never_make_rejection_rpc(tmp_path, monkeypatch, branch, realm):
    wallets, owner, _, _, bundle, active, pending, adapter, transport = make_legacy_rotation_bundle(tmp_path)
    transport.registry_environment = "testnet"
    publication = prepare_rotation_publication(adapter, bundle, b"preflight-branch")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    raw = owner.export_container()
    predecessor = transport.envelope
    calls = []

    def local(**_):
        calls.append("local")
        transport.registry_environment = realm
        if branch == "error":
            raise RuntimeError("synthetic read failure")
        return None if branch == "stale" else predecessor

    transport.get_identity_envelope = local
    transport.get_remote_identity_envelope = lambda **_: pytest.fail("known mismatch must not read remote")
    if branch == "expired":
        monkeypatch.setattr("decent_wallet.identity.time.time", lambda: EXPIRY)
    result = adapter.dispatch_owner_key_rotation(publication, permit)
    assert result.status is PublishStatus.UNKNOWN
    assert result.rejection is None and result.confirmation is None
    assert owner.export_container() == raw
    assert owner.public_key == active and owner.pending_signing_public_key == pending
    assert owner.signing_key_rotation_dispatch_intent == permit.intent
    with pytest.raises(InvalidIdentityRequest):
        adapter.dispatch_owner_key_rotation(publication, permit)
    assert calls == ["local"]
    assert len(transport.writes) == 1
    for wallet in wallets.values():
        wallet.lock()


def legacy_wallet(tmp_path):
    wallets, owner, _, _, bundle, active, pending, adapter, transport = (
        make_legacy_rotation_bundle(tmp_path)
    )
    owner.update_payload({"synthetic_metadata": ["preserve", 42]})
    publication = prepare_rotation_publication(adapter, bundle, b"legacy-setup")
    owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    payload = dict(owner._payload)
    payload["rotation_dispatch_intent"] = dict(payload["rotation_dispatch_intent"])
    payload["rotation_dispatch_intent"].pop("environment")
    envelope = owner._build_envelope(payload)
    owner._persist_envelope(envelope)
    owner.lock()
    return (
        wallets,
        Wallet.open(tmp_path / "alice.dw", PASSWORD),
        bundle,
        active,
        pending,
        transport,
    )


def test_legacy_exact_transfer_explicit_local_binding_and_readonly_recovery(tmp_path):
    wallets, owner, bundle, active, pending, transport = legacy_wallet(tmp_path)
    legacy = owner.signing_key_rotation_dispatch_intent
    assert legacy is not None
    raw = owner.export_container()
    before_payload = dict(owner._payload)
    imported = Wallet.import_container(tmp_path / "legacy-copy.dw", raw, PASSWORD)
    assert imported.export_container() == raw
    adapter = RegistryAdapter(transport, registry_environment="testnet")
    transport.remote_envelope = bundle.finalize()
    transport.get_remote_identity_envelope = lambda **_: pytest.fail(
        "unbound must not read"
    )
    assert adapter.confirm_owner_key_rotation(legacy) is None
    with pytest.raises(RotationInProgress):
        imported.create_signer()
    with pytest.raises(InvalidIdentityRequest):
        imported.bind_legacy_rotation_dispatch_environment(
            "testnet", consent=lambda *_: False
        )
    assert imported.export_container() == raw
    bound = imported.bind_legacy_rotation_dispatch_environment(
        "testnet",
        consent=lambda intent, environment: (
            intent == legacy and environment == "testnet"
        ),
    )
    assert bound == replace(legacy, environment="testnet")
    assert imported.public_key == active
    assert imported.pending_signing_public_key == pending
    assert imported.signing_key_rotation_dispatch_intent == bound
    assert imported._payload["synthetic_metadata"] == ["preserve", 42]
    import decent_wallet.container as c
    expected_payload = dict(before_payload, rotation_dispatch_intent=dict(before_payload["rotation_dispatch_intent"], environment="testnet"))
    assert c._canonical_json(c._encode_value(imported._payload)) == c._canonical_json(c._encode_value(expected_payload))
    with pytest.raises(InvalidContainer):
        imported.update_payload({"rotation_dispatch_intent": legacy._to_payload()})
    for environment in ("testnet", "other"):
        with pytest.raises(InvalidIdentityRequest):
            imported.bind_legacy_rotation_dispatch_environment(
                environment, consent=lambda *_: True
            )
    assert len(transport.writes) == 1
    transport.get_remote_identity_envelope = lambda **_: bundle.finalize()
    confirmation = adapter.confirm_owner_key_rotation(bound)
    assert confirmation is not None
    assert imported.finalize_signing_key_rotation(confirmation) == pending
    for wallet in [*wallets.values(), owner, imported]:
        wallet.lock()


@pytest.mark.parametrize("unbound", [True, False])
def test_unbound_or_mismatched_confirmation_installs_ordinary_adapter_gates(tmp_path, unbound):
    from decent_wallet import IdentityBundle

    wallets, owner, _, _, bundle, active, _, adapter, transport = make_legacy_rotation_bundle(tmp_path)
    ordinary = adapter.create_draft(owner_name=bundle.draft.owner_name, owner_public_key=active)
    common = dict(authenticated_origin="https://wallet.example", environment="testnet", purpose="ordinary update", capability="identity.write", expires_at=EXPIRY)
    submission = adapter.sign_draft(draft=ordinary, signer_public_key=active, signer_factory=owner.create_signer, consent=approved, replay_nonce=b"before-latch", **common)
    ordinary_bundle = IdentityBundle.from_submission(submission)
    publication = prepare_rotation_publication(adapter, bundle, b"gate-setup")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    intent = replace(permit.intent, environment=None if unbound else "other")
    fresh = RegistryAdapter(transport, registry_environment="testnet")
    transport.get_remote_identity_envelope = lambda **_: pytest.fail("must not read")
    assert fresh.confirm_owner_key_rotation(intent) is None
    with pytest.raises(InvalidIdentityRequest):
        fresh.sign_draft(draft=ordinary, signer_public_key=active, signer_factory=lambda: pytest.fail("must not create signer"), consent=lambda _: pytest.fail("must not ask consent"), replay_nonce=b"blocked-sign", **common)
    result = fresh.publish_bundle(ordinary_bundle, consent=lambda _: pytest.fail("must not ask consent"), replay_nonce=b"blocked-publish", **common)
    assert result.status is PublishStatus.FAILED
    assert len(transport.writes) == 1
    for wallet in wallets.values():
        wallet.lock()


def test_legacy_binding_unknown_storage_outcome_locks_session(tmp_path, monkeypatch):
    from decent_wallet import StorageOutcomeUnknown, WalletLockedError

    wallets, owner, _, _, _, _ = legacy_wallet(tmp_path)
    import decent_wallet.container as c

    retained = [
        owner._dek,
        c._WALLET_SECRETS[owner._secret_handle],
        c._PENDING_WALLET_SECRETS[owner._secret_handle],
    ]

    def fail(*_args, **_kwargs):
        raise StorageOutcomeUnknown()

    # Reuse the atomic-write outcome boundary, not a new production fault API.
    monkeypatch.setattr("decent_wallet.container._atomic_write", fail)
    with pytest.raises(StorageOutcomeUnknown):
        owner.bind_legacy_rotation_dispatch_environment(
            "testnet", consent=lambda *_: True
        )
    with pytest.raises(WalletLockedError):
        owner.export_container()
    assert all(not any(buffer) for buffer in retained)
    for wallet in wallets.values():
        wallet.lock()


def shared_vector_transport():
    from test_multisig import MemoryTransport

    vector = json.loads(
        (
            Path(__file__).parent / "vectors/identity-owner-key-rotation-legacy.json"
        ).read_text()
    )
    transport = MemoryTransport()
    transport.remote_envelope = bytes.fromhex(vector["candidate_envelope_cbor_hex"])
    transport.history[bytes.fromhex(vector["predecessor_state_hash_hex"])] = (
        bytes.fromhex(vector["predecessor_envelope_cbor_hex"])
    )
    return vector, transport


@pytest.mark.parametrize("legacy", [False, True])
def test_shared_encrypted_latch_vector_exact_transfer_and_matching_recovery(
    tmp_path, legacy
):
    fixture = json.loads(
        (
            Path(__file__).parent / "vectors/wallet-v2-portable-rotation-latch.json"
        ).read_text()
    )
    raw = base64.b64decode(
        fixture[
            "legacy_unbound_container_base64"
            if legacy
            else "python_bound_container_base64"
        ]
    )
    wallet = Wallet.import_container(tmp_path / "vector.dw", raw, PASSWORD)
    try:
        assert wallet.export_container() == raw
        intent = wallet.signing_key_rotation_dispatch_intent
        assert intent is not None
        assert intent.environment == (None if legacy else "testnet")
        vector, transport = shared_vector_transport()
        with pytest.raises(RotationInProgress):
            wallet.cancel_signing_key_rotation()
        wrong = RegistryAdapter(transport, registry_environment="other")
        assert wrong.confirm_owner_key_rotation(intent) is None
        if legacy:
            adapter = RegistryAdapter(transport, registry_environment="testnet")
            assert adapter.confirm_owner_key_rotation(intent) is None
            sibling_confirmation = RegistryAdapter(
                transport, registry_environment="testnet"
            ).confirm_owner_key_rotation(replace(intent, environment="testnet"))
            assert sibling_confirmation is not None
            with pytest.raises(InvalidIdentityRequest):
                wallet.finalize_signing_key_rotation(sibling_confirmation)
            assert wallet.export_container() == raw
            intent = wallet.bind_legacy_rotation_dispatch_environment(
                "testnet", consent=lambda *_: True
            )
        good = RegistryAdapter(transport, registry_environment="testnet")
        exact = transport.remote_envelope
        assert exact is not None
        transport.remote_envelope = exact + b"\x00"
        assert good.confirm_owner_key_rotation(intent) is None
        transport.remote_envelope = exact
        history = transport.history
        transport.history = {}
        assert good.confirm_owner_key_rotation(intent) is None
        transport.history = history
        confirmation = good.confirm_owner_key_rotation(intent)
        assert confirmation is not None
        assert wallet.finalize_signing_key_rotation(confirmation) == bytes.fromhex(
            vector["successor_owner_public_key_hex"]
        )
        assert not transport.writes
    finally:
        wallet.lock()
    promoted = Wallet.open(tmp_path / "vector.dw", PASSWORD)
    try:
        assert promoted.public_key == bytes.fromhex(
            vector["successor_owner_public_key_hex"]
        )
        assert promoted.pending_signing_public_key is None
        assert promoted.signing_key_rotation_dispatch_intent is None
    finally:
        promoted.lock()


@pytest.mark.parametrize(
    "filename, legacy", [("kotlin-bound.dw", False), ("kotlin-legacy.dw", True)]
)
def test_actual_kotlin_authored_ciphertext_through_python_public_reader(
    tmp_path, filename, legacy
):
    directory = os.environ.get("PORTABLE_LATCH_ARTIFACT_DIR")
    if directory is None:
        pytest.skip("opt-in host-JVM authored ciphertext consumer")
    raw = (Path(directory) / filename).read_bytes()
    wallet = Wallet.import_container(tmp_path / filename, raw, PASSWORD)
    try:
        assert wallet.export_container() == raw
        intent = wallet.signing_key_rotation_dispatch_intent
        assert intent is not None
        assert intent.environment == (None if legacy else "testnet")
        assert wallet.public_key == intent.predecessor_owner_public_key
        assert wallet.pending_signing_public_key == intent.successor_owner_public_key
        with pytest.raises(RotationInProgress):
            wallet.prepare_signing_key_rotation()
        _, transport = shared_vector_transport()
        if legacy:
            adapter = RegistryAdapter(transport, registry_environment="testnet")
            assert adapter.confirm_owner_key_rotation(intent) is None
            sibling_confirmation = RegistryAdapter(
                transport, registry_environment="testnet"
            ).confirm_owner_key_rotation(replace(intent, environment="testnet"))
            assert sibling_confirmation is not None
            with pytest.raises(InvalidIdentityRequest):
                wallet.finalize_signing_key_rotation(sibling_confirmation)
            assert wallet.export_container() == raw
            intent = wallet.bind_legacy_rotation_dispatch_environment(
                "testnet", consent=lambda *_: True
            )
        confirmation = RegistryAdapter(
            transport, registry_environment="testnet"
        ).confirm_owner_key_rotation(intent)
        assert confirmation is not None
        wallet.finalize_signing_key_rotation(confirmation)
        assert not transport.writes
    finally:
        wallet.lock()
    promoted = Wallet.open(tmp_path / filename, PASSWORD)
    try:
        assert promoted.public_key == intent.successor_owner_public_key
        assert promoted.pending_signing_public_key is None
        assert promoted.signing_key_rotation_dispatch_intent is None
    finally:
        promoted.lock()


@pytest.mark.parametrize(
    "environment, valid",
    [
        ("é", True),
        ("testnet/🌍", True),
        ("🌍" * 128, True),
        ("a ", True),
        ("a\u0085", True),
        (None, False),
        ("", False),
        ("\u0085\u00a0\u2007\u202f", False),
        ("🌍" * 129, False),
        ("\ud800", False),
    ],
)
def test_environment_exact_unicode_utf16_contract(environment, valid):
    from decent_wallet.container import valid_registry_environment

    assert valid_registry_environment(environment) is valid


@pytest.mark.parametrize(
    "fault",
    [
        "missing-active",
        "missing-pending",
        "partial-pending",
        "seed-mismatch",
        "equal",
        "predecessor",
        "successor",
        "unknown-field",
        "null-environment",
        *[f"{field}:{kind}" for field in (
            "private_seed", "public_key", "pending_private_seed", "pending_public_key",
            "predecessor_owner_public_key", "successor_owner_public_key",
            "predecessor_state_hash", "envelope_hash",
        ) for kind in ("short", "long", "type")],
        "owner:invalid-utf8", "owner:empty", "owner:oversize",
        "sequence:bool", "sequence:zero", "sequence:negative", "sequence:string", "sequence:float",
    ],
)
def test_public_readers_eagerly_reject_broken_latch_payload(tmp_path, fault):
    import decent_wallet.container as c

    fixture = json.loads(
        (
            Path(__file__).parent / "vectors/wallet-v2-portable-rotation-latch.json"
        ).read_text()
    )
    raw = base64.b64decode(fixture["python_bound_container_base64"])
    envelope = c._parse_container(raw)
    dek, payload = c._unlock_envelope(envelope, PASSWORD)
    try:
        intent = payload["rotation_dispatch_intent"]
        if fault == "missing-active":
            payload.pop("private_seed")
            payload.pop("public_key")
        elif fault == "missing-pending":
            payload.pop("pending_private_seed")
            payload.pop("pending_public_key")
        elif fault == "partial-pending":
            payload.pop("pending_public_key")
        elif fault == "seed-mismatch":
            payload["pending_private_seed"] = b"x" * 32
        elif fault == "equal":
            payload["pending_private_seed"] = payload["private_seed"]
            payload["pending_public_key"] = payload["public_key"]
        elif fault == "predecessor":
            intent["predecessor_owner_public_key"] = b"x" * 32
        elif fault == "successor":
            intent["successor_owner_public_key"] = b"x" * 32
        elif fault == "unknown-field":
            intent["unknown"] = True
        elif fault == "null-environment":
            intent["environment"] = None
        else:
            field, kind = fault.split(":")
            if field == "owner":
                intent["owner_name"] = {"invalid-utf8": b"\xff", "empty": b"", "oversize": b"x" * 1_048_577}[kind]
            elif field == "sequence":
                intent["sequence"] = {"bool": True, "zero": 0, "negative": -1, "string": "2", "float": 2}[kind]
            else:
                target = payload if field in payload else intent
                target[field] = {"short": b"x" * 31, "long": b"x" * 33, "type": "not-bytes"}[kind]
        if fault == "sequence:float":
            # Authenticated low-level typed JSON; production writer deliberately forbids floats.
            from Crypto.Cipher import ChaCha20_Poly1305
            typed = c._encode_value(payload)
            latch_typed = dict(typed["v"])["rotation_dispatch_intent"]
            dict(latch_typed["v"])["sequence"]["v"] = 2.5
            info = {key: envelope["payload"][key] for key in ("algorithm", "nonce")}
            cipher = ChaCha20_Poly1305.new(key=bytes(dek), nonce=c._b64_decode(info["nonce"]))
            cipher.update(c._payload_aad(info))
            ciphertext, tag = cipher.encrypt_and_digest(c._canonical_json(typed))
            envelope["payload"] = dict(info, ciphertext=c._b64_encode(ciphertext), tag=c._b64_encode(tag))
            bad = c._serialize(envelope)
        else:
            bad = c._serialize(c._build_v2_envelope(PASSWORD, bytes(dek), envelope["kdf"], payload))
        path = tmp_path / "invalid.dw"
        path.write_bytes(bad)
        with pytest.raises(InvalidContainer):
            Wallet.open(path, PASSWORD)
        assert path.read_bytes() == bad
        with pytest.raises(InvalidContainer):
            Wallet.import_container(tmp_path / "destination.dw", bad, PASSWORD)
        assert not (tmp_path / "destination.dw").exists()
    finally:
        c._wipe(dek)


@pytest.mark.parametrize("post_replace", [False, True])
def test_binding_recoverable_storage_failures_keep_legacy_keys_and_bytes(
    tmp_path, monkeypatch, post_replace
):
    import decent_wallet.container as c
    from decent_wallet import StorageFailure

    wallets, owner, _, active, pending, transport = legacy_wallet(tmp_path)
    raw = owner.export_container()
    if post_replace:
        original = c._fsync_directory
        calls = []

        def fail_once(directory):
            calls.append(directory)
            if len(calls) == 1:
                raise OSError("synthetic sync failure")
            original(directory)

        monkeypatch.setattr(c, "_fsync_directory", fail_once)
    else:

        def fail(*_args, **_kwargs):
            raise OSError("synthetic preinstall failure")

        monkeypatch.setattr(c, "_stage_file", fail)
    with pytest.raises(StorageFailure):
        owner.bind_legacy_rotation_dispatch_environment(
            "testnet", consent=lambda *_: True
        )
    assert owner.export_container() == raw
    assert owner.public_key == active
    assert owner.pending_signing_public_key == pending
    assert owner.signing_key_rotation_dispatch_intent.environment is None
    assert len(transport.writes) == 1
    for wallet in [*wallets.values(), owner]:
        wallet.lock()


@pytest.mark.parametrize("source", ["python", "kotlin"])
def test_large_positive_integer_real_encrypted_public_readers(tmp_path, source):
    fixture = json.loads((Path(__file__).parent / "vectors/wallet-v2-portable-rotation-latch.json").read_text())
    if source == "kotlin":
        directory = os.environ.get("PORTABLE_LATCH_ARTIFACT_DIR")
        if directory is None:
            pytest.skip("opt-in host-JVM authored ciphertext consumer")
        raw = (Path(directory) / "kotlin-bignum.dw").read_bytes()
    else:
        raw = base64.b64decode(fixture["python_bignum_container_base64"])
    expected = int(fixture["large_positive_sequence_decimal"])
    path = tmp_path / "large.dw"
    wallet = Wallet.import_container(path, raw, PASSWORD)
    try:
        intent = wallet.signing_key_rotation_dispatch_intent
        assert intent is not None
        assert intent.sequence == expected
        assert wallet.export_container() == raw
        assert wallet.public_key == intent.predecessor_owner_public_key
        assert wallet.pending_signing_public_key == intent.successor_owner_public_key
    finally:
        wallet.lock()
    reopened = Wallet.open(path, PASSWORD)
    try:
        intent = reopened.signing_key_rotation_dispatch_intent
        assert intent is not None
        assert intent.sequence == expected
        assert reopened.export_container() == raw
    finally:
        reopened.lock()


def legacy_payload():
    return {
        "owner_name": b"portable-owner",
        "predecessor_owner_public_key": b"a" * 32,
        "successor_owner_public_key": b"b" * 32,
        "predecessor_state_hash": b"c" * 32,
        "sequence": 2,
        "envelope_hash": b"d" * 32,
    }


def test_current_seven_field_intent_preserves_exact_environment():
    payload = dict(legacy_payload(), environment="testnet/é/🌍")
    intent = RotationDispatchIntent._from_payload(payload)
    assert intent.environment == payload["environment"]
    assert intent._to_payload() == payload
    assert intent != replace(intent, environment="other")


@pytest.mark.parametrize("environment", [None, "", " \t\n", "x" * 257, "\ud800", 42])
def test_present_environment_must_be_valid(environment):
    with pytest.raises(InvalidContainer):
        RotationDispatchIntent._from_payload(
            dict(legacy_payload(), environment=environment)
        )


def test_legacy_six_field_intent_stays_unbound():
    intent = RotationDispatchIntent._from_payload(legacy_payload())
    assert intent.environment is None
    assert intent._to_payload() == legacy_payload()
    with pytest.raises(InvalidContainer):
        RotationDispatchIntent._from_payload(dict(legacy_payload(), unknown=True))

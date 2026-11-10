"""Approval lifecycle regressions using public synthetic wallets only."""
from __future__ import annotations

import base64
import json
from dataclasses import replace

import pytest

from decent_wallet import RotationInProgress, Wallet
from test_account_disclosure_lifecycle import (
    GIVEN, HANDLE, IDENTITY_ID, LOGIN_VECTOR, _approved_wallet,
    context_for_handle, continuation_artifacts,
)

NOW = 1_800_000_001
PASSWORD = "correct horse battery"
CHALLENGE = base64.urlsafe_b64encode(b"c" * 32).decode().rstrip("=")


@pytest.fixture(autouse=True)
def deterministic_clock(monkeypatch):
    monkeypatch.setattr("decent_wallet.container.time.time", lambda: NOW)


def _approve(wallet):
    wallet.set_master_account_entity({"given_name": "Ada"})
    context = context_for_handle()
    review = wallet.review_account_disclosure(context, HANDLE, IDENTITY_ID)
    pending = wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _: True)
    return pending, context


def _prepare(wallet, pending, artifacts):
    binding, jwks, outer, request, registration = artifacts
    return wallet.prepare_account_presentation(
        pending, binding_jws=binding, keycloak_jwks=jwks, outer_request=outer,
        request_object=request, registration=registration,
    )


def _accepted_response(uri):
    return json.dumps({"redirect_uri": uri}, separators=(",", ":")).encode()


@pytest.mark.parametrize(("status", "content_type", "body"), [
    (201, "application/json", _accepted_response("https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")),
    (200, "text/application/json", _accepted_response("https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")),
    (200, "application/jsonp", _accepted_response("https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")),
    (200, "application/json; charset", _accepted_response("https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")),
    (200, "application/json", b'{"redirect_uri":'),
    (200, "application/json", b'{"redirect_uri":"https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE","redirect_uri":"https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"}'),
    (200, "application/json", b" " * (16 * 1024 + 1)),
    (200, "application/json", _accepted_response("http://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")),
    (200, "application/json", _accepted_response("https://evil.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")),
    (200, "application/json", _accepted_response("https://site.example.test/callback?x=1#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")),
    (200, "application/json", _accepted_response("https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE&extra=1")),
    (200, "application/json", _accepted_response("https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE&response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE")),
    (200, "application/json", _accepted_response("https://site.example.test/callback#response_code=short")),
])
def test_invalid_direct_post_acceptance_gate_retains_only_ambiguous_exact_retry(tmp_path, status, content_type, body):
    from decent_wallet import PresentationDeliveryOutcome

    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    submission = _prepare(wallet, pending, continuation_artifacts(context, wallet.public_key, NOW))
    committed = (tmp_path / "wallet.json").read_bytes()
    with pytest.raises(ValueError):
        wallet.finish_account_presentation(
            pending, PresentationDeliveryOutcome.ACCEPTED, status_code=status,
            content_type=content_type, response_body=body,
        )
    assert (tmp_path / "wallet.json").read_bytes() == committed
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    retry = wallet.get_account_presentation_retry(pending)
    assert (retry.response_uri, retry.state, retry.presentation_jws, retry.body) == (
        submission.response_uri, submission.state, submission.presentation_jws, submission.body,
    )
    wallet.lock()


def test_valid_direct_post_acceptance_allows_exact_json_media_type_parameters(tmp_path):
    from decent_wallet import PresentationDeliveryOutcome

    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    _prepare(wallet, pending, continuation_artifacts(context, wallet.public_key, NOW))
    wallet.finish_account_presentation(
        pending, PresentationDeliveryOutcome.ACCEPTED, status_code=200,
        content_type="Application/JSON; charset=utf-8",
        response_body=_accepted_response("https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"),
    )
    with pytest.raises(ValueError):
        wallet.get_account_presentation_retry(pending)
    wallet.lock()


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("reopen", [False, True])
@pytest.mark.parametrize("stage", ["proof", "presentation", "retry"])
def test_rotation_latch_blocks_every_disclosure_release(tmp_path, legacy, reopen, stage):
    from test_multisig import make_legacy_rotation_bundle, prepare_rotation_publication, PASSWORD as ROTATION_PASSWORD
    from decent_wallet import PresentationDeliveryOutcome

    wallets, owner, _, _, bundle, _, _, adapter, _ = make_legacy_rotation_bundle(tmp_path)
    pending, context = _approve(owner)
    artifacts = continuation_artifacts(context, owner.public_key, NOW)
    if stage != "proof":
        owner.create_account_login_proof(pending, challenge=CHALLENGE)
    if stage == "retry":
        _prepare(owner, pending, artifacts)
        owner.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    publication = prepare_rotation_publication(adapter, bundle, b"disclosure-latch")
    owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    if legacy:
        # Explicit pre-amendment encrypted test fixture, as in portable-latch tests.
        payload = dict(owner._payload)
        payload["rotation_dispatch_intent"] = dict(payload["rotation_dispatch_intent"])
        payload["rotation_dispatch_intent"].pop("environment")
        envelope = owner._build_envelope(payload)
        owner._persist_envelope(envelope)
        owner._payload, owner._envelope = payload, envelope
    if reopen:
        owner.lock()
        owner = Wallet.open(tmp_path / "alice.dw", ROTATION_PASSWORD)
    with pytest.raises(RotationInProgress):
        if stage == "proof":
            owner.create_account_login_proof(pending, challenge=CHALLENGE)
        elif stage == "presentation":
            _prepare(owner, pending, artifacts)
        else:
            owner.get_account_presentation_retry(pending)
    owner.lock()
    for wallet in wallets.values():
        wallet.lock()


def _session_race(path, pending, artifacts, barrier, results, stage):
    from unittest.mock import patch
    from decent_wallet import WalletError
    with patch("decent_wallet.container.time.time", return_value=NOW):
        wallet = Wallet.open(path, PASSWORD)
        barrier.wait(timeout=15)
        try:
            if stage == "proof":
                wallet.create_account_login_proof(pending, challenge=CHALLENGE)
            else:
                _prepare(wallet, pending, artifacts)
            results.put(True)
        except (WalletError, ValueError):
            results.put(False)
        finally:
            wallet.lock()


@pytest.mark.parametrize("processes", [False, True])
@pytest.mark.parametrize("stage", ["proof", "presentation"])
def test_one_use_across_independently_opened_sessions_and_processes(tmp_path, processes, stage):
    import multiprocessing
    from queue import Queue
    from threading import Barrier, Thread
    wallet, pending, context = _approved_wallet(tmp_path)
    artifacts = continuation_artifacts(context, wallet.public_key, NOW)
    if stage == "presentation":
        wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    wallet.lock()
    if processes:
        runtime = multiprocessing.get_context("spawn")
        barrier, results, worker = runtime.Barrier(2), runtime.Queue(), runtime.Process
    else:
        barrier, results, worker = Barrier(2), Queue(), Thread
    workers = [worker(target=_session_race, args=(tmp_path / "wallet.json", pending, artifacts, barrier, results, stage)) for _ in range(2)]
    for item in workers:
        item.start()
    for item in workers:
        item.join(timeout=20)
        assert not item.is_alive()
        if processes:
            assert item.exitcode == 0
    assert sorted([results.get(timeout=2), results.get(timeout=2)]) == [False, True]


@pytest.mark.parametrize("writer", ["update", "password", "entity", "rotation"])
def test_stale_generic_writers_cannot_resurrect_consumed_approval(tmp_path, writer):
    from decent_wallet import StorageFailure
    wallet, pending, _ = _approved_wallet(tmp_path)
    stale = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    wallet.cancel_account_disclosure(pending)
    durable = (tmp_path / "wallet.json").read_bytes()
    with pytest.raises(StorageFailure):
        if writer == "update":
            stale.update_payload({"note": "synthetic"})
        elif writer == "password":
            stale.change_password("another correct horse battery", "another correct horse battery")
        elif writer == "entity":
            stale.set_master_account_entity({"given_name": "Grace"})
        else:
            stale.prepare_signing_key_rotation()
    assert not stale.is_unlocked
    assert (tmp_path / "wallet.json").read_bytes() == durable
    reopened = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    with pytest.raises(ValueError):
        reopened.create_account_login_proof(pending, challenge=CHALLENGE)
    reopened.lock()
    wallet.lock()


def test_stale_retry_never_releases_bytes_after_terminal_consumption(tmp_path):
    from decent_wallet import PresentationDeliveryOutcome, StorageFailure
    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    _prepare(wallet, pending, continuation_artifacts(context, wallet.public_key, NOW))
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    stale = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.CANCELLED)
    with pytest.raises(StorageFailure):
        stale.get_account_presentation_retry(pending)
    assert not stale.is_unlocked
    wallet.lock()


@pytest.mark.parametrize("operation", ["retry", "finish"])
def test_minimum_submission_expiry_clears_pending_not_just_approval_ttl(tmp_path, monkeypatch, operation):
    from decent_wallet import PresentationDeliveryOutcome
    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    submission = _prepare(wallet, pending, continuation_artifacts(context, wallet.public_key, NOW - 100))
    payload = json.loads(base64.urlsafe_b64decode(submission.presentation_jws.split(".")[1] + "=="))
    assert payload["exp"] == NOW + 199 < pending.expires_at
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    wallet.lock()
    reopened = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    before_retry = (tmp_path / "wallet.json").read_bytes()
    monkeypatch.setattr("decent_wallet.container.time.time", lambda: NOW + 198)
    assert reopened.get_account_presentation_retry(pending).body == submission.body
    assert (tmp_path / "wallet.json").read_bytes() == before_retry
    monkeypatch.setattr("decent_wallet.container.time.time", lambda: NOW + 199)
    with pytest.raises(ValueError):
        if operation == "retry":
            reopened.get_account_presentation_retry(pending)
        else:
            reopened.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    assert reopened.export_container()  # expired approved values durably removed
    reopened.lock()
    again = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    assert again.export_container()
    with pytest.raises(ValueError):
        again.get_account_presentation_retry(pending)
    again.lock()


def test_crash_after_prepare_before_host_outcome_recovers_only_exact_bytes(tmp_path):
    from decent_wallet import PresentationDeliveryOutcome
    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    artifacts = continuation_artifacts(context, wallet.public_key, NOW)
    original = _prepare(wallet, pending, artifacts)
    wallet.lock()  # process lost before sending or recording any outcome
    reopened = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    with pytest.raises(ValueError):
        reopened.get_account_presentation_retry(pending)
    with pytest.raises(ValueError):
        _prepare(reopened, pending, artifacts)
    reopened.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    retry = reopened.get_account_presentation_retry(pending)
    assert (retry.presentation_jws, retry.body, retry.response_uri, retry.state) == (
        original.presentation_jws, original.body, original.response_uri, original.state,
    )
    reopened.lock()


@pytest.mark.parametrize("field", ["rp_client_id", "rp_origin", "action", "purpose", "claims", "identity_id"])
def test_caller_modified_review_is_not_consent_authority(tmp_path, field):
    from decent_wallet.account_disclosure import RequestedAccountClaim
    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.cancel_account_disclosure(pending)
    review = wallet.review_account_disclosure(context, HANDLE, IDENTITY_ID)
    if field == "identity_id":
        changed = replace(review, identity_id="mailto:someone-else@example.test")
    else:
        value = {"rp_client_id": "other-client", "rp_origin": "https://other.example.test",
                 "action": "signup_recovery", "purpose": "Another purpose",
                 "claims": (RequestedAccountClaim(GIVEN, True),)}[field]
        changed = replace(review, context=replace(context, **{field: value}))
    with pytest.raises(ValueError):
        wallet.approve_account_disclosure(changed, [GIVEN], consent=lambda _: True)
    wallet.approve_account_disclosure(review, [GIVEN], consent=lambda _: True)
    wallet.lock()


@pytest.mark.parametrize("fault", ["known_before", "unknown_before", "unknown_after"])
@pytest.mark.parametrize("stage", ["proof", "presentation", "ambiguous", "accepted", "cancelled", "definitive_failure"])
def test_durability_faults_never_return_artifact_and_reopen_exact_commit(tmp_path, monkeypatch, stage, fault):
    import decent_wallet.container as container
    from decent_wallet import PresentationDeliveryOutcome
    wallet, pending, context = _approved_wallet(tmp_path)
    artifacts = continuation_artifacts(context, wallet.public_key, NOW)
    original = None
    if stage != "proof":
        wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    if stage not in {"proof", "presentation"}:
        original = _prepare(wallet, pending, artifacts)
    before = (tmp_path / "wallet.json").read_bytes()
    atomic = container._atomic_write
    committed = []
    signed = []
    sign = container._sign_account_jws

    def observe_sign(*args, **kwargs):
        value = sign(*args, **kwargs)
        signed.append(value)
        return value

    def fail(path, data, **kwargs):
        if fault == "unknown_after":
            atomic(path, data, **kwargs)
            committed.append(data)
        raise container.StorageFailure() if fault == "known_before" else container.StorageOutcomeUnknown()

    monkeypatch.setattr(container, "_atomic_write", fail)
    monkeypatch.setattr(container, "_sign_account_jws", observe_sign)
    error = container.StorageFailure if fault == "known_before" else container.StorageOutcomeUnknown
    with pytest.raises(error):
        if stage == "proof":
            wallet.create_account_login_proof(pending, challenge=CHALLENGE)
        elif stage == "presentation":
            _prepare(wallet, pending, artifacts)
        else:
            wallet.finish_account_presentation(
                pending, PresentationDeliveryOutcome(stage), status_code=200, content_type="application/json",
                response_body=b'{"redirect_uri":"https://site.example.test/callback#response_code=YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE"}',
            )
    assert wallet.is_unlocked is (fault == "known_before" and stage in {"proof", "presentation"})
    assert (tmp_path / "wallet.json").read_bytes() == (committed[0] if committed else before)
    wallet.lock()
    monkeypatch.undo()
    monkeypatch.setattr(container.time, "time", lambda: NOW)
    reopened = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    if stage == "proof":
        if committed:
            with pytest.raises(ValueError):
                reopened.create_account_login_proof(pending, challenge=CHALLENGE)
        else:
            reopened.create_account_login_proof(pending, challenge=CHALLENGE)
            with pytest.raises(ValueError):
                reopened.create_account_login_proof(pending, challenge=CHALLENGE)
    elif stage == "presentation" and not committed:
        _prepare(reopened, pending, artifacts)
        with pytest.raises(ValueError):
            _prepare(reopened, pending, artifacts)
    elif committed and stage in {"accepted", "cancelled", "definitive_failure"}:
        assert reopened.export_container()
        with pytest.raises(ValueError):
            reopened.get_account_presentation_retry(pending)
        with pytest.raises(ValueError):
            _prepare(reopened, pending, artifacts)
    else:
        # A prepared write may have committed even when the host saw no bytes.
        # Reopen never re-signs: explicitly classify the interrupted send unknown.
        with pytest.raises(ValueError):
            _prepare(reopened, pending, artifacts)
        reopened.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
        monkeypatch.setattr(container, "_sign_account_jws", lambda *_a: pytest.fail("retry must not sign"))
        retry = reopened.get_account_presentation_retry(pending)
        assert retry.presentation_jws == (signed[-1] if stage == "presentation" else original.presentation_jws)
        if original:
            assert (retry.body, retry.response_uri, retry.state) == (original.body, original.response_uri, original.state)
        with pytest.raises(ValueError):
            _prepare(reopened, pending, artifacts)
    reopened.lock()


@pytest.mark.parametrize("writer", ["latch", "cancel", "finalize", "reject", "bind"])
def test_every_rotation_writer_rejects_stale_approved_snapshot(tmp_path, writer):
    from test_multisig import make_legacy_rotation_bundle, prepare_rotation_publication, PASSWORD as RPASSWORD
    from decent_wallet import StorageFailure
    wallets, owner, _, _, bundle, _, _, adapter, transport = make_legacy_rotation_bundle(tmp_path)
    pending, _ = _approve(owner)
    publication = prepare_rotation_publication(adapter, bundle, b"stale-writer")
    operation_arg = None
    if writer not in {"latch", "cancel"}:
        permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
        if writer == "finalize":
            transport.remote_envelope = bundle.finalize()
            operation_arg = adapter.confirm_owner_key_rotation(permit.intent)
            assert operation_arg is not None
        elif writer == "reject":
            transport.reject_expired = True
            operation_arg = adapter.dispatch_owner_key_rotation(publication, permit).rejection
            assert operation_arg is not None
        else:
            payload = dict(owner._payload)
            payload["rotation_dispatch_intent"] = dict(payload["rotation_dispatch_intent"])
            payload["rotation_dispatch_intent"].pop("environment")
            envelope = owner._build_envelope(payload)
            owner._persist_envelope(envelope)
            owner._payload, owner._envelope = payload, envelope
    stale = Wallet.open(tmp_path / "alice.dw", RPASSWORD)
    owner.cancel_account_disclosure(pending)
    durable = (tmp_path / "alice.dw").read_bytes()
    with pytest.raises(StorageFailure):
        if writer == "latch":
            stale.latch_signing_key_rotation_dispatch_intent(bundle, publication)
        elif writer == "cancel":
            stale.cancel_signing_key_rotation()
        elif writer == "finalize":
            stale.finalize_signing_key_rotation(operation_arg)
        elif writer == "reject":
            stale.resolve_signing_key_rotation_rejection(operation_arg)
        else:
            stale.bind_legacy_rotation_dispatch_environment("testnet", consent=lambda *_: True)
    assert not stale.is_unlocked
    assert (tmp_path / "alice.dw").read_bytes() == durable
    for wallet in wallets.values():
        wallet.lock()


@pytest.mark.parametrize("stage", ["proof", "presentation", "retry"])
@pytest.mark.parametrize("reopen", [False, True])
def test_promoted_owner_cannot_use_predecessor_approval(tmp_path, stage, reopen):
    from test_multisig import make_legacy_rotation_bundle, prepare_rotation_publication, PASSWORD as RPASSWORD
    from decent_wallet import PresentationDeliveryOutcome
    wallets, owner, _, _, bundle, active, successor, adapter, transport = make_legacy_rotation_bundle(tmp_path)
    pending, context = _approve(owner)
    artifacts = continuation_artifacts(context, active, NOW)
    if stage != "proof":
        owner.create_account_login_proof(pending, challenge=CHALLENGE)
    if stage == "retry":
        _prepare(owner, pending, artifacts)
        owner.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
    publication = prepare_rotation_publication(adapter, bundle, b"promote-approval")
    permit = owner.latch_signing_key_rotation_dispatch_intent(bundle, publication)
    transport.remote_envelope = bundle.finalize()
    confirmation = adapter.confirm_owner_key_rotation(permit.intent)
    assert owner.finalize_signing_key_rotation(confirmation) == successor
    if reopen:
        owner.lock()
        owner = Wallet.open(tmp_path / "alice.dw", RPASSWORD)
    with pytest.raises(ValueError):
        if stage == "proof":
            owner.create_account_login_proof(pending, challenge=CHALLENGE)
        elif stage == "presentation":
            _prepare(owner, pending, artifacts)
        else:
            owner.get_account_presentation_retry(pending)
    assert owner.export_container()  # Owner mismatch invalidates the predecessor's approval.
    owner.lock()
    for wallet in wallets.values():
        wallet.lock()


@pytest.mark.parametrize("operation", ["create", "import", "migrate"])
def test_initial_container_paths_require_durable_exact_readback(tmp_path, monkeypatch, operation):
    import decent_wallet.container as container
    from test_container import LEGACY_V1_FIXTURE, PASSWORD as LEGACY_PASSWORD
    from decent_wallet import StorageOutcomeUnknown
    source = Wallet.create(tmp_path / "source.dw", PASSWORD, PASSWORD, {"note": "synthetic"})
    raw = source.export_container()
    source.lock()
    target = tmp_path / "target.dw"
    if operation == "migrate":
        target.write_bytes(LEGACY_V1_FIXTURE.read_bytes())
    monkeypatch.setattr(container, "_atomic_write", lambda *_a, **_kw: None)
    with pytest.raises(StorageOutcomeUnknown):
        if operation == "create":
            Wallet.create(target, PASSWORD, PASSWORD, {"note": "synthetic"})
        elif operation == "import":
            Wallet.import_container(target, raw, PASSWORD)
        else:
            Wallet.migrate_container(target, LEGACY_PASSWORD)


@pytest.mark.parametrize("fault", ["read_error", "mismatch"])
@pytest.mark.parametrize("stage", ["proof", "presentation", "finalize"])
def test_post_commit_readback_faults_lock_without_releasing_artifacts(tmp_path, monkeypatch, fault, stage):
    import decent_wallet.container as container
    from decent_wallet import PresentationDeliveryOutcome, StorageOutcomeUnknown
    wallet, pending, context = _approved_wallet(tmp_path)
    artifacts = continuation_artifacts(context, wallet.public_key, NOW)
    if stage != "proof":
        wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    if stage == "finalize":
        _prepare(wallet, pending, artifacts)
    atomic, read = container._atomic_write, container._read
    saved = []
    def write_then_break_read(path, data, **kwargs):
        atomic(path, data, **kwargs)
        saved.append(data)
        def broken(_path):
            if fault == "read_error":
                raise container.StorageFailure()
            return b"not-the-written-container"
        monkeypatch.setattr(container, "_read", broken)
    monkeypatch.setattr(container, "_atomic_write", write_then_break_read)
    with pytest.raises(StorageOutcomeUnknown):
        if stage == "proof":
            wallet.create_account_login_proof(pending, challenge=CHALLENGE)
        elif stage == "presentation":
            _prepare(wallet, pending, artifacts)
        else:
            wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.CANCELLED)
    assert not wallet.is_unlocked
    assert (tmp_path / "wallet.json").read_bytes() == saved[0]
    monkeypatch.setattr(container, "_read", read)
    monkeypatch.setattr(container, "_atomic_write", atomic)
    reopened = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    if stage == "proof":
        with pytest.raises(ValueError):
            reopened.create_account_login_proof(pending, challenge=CHALLENGE)
    elif stage == "presentation":
        with pytest.raises(ValueError):
            _prepare(reopened, pending, artifacts)
        reopened.finish_account_presentation(pending, PresentationDeliveryOutcome.AMBIGUOUS)
        assert reopened.get_account_presentation_retry(pending).body
    else:
        assert reopened.export_container()
    reopened.lock()


@pytest.mark.parametrize("fault", ["permissions", "nonempty", "symlink", "hardlink", "unsupported", "lock_error", "timeout", "disk_read"])
def test_lock_and_revision_failures_close_session_without_artifact(tmp_path, monkeypatch, fault):
    import os
    import sys
    import fcntl
    import decent_wallet.container as container
    from decent_wallet import StorageFailure
    wallet, pending, _ = _approved_wallet(tmp_path)
    target = tmp_path / "wallet.json"
    sidecar = tmp_path / ".wallet.json.lock"
    before = target.read_bytes()
    if fault == "permissions":
        sidecar.chmod(0o644)
    elif fault == "nonempty":
        sidecar.write_bytes(b"not-empty")
    elif fault == "symlink":
        sidecar.unlink()
        sidecar.symlink_to(target)
    elif fault == "hardlink":
        sidecar.unlink()
        os.link(target, sidecar)
    elif fault == "unsupported":
        monkeypatch.setitem(sys.modules, "fcntl", None)
    elif fault in {"lock_error", "timeout"}:
        def fail(*_):
            raise OSError() if fault == "lock_error" else BlockingIOError()
        monkeypatch.setattr(fcntl, "flock", fail)
        if fault == "timeout":
            ticks = iter(range(1000))
            monkeypatch.setattr(container.time, "monotonic", lambda: next(ticks))
    else:
        monkeypatch.setattr(container, "_read", lambda *_: (_ for _ in ()).throw(StorageFailure()))
    with pytest.raises(StorageFailure):
        wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    assert not wallet.is_unlocked
    assert target.read_bytes() == before


def test_lock_sidecar_is_empty_private_and_stable_across_replacements(tmp_path):
    wallet, pending, _ = _approved_wallet(tmp_path)
    sidecar = tmp_path / ".wallet.json.lock"
    inode = sidecar.stat().st_ino
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    wallet.cancel_account_disclosure(pending)
    wallet.update_payload({"note": "synthetic"})
    wallet.change_password("another correct horse battery", "another correct horse battery")
    assert sidecar.stat().st_ino == inode
    assert sidecar.stat().st_mode & 0o777 == 0o600
    assert sidecar.read_bytes() == b""
    wallet.lock()


def test_restart_recovery_without_host_handle_is_explicit_durable_and_never_resigns(tmp_path, monkeypatch):
    import decent_wallet.container as container
    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    original = _prepare(wallet, pending, continuation_artifacts(context, wallet.public_key, NOW))
    wallet.lock()
    del pending  # host lost its in-memory DTO as well as the send outcome
    reopened = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    recover = getattr(reopened, "recover_account_presentation_retry", None)
    assert callable(recover), "unlock must allow explicit exact prepared-submission recovery"
    monkeypatch.setattr(container, "_sign_account_jws", lambda *_: pytest.fail("recovery must not sign"))
    retry = recover()
    assert (retry.body, retry.presentation_jws, retry.response_uri, retry.state) == (
        original.body, original.presentation_jws, original.response_uri, original.state,
    )
    reopened.lock()
    again = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    assert again.get_account_presentation_retry(retry.pending).body == original.body
    again.lock()


@pytest.mark.parametrize("fault", ["known_before", "unknown_before", "unknown_after"])
def test_recovery_transition_faults_return_no_bytes_and_preserve_exact_submission(tmp_path, monkeypatch, fault):
    import decent_wallet.container as container
    wallet, pending, context = _approved_wallet(tmp_path)
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    original = _prepare(wallet, pending, continuation_artifacts(context, wallet.public_key, NOW))
    wallet.lock()
    reopened = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    before = (tmp_path / "wallet.json").read_bytes()
    atomic = container._atomic_write
    written = []
    def fail(path, data, **kwargs):
        if fault == "unknown_after":
            atomic(path, data, **kwargs)
            written.append(data)
        raise container.StorageFailure() if fault == "known_before" else container.StorageOutcomeUnknown()
    monkeypatch.setattr(container, "_atomic_write", fail)
    with pytest.raises(container.StorageFailure if fault == "known_before" else container.StorageOutcomeUnknown):
        reopened.recover_account_presentation_retry()
    assert not reopened.is_unlocked
    assert (tmp_path / "wallet.json").read_bytes() == (written[0] if written else before)
    monkeypatch.setattr(container, "_atomic_write", atomic)
    again = Wallet.open(tmp_path / "wallet.json", PASSWORD)
    retry = again.recover_account_presentation_retry()
    assert (retry.body, retry.presentation_jws, retry.response_uri, retry.state) == (
        original.body, original.presentation_jws, original.response_uri, original.state,
    )
    again.lock()


def test_recovery_cannot_mint_a_presentation_from_approval_or_after_consumption(tmp_path):
    from decent_wallet import PresentationDeliveryOutcome
    wallet, pending, context = _approved_wallet(tmp_path)
    with pytest.raises(ValueError):
        wallet.recover_account_presentation_retry()
    wallet.create_account_login_proof(pending, challenge=CHALLENGE)
    with pytest.raises(ValueError):
        wallet.recover_account_presentation_retry()
    _prepare(wallet, pending, continuation_artifacts(context, wallet.public_key, NOW))
    wallet.finish_account_presentation(pending, PresentationDeliveryOutcome.CANCELLED)
    with pytest.raises(ValueError):
        wallet.recover_account_presentation_retry()
    wallet.lock()


def test_modified_review_during_callback_is_rejected_without_value_leak(tmp_path, capsys, caplog):
    from decent_wallet.account_issuance import AccountDisclosureError
    private = "SYNTHETIC_PRIVATE_VALUE_MARKER_NOT_FOR_LOGS_OR_ERRORS_062"
    wallet, pending, context = _approved_wallet(tmp_path, {"given_name": private})
    wallet.cancel_account_disclosure(pending)
    review = wallet.review_account_disclosure(context, HANDLE, IDENTITY_ID)
    def mutate(candidate):
        object.__setattr__(candidate.context, "rp_client_id", private)
        return True
    with pytest.raises(AccountDisclosureError) as error:
        wallet.approve_account_disclosure(review, [GIVEN], consent=mutate)
    assert private not in str(error.value) + repr(error.value) + repr(review)
    assert wallet.export_container()
    output = capsys.readouterr()
    assert private not in output.out + output.err + caplog.text
    wallet.lock()


def _stale_process_writer(path, writer, ready, consumed, results):
    from decent_wallet import StorageFailure
    wallet = Wallet.open(path, PASSWORD)
    ready.set()
    if not consumed.wait(timeout=15):
        raise RuntimeError("synthetic test coordination timeout")
    try:
        if writer == "update":
            wallet.update_payload({"note": "synthetic"})
        elif writer == "password":
            wallet.change_password("another correct horse battery", "another correct horse battery")
        elif writer == "entity":
            wallet.set_master_account_entity({"given_name": "Grace"})
        else:
            wallet.prepare_signing_key_rotation()
        results.put((False, not wallet.is_unlocked))
    except StorageFailure:
        results.put((True, not wallet.is_unlocked))
    finally:
        wallet.lock()


@pytest.mark.parametrize("writer", ["update", "password", "entity", "rotation"])
def test_stale_other_process_cannot_resurrect_consumed_state(tmp_path, writer):
    import multiprocessing
    runtime = multiprocessing.get_context("spawn")
    ready, consumed, results = runtime.Event(), runtime.Event(), runtime.Queue()
    wallet, pending, _ = _approved_wallet(tmp_path)
    child = runtime.Process(target=_stale_process_writer, args=(tmp_path / "wallet.json", writer, ready, consumed, results))
    child.start()
    try:
        assert ready.wait(timeout=15)
        wallet.cancel_account_disclosure(pending)
        durable = (tmp_path / "wallet.json").read_bytes()
        consumed.set()
        child.join(timeout=20)
        assert not child.is_alive() and child.exitcode == 0
        assert results.get(timeout=2) == (True, True)
        assert (tmp_path / "wallet.json").read_bytes() == durable
    finally:
        if child.is_alive():
            child.terminate()
            child.join(timeout=5)
        wallet.lock()

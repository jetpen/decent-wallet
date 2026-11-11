# Python wallet Account Disclosure core API

This is the narrow Issue #62 Python-core contract for the next consumer slice. It adds no Android UI, app-link handler, HTTP client, browser/OIDC exchange, Keycloak, RP, Registry, or Storage integration. Do not send the context or claim values to a transport or signer outside the wallet.

```python
review = wallet.review_account_disclosure(parsed_context, opaque_handle, identity_id)
pending = wallet.approve_account_disclosure(
    review, approved_claim_ids, consent=callback, now=None
)
proof = wallet.create_account_login_proof(pending, challenge=wallet_login_challenge, now=None)
submission = wallet.prepare_account_presentation(
    pending,
    binding_jws=raw_binding,
    keycloak_jwks=trusted_https_fetched_jwks,
    outer_request=outer_authorization_parameters,
    request_object=raw_signed_request_object,
    registration=explicit_trusted_rp_registration,
    now=None,
)
retry = wallet.get_account_presentation_retry(pending)
wallet.finish_account_presentation(
    pending, PresentationDeliveryOutcome.AMBIGUOUS
)
```

- `review_account_disclosure()` validates context shape again, checks the 32-byte base64url opaque handle and its profile-derived transaction ID, then returns immutable display data. Only the latest exact wallet-issued review in that unlocked session can be approved; caller-constructed/replaced reviews are not authority. The wallet fingerprints the complete consent data and rechecks it after the callback. Entity mapping is exact: `urn:decent:account:v1:<name>` maps only to the string key `<name>` in `master_account_entity`. No aliasing, normalization, derivation, or fallback occurs. Missing required, invalid, empty, or over-1024-byte values reject; absent optional values are unavailable and omitted if not selected.
- `approve_account_disclosure()` calls the host consent callback without holding the wallet lock. It rechecks unlock state, expiry, current entity snapshot, and pending-state admission afterward. A required claim must be selected, and only one active approval exists per wallet. The callback must be an explicit affirmative result (`True`). No proof or presentation exists until the encrypted v2 payload write succeeds.
- `create_account_login_proof()` returns `WalletLoginProofRequest.proof`, exactly the unchanged four-string `decent-wallet-login-v1` object. It has no account claims and is one-use for the approval. No generic seed/signing capability is exposed.
- `prepare_account_presentation()` re-verifies the raw Keycloak binding with the supplied trusted JWKS and raw signed RP Request Object/outer request with the explicit registration. The core rejects trusted issuer JWKS sets with more than 64 keys before selection. Caller-constructed `VerifiedOwnerKeyBinding` and `VerifiedOID4VPRequest` objects are not inputs or authority. The wallet checks the current Owner key and persists the exact compact dual-JWS plus exact URL-encoded UTF-8 form body, response URI, and state before returning `AccountPresentationSubmission`.
- The transport sends only `submission.body` to `submission.response_uri`; neither field may be substituted. An ambiguous outcome preserves exactly those bytes. `get_account_presentation_retry()` is valid only after the host records `AMBIGUOUS`, and returns the same URI/state/body/JWS. There is no regeneration or claim change on retry.
- `ACCEPTED` is valid only for HTTP 200 with a `Content-Type` whose media type is exactly `application/json` (ASCII case-insensitive), optionally followed by syntactically valid MIME parameters such as `charset=utf-8`; substring lookalikes such as `application/jsonp` and `text/application/json` are rejected. The bounded response must be strict JSON with no duplicate object members and contain a same-origin `redirect_uri` with no query and exactly one 32-byte base64url `response_code` in its fragment. That redirect and code are unauthenticated completion handoff data, not proof of OIDC authentication, transaction completion, or authorization; the wallet never navigates to or follows the URI. Invalid `ACCEPTED` evidence raises without consuming or rewriting the pending approval; the host may conservatively classify an uncertain send as `AMBIGUOUS` and retry only the byte-identical saved submission. A valid accepted response consumes the pending record. A known failure or cancellation consumes the pending record. Do not label an unknown send as definitive failure.
- Already-approved encrypted state survives lock, background, and restart; continuation requires reopening/unlocking. Active approvals block export and active-approval imports are rejected without changing exact-byte import semantics for other containers. Expired records are cleared before proof/export/use. Unapproved consent UI remains transient and may be cancelled on background.

The owner key, JWS signing input, and raw private seed never cross this API. `repr()` of lifecycle DTOs is value-redacted. The existing container's atomic-write semantics remain authoritative: known failures return no artifact; `StorageOutcomeUnknown` locks the wallet and returns no artifact. If atomic storage reports an unresolved outcome, the implementation cannot claim that durable deletion succeeded.

## Expiry and interrupted-send recovery

The encrypted submission retains the effective minimum of the request, binding,
credential, presentation, and approval expiries. Retry and finalization clear
expired pending values durably before use; retry never extends this minimum.
Both bound and legacy-unbound rotation dispatch latches block proof issuance,
presentation signing, and retry/recovery. Promotion to another Owner key
invalidates an approval bound to the predecessor key.

`prepared` means the exact submission is committed, but the host has not recorded
a delivery outcome. It does **not** authorize a fresh presentation. After an
interruption, a host that retained `pending` may explicitly classify the outcome
as `AMBIGUOUS` with `finish_account_presentation()`, then obtain the exact retry.
If the host also lost its pending DTO, the unlocked wallet exposes:

```python
submission = wallet.recover_account_presentation_retry()
```

This explicit conservative recovery operation accepts only an unexpired
`prepared` or `ambiguous` submission, commits the `AMBIGUOUS` transition, validates
current disk/key/rotation state, and returns the saved URI/state/JWS/form body and
opaque pending handle. It never signs, recovers a consumed approval, or recovers
a wallet-login proof. A write/validation failure returns no bytes; uncertain
commits and failed finalization/recovery lock the session. Reopen then observes
the exact durable outcome: prepared/ambiguous can recover only identical bytes;
consumed state cannot recover anything. A proof write that committed before an
error remains used even though the host received no proof; cancel/start a fresh
transaction rather than reissue that proof. A known-before-write proof or
presentation failure leaves the prior durable state available. No recovery API
establishes whether the RP received or accepted a send.

## Cooperating-session concurrency boundary (Python only)

All Python writers (generic payload, entity, password, approval/proof/submission,
expiry/cancel/finalization, rotation prepare/cancel/latch/bind/reject/promote) use
the same empty `.<wallet filename>.lock` sidecar in the wallet directory.
Create/import and v1 migration also take that guard; migration holds it across
read/authenticate/replace. The sidecar is stable across atomic wallet replacement
and is **never unlinked on close**. It contains no key, claim, or plaintext state.
Directory aliases are resolved before selecting the lock path. The wallet directory
and lock sidecar must be owned by the current user. On POSIX the directory must
also not be group/world writable, and the sidecar must be mode 0600. On Windows,
the sidecar uses the filesystem's inherited ACL; reparse-point sidecars and
symlink/hardlinked wallets are rejected.

POSIX uses a bounded five-second advisory `flock`; Windows uses a bounded
five-second one-byte `msvcrt.locking` byte-range lock. On either backend,
optimistic comparison with the session's authenticated envelope makes the disk
revision check and write atomic relative to cooperating writers. A stale session
fails with value-free `StorageFailure`, locks, and must reopen; it is not silently
rebased. Every successful write is read back exactly before an artifact returns.
Retry holds the same guard while validating disk state and selecting saved bytes.
Instance lock precedes the file guard; no file guard is held during consent or
while calling another operation that acquires it. Independent processes are
covered by synthetic local-process POSIX tests and platform-isolated Windows
locking tests.

Unsupported locking platforms, lock acquisition errors/timeouts, stale/failed
revision reads, and uncertain write/readback outcomes fail closed. This is not a
distributed lock, filesystem certification, or Android coordination mechanism.
Use an owner-protected local directory and a filesystem with functioning native
advisory/byte-range locks; network filesystems, cross-machine coordination,
old/noncooperating writers, manual replacement/unlinking of the sidecar, hostile
same-user processes, and rollback of externally copied old encrypted backups
are outside this guarantee. Locking cannot revoke bytes already returned to a
caller, and encrypted deletion is not physical erasure. Container wire version 2
and all shared fixtures remain unchanged; pending state is private encrypted
payload data, not a new transport profile.

## Proposal-only Android native continuation capability

The Android wallet library has an isolated, non-conformant implementation slice for the native-continuation proposal in ecosystem PR #53. The proposal has not been incorporated into the normative profile; this API is not evidence of consumer conformance, and app/UI/network polling remain unimplemented.

After the wallet has issued the one-use login proof, a client that received the proposal's capability may call `WalletSession.installNativeContinuationCapability(pending, encodedCapability, expiresAtEpochSeconds)`. This persistence API does not authenticate the provider response or establish the provider's proof-acceptance timestamp; a future transport client must authenticate the configured provider and validate the exact response and proof-relative expiry before invoking it. The method accepts only a canonical base64url-no-pad encoding of exactly 32 bytes, for the exact active pending approval with proof already issued. It persists the bytes inside the existing authenticated encrypted wallet-container v2 pending record—without a new key, file, or envelope—and bounds expiry to the approval expiry and 300 seconds from installation. Duplicate installation and stale/invalid/expired approvals fail with a value-free wallet error.

After reopen, `nativeContinuationCapability(pending)` returns a closeable `NativeContinuationCapability` while it remains valid. Callers may obtain an owned byte copy with `copyCapabilityBytes()` and must wipe that copy when finished; the wallet cannot revoke copies already returned. The object checks an elapsed-time deadline on each access and wipes its internal copy on first post-expiry access; callers must also close it to wipe the internal copy sooner. Expired persisted capability state is durably removed before the getter returns `null`. The containing pending approval remains subject to existing export/import and lock rules.

Android runtime qualification and independent human security/privacy review remain open; this proposal-only slice is not qualified for deployment or conformance.

This slice does not implement proposal opt-in/context validation, proof-response HTTP parsing, capability polling, RP Request Object retrieval, or Android app handoff. Do not treat it as normative signup-continuation support until ecosystem #51 adopts the amendment and the remaining client/provider/RP acceptance gates are verified.

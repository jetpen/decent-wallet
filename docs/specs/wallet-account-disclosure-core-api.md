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
- `ACCEPTED` is valid only for HTTP 200 with a `Content-Type` whose media type is exactly `application/json` (ASCII case-insensitive), optionally followed by syntactically valid MIME parameters such as `charset=utf-8`; substring lookalikes such as `application/jsonp` and `text/application/json` are rejected. The bounded response must be strict JSON with no duplicate object members and contain a same-origin `redirect_uri` with no query and exactly one 32-byte base64url `response_code` in its fragment. That redirect and code are unauthenticated completion handoff data, not proof of OIDC authentication, transaction completion, or authorization; the wallet never navigates to or follows the URI. Invalid `ACCEPTED` evidence raises and durably changes the presentation state to `acceptance_uncertain`, retaining the exact encrypted submission but making retry unavailable; the host must tell the user to check with the relying party. If that state write fails, no retry artifact is returned and storage failure/unknown-outcome semantics apply; a known-before-write failure leaves the earlier durable state unchanged, so storage unavailability remains a boundary to restart-safe revocation. A valid accepted response consumes the pending record. A known failure or cancellation consumes the pending record. Do not label an unknown send as definitive failure.
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

## Normative native continuation persistence API

Ecosystem #51 adopted the native-continuation protocol in [the normative v1 profile](https://github.com/jetpen/decent-ecosystem/blob/4545d5de8856a576828fb00c17413e9b49d1ad1f/docs/protocol/wallet-account-disclosure/v1/PROFILE.md#11-native-continuation). The local persistence APIs described here implement only a storage primitive under that contract; neither API establishes full protocol or consumer conformance. In particular, this API slice does not prove that a caller authenticated the provider response, checked the expiry relative to proof acceptance, performed the native continuation exchange, or completed the remaining client/provider/RP/runtime and independent human-review gates.

After the wallet has issued the one-use login proof, a caller may install a received capability with `WalletSession.installNativeContinuationCapability(pending, encodedCapability, expiresAtEpochSeconds)` (Android) or `wallet.install_native_continuation_capability(pending, encoded_capability, expires_at)` (Python). The protocol requires 32 independent CSPRNG bytes encoded as canonical base64url without padding. The local API checks only the encoding and 32-byte length; it cannot attest the capability's entropy or random-generation source. The exact active pending approval must have its proof durably issued. The local API validates encoding, pending/proof eligibility, and local storage bounds only. The authenticated provider transport caller must authenticate the response and enforce the protocol's proof-acceptance-relative expiry before calling the local install API; the local persistence method cannot establish that condition itself.

The expiry must be an exact integer timestamp in the future, no later than the pending approval's persisted expiry, and no later than 300 seconds after local installation. The transport caller must additionally enforce the profile's exact-integer, proof-acceptance-relative expiry bound and context/transaction expiry before install. If the winning proof response is lost before capability bytes are durably stored, the wallet cannot recover the capability or retry that same transaction; start a new transaction under the profile. The persisted nested record contains exactly the capability bytes and expiry inside the existing authenticated encrypted wallet-container v2 payload; there is no separate key, envelope, file, or wire format. Duplicate installation and stale, malformed, or ineligible approvals fail with a value-free wallet error. The existing container v2 envelope, login-proof four-field contract, adopted wire bytes, and shared vectors are unchanged.

After reopen, the getter (`nativeContinuationCapability(pending)` / `native_continuation_capability(pending)`) returns a closeable object while valid, or `null`/`None` when no capability is stored. Callers may obtain a mutable owned copy (`copyCapabilityBytes()` / `copy_capability_bytes()`) and must wipe it when finished; the wallet cannot revoke copies already returned. The object checks both wall-clock expiry and an in-memory monotonic deadline on each access and wipes its internal copy on expiry or close. That monotonic deadline protects copies held by the current process; it does not survive restart, so persisted expiry checks after reopen rely on the host wall clock. Expired persisted capability state is durably removed before the getter returns absence, and terminal cancellation/consumption removes it with the pending approval. The persistence seam does not implement or claim provider HTTP, OIDC/login callback validation, polling, RP Request Object retrieval, Android app handoff/UI, or runtime qualification.

On Android, `WalletSession.prepareAccountPresentation(pending, issuerJwks, outerAuthorizationParameters, requestObjectJws, registration)` is the native-consumer overload: the app supplies only poll-derived outer metadata and the signed Request Object, while the wallet extracts the embedded `decent_account.owner_key_binding` JWS and passes it into the existing full preparation/verifier path. Extraction is deliberately untrusted parsing only; the JWS is not authority until the Request Object signature, trusted RP registration, binding signature/context/hash, approval, and wallet-owned key checks all succeed. The strict Request Object parser rejects malformed compact objects, missing binding fields, and duplicate JSON members. The existing explicit-binding overload remains available and unchanged for the browser-only flow; no Request Object, binding, or presentation wire bytes are rewritten by this overload.

The core parser accepts the optional `decent_native_continuation` marker only when it is the literal JSON boolean `true`; absence preserves the browser-only path and `false` or any other value is rejected. It persists this opt-in in the encrypted pending approval. For native-marked context, the authenticated Keycloak binding must contain exactly one additional claim, `continuation_capability_hash`, equal to unpadded canonical base64url SHA-256 of the decoded 32-byte capability; the wallet checks it only after JWS authentication and compares it in constant time to the locally persisted capability bytes. Browser-only bindings must not contain that claim. The core does not compare an initial signed RP opt-in request with the context because that artifact is not present at this seam; that gate belongs to issue #66. See #51 §11 for the normative contract.

Before native presentation signing, the wallet requires an unexpired stored capability and bounds the signed request/credential expiry by approval, context, binding, request, and capability expiries. A verified capability-hash mismatch invalidates the pending approval and capability durably; storage/operational failures remain distinguishable and fail closed. Once the exact form submission is durably prepared, the capability is cleared atomically with that prepared state; ambiguous retry continues to return only the exact persisted submission. Browser-only serialization and flow remain unchanged.

Issue #51 still has separate Wallet, Keycloak, RP, runtime and independent human-review gates. This Python slice is an additive core persistence API, not evidence that those gates or full protocol/consumer conformance have passed.

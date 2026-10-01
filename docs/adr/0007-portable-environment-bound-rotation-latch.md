# ADR-0007: Portable environment-bound rotation-dispatch latch

**Status:** Accepted (owner-approved contract; target runtime acceptance remains pending)

**Scope:** The encrypted container-v2 rotation latch and explicit legacy recovery only.

## Decision chronology

ADR-0001 established the six public envelope/key/history bindings and no-retry key-retention safeguards. ADR-0002 introduced authenticated container v2 to prevent older v1 readers ignoring that latch. ADR-0003 added explicit v1 migration; ADR-0006 narrowed direct-DHT guarantees without weakening the latch. A subsequent cross-platform audit found Python's exact six-field decoder rejected Android's seven-field environment-bound intent, while Android rejected Python's six-field latch. Passing unlatched container vectors did not establish latched portability.

The owner then explicitly chose: **“Standardize an environment-bound portable latch, with explicit compatibility/recovery handling for legacy six-field intents.”** This amendment implements that choice; it does not retroactively change the earlier ABI or upgrade historical runtime evidence.

## Format and compatibility

Within supported container **v2**, recognize exactly two dispatch-intent payload maps:

- Legacy six: `owner_name`, `predecessor_owner_public_key`, `successor_owner_public_key`, `predecessor_state_hash`, `sequence`, `envelope_hash`.
- Current seven: those same six fields plus **`environment`**, a non-null valid text realm identifier.

Unknown fields and present null/blank/malformed environments are rejected. Absence alone denotes an **unbound legacy** intent, represented as `None`/`null` in the API, never as a default realm. Both public open/import paths validate the latch and actual seed-derived active/pending keys before returning an unlocked session or installing an imported file. Missing/partial/invalid/equal key pairs and predecessor/successor linkage mismatches fail closed. Owner Name stays exact valid UTF-8 (1..1,048,576 bytes); hashes/public keys stay 32 bytes; sequence stays a positive integer.

Environment is exact valid Unicode scalar text, **1..256 UTF-16 code units**, and not exclusively Unicode White_Space (`0009..000D`, `0020`, `0085`, `00A0`, `1680`, `2000..200A`, `2028`, `2029`, `202F`, `205F`, `3000`). Both runtimes reject unpaired surrogates. Supplementary scalars count as two units. No trimming, case folding, normalization, encoding substitution, inferred network name, or peer-derived identifier is allowed.

Container outer version, algorithms, typed-value encoding, and version-bound DEK/payload AAD remain unchanged. This is an optional-field extension inside the already-latch-aware v2 payload, with **new readers explicitly recognizing both exact shapes**. Old Python six-field readers reject seven-field files; old Android seven-field readers reject six-field files. They are **not forward-compatible**. Fail-closed rejection by those readers, rather than ignored latch state or unsafe signing, is why no new outer version is needed. V1 direct open/import and unknown outer versions remain rejected; ADR-0003 migration is unchanged.

## Trusted environment configuration

New public publication preparation must produce seven-field bound intents. Python callers explicitly supply `registry_environment` to `RegistryAdapter`; the consent `environment` must match. For concrete `RegistryTransport`, callers also explicitly configure `registry_environment` on the transport and it must match the adapter and latch. Missing configuration disables rotation preparation/confirmation, not ordinary non-rotation use. Injected transports without their own realm property use the explicitly configured adapter boundary; if a transport exposes a realm property, it must match. Android retains its explicit `AndroidIdentityTransport.registryEnvironment`/`AndroidRegistryDhtConfig` configuration.

These labels are **trusted caller configuration**, not network-authenticated realm identities. Neither supplying a label nor independent read-back proves public DHT consensus, global commit, deployment identity, or convergence. ADR-0006 remains authoritative. Hosts must select the actual intended peers and realm together, never invent a production default.

Environment is included in Python publication/confirmation/rejection/latch capability equality and in Android intent equality. Mismatched/unconfigured confirmation makes zero transport calls and issues no confirmation. Python still installs its per-owner mutation gate before returning an unavailable/mismatched/unbound confirmation. Exact envelope hash, raw Owner Name, authenticated complete predecessor history, old/new public keys and exact sequence increment remain required; matching a realm alone is never confirmation.

## Legacy recovery

An unbound six-field latch remains inspectable, exactly exportable/importable and blocks signing, pending preparation/cancellation, conflicting publication, dispatch and finalization. Both keys and the latch remain retained. No environment inference and no remote confirmation reads occur while unbound.

The only local upgrade is explicit caller-consented atomic binding:

- Python: `wallet.bind_legacy_rotation_dispatch_environment(environment, *, consent)`; `consent(intent, environment)` must return exactly `True`.
- Android: `wallet.bindLegacyRotationDispatchEnvironment(environment, consent)`; the callback reviews the legacy intent and requested realm.

Both methods accept **six-to-seven only**. Any bound intent, including a same-environment repeat, is rejected; different-environment rebinding is forbidden. Invalid realm, denial, callback failure, or changed session/latch during consent is rejected. The successful write preserves all six original public fields, both secret/public key pairs and unrelated payload metadata, adding only the realm. Generic metadata cannot edit key/latch fields. The existing authenticated atomic replacement boundary is reused: recoverable failure preserves the original legacy session/container; unknown persistence outcome raises the existing typed unknown-storage exception and locks/clears the session's retained secret buffers. No decrypted file/backup is written.

Binding invokes no Registry API, retries no publication and returns **only an intent**, never a dispatch permit/publication capability. It cannot resume the historical write. After successful local binding, only fresh read-only exact-envelope/history confirmation in the matching configured realm may issue the capability for durable promotion. A Python adapter already gating the legacy intent may register the same six bindings plus realm for read-only recovery, never marking it dispatch-ready. A new adapter works as well. The gate clears only after durable confirmed promotion.

Exact export/import **never rewrites supplied ciphertext**, including legacy bytes. Binding and promotion are separate explicit state-changing operations and necessarily reseal ciphertext.

## Evidence and limits

`tests/vectors/wallet-v2-portable-rotation-latch.json` contains synthetic Python-authored bound and legacy encrypted v2 containers tied to the canonical legacy operation-5 vector. Python and Kotlin public readers consume them. `PortableLatchTest.actualKotlinPublicAuthoringExportsBoundAndLegacyCiphertext` authors the bound latch through real Kotlin wallet/draft/preparation/latch APIs on the host JVM, then exports exact ciphertext; an opt-in Python consumer reads those actual artifacts. The legacy artifact is an explicit synthetic representation of the pre-amendment six-field state, not new production preparation output.

Host tests cover exact transfer, key retention, conflict blocking, realm mismatch without RPC, legacy consent/binding/storage faults and read-only confirmation/promotion. They do not constitute fresh APK/device, installed-package, remote Registry, or public-DHT acceptance. Those previous results predate this production change and must be rerun separately. Issue #18 is not closed by this amendment.

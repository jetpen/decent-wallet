# Decentralized Wallet

A Python wallet library for a decentralized ecosystem. It keeps private keys within the wallet boundary and mediates user-authorized cryptographic operations without disclosing wallet secrets.

Current implementation includes:

- Argon2id-protected, XChaCha20-Poly1305 encrypted wallet containers.
- Version-2 authenticated container format. Version-1 and other unsupported formats are rejected without migration, as recorded in [ADR-0002](docs/adr/0002-wallet-container-v2-dispatch-intent.md).
- Atomic container writes, exact encrypted-container export/import, password rewrapping, bounded authentication delay, and lock/inactivity handling.
- Local owner-key rotation: persist one encrypted pending successor; build and validate operation-5 drafts; locally prove possession without returning the proof signature; prepare publication consent, latch the exact envelope hash, conditionally dispatch, independently confirm via a fresh remote read, and promote the successor only from adapter-issued confirmation. Ambiguous outcomes retain both keys and the encrypted intent. This is a Python-core API over an injected transport; no production Registry transport is included, and Registry deployment compatibility is not verified.
- CSRNG-only Ed25519 key generation and public-key derivation.
- Canonical Identity SignedUpdate validation and protocol-specific signing.
- One-operation, timeout-invalidated signer capabilities with concurrent-use protection.
- Public-only Identity/Registry adapter with canonical consent transcripts, replay/expiry handling, stale-state conditional writes, detached threshold proofs, and exact read-back confirmation.
- Immutable public Identity drafts and portable proof bundles with independent signing, canonical exchange, merge, threshold validation, finalization, conditional publication, and exact read-back confirmation.

The canonical accepted specification is [docs/specs/wallet-implementation.md](docs/specs/wallet-implementation.md). Interactive consent UI, platform adapters, Registry/DHT transport implementations, and command-line or graphical interfaces remain outside the current library implementation.

## Deployment

### Prerequisites

- Python 3.12 or newer.
- A supported platform for the project dependencies: `argon2-cffi`, `cbor2`, `cryptography`, and `pycryptodome`.
- A filesystem location where the application can create a wallet container with restrictive permissions.

The wallet is a library component, not a network service. It does not require a daemon, database, Registry/DHT node, or external account service for local container and signing operations.

### Installation

Install the package into the application's virtual environment:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install .
```

Install the test extra when developing the package:

```bash
python -m pip install '.[test]'
```

The package does not currently define a `console_scripts` entry point. There is no shipped CLI parameter set or graphical user interface; applications integrate through the Python API documented below.

## Usage

Use `Wallet.create_with_generated_key()` for a new signing wallet. The application must obtain passwords through its own secure, non-logging input mechanism. Do not place passwords, seeds, or private-key material in source code, command arguments, environment variables, logs, or temporary files.

```python
from pathlib import Path

from decent_wallet import Wallet

wallet_path = Path("wallet.dw")
password = obtain_password_from_secure_ui()

wallet = Wallet.create_with_generated_key(
    wallet_path,
    password,
    password,
    inactivity_minutes=5,
)
try:
    public_key = wallet.public_key

    # canonical_update must be the exact canonical Identity SignedUpdate
    # bytes prepared by the application's Registry adapter.
    canonical_update = prepare_canonical_identity_update(public_key)
    signer = wallet.create_signer(timeout_seconds=60.0)
    signature = signer.sign_identity_update(canonical_update)
finally:
    wallet.lock()
```

`obtain_password_from_secure_ui()` and `prepare_canonical_identity_update()` are application or ecosystem-adapter functions; they are placeholders in this example. The signer accepts only canonical Identity SignedUpdate bytes, hashes those bytes internally as required by the protocol, and returns the detached Ed25519 signature. It does not expose a generic arbitrary-message signing method or private-key export.

### Main API operations

- `Wallet.create_with_generated_key(path, password, confirmation, *, inactivity_minutes=5)` creates a new encrypted wallet and generates its Ed25519 key through the approved CSRNG boundary.
- `Wallet.open(path, password, *, inactivity_minutes=5)` opens an existing encrypted wallet.
- `wallet.export_container()` returns the exact encrypted-container bytes from an unlocked wallet for explicit transfer; it does not decrypt or reserialize the artifact.
- `Wallet.import_container(path, data, password, *, inactivity_minutes=5)` authenticates the exact container bytes and atomically creates a new file only when `path` does not already exist; it returns the imported unlocked wallet.
- `wallet.public_key` returns the raw public key for a generated signing wallet.
- `wallet.create_signer(*, timeout_seconds=60.0)` creates a one-operation signer capability.
- `signer.sign_identity_update(canonical_update)` validates and signs one canonical Identity update, then invalidates the capability.
- `wallet.change_password(password, confirmation)` atomically rewraps the existing wallet DEK.
- `wallet.prepare_signing_key_rotation()` creates and durably stores one pending successor key and returns only its public key. Repeated calls return the same pending key until cancellation; the active key remains unchanged.
- `wallet.pending_signing_public_key` returns the pending successor's public key or `None`; `wallet.cancel_signing_key_rotation()` atomically removes an unfinalized successor. `wallet.prove_pending_signing_key_rotation(draft)` signs and verifies the exact operation-5 update locally, then discards the proof-of-possession signature and returns no signing material.
- `RegistryAdapter.prepare_owner_key_rotation_publication(bundle, ...)` validates the complete operation-5 bundle and requires `transport.supports_owner_key_rotation is True` plus a fresh remote-read method before consent. The flag must be true only for a pinned Registry deployment known to validate operation 5. It obtains consent over the exact finalized envelope, rechecks state and expiry, then returns `PublicationResult(status=PublishStatus.READY, publication=...)` without dispatching. Unsupported transport fails before consent or latching.
- `wallet.latch_signing_key_rotation_dispatch_intent(bundle, publication)` accepts only the matching prepared capability and bundle bound to the active and pending keys. After the encrypted intent is atomically persisted, it invalidates existing signer capabilities, blocks signing/cancellation/republishing, and returns a sealed, process-local `RotationDispatchPermit`. The persisted `RotationDispatchIntent` alone cannot authorize dispatch.
- `adapter.dispatch_owner_key_rotation(publication, permit)` is one-use and conditionally dispatches only with the wallet-minted permit. It returns confirmed only after fresh remote read-back validates the exact envelope and predecessor chain; ambiguous outcomes remain unknown and latched. While latched, the adapter blocks ordinary signing and publication for that owner. After reopening a wallet with a persisted intent, call `adapter.confirm_owner_key_rotation(intent)` before any other mutating adapter operation; this read-only recovery installs the same write gate and never dispatches.
- `wallet.resolve_signing_key_rotation_rejection(rejection)` clears only a matching one-use adapter-issued pre-write rejection. `wallet.finalize_signing_key_rotation(confirmation)` promotes the successor only after matching adapter-issued confirmation, atomically persists it, then wipes the predecessor seed.
- `wallet.signing_key_rotation_dispatch_intent` returns the persisted non-secret intent or `None`. The intent survives lock/reopen and exact encrypted-container export/import.
- `wallet.background()` and `wallet.lock()` invalidate capabilities and clear active wallet secrets.
- `wallet.check_inactivity()` enforces the configured inactivity timeout.
- `RegistryAdapter(transport, replay_store=None)` accepts only public owner/signer keys and a signer factory; the transport receives canonical public envelopes, an expected-state precondition, and an atomic expiry deadline, never a wallet or private key. Every non-genesis version-1 state requires exact predecessor history by state hash back to the signed anchor; incomplete history or chains exceeding 1,024 transitions fail closed. Rotation requires `supports_owner_key_rotation is True` and `get_remote_identity_envelope(owner_name_hex=...)` to bypass local durable cache and write-through state. The flag is a trusted adapter configuration assertion, not a network handshake; set it only for a pinned Registry deployment with operation-5 validation and independent read-back. A Registry adapter can back the read with the Registry DHT's fresh `read_remote_identity_envelope()` method, using SHA-256 of the raw owner-name bytes as the DHT object key.
- `adapter.submit_identity(...)` returns confirmed, unknown, stale, consent, failure, or proof-ready outcomes. Thresholds greater than one return a detached public proof instead of publishing an incomplete envelope.
- `adapter.create_draft(...)` derives the next sequence and binds the canonical update to the current public state. `adapter.create_owner_key_rotation_draft(...)` constructs an operation-5 draft from a verified predecessor; legacy predecessors require a successor 2-of-3 set, while version-1 predecessors preserve their signer set, threshold, and epoch. `adapter.sign_draft(...)` obtains consent and returns one local `IdentityProof` without publishing. Consent callbacks receive the exact non-secret `review_payload` bytes and matching payload hash for application rendering.
- `IdentityBundle.from_submission(...)`, `bundle.merge(...)`, `bundle.to_cbor()` / `IdentityBundle.from_cbor(...)`, and `bundle.finalize()` support public bundle exchange and threshold validation. Operation-5 bundles can be finalized locally, but `adapter.publish_bundle(...)` and `adapter.confirm_bundle(...)` reject them; the emitted envelope is not evidence of Registry acceptance.
- `adapter.publish_bundle(...)` requires a fresh purpose-bound publication consent, replay nonce, and expiry; the expiry is not trusted from exchanged bundle metadata. It uses the expected-state hash and reads back the exact envelope through the injected transport. This interface does not itself guarantee that the transport bypasses a Registry-local durable cache; operation-5 rotation confirmation requires the uncached fresh remote read specified in §10.2. Ambiguous writes return `unknown`; `adapter.confirm_bundle(...)` performs read-back only and never retries publication.
- Legacy drafts finalize to the existing two-field envelope. Version-1 drafts, including operation 5, finalize to the existing explicit-signer envelope; local draft/bundle CBOR v2 carries predecessor history and remains separate from both Registry envelopes. `decent-registry` main has operation-5 and independent read-back support (PRs #109 and #110); no production wallet transport or target deployment is included here.
- `InMemoryReplayNonceStore` is suitable for isolated processes; applications spanning restarts must inject a durable atomic `ReplayNonceStore` implementation.

`Wallet.create()` is available for encrypted wallet-local metadata that does not contain signing material. Its public payload API rejects `private_seed` and `public_key`; generated signing wallets must use `create_with_generated_key()`.

## Development verification

Run the test suite and package checks from the repository root:

```bash
python -m pytest -q
python -m compileall -q src tests
python -m pip check
git diff --check
```

Ecosystem-wide identity and account storage, Registry/DHT operation, site policy, site sessions, consent UI, and cross-device transfer remain separate responsibilities. See the implementation specification for the planned boundaries and deferred capabilities.

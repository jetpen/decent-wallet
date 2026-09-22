# Decentralized Wallet

A Python wallet library for a decentralized ecosystem. It keeps private keys within the wallet boundary and mediates user-authorized cryptographic operations without disclosing wallet secrets.

Current implementation includes:

- Argon2id-protected, XChaCha20-Poly1305 encrypted wallet containers.
- Atomic container writes, password rewrapping, bounded authentication delay, and lock/inactivity handling.
- CSRNG-only Ed25519 key generation and public-key derivation.
- Canonical Identity SignedUpdate validation and protocol-specific signing.
- One-operation, timeout-invalidated signer capabilities with concurrent-use protection.

The implementation-ready specification is [docs/specs/wallet-implementation.md](docs/specs/wallet-implementation.md). Consent workflows, multisignature orchestration, platform adapters, Registry/DHT integration, and command-line or graphical interfaces remain outside the current library implementation.

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
- `wallet.public_key` returns the raw public key for a generated signing wallet.
- `wallet.create_signer(*, timeout_seconds=60.0)` creates a one-operation signer capability.
- `signer.sign_identity_update(canonical_update)` validates and signs one canonical Identity update, then invalidates the capability.
- `wallet.change_password(password, confirmation)` atomically rewraps the existing wallet DEK.
- `wallet.background()` and `wallet.lock()` invalidate capabilities and clear active wallet secrets.
- `wallet.check_inactivity()` enforces the configured inactivity timeout.

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

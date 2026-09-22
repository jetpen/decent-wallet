# Decentralized Wallet

A wallet component for a decentralized ecosystem that keeps private keys within the wallet boundary and mediates user-authorized cryptographic operations without disclosing wallet secrets.

Current specification work covers:

- Strongly encrypted, password-initialized wallet storage and secret lifecycle.
- CSRNG-only key generation and signing integration with the Identity/Registry toolchain.
- Explicit consent for application challenge signing, disclosure, and capability decisions.
- Independent multisignature draft, signing, exchange, merge, finalization, and publication workflows.
- Portable encrypted-container transfer across Android, iPhone, and optional desktop/Podman implementations.
- Key rotation, password rewrapping, wallet-format migration, and mandatory security acceptance tests.

The implementation-ready specification is [docs/specs/wallet-implementation.md](docs/specs/wallet-implementation.md). The repository currently contains specification and research artifacts, not a wallet implementation. Ecosystem-wide identity and account storage, Registry/DHT operation, site policy, and site sessions are out of scope.
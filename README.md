# Decentralized Wallet

A wallet component for a decentralized ecosystem that keeps private keys within the wallet boundary and mediates user-authorized cryptographic operations without disclosing wallet secrets.

Current specification work covers:

- Strongly encrypted, password-initialized wallet storage and secret lifecycle.
- CSRNG-only key generation and signing integration with the Identity/Registry toolchain.
- Explicit consent for application challenge signing, disclosure, and capability decisions.
- Independent multisignature draft, signing, exchange, merge, finalization, and publication workflows.

The repository is currently defining implementation-ready specifications. Ecosystem-wide identity and account storage, Registry/DHT operation, site policy, and site sessions are out of scope.

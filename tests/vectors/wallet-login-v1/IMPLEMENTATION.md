## Wallet-login v1 proof-core vertical slice

`docs/protocol/wallet-login/v1/` defines the ecosystem-owned protocol vector package: manifest, positive proof vector, ten proof-level negative mutations and a boundary README. The package is independent of Storage grant semantic-v1. Run `python docs/protocol/wallet-login/v1/verify.py` from the ecosystem checkout to verify structure and manifest hashes. The deterministic signing seed in the positive fixture is deliberately public test-only material; never use it as a real wallet key or ship it in a runtime artifact.

The linked Keycloak branch implements bounded strict parsing of the four-field wallet proof, duplicate/unknown/missing-field rejection, strict UTF-8 and exact `identity_id` preservation, RFC 8785 JCS UTF-8 signing bytes, and JDK Ed25519 verification against current public-key material supplied by a future Registry adapter. Tests load the positive and negative vector files, verify expected key/signature/canonical bytes, and execute all ten declared negative mutations.

Local verification: all Maven tests/package pass, and the pinned Keycloak 26.8.0 provider image builds. The existing Authenticator remains fail-closed. No current Registry adapter, HTTPS challenge/QR/status transport, pending transaction or replay state, account mapping/signup behavior, cluster race evidence, or OIDC Code + PKCE flow is implemented. This is a reviewable **proof-core** slice, not a complete interactive vertical flow or end-to-end qualification.

## Branches and review

- `decent-ecosystem`: `feat/wallet-login-v1-vectors`, based on approved contract package revision `5fa46362dea1c7b1f53a27df3f5fc0a60556d1ef`.
- `decent-keycloak`: `feat/wallet-login-v1-proof-verifier`, based on provider repository setup commit `ef94f1b958a9e0c3a411d725b82f133d2b919a65`.

The Keycloak tests now use byte-for-byte vendored fixtures in `src/test/resources/wallet-login-v1/`, check the manifest SHA-256 digests, and pass with no ecosystem checkout available. Update those test resources only from an explicitly reviewed ecosystem vector revision. Merge/review the ecosystem vectors first, then bump the vendored fixture package to that exact revision. The two review PRs are not open yet. Keep ecosystem #46 and Keycloak #1 open until their complete acceptance criteria—not just this proof-core slice—are satisfied.

# Wallet Account Disclosure v1 consumer fixtures

These files are copied byte-for-byte from `jetpen/decent-ecosystem` commit `b861b8c7a088dd21c79e064c8dbb52a0e0e96eb8`, under `docs/protocol/wallet-account-disclosure/v1/`. `source-manifest.json` pins SHA-256 for every copied file. Consumer tests must use these fixtures unchanged; update them only by deliberately adopting a later ecosystem package revision and changing the pinned manifest in the same reviewed update.

The source commit is the verified merge commit for ecosystem PR #52. The copied `PROFILE.md` and original README contain a pre-merge publication-status sentence that became stale after that commit; the ecosystem issue #51 current body and PR metadata establish that the profile is merged and normative. The profile and vectors themselves are preserved exactly, not edited to correct status prose.

The vectors are public synthetic test material. They are not production credentials or private keys. Passing a local wallet test against them proves only the behavior explicitly exercised by that test, not Keycloak, RP, live OIDC, or cross-component qualification.

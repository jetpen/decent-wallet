# Wallet-login v1 protocol vectors

This folder is owned by the ecosystem protocol package and records machine-readable **wallet proof-core vectors** for the approved `decent-wallet-login-v1` profile. It is not a Storage grant or RFC 7523 profile.

## Wire proof

The wallet response is a closed JSON object with exactly four string members: `profile`, `challenge`, `identity_id`, `signature`. Unknown, missing or duplicate members are rejected.

The signed bytes are RFC 8785 JCS followed by UTF-8 encoding of the object containing only `profile`, `challenge`, and `identity_id`; `signature` is excluded. The signature uses Ed25519, exactly 64 bytes, encoded base64url without padding. `identity_id` is its exact raw UTF-8 value; there is no case folding or Unicode normalization.

`challenge` is base64url without padding of SHA-256 over 32 cryptographically random bytes. The vector provides a fixed public test nonce so consumers can reproduce the challenge. The production protocol never reuses vector nonce/key material.

## Files and usage

- [`manifest.json`](manifest.json) names the profile and vector files.
- [`vectors/valid-basic.json`](vectors/valid-basic.json) gives exact public test material, derived challenge, canonical signing bytes, Ed25519 key/signature and proof.
- [`vectors/negative.json`](vectors/negative.json) defines stable negative mutations.
- [`verify.py`](verify.py) validates JSON syntax, declared paths, fixture structure, and SHA-256 digests in the manifest (`python verify.py`).

The deterministic private seed in the positive vector is intentionally public fixture data. **It must never be treated as a real wallet credential or included in a production runtime artifact.**

These vectors prove only JSON/proof serialization and Ed25519 verification. HTTP transaction state, current Registry resolution, origin/session binding, expiry, replay consumption, account/signup behavior and OIDC completion require separate Keycloak and relying-party integration tests. Passing this fixture suite is not end-to-end wallet-login qualification.

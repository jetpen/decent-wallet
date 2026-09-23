# Decent Wallet Context

This context defines wallet identity and key-lifecycle language, distinguishing stable Identity naming from its cryptographic owner key and authorization signer set.

## Identity

**Owner Name**:
The raw UTF-8 byte string that identifies an Identity and determines its Registry lookup key.
_Avoid_: normalized owner name, mutable identity name

**Identity Owner Key**:
The Ed25519 public key recorded as `owner_public_key` for an Identity.
_Avoid_: account key, signer-set key

**Owner-Key Rotation**:
Replacement of an Identity Owner Key with a successor while retaining the same Owner Name and Registry lookup key.
_Avoid_: signer-set replacement, key update

**Signer-Set Replacement**:
A change to the version-1 set of public keys authorized to sign Identity updates, distinct from changing the Identity Owner Key.
_Avoid_: owner-key rotation

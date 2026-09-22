# Issue #3: CSRNG key-generation and Identity/Registry signing boundary

**Status:** research findings for `jetpen/decent-wallet#3` (not an implementation and not a
GitHub issue resolution). The wallet repository currently contains specification and
handoff documentation, but no wallet key-generation or signing implementation.

## Decision-oriented summary

1. **Use Ed25519 and the existing Registry wire formats; do not invent a wallet wire
   format.** The Identity Record key is `SHA-256(raw owner-name bytes)`. The signed
   preimage is canonical CBOR `SignedUpdate`; the project signs
   `SHA-256(canonical SignedUpdate bytes)` with Ed25519. Legacy output is a canonical
   two-field `SignedEnvelope`; version-1 multisignature output is a separate, explicit
   three-field envelope.
2. **Make key generation one wallet-local, fail-closed boundary.** Acquire exactly 32
   bytes from the OS-backed CSRNG, construct Ed25519 from those bytes, and treat provider
   replacement, exceptions, wrong types, and wrong lengths as fatal. There is no
   fallback to `random`, `create_new_key_pair()`, time, process data, or a caller-supplied
   PRNG in production.
3. **Keep the private key below the Identity/Registry publication boundary.** The wallet
   may call local/shared pure crypto and codec primitives, but the network-facing
   Identity/Registry API should receive only public key material and a complete signed
   envelope. The current legacy Registry builder accepts a private-key *path*; that is
   useful evidence of the established toolchain but is not a safe wallet-to-service
   boundary when the Registry is a separate process.
4. **The implementation-ready MVP boundary should be:** wallet generates and stores the
   key inside encrypted wallet storage; wallet obtains/constructs the exact canonical
   Identity `SignedUpdate`; wallet signs the prescribed digest after explicit consent;
   wallet returns the public key plus signature/envelope (or a detached v1 proof); and
   Identity/Registry validates and publishes the finalized envelope. No private material
   crosses this boundary.

## Claim classes and repository state

### Implemented and code-backed

**Registry (current `main`)** implements Ed25519, canonical CBOR, legacy Identity and
Provider records, and version-1 explicit-signer multisignature records. The canonical
Registry documentation says that private keys are local key-store material and that
records contain public verification material and signatures only:

- [Registry protocol concepts](https://github.com/jetpen/decent-registry/blob/main/docs/protocol-concepts.md)
- [Registry multisignature records](https://github.com/jetpen/decent-registry/blob/main/docs/multisignature-records.md)
- [Registry `encoding.py`](https://github.com/jetpen/decent-registry/blob/main/src/decent_registry/encoding.py)
- [Registry `signed_envelope.py`](https://github.com/jetpen/decent-registry/blob/main/src/decent_registry/signed_envelope.py)
- [Registry `verification.py`](https://github.com/jetpen/decent-registry/blob/main/src/decent_registry/verification.py)
- [Registry `multisig_bundle.py`](https://github.com/jetpen/decent-registry/blob/main/src/decent_registry/multisig_bundle.py)

**Identity** delegates network, DHT, and Registry validation to `decent-registry`. Its
legacy `put_identity` path passes a private-key path to the Registry builder; its
finalized-envelope path reads exact envelope bytes and publishes them without private
key arguments. It derives `owner_name_hex` from raw UTF-8 identifier bytes with no
normalization:

- [Identity resolver](https://github.com/jetpen/decent-identity/blob/main/src/decent_identity/identity_resolver.py)
- [Identity README](https://github.com/jetpen/decent-identity/blob/main/README.md)
- [Registry service](https://github.com/jetpen/decent-registry/blob/main/src/decent_registry/registry_service.py)

### Researched or documented but unimplemented in the wallet

The ecosystem handoff explicitly assigns the wallet CSRNG policy, key lifecycle, secure
storage, signing integration, finalized-envelope handoff, and secret-disclosure tests
to the wallet repository. The wallet `README` states that private keys stay within the
wallet boundary, but the repository has no implementation. The Registry's own CSRNG
enhancement is also still an open issue and its implementation is on an unmerged branch,
not current `main`:

- [Wallet component handoff](https://github.com/jetpen/decent-ecosystem/blob/main/docs/components/decent-wallet.md)
- [Wallet README](https://github.com/jetpen/decent-wallet/blob/main/README.md)
- [Registry issue #105](https://github.com/jetpen/decent-registry/issues/105)
- [Unmerged CSRNG implementation commit](https://github.com/jetpen/decent-registry/commit/b3ca8679de497a108c43d0b370bbdf6e723d7f81)
- [Follow-up CSRNG boundary tests](https://github.com/jetpen/decent-registry/commit/1ae8344b698938bc384c9e59b10b4e764fb7f9ec)

The local repository check confirms commit `1ae8344` is not an ancestor of Registry
`main`. Therefore the CSRNG API below is evidence from the proposed/working Registry
change, not a claim that the released/current `main` CLI already enforces it.

### Proposed MVP design

The wallet should implement the secret boundary described below and use the existing
Registry codec, signature, validation, and finalized-envelope paths. A small in-memory
signer API or adapter is still required: the current legacy Registry builder is
filesystem-path based, while the wallet must not hand a PEM path or private bytes to a
separate Registry/Identity process. This report does not claim that such a wallet API
exists today.

### Long-term vision

Seed phrases, hardware-backed/non-exportable signers, recovery policies, key rotation,
portable identity, and multi-device synchronization are not established by Issue #3.
The Registry research describes these as separate future decisions; none should change
the current Identity Record wire contract or be smuggled into the MVP signing API.

## Existing algorithms and wire formats

### Key and signature primitives

| Item | Established behavior |
|---|---|
| Key algorithm | Ed25519 only in current Identity/Registry records. |
| Private input | 32 raw bytes used as the Ed25519 private-key input/seed. Registry CLI serializes it locally as unencrypted PKCS#8 PEM; PEM is not wire data. |
| Public key | 32 raw Ed25519 bytes in `owner_public_key` or a v1 signer-set entry. |
| Signature | 64 raw Ed25519 bytes. |
| Project signing message | `SHA-256(canonical_cbor(SignedUpdate))`; the resulting 32-byte digest is passed to the Ed25519 `sign`/`verify` operation. This is a project pre-hash convention; do not relabel it Ed25519ph without a protocol change. |
| Identifier/object key | Identity DHT key is `SHA-256(owner_name_bytes)`, where the bytes are the identifier's raw UTF-8 bytes and no normalization is performed. |
| Serialization | Canonical CBOR (`cbor2.dumps(..., canonical=True)`), with Registry decoders rejecting non-canonical input and wrong map shapes. |

The library boundary is consistent with the authoritative APIs: `cryptography` accepts a
32-byte Ed25519 private input and returns a 64-byte signature; its public-key API uses
32-byte raw public bytes. RFC 8032 specifies 32 octets of cryptographically secure
random data for Ed25519 key generation and the 32+32-octet signature structure:

- [cryptography Ed25519 API](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/)
- [RFC 8032 §5.1.5–§5.1.7](https://www.rfc-editor.org/rfc/rfc8032#section-5.1.5)
- [RFC 8032 test vectors](https://www.rfc-editor.org/rfc/rfc8032#section-7.1)

### Legacy single-owner Identity Record

```text
SignedUpdate = {
  1: record_fields,
  2: {},
  3: seq,
}
record_fields = {
  1: owner_name_bytes,
  2: owner_public_key,       # 32 bytes
}

SignedEnvelope = {
  1: signed_update_bytes,    # canonical CBOR bytes
  2: signature,               # 64-byte Ed25519 signature
}
```

`build_identity_envelope` constructs exactly this shape, signs the SHA-256 digest of the
canonical inner bytes, and wraps it. Registry validation additionally checks the derived
lookup key, signature, strict `seq` increase, and Owner Binding. The stored DHT value is
the complete envelope, not a private key or a PEM file.

### Version-1 explicit-signer Identity Record

The current v1 multisignature format keeps the Identity Record fields and adds
authorization to the inner update:

```text
SignedUpdate = {
  1: {1: owner_name_bytes, 2: owner_public_key},
  2: {},
  3: seq,
  4: authorization,
}
authorization = {
  1: 1,                       # explicit Ed25519 scheme
  2: 1,                       # Identity Record
  3: operation,               # genesis/update/replace/upgrade
  4: epoch,
  5: threshold,
  6: [{1: signer_id, 2: public_key}, ...],
  7: predecessor_state_hash, # 32 bytes
}

SignedEnvelopeV1 = {
  1: 1,
  2: signed_update_bytes,
  3: [{1: signer_id, 2: signature}, ...],
}
```

Signer IDs, signer public keys, proof signatures, thresholds, predecessor hashes,
canonical ordering, and operation-specific transition rules are validated by the
Registry. Every proof signs the same exact canonical `signed_update_bytes`; the bundle
workflow rejects a proof for different bytes. `sign_bundle` takes one local private-key
object and returns a detached proof; it does not put the private key in the bundle.
`finalize_bundle` emits a publishable envelope only after the applicable proof rule is
met. Partial bundles are local artifacts and must not be submitted as Registry state.

Canonical deterministic encoding matters here: RFC 8949 requires preferred serialization,
no indefinite-length items, and deterministic bytewise lexicographic map-key ordering for
its core deterministic encoding requirements. The Registry adds its own strict schema and
ordering checks on top:

- [RFC 8949 §4.2.1](https://www.rfc-editor.org/rfc/rfc8949#section-4.2.1)
- [Registry v1 wire documentation](https://github.com/jetpen/decent-registry/blob/main/docs/multisignature-records.md#2-wire-format)
- [Registry local bundle workflow](https://github.com/jetpen/decent-registry/blob/main/docs/multisignature-records.md#4-local-multisignature-bundle-workflow)

## CSRNG API and failure boundary

### Required contract

The wallet's production generation function should have one auditable path equivalent to:

```text
generate_ed25519_private_key() -> Ed25519PrivateKey
  seed = approved_system_csrng.token_bytes(32)
  require exact built-in bytes type and length 32
  return Ed25519PrivateKey.from_private_bytes(seed)
```

The Python `secrets` documentation identifies `secrets` as cryptographically strong,
preferred over `random`, and backed by the most secure randomness source provided by the
operating system. It defines `token_bytes(nbytes)` as returning that many random bytes.
That is the platform/library assumption to document; it is not evidence that
`Ed25519PrivateKey.generate()` exposes a sufficient provider/failure policy for this
wallet contract.

- [Python `secrets` documentation](https://docs.python.org/3/library/secrets.html#random-numbers)
- [`secrets.token_bytes`](https://docs.python.org/3/library/secrets.html#secrets.token_bytes)
- [RFC 4086 randomness requirements](https://www.rfc-editor.org/rfc/rfc4086)

The Registry CSRNG branch supplies a concrete reference implementation: a shared
`generate_ed25519_private_key` obtains exactly 32 bytes from an OS-backed `secrets`
boundary, rejects replacement of the approved provider, catches provider exceptions,
rejects malformed/wrong-length output, and raises a privacy-safe `KeyGenerationError`.
Its PEM writer acquires and serializes entropy before opening the destination, uses a
restrictive temporary file and atomic no-overwrite linking, and cleans up on failure.
The follow-up tests explicitly check that a failing CSRNG does not call
`create_new_key_pair` as a fallback, does not create/modify output, and does not expose
provider details or key material in CLI output.

Those semantics are the recommended wallet contract, but the branch is not current
Registry `main`. The wallet should reuse the generation primitive's security policy,
not the PEM writer: wallet storage must be encrypted and must not be replaced by an
ordinary unencrypted PEM file.

### Failure behavior (MVP MUST)

- CSRNG unavailable, raises, is monkey-patched/replaced, returns a non-`bytes` value, or
  returns anything other than 32 bytes: **fatal failure**.
- No PRNG, time, PID, counters, deterministic fixture, `create_new_key_pair`, or library
  fallback after CSRNG failure.
- No wallet record, output file, envelope, public-key registration, or partially written
  artifact is committed after generation failure.
- Errors/logs are fixed, redacted categories (for example, `key generation failed`),
  never provider exceptions, random bytes, PEM, or private-key serialization.
- Test injection, if needed, is explicit and test-only; production callers cannot pass a
  general provider through the public wallet API.

The Registry node's internal persisted libp2p node identity generation is a separate
operational path. It must not be used as a fallback for wallet owner-key generation.

## Wallet ↔ Identity/Registry signing boundary

### Inputs and outputs

**Wallet-local inputs:** user consent; raw owner-name bytes/identifier selected by the
application; the current `seq`/operation context; and, for v1, signer-set metadata and
exact canonical bundle bytes. The wallet may inspect and display public request metadata
before consent.

**Wallet-local secrets:** the Ed25519 private key/seed and encrypted wallet unlock
material. These remain in the wallet process/storage. The signer should accept a typed
request or exact canonical bytes, but never expose a secret through a return value,
callback, filesystem path, exception, log, clipboard, telemetry, or temporary file.

**Wallet outputs permitted to leave:**

- 32-byte `owner_public_key` (and, for v1, signer-set public keys and non-secret signer IDs);
- raw owner-name bytes as the Identity Record field and/or the derived 32-byte lookup key;
- canonical `SignedUpdate` bytes when needed for detached signing/exchange;
- one 64-byte legacy signature, detached v1 proof, or a finalized canonical SignedEnvelope;
- non-secret `seq`, operation, epoch, threshold, predecessor/state hashes, and validation
  results;
- a consent/failure/cancellation result, without secret-bearing diagnostics.

**Never permitted to leave:**

- 32-byte Ed25519 seed/private input, private-key objects, PKCS#8 PEM/DER, or raw private
  bytes;
- wallet password, password-derived encryption key, mnemonic, passphrase, BIP-39 seed,
  SLIP-0010 chain code, recovery shares, hardware authorization secrets, or unlock tokens;
- secret-bearing error text, debug logs, metrics, crash reports, test fixtures, URLs,
  command-line arguments, Registry/DHT values, partial bundles, or temporary files.

### Recommended call sequence

1. Wallet creates the key using the single CSRNG boundary and stores it in encrypted local
   storage. It derives the public key locally.
2. A pure Registry codec/adapter constructs the Identity Record's canonical
   `SignedUpdate` using the public key and raw owner-name bytes. The wallet displays the
   non-secret operation summary and obtains explicit user authorization.
3. The wallet signs `SHA-256(signed_update_bytes)` locally. For legacy mode it produces
   the canonical `{1, signed_update_bytes, 2, signature}` envelope. For v1 it produces a
   detached proof over the exact bytes; signer wallets exchange/merge proofs locally and
   finalize only after the threshold rule is satisfied.
4. Only the complete legacy or v1 SignedEnvelope is handed to
   `RegistryService.put_identity_envelope` / Identity's finalized-envelope path. The
   Registry validates canonical bytes, lookup-key binding, Ed25519 signatures, Owner
   Binding, `seq`, and v1 transition rules before DHT publication.
5. The wallet may retain its local encrypted key and audit metadata; it must not retain or
   publish partial Registry state as if it were accepted state.

This sequence reuses the established protocol and the existing finalized-envelope path.
It requires a wallet-facing in-memory signer/adapter because the current legacy
`build_identity_envelope` takes `owner_privkey_pem_path`. A future API may accept a
private signer object/callback, but that API must remain local to the wallet process; do
not pass a private key into the network-facing Registry service.

## MVP scope and unresolved decisions

**Recommended MVP:** implement one-wallet legacy Identity Record creation/update first,
with the exact existing wire shape, plus a separate v1 proof adapter if multisignature
participation is included in the first wallet release. In both cases, publish only a
complete envelope through the finalized-envelope path. Registry remains the authority
for validation and DHT publication; the wallet remains the authority for key custody,
secret operations, and user consent.

The following must be resolved in the wallet specification before coding:

- encrypted wallet storage format, unlock/lock lifecycle, and crash/backup behavior;
- whether the wallet stores a raw seed, PKCS#8, or another encrypted local representation;
- the exact public Python/API boundary for canonicalization and in-memory signing;
- how the wallet learns/chooses `seq` without bypassing Registry monotonicity;
- whether legacy single-owner signing, v1 multisignature signing, or both are MVP;
- zeroization and memory-lifetime guarantees (ordinary Python cannot guarantee complete
  zeroization of immutable copies);
- hardware-backed signing and recovery/rotation, which should remain separate interfaces.

No evidence supports publishing private material, using a seed phrase as an Identity
Record field, treating a partial bundle as Registry state, or allowing CSRNG degradation.

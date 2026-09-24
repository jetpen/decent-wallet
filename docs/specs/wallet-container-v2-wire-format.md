# Wallet-container v2 wire format

Status: normative writer profile for the current Python wallet-container v2 implementation. Cross-platform readers and writers should consume the known-answer fixture at [`tests/vectors/wallet-container-v2.json`](../../tests/vectors/wallet-container-v2.json). This document does not define native UI, platform key storage, or v1 migration; v1 migration is specified in [ADR-0003](../adr/0003-wallet-container-v1-to-v2-migration.md).

## 1. Byte and JSON conventions

- Text is Unicode encoded as UTF-8 without a BOM. Strings are not Unicode-normalized. Canonical writers use valid Unicode scalar values only; raw files with invalid UTF-8 are rejected. JSON-escaped lone surrogates are outside the interoperable profile and must not be emitted.
- Writers serialize JSON using the equivalent of Python's `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")`.
- Consequently, object keys are ordered lexicographically by Unicode code-point sequence; output has no insignificant whitespace; non-ASCII scalar values are emitted as UTF-8 rather than `\\u` escapes; JSON control characters and quotation marks use JSON escapes. Floats and non-finite numbers are not part of the wallet payload type system.
- Binary fields use standard RFC 4648 Base64 with the standard alphabet and `=` padding, with no whitespace. Decoders reject invalid alphabet, padding, or required byte lengths.
- Canonical serialization is the required writer form. The current Python reader parses UTF-8 JSON and validates the decoded schema but does not require the original file's whitespace or object-key order to be canonical. Do not rely on acceptance of noncanonical encodings or duplicate JSON object names for interoperability; conforming writers emit canonical JSON with unique names.

The canonicalization rule applies recursively to JSON objects. In addition, wallet payload maps have their own typed representation below; their entries are sorted by key before JSON serialization.

## 2. Outer envelope

A v2 container is the canonical UTF-8 JSON serialization of an object with exactly these top-level members:

```json
{
  "format": "decent-wallet",
  "version": 2,
  "kdf": { "algorithm": "argon2id", "memory_kib": 65536, "time_cost": 3, "parallelism": 4, "salt": "<base64-16-bytes>" },
  "wrap": { "algorithm": "xchacha20-poly1305", "nonce": "<base64-24-bytes>", "ciphertext": "<base64>", "tag": "<base64-16-bytes>" },
  "payload": { "algorithm": "xchacha20-poly1305", "nonce": "<base64-24-bytes>", "ciphertext": "<base64>", "tag": "<base64-16-bytes>" }
}
```

The example is schematic; production files contain no comments or placeholders. Missing or extra envelope/KDF/wrap/payload members are invalid. The current reader limits the complete file to 16 MiB. Only version 2 is accepted by ordinary `Wallet.open()` and `Wallet.import_container()`; explicit v1 migration is a separate operation.

## 3. Password KDF and DEK wrapping

1. Encode the password as UTF-8 without normalization. The wallet API enforces its password-length policy separately; the cryptographic KDF input is these UTF-8 bytes.
2. Decode the 16-byte `kdf.salt`.
3. Derive a 32-byte KEK with Argon2id version 19 (Argon2 1.3), memory cost 65,536 KiB, time cost 3, parallelism 4, and output length 32 bytes.
4. The wallet DEK is 32 bytes. Wrap it with XChaCha20-Poly1305 using the KEK, a 24-byte nonce, and the AAD below. Store the ciphertext and 16-byte tag as separate Base64 fields under `wrap`.

The exact wrap AAD is the canonical JSON serialization of the parsed `kdf` object together with the format and version:

```text
canonical_json({"format":"decent-wallet","version":2,"kdf":kdf})
```

The raw JSON spelling of the outer file is not AAD; the authenticated input is the reconstructed, canonical object shown above.

## 4. Typed payload and payload encryption

The payload plaintext is canonical JSON for a typed root map. The typed encoder supports only these values:

- null: `{"t":"null"}`
- boolean: `{"t":"bool","v":<boolean>}`
- string: `{"t":"str","v":<string>}`
- integer: `{"t":"int","v":<base-10 JSON integer>}`; integers are exact and may not be represented as floating point
- bytes: `{"t":"bytes","v":<standard padded Base64>}`
- list: `{"t":"list","v":[<typed value>,...]}`
- map: `{"t":"map","v":[[<string key>,<typed value>],...]}`

Map entries are sorted by key's Unicode code-point sequence and encoded as two-element arrays. Map keys must be strings and unique. The decoded root must be a map. Unsupported values such as floats are rejected. Booleans are encoded before integers and retain their distinct type.

Encrypt the canonical typed-payload bytes with XChaCha20-Poly1305 using the wallet DEK, a 24-byte payload nonce, and this exact AAD:

```text
canonical_json({"format":"decent-wallet","version":2,"payload":{"algorithm":"xchacha20-poly1305","nonce":payload.nonce}})
```

Only the payload algorithm and nonce appear in payload AAD; the ciphertext and tag are not included. Store the ciphertext and 16-byte tag separately under `payload`.

## 5. Known-answer vector

`tests/vectors/wallet-container-v2.json` is a fixed-input, public, synthetic test vector. Its plaintext password, DEK, Ed25519 seed, and payload are deliberately non-secret test values. They must never be reused in real wallets. The fixture's `$bytes_hex` marker is only a human-readable representation for byte inputs in the vector file; it is not part of the wallet wire format.

The fixture records the fixed inputs and expected Argon2id result, both AAD byte strings, typed-payload bytes, wrap/payload ciphertexts and tags, full canonical envelope bytes, and the resulting public key. `tests/test_container_vectors.py` checks those outputs and opens the fixed envelope through the public `Wallet.open()` API. Its negative cases cover authenticated-field tampering and a v2-to-v1 version relabel/AAD mismatch. Encryption in ordinary wallet creation remains randomized; the fixed values exist only in the test vector and test verification.

## 6. Version binding and failure behavior

Both AEAD contexts bind `version: 2`; relabeling a v2 envelope as v1 must fail authentication when evaluated with v1 AAD. Unknown, older, and newer formats fail closed under normal open/import. Wrong passwords and authentication failures return the wallet's stable unlock-failed error category. This format description does not change the v1 migration and rollback contract in ADR-0003.

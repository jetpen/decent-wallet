# Decent Wallet Account Disclosure v1

**Status:** Adopted as a normative v1 profile by the protocol owner. Requirements in this document are normative. The package is committed on [PR #52](https://github.com/jetpen/decent-ecosystem/pull/52) but not yet merged; [ecosystem issue #51](https://github.com/jetpen/decent-ecosystem/issues/51) remains open for merge and component qualification.

## 1. Scope and trust boundaries

This profile defines how a wallet discloses a user-approved subset of fields from its local Master Account Entity to one relying party (RP) using OpenID for Verifiable Presentations (OpenID4VP) 1.0. It composes with the project's OIDC Authorization Code + PKCE wallet-login flow. The disclosure is a self-assertion by the Identity Owner Key; it is not a third-party attestation.

The Master Account Entity is persisted only inside the authenticated wallet-container v2 payload. It is never uploaded, replicated, or disclosed to `decent-simple-storage`, Keycloak, or Registry. A presentation discloses selected values directly from wallet to RP. It is not a Storage grant, site session, or authorization to access resources. Site-specific Account Entity creation/enrollment and Storage authorization remain separate wallet-approved actions.

The existing `decent-wallet-login-v1` proof remains exactly `{profile,challenge,identity_id,signature}`. It MUST NOT contain account claims. Keycloak remains the sole component that resolves the exact current Registry Owner Key for that proof. The RP validates OIDC and the OID4VP presentation, performs no Registry lookup, and maps its account by `(iss, sub)`.

### 1.1 Actors

- **Wallet:** holds the Master Account Entity and Identity private key, collects one wallet approval per account-creation transaction, retains one-use pending approval, validates the post-OIDC continuation, and sends the presentation directly to the RP.
- **Keycloak:** validates the RP's signed account request and current Registry Owner Key, binds the requested site action and OIDC transaction, and issues the OIDC result and signed Owner-Key binding statement. It never receives account values.
- **RP:** owns signup/login UX and the local account/session; it validates OIDC before requesting the OID4VP continuation, and creates a local account only after validating the matching presentation.
- **Registry:** resolves current identity keys only through Keycloak's authentication path; no account claim or disclosure data is written to Registry.

## 2. Notation and common rules

The terms MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, and MAY are normative in this adopted profile. JSON messages are UTF-8. All JSON parsers MUST reject duplicate member names, invalid UTF-8, non-finite numbers, invalid Unicode scalar sequences, and unknown members in closed objects. Byte strings use base64url without padding unless a standard encoding explicitly says otherwise. Comparisons of identifiers, URIs, action values, claim IDs, and token claims are exact and case-sensitive unless this profile defines a canonicalization rule.

The profile identifier is `decent-account-disclosure-v1`; the OpenID4VP custom credential-format identifier is `decent_account_jwt_v1`. These are distinct identifiers and MUST NOT be interchanged.

Standard OpenID4VP transport envelopes are not closed custom objects: receivers MUST ignore unrecognized top-level parameters in the Authorization Request (including its signed Request Object), Authorization Response, and `direct_post` endpoint's JSON reply, as required by OpenID4VP §§5, 8.1 and 8.2. Unrecognized `client_metadata` entries MUST likewise be ignored under §5.1; they MUST NOT override the statically configured RP identity, certificate trust, or supported profile format. Under §6, receivers MUST also ignore unknown properties throughout DCQL, including the root, Credential Query, Claim Query, and format-specific `meta` object; selection and binding comparisons use only recognized fields after authenticating the complete Request Object. V1 senders emit `meta={}`; the custom format defines no recognized `meta` properties. V1 does not support DCQL `credential_sets`, `trusted_authorities`, or Claim Query `values`/`intent_to_retain`; these known constraints MUST be rejected rather than silently ignored. Ignored parameters MUST NOT supply identity, consent, account fields, or alternatives to validated known parameters; the original complete Request Object signature MUST still be verified. V1 does not support `transaction_data`: its presence in either the outer request or Request Object MUST cause rejection, not silent ignoring. All known required fields and profile bindings remain mandatory; known malformed or conflicting parameters MUST NOT be treated as unrecognized. The custom `decent_account` extension, Keycloak context/binding, credential, VP, and `vp_token` query-ID map remain closed. V1 senders MUST emit only the profile-defined transport parameters; the receiver allowances are compatibility rules, not permission for senders to add data.

All profile timestamps are integer Unix seconds. Unless a message explicitly names a different audience, protocol identifiers are compared as exact strings; do not normalize a URI before comparison.

## 3. Account actions and one-consent flow

V1 account-field disclosure supports two account-creation actions. `signup` creates a new Keycloak-local principal only when the exact principal does not already exist. `signup_recovery` is a distinct fresh-proof action used when an enabled exact Keycloak-local principal already exists but the RP-local account does not; it is not limited to identities created by a previous attempt at that RP. It may authenticate that exact existing principal only for this bound account-creation action. The RP MUST use `decent_account_action` with the exact selected action and MUST bind it to the registered OIDC client, its AuthenticationSession, the wallet transaction, and the OID4VP continuation. `prompt=login` MUST NOT be used to represent either account-creation action.

A `signup_recovery` attempt MUST start a new end-to-end transaction with fresh OIDC state, nonce and PKCE verifier, Request Object `jti`/`request_id`, wallet-login proof, and wallet approval; it MUST NOT resume or reuse any prior transaction or pending consent. Keycloak MUST require the exact existing Identity mapping and fresh valid proof. The RP MUST initiate recovery only for an absent local `(iss, sub)` account; if an account already exists, it MUST use the separate login path and disclose no fields. Recovery is limited to creating a site account for an existing Keycloak identity; it is not general password or identity recovery.

For either action, one wallet approval covers the fresh wallet-login proof and the RP's exact purpose/requested claim set. The Wallet MUST show the RP, selected action, purpose, and exact available values before approval. It MUST NOT prompt a second time to fulfill a matching post-OIDC continuation. The Wallet MUST disclose no fields until it validates the Keycloak Owner-Key binding statement and matches the continuation to the pending approval.

### 3.1 OIDC Authorization Request

The RP MUST use OIDC Authorization Code + PKCE and a signed OIDC Request Object conforming to RFC 9101 (JAR). The RP's public signing key and permitted algorithm MUST be registered in the Keycloak OIDC client configuration. V1 requires ES256 for this Request Object. The Request Object MUST be signed, and Keycloak MUST reject unsigned requests, `alg=none`, symmetric algorithms, unregistered keys, untrusted issuers, unsupported algorithms, invalid `aud`, and expired/replayed request objects.

The Request Object MUST contain the ordinary OIDC parameters required for Authorization Code + PKCE plus:

- `decent_account_action`: exactly one of `signup` or `signup_recovery`;
- `decent_account_request`: the closed request object below;
- the exact RP `client_id`, which is also the request `iss`;
- `aud`: the exact configured Keycloak realm issuer;
- fresh `state` and `nonce` values, each at least 128 bits of CSPRNG entropy;
- `iat`, `exp` no more than 300 seconds after `iat`, and a unique `jti`.

`decent_account_request` has exactly these members:

```json
{
  "profile": "decent-account-disclosure-v1",
  "request_id": "<base64url-no-pad-128-bit-random-value>",
  "purpose": "Create a site account at Example Site",
  "claims": [
    {"id": "urn:decent:account:v1:given_name", "required": true},
    {"id": "urn:decent:account:v1:email", "required": false}
  ]
}
```

The RP MUST use one unique `request_id` per account-creation attempt, including recovery. The object MUST contain 1–16 distinct registered claim IDs. `required` MUST be a JSON boolean. The `purpose` MUST contain 1–160 Unicode scalar values and at least one non-whitespace character. It MUST contain no C0/C1 control or Unicode bidirectional-control characters. The wallet MUST display it exactly as plain text and MUST NOT parse it as HTML or markup; the signed wire value is never rewritten. It MUST identify the site and whether this is new signup or account creation for an existing Keycloak identity, in user-understandable terms. The claim list is the maximum disclosure set for the transaction; it MUST NOT contain field values.

Keycloak MUST validate that the registered client, Request Object `iss`, and `client_id` are identical; that `aud` identifies the exact Keycloak issuer; that `decent_account_action` is exactly `signup` or `signup_recovery`; and that the extension has a valid profile, request ID, purpose, and only registered claim IDs. Keycloak MUST bind the validated request, OIDC `nonce`, OIDC `state`, client, action, and expiry to the AuthenticationSession. It MUST reject duplicate `request_id` values for the same client during the validity window. Keycloak MUST NOT persist or relay Master Account Entity values.

### 3.2 Keycloak wallet context

The existing wallet-login challenge response stays unchanged. In particular, the GET response remains exactly `{profile,challenge,csrf_token}` and contains no account field values. To expose the already-validated claim request to the wallet before the one approval, Keycloak MUST provide a distinct same-origin read-only context endpoint:

`GET /realms/{realm}/decent-wallet-login/v1/transactions/{handle}/disclosure-context`

The opaque transaction `handle` remains the existing 256-bit base64url-no-pad wallet-login locator. Keycloak MUST return `Cache-Control: no-store`, `Referrer-Policy: no-referrer`, `Content-Type: application/json`, and no redirect. It MUST return no OIDC tokens, wallet proof, Registry record, owner key, or claim value. The response has exactly these members:

```json
{
  "profile": "decent-account-disclosure-v1",
  "keycloak_issuer": "https://login.example/realms/site",
  "rp_client_id": "site-client",
  "rp_display_name": "Example Site",
  "rp_origin": "https://site.example",
  "action": "signup",
  "request_id": "<request-id-from-validated-rp-request>",
  "transaction_id": "<derived-keycloak-transaction-id>",
  "oidc_nonce": "<exact-oidc-request-nonce>",
  "purpose": "Create a site account at Example Site",
  "claims": [
    {"id": "urn:decent:account:v1:given_name", "required": true},
    {"id": "urn:decent:account:v1:email", "required": false}
  ],
  "expires_at": 1799999999
}
```

The issuer, RP client, display name, and origin MUST come from trusted Keycloak realm/client configuration, not an untrusted Host header, arbitrary forwarded header, or browser-supplied URL. `request_id`, purpose, and claims MUST come from the RP Request Object after signature validation. The `oidc_nonce` MUST be the exact nonce bound to the OIDC AuthenticationSession. The response MUST correspond to the wallet-login handle and the currently pending transaction; stale, unknown, or cross-client handles fail closed.

`transaction_id` is derived by both Keycloak and Wallet as:

`BASE64URL_NOPAD(SHA-256(ASCII(handle)))`

The result is a correlation identifier, not a bearer credential. It MUST NOT be used in place of the raw handle for transaction lookup. Keycloak MUST bind the derived ID to its authenticated OIDC transaction. The Wallet MUST independently derive it from the handle in the scanned transaction URL and compare it with the context response.

## 4. Wallet consent and pending approval

The Wallet MUST verify normal HTTPS certificate/hostname validation for the configured Keycloak origin before retrieving challenge or disclosure context. It MUST reject HTTP, unconfigured origins, redirects to another origin, malformed handles, and unexpected URL components. The Wallet MUST display the normalized configured site origin and configured site name, not free-form QR text.

Before sending the wallet-login proof, the Wallet MUST show one approval screen with:

- the Keycloak site origin/name and RP display name/origin;
- a human-readable label for the exact selected action (`signup` creates a new Keycloak identity; `signup_recovery` creates a site account for an existing Keycloak identity) and the exact RP purpose;
- a clear warning that the exact Identity ID appears as issuer/subject in the signed credential and presentation, and the stable Owner-Key thumbprint appears in the credential and Keycloak binding; relying parties can correlate this user's presentations across sites, and V1 provides no pairwise identifier;
- every requested field ID and its available value;
- which claims are required and which optional claims the user may omit;
- a clear statement that the values are owner-asserted and contact claims are not verified by this signature.

The user may deny/cancel the whole request. Required claims cannot be individually omitted; if unavailable or denied, the Wallet MUST deny without partial approval. The user MAY omit any optional claim. After approval, the Wallet MUST persist one pending record inside the existing authenticated encrypted wallet-container v2 payload, bound to the exact issuer, RP client/origin, action, request ID, purpose, OIDC nonce, Keycloak transaction ID, full requested claim list, user-approved subset, exact selected values, and expiry. It MUST NOT create another encryption key, record envelope, or plaintext cache on disk.

The pending approval MUST expire at the earliest of the Keycloak transaction expiry and 300 seconds after creation. It MUST be single-use. Authentication failure, cancellation, mismatch, expiry, or replay MUST produce no disclosure. A mismatch invalidates that pending approval; a new wallet approval is required. A valid retry MAY resend the exact byte-identical presentation/JWS after an ambiguous network result, but MUST NOT create a second presentation, alter values, or ask the user to approve again.

## 5. Keycloak Owner-Key binding statement

After successful wallet proof verification and OIDC transaction completion, Keycloak MUST include a `decent_owner_key_binding` claim in the OIDC ID token. The claim value is a compact JWS signed by the Keycloak realm key, using `RS256` and protected `typ=decent-owner-key-binding+jwt`. Keycloak MUST publish the matching public signing key in its configured OIDC JWKS. The same claim value MUST be usable by RP and Wallet after signature validation.

The compact JWS payload is a closed object with exactly:

```json
{
  "v": 1,
  "iss": "https://login.example/realms/site",
  "aud": "site-client",
  "sub": "<opaque-keycloak-subject>",
  "identity_id": "<exact-identity-id-from-wallet-proof>",
  "owner_key": {"kty": "OKP", "crv": "Ed25519", "x": "<base64url-no-pad-32-byte-public-key>"},
  "owner_key_thumbprint": "<RFC7638-jwk-thumbprint>",
  "action": "signup",
  "transaction_id": "<derived-keycloak-transaction-id>",
  "request_id": "<validated-rp-request-id>",
  "oidc_nonce": "<exact-oidc-nonce>",
  "iat": 1799999700,
  "exp": 1799999999,
  "jti": "<base64url-no-pad-256-bit-random-value>"
}
```

The payload MUST be signed only after Keycloak has verified the exact raw `identity_id` against the current Registry-resolved Ed25519 Owner Key and verified the wallet proof. `owner_key` MUST be the exact public key used for that proof; its RFC 7638 thumbprint MUST equal `owner_key_thumbprint`. Private JWK members MUST NOT be present. `aud` MUST be the exact RP OIDC `client_id`; `sub` MUST equal the outer ID-token `sub`; `iss` MUST equal the outer ID-token issuer; `oidc_nonce` MUST equal the outer ID-token nonce and the nonce in the validated RP request; `transaction_id`, `request_id`, and `action` MUST match the Keycloak AuthenticationSession. `exp` MUST be no more than 300 seconds after `iat` and no later than the OIDC transaction expiry or the outer ID-token `exp`. `jti` MUST be unique per issuer.

The ID token and binding statement MUST contain no Master Account Entity fields. The RP MUST validate the OIDC authorization transaction with a maintained OIDC implementation: bind the authorization response's `state` to the initiating local transaction and validate the authorization-code exchange using the exact stored PKCE verifier. Separately, it MUST validate the ID token's signature/allowed algorithm, exact issuer, audience, authorized party where applicable, expiry/time, and OIDC `nonce`. It MUST then validate the nested binding JWS and all relationships above. The Wallet MUST validate the nested binding JWS against the Keycloak issuer's trusted discovery/JWKS and compare its issuer, RP client, action, transaction ID, request ID, OIDC nonce, expiry, and identity ID with the pending approval. The Wallet MUST NOT perform Registry lookup.

This mechanism does not give the Wallet cryptographic evidence that the RP actually validated OIDC: only the RP can validate its own code exchange and browser session. The binding statement authenticates the Owner Key and Keycloak transaction; the RP-signed Request Object authenticates the RP's continuation request. V1 therefore trusts the RP to issue that request only after successful OIDC validation, and requires RP tests to prove the ordering. The Owner-Key binding statement is not a Keycloak-signed OIDC-completion receipt. A deployment that requires the Wallet itself to verify successful RP OIDC validation needs a separately designed Keycloak-signed one-use completion receipt; that is not silently implied by this profile.

## 6. OpenID4VP continuation request

The RP MUST create the OID4VP Authorization Request only after it has validated the successful OIDC callback, ID token, and binding JWS. It MUST perform its local `(iss, sub)` account-state check first. If the RP local account already exists for that subject, it MUST NOT create a disclosure request or accept profile fields; it directs the user to its login path.

V1 uses OpenID4VP 1.0 with a pre-registered verifier identity using the `x509_san_dns` Client Identifier Prefix, `response_type=vp_token`, `response_mode=direct_post`, a signed Request Object delivered by `request_uri`, and a registered HTTPS `response_uri`. `client_id` is `x509_san_dns:<lowercase-DNS-name>` and MUST match the DNS subjectAltName in the leaf certificate in the signed Request Object's `x5c` chain. The Wallet MUST validate the certificate chain, signature, validity time, SAN, and exact relationship between `client_id` and the configured site origin. The `response_uri` hostname MUST equal the DNS name in `client_id`; arbitrary redirects and request-selected alternate endpoints are forbidden.

The Request Object MUST be signed using ES256, contain `client_id` equal to the outer Authorization Request's `client_id`, and use `aud=https://self-issued.me/v2` for this static-discovery profile. The Request Object MUST omit `iss`; if present, the Wallet MUST ignore it as required by OpenID4VP. The Request Object MUST be returned from `request_uri` using `Content-Type: application/oauth-authz-req+jwt`, HTTPS, `Cache-Control: no-store`, and a lifetime no longer than 300 seconds. The `response_uri` MUST be the exact registered endpoint in the RP's static metadata. `client_metadata.vp_formats_supported` MUST advertise `decent_account_jwt_v1` with `alg_values=["EdDSA"]`.

The sender's Authorization Request MUST contain only the exact same `client_id` and `request_uri` (and no conflicting authorization parameters). Receivers ignore unrecognized parameters under §2, but MUST reject additional known authorization parameters in this outer envelope rather than allowing them to override the signed Request Object. Its DCQL Credential Query MUST have `id="account"`, `format="decent_account_jwt_v1"`, `multiple=false`, `meta={}`, `require_cryptographic_holder_binding=true`, the exact registered claim paths from the signed extension, and the profile-defined `claim_sets` alternatives below. Each DCQL claim uses a short unique `id` (`given_name`, `family_name`, `email`, `phone`, or `locale`) and a `path` of `["claims", "urn:decent:account:v1:<name>"]` into the inner credential. The query MUST include every initial claim, including optional claims; it MUST NOT remove an optional claim to encode wallet consent. The RP MUST include exactly all combinations of required claims plus each possible subset of optional claims in `claim_sets`, ordered by increasing disclosed-claim count and then by the original claim order. V1 requires at least one required claim and allows at most four optional claims, so the query has at most 16 alternatives. The Wallet MUST select only a claim set exactly matching the user's explicit approval and available local values; it MUST NOT return any claims unless it can satisfy one whole `claim_set`. A required claim the user denies or the Wallet lacks causes cancellation. Optional claims omitted by the user or unavailable locally are left out of the selected claim set. This profile's user-selection rule is the reason the Wallet may return a later alternative instead of the first lower-disclosure set; it MUST NOT treat the Verifier's ordering preference as user consent.

The request MUST contain a fresh OID4VP `nonce` of at least 256 bits and a separate fresh `state` of at least 128 bits. These values MUST be independent of OIDC `state`, OIDC `nonce`, Keycloak transaction ID, RP request ID, wallet-login challenge, and QR handle. The DCQL query MUST request one `decent_account_jwt_v1` presentation and only registered claim IDs from the initial request. The `decent_account` extension MUST contain exactly:

```json
{
  "profile": "decent-account-disclosure-v1",
  "rp_oidc_client_id": "site-client",
  "action": "signup",
  "request_id": "<same-initial-request-id>",
  "transaction_id": "<same-keycloak-transaction-id>",
  "purpose": "Create a site account at Example Site",
  "owner_key_binding": "<exact-compact-decent-owner-key-binding-jws>",
  "claims": [
    {"id": "urn:decent:account:v1:given_name", "required": true},
    {"id": "urn:decent:account:v1:email", "required": false}
  ]
}
```

This extension MUST match the binding statement and initial consent context exactly. The RP MUST NOT alter purpose, claim IDs, required flags, action, request ID, transaction ID, or binding statement. It MUST include all claims from the initial RP request in the DCQL `claims` array, including optional claims, and create the complete profile-defined `claim_sets` from the required flags; it MUST NOT omit an optional path to encode the user's later choice. For each selected DCQL short claim ID, its `path` MUST resolve to the corresponding namespaced member in the inner credential's `claims` object. The selected short IDs MUST equal one requested `claim_set`; the path-resolved namespaced IDs MUST equal the user's explicitly approved subset, and every value MUST be present locally. The Wallet MUST NOT return any claims unless it can satisfy one whole requested `claim_set`. The OID4VP request MUST NOT contain profile values, access tokens, the OIDC ID token, or the raw QR handle.

## 7. Presentation format and claim registry

### 7.1 Custom OpenID4VP format

`decent_account_jwt_v1` is a project-defined OpenID4VP format. It represents an Owner-issued self-asserted account credential inside a separate Owner-signed Verifiable Presentation. The Identity Owner Key is both Credential Issuer and Presentation Holder; `iss` and `sub` are the exact raw Identity ID in both objects. The credential makes no third-party or external truth claim. The two compact JWS objects make the issuer signature and the holder-binding proof structurally distinct, even though the same key signs both. V1 does not claim W3C VC data-model, SD-JWT VC, or third-party attestation conformance. Wallet and RP MUST advertise/support the custom format in OID4VP metadata and MUST reject a peer that does not support it.

OpenID4VP `require_cryptographic_holder_binding=true` requires the Wallet to return a Verifiable Presentation of a Verifiable Credential. For this format, the inner `decent_account_assertion_v1` JWS is the credential issued by the Identity Owner Key; the outer `decent_account_presentation_v1` JWS is the VP and its cryptographic holder-binding proof. The holder signature covers the complete VP payload, including the exact embedded credential JWS, verifier audience, OID4VP nonce, times, and presentation JTI. The RP MUST verify both signatures against the same Owner Key from the Keycloak binding statement and MUST verify exact issuer/subject equality. This format-specific mapping is not a generic OpenID4VP interoperability claim.

The `vp_token` is a JSON object mapping DCQL Credential Query ID `account` to an array containing exactly one outer presentation JWS: `{"account":["<compact-presentation-JWS>"]}`. The HTTP form parameter `vp_token` carries that JSON-encoded object. The outer JWS protected header has exactly:

```json
{"alg":"EdDSA","kid":"<RFC7638-owner-key-thumbprint>","typ":"decent-account-presentation+jwt"}
```

The inner credential JWS protected header has exactly:

```json
{"alg":"EdDSA","kid":"<RFC7638-owner-key-thumbprint>","typ":"decent-account-credential+jwt"}
```

Both protected headers and payloads MUST be serialized using RFC 8785 JCS, encoded as UTF-8, then base64url-no-pad encoded as required by JWS Compact Serialization. Each signing input is standard ASCII `BASE64URL(protected) + "." + BASE64URL(payload)` and each signature is Ed25519 over that exact input. Both signatures use the same current Registry Identity Owner Key that Keycloak used to verify the wallet-login proof, as identified by the Keycloak binding JWS.

### 7.2 Closed credential and presentation payloads

The inner credential payload has exactly:

```json
{
  "profile": "decent-account-disclosure-v1",
  "credential_type": "decent_account_assertion_v1",
  "iss": "<exact-identity-id>",
  "sub": "<exact-identity-id>",
  "iat": 1799999700,
  "exp": 1799999999,
  "jti": "<base64url-no-pad-256-bit-credential-jti>",
  "action": "signup",
  "rp_oidc_client_id": "site-client",
  "request_id": "<same-initial-request-id>",
  "transaction_id": "<same-keycloak-transaction-id>",
  "purpose": "Create a site account at Example Site",
  "owner_key_thumbprint": "<RFC7638-jwk-thumbprint>",
  "owner_binding_jti": "<binding-statement-jti>",
  "claims": {
    "urn:decent:account:v1:given_name": "Ada",
    "urn:decent:account:v1:email": "ada@example.test"
  }
}
```

The outer VP payload has exactly:

```json
{
  "profile": "decent-account-disclosure-v1",
  "iss": "<exact-identity-id>",
  "sub": "<exact-identity-id>",
  "aud": "x509_san_dns:site.example",
  "nonce": "<exact-oid4vp-nonce>",
  "iat": 1799999700,
  "exp": 1799999999,
  "jti": "<base64url-no-pad-256-bit-presentation-jti>",
  "vp": {
    "type": ["decent_account_presentation_v1"],
    "verifiableCredential": ["<one compact decent_account_assertion_v1 JWS>"]
  }
}
```

The inner credential MUST populate `iss` and `sub` with the exact raw Identity ID from the pending wallet-login proof. Its action, RP, purpose, request, transaction, Owner Key thumbprint, binding JTI, and claims MUST match the verified continuation and pending approval. `iat` MUST be no more than 60 seconds in the future. `exp` MUST be greater than `iat`, no more than 300 seconds after `iat`, and no later than the minimum expiry of the pending approval and Keycloak binding statement. Credential `jti` MUST be a new 256-bit random identifier. The outer VP MUST use the same `iss` and `sub`, set `aud` to the exact OpenID4VP `client_id` and `nonce` to the exact request nonce, and have an independent new 256-bit random `jti`. Its `exp` MUST be no later than the credential expiry, pending approval expiry, or OID4VP request expiry. The RP MUST reject unknown/additional members, duplicate or mismatched identifiers, and every unrequested claim.

The RP MUST verify the outer holder-binding signature and the inner credential-issuer signature with the Owner public JWK in the Keycloak-signed binding JWS; verify that both `kid` values and the credential thumbprint equal its RFC 7638 thumbprint; and validate the identity, audience, nonce, times, action, transaction, request, purpose, and claim set. The DCQL claim path `['claims', claim_id]` addresses the inner credential's `claims` object. The RP MUST NOT query Registry. The two signatures prove assertion source, integrity, holder possession, and transaction binding only; they do not prove the truth or reachability of claims.


### 7.3 V1 claim registry

The Master Account Entity remains schema-open and local to the Wallet. V1 disclosure is restricted to the finite allowlist below. Each value is a non-empty JSON string with at most 1024 UTF-8 bytes; empty strings, nulls, arrays, objects, and numeric values are rejected. The JSON Schema's `minLength`/`maxLength` enforce a 1–1024 character bound, but `maxLength` does not enforce UTF-8 byte length. Every consumer MUST separately reject values whose UTF-8 encoding exceeds 1024 bytes, before signing or accepting them. No string normalization is performed by the protocol. An implementation MAY apply input validation when editing an entity, but MUST preserve and sign the selected stored value exactly.

| Claim ID | Meaning | Verification semantics |
|---|---|---|
| `urn:decent:account:v1:given_name` | Owner-asserted given name | Not externally verified. |
| `urn:decent:account:v1:family_name` | Owner-asserted family name | Not externally verified. |
| `urn:decent:account:v1:email` | Owner-asserted email address | Does not prove inbox ownership or reachability. |
| `urn:decent:account:v1:phone` | Owner-asserted phone number | Does not prove number ownership or reachability. |
| `urn:decent:account:v1:locale` | Owner-selected BCP 47 language tag | Syntax may be validated as BCP 47; no other claim is implied. |

A Wallet MUST reject unknown claim IDs. It MUST source values only from the Master Account Entity; it MUST NOT synthesize, derive, or disclose other claims. A presentation MUST include exactly the user-approved claims requested by the continuation, no more than 16 claims, and the complete outer compact VP JWS MUST be no more than 16 KiB UTF-8. If a required claim is absent or not approved, the Wallet sends an OID4VP error/cancellation with no `vp_token`. If an optional claim is absent or omitted by the user, it is omitted from the inner credential's `claims` object.

## 8. OID4VP response and RP account behavior

The Wallet MUST send the OID4VP Authorization Response to the exact `response_uri` using OpenID4VP `direct_post`, HTTPS, and UTF-8 `application/x-www-form-urlencoded` encoding. The response MUST carry the exact `state` and a JSON-encoded `vp_token` object shaped as `{"account":["<one compact presentation JWS>"]}`; it MUST NOT put the presentation or transaction secrets in a URL, referrer, QR, log, analytics record, or Keycloak request. The response endpoint MUST use no-store policy and redact request/response contents from telemetry. On successful processing, the endpoint MUST return HTTP 200 with `Content-Type: application/json`, `Cache-Control: no-store`, and a JSON `redirect_uri` required by this v1 profile (the member is optional in base OpenID4VP `direct_post`). That URI MUST be an RP-controlled, same-origin callback carrying a fresh 256-bit one-use `response_code` in its fragment. The callback MUST exchange the code for only a bounded transaction-complete status, never profile values or an authenticated session; it MUST consume the code once, remove the fragment from browser history immediately, and return no-store/no-referrer headers. The RP's original browser session polls its own authenticated OIDC transaction; the response code is not an OIDC credential. A response code expires within 60 seconds, is bound to the accepted direct-post transaction, and cannot be used to fetch presentation content. Error responses follow the OpenID4VP Authorization Error Response shape and disclose no claim values.

The RP MUST first validate the OIDC authorization transaction and ID token as specified in §5, and bind that transaction to the signed Request Object, state, nonce, client, and PKCE verifier. It MUST then verify the Keycloak binding JWS and OID4VP Request Object, verify the outer presentation and inner credential signatures, validate the credential claims, then atomically consume the binding JTI, credential JTI, and presentation JTI with site-account creation. The RP's database transaction MUST enforce a unique `(iss, sub)` account key and unique `(keycloak_issuer, binding_jti)`, `(rp_client_id, credential_jti)`, and `(rp_client_id, presentation_jti)` replay keys. Account creation, all replay-consumption records, and an immutable accepted-response digest MUST be one atomic commit. The digest MUST cover the exact decoded OID4VP `state` and the complete compact presentation JWS bytes; the endpoint MUST reject duplicate form parameters and malformed or conflicting known parameters; it MUST ignore unrecognized form parameters as required by OpenID4VP §8.1. If the platform cannot provide that transaction, it MUST use an equivalent idempotent transaction/outbox scheme and MUST NOT claim v1 conformance until race behavior is verified.

### 8.1 Keycloak and RP account-state rules

Every RP MUST declare exactly one site-local signup policy, `open` or `closed`; missing or invalid configuration MUST fail closed and MUST NOT create an account. This policy is enforced by the RP and does not change Keycloak's exact-identity/new-principal rules. Under `open`, the RP permits account creation without administrator approval, then applies the site's ordinary authorization rules. Under `closed`, after successful OIDC validation and a matching accepted wallet disclosure, the RP MUST create the new site account in a pending administrator-approval state and MUST withhold all site access until a site administrator explicitly approves it. Disclosure consent or successful OIDC authentication is not administrator approval. Administrator approval MUST NOT expand the approved disclosure or repeat/trigger profile release.

- **Login:** Keycloak requires a fresh wallet proof and an existing exact Identity mapping. The RP validates OIDC and maps `(iss, sub)` to an existing local account. Login has no OID4VP disclosure; a closed-policy account still pending approval remains denied access.
- **Signup with a new Keycloak-local principal:** Keycloak verifies current Registry state and proof, then creates exactly one principal for the exact Identity ID. It does not create an RP account.
- **Signup with an existing exact Keycloak-local principal:** under the `signup` action, Keycloak MUST fail without authenticating that principal, issuing a signup binding statement, creating a duplicate, or causing profile disclosure. The RP MAY direct the user to the separate login action; login itself has no OID4VP disclosure.
- **Signup recovery with an existing exact Keycloak-local principal:** under `signup_recovery`, Keycloak MUST require a fresh wallet proof and current Registry verification for the exact existing Identity mapping; it MUST NOT create or alter a Keycloak principal. It MAY authenticate that exact principal only for this bound recovery transaction and issue a binding statement with `action=signup_recovery`. Missing, ambiguous, disabled, or nonmatching mappings MUST fail closed. The RP MUST verify that no local `(iss, sub)` account exists before issuing the recovery transaction; an existing account uses login and receives no disclosure. If no Keycloak principal exists, recovery MUST fail and MUST NOT create one.
- **RP account already exists:** after OIDC validation, the RP finds an existing `(iss, sub)` account and MUST NOT issue an OID4VP continuation or disclose fields. It directs the user to login.
- **RP account absent:** after successful OIDC and a fresh matching continuation, the RP MUST create the site-local account from only the fields in the accepted presentation. For `open`, administrator approval is not required for account creation; ordinary site authorization applies. For `closed`, the account MUST be recorded as pending administrator approval and all site access MUST remain withheld until approval. The RP MUST NOT perform Registry lookups and MUST NOT create a Storage Account Entity, Storage grant, or provider enrollment from these fields.
- **Concurrent account creation:** a unique `(iss, sub)` constraint and atomic replay/account transaction allow at most one site account. A losing concurrent signup or recovery response does not disclose or create a duplicate; it receives a generic already-completed/continue-to-login result.
- **OIDC failure:** the RP creates no continuation and no site account; the Wallet releases no fields.
- **OIDC success but disclosure/network failure:** no RP account exists unless the atomic account transaction committed. The Keycloak principal created for the attempted signup may remain. The user may start a separate `signup_recovery` transaction with fresh proof and fresh wallet consent; this action requires the exact existing principal and an absent RP account. Same-transaction byte-identical response retry remains governed by §9 and does not start a new signup or recovery action.
- **Failure after presentation validation but before account commit:** RP rolls back both account creation and replay markers. The same byte-identical response may be retried only within the original unexpired transaction; otherwise a fresh end-to-end approval is required.
- **Failure after atomic commit:** the RP treats the account as created and returns an idempotent success only when the retry's accepted-response digest, transaction, and account subject exactly match the committed receipt; it does not consume a second presentation or duplicate account. A different response or subject MUST fail without revealing account existence.

The provider-principal rules follow the owner-confirmed requirement: explicit `signup` creates only a new Keycloak-local principal and fails when the exact principal already exists; `signup_recovery` is the separate, fresh-proof path for creating an RP account for an existing exact principal when no RP account exists. Login remains separate and never releases account fields.

## 9. One-use state, expiry, and errors

The Wallet approval lifecycle is:

```text
PENDING -> OIDC_BOUND -> CONTINUATION_VERIFIED -> PRESENTATION_SENT -> CONSUMED
    |            |                 |                    |
    +-> DENIED   +-> EXPIRED       +-> FAILED           +-> EXPIRED
```

The Keycloak transaction is one-use for wallet proof. The RP binding JTI, credential JTI, and presentation JTI are one-use under the atomic RP transaction in §8. Before commit, a retry may repeat the same decoded `state` and byte-identical compact presentation JWS only for the same OIDC transaction, signed request, binding JTI, credential JTI, presentation JTI, and unexpired state. After commit, the RP may return idempotent success only by matching the immutable accepted-response digest and receipt containing `keycloak_issuer`, `binding_jti`, transaction ID, account subject, credential JTI, presentation JTI, and response digest, all stored atomically with the account. The matching receipt case is an exception only for returning the already-committed bounded completion status: it MUST NOT re-accept the response, consume another presentation, repeat account creation, or return claim values. A changed payload, claim, audience, nonce, action, client, purpose, transaction, or key is replay/mismatch and MUST fail. Concurrent identical retries MUST converge on that single committed receipt; concurrent differing responses MUST fail closed.

The RP MUST reject an expired or already-consumed binding, credential, or presentation for every new acceptance. Only the exact post-commit receipt match above may return the same bounded completion status; if replay state is unavailable, the RP MUST fail closed. Keycloak MUST reject stale, replayed, or cross-session account requests and MUST not issue a binding statement on invalid Registry/proof state. The Wallet MUST reject a continuation with any mismatch and erase its pending values on denial, cancellation, expiry, successful consumption, or mismatch.

Errors MUST NOT reveal whether a particular Identity ID, claim, email/phone value, local account, or Owner Key exists. Logs MUST redact raw Identity IDs, QR handles, JWS values, tokens, claims, claim values, signatures, and proof bodies. Operational audit may store non-reversible transaction digests, bounded outcome codes, and timestamps subject to a documented retention policy.

## 10. Limits and privacy requirements

- Request claim count: 1–16; presentation claim count: 1–16; claim value: at most 1024 UTF-8 bytes; compact presentation: at most 16 KiB; malformed or oversized input fails before expensive processing.
- OIDC request object, Keycloak transaction, binding statement, and OID4VP request/presentation lifetimes are each at most 300 seconds; accepted clock skew is 60 seconds. Every validation uses the earliest relevant expiry.
- The transaction handle, OIDC state/nonce, OID4VP state/nonce, account request ID, binding JTI, and presentation JTI are independent values with separate purposes and MUST NOT be reused across transactions.
- HTTPS certificate and hostname validation is mandatory for all endpoints. No redirects to another origin, untrusted forwarded-host selection, arbitrary response URI, or client-controlled callback is allowed.
- Request URI and response URI resources use `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. Query strings, bodies, identity values, profile values, tokens, and proof material are redacted from access logs and telemetry.
- Keycloak and Storage receive no claim values. Registry stores no Master Account Entity or claim values. RP receives only fields the user approved and only after successful OIDC and valid binding.
- A valid owner signature is never represented as external verification. In particular, email and phone values are not verified contact channels.
- V1 discloses the exact Identity ID as credential/presentation issuer and subject, and exposes a stable Owner-Key thumbprint. Relying parties can correlate presentations across sites; V1 does not provide pairwise identifiers or unlinkability. The Wallet MUST explain this before approval as required by §4.

## 11. Conformance artifacts and qualification boundaries

The sibling files in this package define the JSON Schemas, a machine-readable vector manifest, cryptographically valid positive fixtures, and negative vectors. `verify.py` checks schema validity, strict duplicate-member handling, canonical JCS bytes, JWS signatures, Keycloak binding relationships, exact claim allowlists, audience/nonce/action/transaction binding, and required rejection cases.

Passing the ecosystem verifier proves only that the package's fixed public vectors and schema are internally consistent. It does not prove wallet UI behavior, encrypted pending-state persistence, Keycloak HTTP/Registry behavior, real OIDC, multi-node durability, RP application database atomicity, or actual no-disclosure ordering. Each component repository MUST consume these exact fixtures unchanged and run its own contract tests. The first RP must also prove no profile claim reaches Keycloak/Storage and no account is created before validating OIDC and the matching presentation.

## 12. Remaining publication, security, and implementation gates

Before issue #51 can be marked complete or closed, publish/merge this adopted profile and its vectors; independent security/privacy review must record what each signature proves and does not prove; wallet, Keycloak, and first-RP consumers must run the unchanged vectors and their integration tests; Keycloak/RP tests must prove `signup` creates only a previously absent principal, `signup_recovery` requires a fresh proof for an enabled existing exact principal plus an absent RP account, and recovery fails without disclosure when either precondition is false or the principal is disabled; RP tests must cover open/closed policy and prove closed accounts cannot access the site before administrator approval; and the RP must prove no disclosure occurs before OIDC transaction/ID-token validation. Those component tests belong in their owner repositories, not in this ecosystem package. The issue remains open until every live acceptance criterion and review gate is evidenced.

## 13. Standards references

- [OpenID for Verifiable Presentations 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html): Authorization Requests, Request Objects, static discovery audience, `x509_san_dns`, DCQL, `vp_token`, nonce/audience binding, and `direct_post`. This project-defined format is an explicit extension and does not claim generic wallet support.
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0-final.html): Authorization Code flow, ID-token validation, issuer, audience, nonce, and `azp`.
- [RFC 9101](https://www.rfc-editor.org/rfc/rfc9101): OAuth 2.0 JWT-Secured Authorization Request (JAR).
- [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515): JSON Web Signature.
- [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638): JSON Web Key Thumbprint.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JSON Canonicalization Scheme.
- [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280): X.509 certificate and DNS Subject Alternative Name validation.

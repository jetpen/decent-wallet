# OID4VP Authorization Request verifier boundary

`decent_wallet.oid4vp_request.verify_oid4vp_authorization_request` is an offline verifier seam. Callers provide the outer Authorization Request mapping, the already-fetched compact signed Request Object, immutable static registration metadata (OID4VP `client_id`, OIDC RP client ID, exact origin, exact response URI, SAN DNS name, and SHA-256 trust-anchor fingerprint), the authenticated pending disclosure context, the exact Owner-Key binding JWS previously validated against that context, and an independently verified binding result. The verifier requires static origin and OIDC client registration to match `context.rp_origin` and `context.rp_client_id`; it does not infer trust metadata from the request.

The verifier verifies the Request Object signature and pinned certificate sequence before accepting claims. Its certificate check is a deliberately small pinned-chain check, not a general-purpose PKI path builder; deployments requiring complete PKIX policy processing must supply that through a maintained verifier before using this slice. It validates Request Object time bounds, endpoint and client bindings, the closed `decent_account` extension, and supported DCQL selection rules. Standard transport and DCQL envelopes permit unrecognized members as required by the profile; recognized unsupported fields such as `transaction_data`, `credential_sets`, `trusted_authorities`, `values`, and `intent_to_retain` are rejected.

## Caller duties and limits

The caller owns transport: fetch `request_uri` only over HTTPS, reject redirects, enforce a bounded response body and the expected `application/oauth-authz-req+jwt` content type, use `Cache-Control: no-store`, and prevent request URLs from leaking through referrer headers/policy. The caller must authenticate the pending context and Owner-Key binding (including its OIDC transaction), and must bind the request result to user consent and available local values.

This verifier module does not fetch URLs, follow redirects, parse or validate an OIDC callback or ID token, persist pending/consent state, render UI or obtain consent, sign a VP/presentation, validate a `direct_post` response or reply, access Android UI or Registry, or modify issue tracking. The Android core contains the corresponding offline verifier as `WalletOid4vpRequestVerifier`, with an immutable static registration, raw request artifacts, authenticated context, and verified Owner-Key binding as explicit inputs; its pinned-certificate sequence check has the same deliberate limitation and is not a general PKIX path builder. The Python Wallet's separate encrypted one-use lifecycle, proof gate, raw-artifact re-verification and presentation issuance are documented in [wallet-account-disclosure-core-api.md](wallet-account-disclosure-core-api.md). This is not end-to-end OID4VP qualification, a general PKI path-builder, or a substitute for independent protocol/security review.

## Stage ownership and returned data

The verifier accepts only a real `WalletAccountDisclosureContext` and `VerifiedOwnerKeyBinding`. The verified binding result includes a SHA-256 digest of the exact compact binding JWS; the request verifier recomputes and compares it, so callers cannot pair a valid result with a different binding token. OIDC callback/ID-token validation remains a caller precondition and is not inferred from either object.

Unrecognized standard transport members are ignored, including unknown outer Authorization Request members, signed Request Object members, client metadata, and DCQL root/Credential Query/Claim Query/`meta` members. Known unsupported or conflicting members are rejected: `transaction_data`, DCQL `credential_sets`, `trusted_authorities`, `values`, and `intent_to_retain`. The returned `dcql_query` is a normalized projection of recognized selection fields only; ignored attacker-controlled fields are never exposed as consent inputs.

The shared 29-case negative bundle is pinned to its ecosystem provenance and is consumed unchanged. Request-slice disposition is classified by owning stage:

| Stage | Shared vector IDs | Request-slice disposition |
|---|---|---|
| OIDC prerequisite | `oidc-not-validated`, `oidc-validation-marker-missing` | Do not invoke the request verifier. The missing/false marker is an upstream precondition failure, not a request signature failure. |
| Context | `login-action-with-disclosure`, `purpose-bidi-control` | Reject in the initial OIDC request/context owner. |
| Owner binding | `recovery-binding-action-mismatch`, `context-transaction-mismatch`, `binding-wrong-rp-audience`, `binding-expired` | Reject in context/binding verification before the signed OID4VP request can authorize consent. |
| Request | `request-unsupported-transaction-data`, `outer-unsupported-transaction-data`, `request-response-uri-host-mismatch`, `request-nonfinite-number-overflow`, `dcql-missing-required-meta`, `dcql-claim-sets-incomplete` | Reject in this verifier. |
| Presentation | `presentation-wrong-nonce`, `presentation-extra-claim`, `claim-value-utf8-byte-limit`, `presentation-expired`, `presentation-expiry-after-credential`, `presentation-owner-binding-mismatch`, `presentation-invalid-signature`, `credential-invalid-signature`, `presentation-duplicate-json-member`, `required-claim-omitted`, `presentation-request-id-mismatch`, `presentation-total-size-limit`, `presentation-invalid-unicode-scalar` | Pass request validation; reject later in the presentation/credential verifier. |
| Direct post | `direct-post-state-mismatch`, `direct-post-vp-token-wrong-shape` | Pass request validation; reject later at the direct-post endpoint. |

The request tests additionally generate independent ES256 Request Objects and a fresh self-signed test certificate to exercise semantic mutations without changing the pinned fixtures. These are offline application-path tests, not PKI or live RP qualification.

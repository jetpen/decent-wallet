# Android wallet native continuation client

This installable Android application consumes `:platforms:android-wallet`. The legacy wallet-login consent route remains available: after the transaction's disclosure-context endpoint returns the exact login-only `204`, the Activity fetches the existing challenge and presents the existing wallet-login prompt.

Native signup/recovery is optional and fail-closed. A host that implements `WalletLoginHost` must explicitly return `NativeDisclosureTrustConfig` containing the expected Keycloak issuer, trusted issuer JWKS, and a statically configured `TrustedWalletRelyingPartyRegistration`. Missing configuration never downgrades a native context to wallet login. The app does not derive trust material or RP registration fields from unsigned context or continuation responses.

For a native context, `WalletLoginActivity` calls the core disclosure review API before consent and renders the reviewed identity, RP, action, purpose, each available requested claim value, and required/optional selection in one approval screen. Approval persists a single consent, creates the existing wallet-login proof, makes one proof POST, persists the returned continuation capability in the encrypted wallet, polls until a same-origin Request Object is ready, fetches it, and calls the wallet-owned `prepareAccountPresentation` overload. It then sends the core-persisted body once and reports observed delivery through `finishAccountPresentation`; network failures and 5xx responses are recorded as ambiguous with the exact prepared submission retained, but never retried automatically. Deny, cancel, expiry, invalid context, missing trust, and pre-submission errors do not yield a presentation. Core remains responsible for signed parsing, verification, claim selection, and wallet state.

`NativeDisclosureHttpClient` enforces bounded response reads, TLS verification, no cookies/authenticator/redirects, disabled connection retry, fixed same-origin continuation routes, bearer-only capability transmission, and byte-exact one-shot presentation delivery. Host tests cover missing-trust rejection, challenge expiry, exact proof challenge use with a distinct context OIDC nonce, consent-copy content, binding/context mismatch and expiry no-output paths, and the scripted single-approval workflow through one presentation submission. These use scripted operation seams and are orchestration/unit evidence, not live provider or end-to-end qualification. Instrumentation on the disposable `Medium_Phone` AVD (Android 8/API 26, x86) passed 7 tests, including the app-link rejection matrix, login approval/denial/cancellation against the test-TLS fixture, and native-context no-trust downgrade rejection. This remains limited to the tested AVD, fixture, and cases: no full native-consent-to-presentation instrumentation pass or live Keycloak/RP qualification has run.

Configure the exact provider host at build time with `-PwalletLoginHost=<DNS-host>` and optional `-PwalletLoginPort=<port>`. The default `.invalid` host is not deployable. Host tests and compile tasks:

```sh
./gradlew :apps:android-wallet-client:testDebugUnitTest
./gradlew :platforms:android-wallet:testDebugUnitTest
./gradlew :apps:android-wallet-client:compileDebugAndroidTestKotlin
```

Dependency locking and Gradle dependency verification are enabled. App Link domain verification and browser handoff remain unrun. The API 26 emulator tests covered the app-link rejection matrix, legacy login proof flow, and native-context no-trust rejection. Native signup consent-to-presentation runtime and live provider qualification remain unrun. The implementation is scoped to Activity-level native continuation and does not claim full Issue #66/#62 release qualification.

# Wallet #80 diagnostics and privacy audit

## Scope and method

This is a source review of the wallet Android client's production code at the issue-80 integration candidate based on `962a5d58f2e5e7594fcb935bdd2d166ee3d26115`. It covers the tracked Kotlin production files under `apps/android-wallet-client/src/main` and `src/qualification`, their HTTP and Activity error paths, the client module dependencies, and the two client transport regression tests. The review searched for Android `Log`, `println`, stack-trace printing, Java logging, Timber/SLF4J, crash-reporting/analytics and breadcrumb APIs, then traced transaction, proof, identity, continuation and response data through the inspected transport/UI paths.

This is not an emulator/logcat observation, a review of Android OS crash reporting or third-party library internals, a whole-process memory-erasure claim, or an audit of the wallet core or Keycloak/RP services.

## Findings

| Sensitive value / channel | Source-reviewed behavior | Finding and evidence limit |
|---|---|---|
| Transaction URL and opaque handle | `WalletLoginTransactionUrl` feeds `NativeWalletLoginHttpClient` and `NativeDisclosureHttpClient` request URLs; transport failures are converted to fixed, value-free exception types/messages. | No app-owned diagnostic/logging sink was found in the inspected production source. A malformed challenge regression asserts the transaction URL and synthetic response/identity/signature markers are absent from the thrown failure and its cause chain. It does not observe device logcat. |
| Challenge and proof/signature | `NativeDisclosureWorkflow` and `WalletLoginActivity` pass the challenge to proof creation and submit the resulting proof through the native HTTP client. | No app-owned logging or exception interpolation was found. The proof is intentionally transmitted to its protocol endpoint; this audit does not classify that required protocol output as a diagnostic sink or qualify a live provider. |
| Identity ID | The approval screens deliberately show the exact identity to the owner; the proof and signup review use it as specified. | User-visible consent and protocol payload are not diagnostics. The inspected UI does not forward identity values into a logging API. Tests do not claim to suppress the value from the consent screen or required proof. |
| Cookies/browser state | The client configures `CookieJar.NO_COOKIES`, disables authenticators, redirects, retries and cache, and its transport tests inspect browser-credential headers. | The existing transport tests cover absence of browser metadata on exercised requests; this source audit does not qualify browser-session preservation or a live Chromium handoff. |
| Response bodies | HTTP response bytes are consumed by the relevant parser/flow; the native transport uses bounded reads and fixed transport exceptions. | No app-owned diagnostic sink was found. New regressions put synthetic sensitive markers in malformed challenge/error responses and assert those markers and actual transaction/capability URL components do not appear in failure messages or causes. They do not claim that response data is absent from the intended parser or transport flow. |
| UI status and exception handling | Activities show fixed, generic failure/status text on transport/import errors; consent and recovery screens intentionally show transaction-relevant owner/RP information. | No caught transport exception or raw response is interpolated into those failure messages in the reviewed paths. This source review does not assert that all user-visible UI is free of identity/claim information; explicit consent requires selected details to be displayed. |

## Regression coverage added

- `NativeWalletLoginHttpClientTest.malformedChallengeFailureDoesNotExposeResponseOrIdentityMarkers` exercises malformed HTTP input through the production challenge-fetch operation and inspects the resulting exception and cause chain.
- `NativeDisclosureHttpClientTest.rejectedContinuationPollDoesNotExposeResponseCapabilityOrTransactionMarkers` exercises an HTTP failure through the production continuation poll and checks the exception/cause chain for synthetic response markers and the actual bearer/transaction values.

These are JVM/MockWebServer tests of the inspected client exception boundary, not device logcat capture or live qualification.

## Conclusion

Within the reviewed wallet Android client source and the two tested exception paths, no production app-owned diagnostics/logging sink was found for the named values, and the tested transport failures expose fixed errors without those values. Keep the claim limited to those inspected source paths and exercised exception branches. Repeat this review if logging, crash-reporting, analytics, or new diagnostic output is added. Android runtime/logcat, third-party internals, broader wallet-core sinks, and the remaining Wallet #80 qualification gates remain unverified.

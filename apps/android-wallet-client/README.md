# Native Android wallet-login client foundation

This installable Android application module is the wallet-login-only foundation from the Issue #62 plan. It consumes `:platforms:android-wallet` and does not change the `decent-wallet-login-v1` proof, wallet-container format, adopted #51 disclosure profile, or provider/RP behavior.

Configure the exact provider host at build time with `-PwalletLoginHost=<DNS-host>` and an optional `-PwalletLoginPort=<port>`. The default host is a reserved `.invalid` value and is not a deployable provider. The exported HTTPS App Link reaches an exact route parser before any network call. The host application must implement `WalletLoginHost` and return only an already-unlocked `WalletSession` plus the exact identity ID; this app does not acquire passwords, inspect private keys, or offer generic signing.

The native HTTP client uses platform TLS verification, has no cookie jar or authenticator, does not follow redirects, and disables connection-failure retry. It issues GET/POST only to the parsed transaction URL. Challenge `csrf_token` is required and parsed but never submitted. The consent screen shows the normalized origin and exact identity ID; approve invokes `WalletSession.createWalletLoginProofRequest`. Deny, cancel, invalid input, locked/missing session, expiry, TLS/network error, and POST error do not generate another submission attempt. The screen is limited to wallet login; it does not claim signup consent, Account Entity field display, or #51 continuation handling.

Build and host tests:

```sh
./gradlew :apps:android-wallet-client:testDebugUnitTest
./gradlew :apps:android-wallet-client:compileDebugAndroidTestKotlin
./gradlew :apps:android-wallet-client:assembleDebug :apps:android-wallet-client:assembleRelease
```

Dependency locking and Gradle dependency verification are enabled. Host tests are not emulator/runtime qualification. Android App Link domain verification, browser handoff, instrumentation/runtime TLS+consent flow, and provider qualification remain unrun. The Issue #66/#62 continuation integration—fixed-origin capability polling and matching post-OIDC OID4VP fulfillment under adopted #51—remains a separate open slice; no continuation wire or lifecycle behavior is implemented here.

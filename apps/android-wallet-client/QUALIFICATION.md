# Qualification trust configuration

This app is a visibly separate `org.decentwallet.wallet.client.qualification` build, version `0.2.0-qualification` (`versionCode=2`). It has a qualification-owned wallet setup host and uses the existing wallet-login Activity after owner setup. It does not package debug fixture host/TLS override classes or the test CA. Standard debug remains the instrumentation fixture host; standard release is disabled.

On first launch, choose an existing encrypted wallet container, enter its associated Identity ID exactly, and unlock using its password. The document-picker stream is bounded at 16 MiB. The encrypted container is imported to a new app-private path derived from its SHA-256; if that exact container was already imported, the app opens the existing file without overwrite. Invalid container/password errors are generic. Password and container buffers are cleared after use; no wallet or password is generated or embedded. Only the unlocked `WalletSession` and entered Identity ID are held in process memory. Returning from background/recreation or restarting requires another unlock. No identity is inferred from a provider transaction.

The Android source-set split keeps the mutable identity-installing fixture host and test CA inside the standard debug/instrumentation build inputs; qualification instrumentation can compile that test bridge, while the qualification APK source set does not include it. Verify this separation in both built artifacts before treating the qualification APK as release-ready.

The configuration file is **public trust material**, never wallet secrets. Supply a real JSON file with `-PwalletQualificationTrustConfig=/absolute/path/to/trust_config.json`, or place `trust_config.json` in `src/qualification/assets/`. The provenance SHA-256 covers whichever of those two inputs was selected. Do not commit private keys, tokens, wallet/user data, or certificate private-key material. The example uses intentionally invalid issuer parameters and must not be used as trust:

```json
{
  "keycloak_display_name": "Issuer shown to the user",
  "issuer": "https://provider.example.invalid/realms/REPLACE_ME",
  "issuer_jwks": { "keys": [{"kty":"RSA","kid":"issuer-signing-key","use":"sig","alg":"RS256","n":"PUBLIC_MODULUS_BASE64URL","e":"AQAB"}] },
  "rp": {
    "client_id": "x509_san_dns:rp.example.invalid",
    "x509_san_dns": "rp.example.invalid",
    "origin": "https://rp.example.invalid",
    "response_uri": "https://rp.example.invalid/oid4vp/direct-post",
    "trust_anchor_sha256": "64-lowercase-hex-SHA256-certificate-pin",
    "rp_client_id": "registered-OIDC-client-id"
  }
}
```

Obtain the exact HTTPS issuer realm, public signing JWKS, RP registered IDs, certificate SAN/DNS, HTTPS origin/response URI and SHA-256 pin from the actual provider and RP registration. The issuer host must exactly match `-PwalletLoginHost`; issuer and RP URI, public RSA key parameters, RP DNS and pin are validated. Redirects and trust-all TLS are not enabled. Trust is never inferred from provider transactions or unsigned context. With no trust file, native account disclosure/signup is unavailable and fails closed; the wallet-login path may still operate when the provider returns the existing login-only context.

Build an **offline, unconfigured** candidate only with explicit opt-in:

```sh
./gradlew :apps:android-wallet-client:assembleQualificationDebug \
  -PwalletLoginHost=ben-x260.tailca8b51.ts.net -PwalletLoginPort=443 \
  -PwalletQualificationOffline=true
```

The offline APK is not live qualification evidence and contains no trust config. Configured builds instead pass `-PwalletQualificationTrustConfig=...` and must not set offline mode. Missing trust otherwise blocks the qualification build. The provenance asset records committed source revision, trust-config SHA-256 (or `none`) and the offline flag. Since revision is `git rev-parse HEAD`, a dirty/uncommitted tree is not source-bound to those changes; commit the candidate before making source-bound claims.

Build/test without booting an emulator:

```sh
./gradlew --no-daemon --dependency-verification=strict \
  -PwalletLoginHost=ben-x260.tailca8b51.ts.net -PwalletLoginPort=443 \
  -PwalletQualificationOffline=true \
  :apps:android-wallet-client:testQualificationDebugUnitTest \
  :apps:android-wallet-client:testStandardDebugUnitTest \
  :platforms:android-wallet:testDebugUnitTest \
  :apps:android-wallet-client:compileQualificationDebugAndroidTestKotlin \
  :apps:android-wallet-client:compileStandardDebugAndroidTestKotlin \
  :apps:android-wallet-client:assembleQualificationDebug
```

Host tests, Android-test compilation and APK assembly do not establish browser handoff, verified App Links/domain association, Android runtime import, live Keycloak/RP, Funnel, Registry/OIDC behavior, TLS negative controls or end-to-end acceptance. Those remain `not_run` pending a separately authorized runtime/live run and sanitized receipt.

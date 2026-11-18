# Changelog

## 0.4.0

Initial Swift SDK, version-aligned with `@last1id/sdk` 0.4.

- PKCE S256, state, nonce, and authorize URL building for `https://auth.last1.id`.
- Sign in with `ASWebAuthenticationSession`, including an HTTPS universal-link callback on iOS 17.4 and macOS 14.4, a custom-scheme callback on iOS 16 and macOS 13, and an ephemeral session option.
- Public-client code exchange (no client secret) and a backend handoff of `{ code, codeVerifier, nonce }` for confidential exchange. `state` is checked on the device and is not part of the handoff.
- RS256 ID token verification. JWKS fetches for the same verifier share one in-flight request. A cold cache is fetched once. An unknown `kid` is fetched again after 45 seconds, and that refetch replaces the whole key set. Clock skew is 60 seconds. `audience` overrides the values checked against `aud` and `azp`, and defaults to `clientID` (the App ID slug).
- Keychain token store, refresh-token rotation with concurrent refreshes coalesced, userinfo, revoke, and sign-out. An `id_token` on the refresh response is verified with no nonce, and `iss`, `sub`, and `aud` must match the stored ID token before it is saved.
- `print`, `debugDescription`, and `dump` redact token values.
- No telemetry and no logging of tokens.

# Changelog

## 0.5.0

Aligned with `@last1id/sdk` 0.5.0.

- Discovery reads optional `end_session_endpoint`. A present value that is not an https URL on the issuer host is rejected. A missing value falls back to `{issuer}/oauth/logout`.
- `signOut()` still revokes and clears the Keychain. It now returns the end-session URL. The result can be ignored.
- `endSessionURL()` builds that URL with the stored id_token as `id_token_hint`.
- `email_verified` is kept only when it is a JSON boolean. A string such as `"true"` is dropped, and the rest of the token is still accepted. The issuer emits a boolean.
- `signIn`, `signInForBackendExchange`, and `beginAuthorization` accept an optional caller `state`, `nonce`, and PKCE verifier or pair. A verifier must be 43 to 128 unreserved characters. The challenge must be the S256 digest of that verifier. Supplied values are sent unchanged and are the values checked against the callback `state` and the ID token `nonce`.
- `Last1IDSession.idToken` is the raw ID token from the token response.
- `Last1IDCallbackParser` is public. `parse` returns `code`, `state`, and `error` without checking state. `authorizationCode` still requires the expected state. A redirect that repeats `code`, `state`, or `error` is rejected.
- A caller-supplied `state` should be high-entropy. The generated value already is.
- A public-client backend may call `exchangeAuthorizationCode` with the code and verifier and no client secret. A confidential backend still sends its secret. The README describes both.
- Default scopes stay `openid profile email offline_access`.

## 0.4.0

Initial Swift SDK, version-aligned with `@last1id/sdk` 0.4.

- PKCE S256, state, nonce, and authorize URL building for `https://auth.last1.id`.
- Sign in with `ASWebAuthenticationSession`, including an HTTPS universal-link callback on iOS 17.4 and macOS 14.4, a custom-scheme callback on iOS 16 and macOS 13, and an ephemeral session option.
- Public-client code exchange (no client secret) and a backend handoff of `{ code, codeVerifier, nonce }` for confidential exchange. `state` is checked on the device and is not part of the handoff.
- RS256 ID token verification. JWKS fetches for the same verifier share one in-flight request. A cold cache is fetched once. An unknown `kid` is fetched again after 45 seconds, and that refetch replaces the whole key set. Clock skew is 60 seconds. `audience` overrides the values checked against `aud` and `azp`, and defaults to `clientID` (the App ID slug).
- Keychain token store, refresh-token rotation with concurrent refreshes coalesced, userinfo, revoke, and sign-out. An `id_token` on the refresh response is verified with no nonce, and `iss`, `sub`, and `aud` must match the stored ID token before it is saved.
- `print`, `debugDescription`, and `dump` redact token values.
- No telemetry and no logging of tokens.

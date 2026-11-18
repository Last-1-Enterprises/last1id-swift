# Last1ID

Swift package for **Sign in with Last1 ID**. A third-party iOS or macOS app uses the same public OIDC provider as Last 1 Enterprises' own apps: authorization code, PKCE S256, and RS256 ID tokens from `https://auth.last1.id`.

The library product and the Swift module are both named `Last1ID`. It links only Apple frameworks (CryptoKit, Security, AuthenticationServices). There is no telemetry. Token values are not written to logs. `print`, `debugDescription`, and `dump` of the token types show `redacted`.

| | |
|---|---|
| Platforms | iOS 16+, macOS 13+ |
| Issuer | `https://auth.last1.id` |
| License | Apache-2.0 (`LICENSE` in this folder) |
| Version | 0.5.0, aligned with `@last1id/sdk` 0.5 |

## Install

The package needs the Swift 6 toolchain (Xcode 16 or later).

Add the Swift package from [Last-1-Enterprises/last1id-swift](https://github.com/Last-1-Enterprises/last1id-swift):

```swift
dependencies: [
    .package(url: "https://github.com/Last-1-Enterprises/last1id-swift", from: "0.5.0"),
],
targets: [
    .target(
        name: "App",
        dependencies: [
            .product(name: "Last1ID", package: "last1id-swift"),
        ]
    ),
]
```

## Register the app

1. Open **App clients** in the last1.id developer console.
2. Click **Register app**. Set the App ID slug and the display name.
3. Register the redirect URI exactly. Register both `https://app.example.com/auth/callback` and `myapp://callback` if the app uses both.
4. Register the app yourself as a **public native client** in the Last1 ID developer console. Anyone signed in at Last1 ID can do this under App clients. On the server that is `token_endpoint_auth_method: none`. A public client has no secret. PKCE S256 is required. If the form still shows a client secret, do not copy it into the app.
5. Use the **App ID slug** as `clientID`. That slug is the public Client ID for every Last1 ID SDK. The authorize and token endpoints still accept the client row UUID for backward compatibility. The ID token `aud` is the slug. Verification checks `aud` and `azp` against `clientID` unless you pass `audience`. If a caller still sends the UUID as `clientID`, set `audience` to `[slug]`.

Request only the scopes you need. `openid` is required. Add `offline_access` to get a refresh token. Add `identity_proof:read` when you need `last1_verified`.

## Universal link callback

Prefer an `https` redirect on a domain the app controls. Register that exact URI in the Last1 ID developer console. Add the Associated Domains entitlement and serve an Apple App Site Association file for that domain. Keep a custom scheme as the fallback for systems that cannot use an HTTPS callback.

Use the HTTPS callback on iOS 17.4+ and macOS 14.4+.

1. Register `https://app.example.com/auth/callback` as a redirect URI.
2. Add the Associated Domains entitlement `applinks:app.example.com`.
3. Serve Apple App Site Association at `https://app.example.com/.well-known/apple-app-site-association` and include the callback path:

```json
{
  "applinks": {
    "details": [
      {
        "appIDs": ["TEAMID.com.example.app"],
        "components": [
          { "/": "/auth/callback" }
        ]
      }
    ]
  }
}
```

3. Configure the SDK with the same host and path:

```swift
callback: .https(host: "app.example.com", path: "/auth/callback")
```

`ASWebAuthenticationSession.Callback.https(host:path:)` is not available before iOS 17.4 / macOS 14.4. On those older systems use a custom scheme, or the SDK throws `httpsCallbackUnavailable`.

## Custom scheme callback

Use a custom scheme when the device cannot claim an HTTPS universal link. The server accepts a dotted reverse-DNS scheme. Register `com.example.app:/callback` as a redirect URI in the developer console. Add a URL type for `com.example.app` in Info.plist. Then:

```swift
callback: .customScheme("com.example.app")
redirectURI: URL(string: "com.example.app:/callback")!
```

## Quickstart

Create the client and the sign-in helper on the main actor. iOS must pass the window that presents the browser session. Last1 ID does not set a browser session cookie. Set `prefersEphemeralSession` when the system browser should not persist cookies for this sign-in. Silent sign-in uses `id_token_hint`, not a cookie.

```swift
import Last1ID

let redirect = URL(string: "https://app.example.com/auth/callback")!
// clientID is the App ID slug, the public Client ID.
let configuration = Last1IDConfiguration(
    clientID: "example-app",
    redirectURI: redirect,
    callback: .https(host: "app.example.com", path: "/auth/callback"),
    scopes: ["openid", "profile", "email", "offline_access", "identity_proof:read"]
)
let store = Last1IDKeychainTokenStore(account: configuration.clientID)
let client = Last1IDClient(configuration: configuration, tokenStore: store)
let signIn = Last1IDSignIn(client: client)

let session = try await signIn.signIn {
    view.window!
}
// session.claims.sub is the last1.id identity UUID.
// session.claims.email, emailVerified, name, amr, acr,
// last1Verified, last1VerifiedAt
```

A longer UIKit sketch is in `Examples/SignInSnippet.swift`.

The access token and refresh token stay in the Keychain store (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, this device only, not synced). On macOS the app must be signed with an app identifier, or the Keychain returns -34018. Read tokens with `storedTokens()` only at the moment you send a request, and do not log the value.

```swift
let profile = try await client.userInfo()
try await client.signOut()
```

`userInfo()` refreshes once when Last1 ID returns `invalid_token`. `signOut()` revokes the refresh token, deletes the Keychain item even if the network call fails, and returns the end-session URL. Open that URL to end the Last1 browser session. `endSessionURL()` builds the same URL without clearing the store. `revoke()` is the server call alone, so a failure can be retried. `email_verified` is kept only when it is a JSON boolean. A string value is dropped and the rest of the token is accepted. The issuer sends a boolean. `session.idToken` is the raw token.

## Backend exchange

The phone runs PKCE and the browser session, then your backend exchanges the code. Two backends are supported.

A **public** backend is the same native public client. It calls `exchangeAuthorizationCode` with the code and the verifier. It does not send a client secret.

```swift
let handoff = try await signIn.signInForBackendExchange {
    view.window!
}
let session = try await backendClient.exchangeAuthorizationCode(
    code: handoff.code,
    codeVerifier: handoff.codeVerifier,
    nonce: handoff.nonce
)
// session.idToken is the raw ID token. session.claims is already verified.
```

`backendClient` uses the same `clientID` and `redirectURI`. The token request is `grant_type`, `code`, `redirect_uri`, `client_id`, and `code_verifier`. There is no `client_secret` field.

A **confidential** backend keeps the client secret on the server. The device still never sees that secret. The backend posts the same fields plus `client_secret`.

To supply your own `state`, `nonce`, or PKCE, pass them to `signIn` or `signInForBackendExchange`. A caller-supplied `state` should be high-entropy: at least 128 bits from a cryptographic random source. A short or guessable value is not safe. The SDK's generated state already is. A verifier is 43 to 128 unreserved characters (RFC 7636). A pair's challenge must be the S256 digest of that verifier. Those values are sent unchanged. The callback `state` and the ID token `nonce` are checked against them. `Last1IDCallbackParser.parse` reads `code`, `state`, and `error` when the app handles the redirect URL itself. `authorizationCode` still requires the state from the attempt.

```swift
let handoff = try await signIn.signInForBackendExchange {
    view.window!
}
// Send handoff to your API over your own authenticated channel.
// Fields: code, codeVerifier, nonce, clientID, redirectURI, issuer.
```

The device never sees the client secret. The backend posts form fields to `{issuer}/oauth/token`:

```
grant_type=authorization_code
code=<handoff.code>
redirect_uri=<the same redirect URI>
client_id=<the same client id>
client_secret=<server secret>
code_verifier=<handoff.codeVerifier>
```

Then the backend checks the ID token: RS256, `iss`, `aud`/`azp`, `exp`, `iat`, `nbf` (60 seconds of skew), and `nonce == handoff.nonce`. `aud` is the App ID slug. On Apple platforms, `Last1IDIDTokenVerifier` does that check. Pass `audience: [slug]` when the confidential client's `client_id` is still the row UUID. Reject `alg` of `none` or `HS256`.

`state` is checked on the device before the handoff is returned. It is not part of the handoff.

## Verification

`Last1IDIDTokenVerifier` and the code exchange path both:

- Accept `alg` `RS256` only. `none`, `HS256`, and any other algorithm fail before a key is used.
- Resolve `kid` from the issuer JWKS. The set is cached. Concurrent checks share one in-flight fetch, and a cold cache is fetched once. An unknown `kid` is fetched again after 45 seconds. That refetch replaces the whole set, so a removed key is no longer trusted.
- Reject a `kid` that is not in `allowedKeyIDs` when that list is set. Leave the list nil unless you ship key updates with the app. A stale pin breaks sign-in at rotation.
- Verify the signature with `SecKey` (RSA PKCS#1 v1.5, SHA-256).
- Require `iss` to match the configured issuer. Discovery is refused when its `issuer` or its endpoints are not that https host.
- Require `aud` to contain the expected audience. That value defaults to `clientID`, the App ID slug. Pass `audience` when `clientID` is still the row UUID. If `azp` is present it must be one of those values. If `aud` has more than one value, `azp` is required.
- Apply a 60 second skew to `exp`, `iat`, and `nbf`.
- Require `nonce` to match the value sent on the authorize request.

Discovery is fetched from `{issuer}/.well-known/openid-configuration` and cached for the life of the client. `discovery(forceRefresh: true)` replaces that cache and drops the JWKS verifier built from it. The live provider advertises response type `code`, PKCE `S256`, token auth `none` / `client_secret_basic` / `client_secret_post`, ID tokens `RS256`, and `prompt` `none`.

## Silent sign-in

`prompt=none` needs an `id_token_hint`. Pass one, or omit it and the SDK uses the ID token already in the store. Last1 ID does not set a browser session cookie, so a hint that fails comes back as `login_required`. The system browser may still appear for a moment. `prefersEphemeralSession` asks that browser not to persist cookies for the sign-in.

```swift
let session = try await signIn.signIn(prompt: "none") {
    view.window!
}
```

## Refresh

Refresh tokens rotate. Concurrent callers share one in-flight refresh through the client actor, so a burst of 401s does not present the same refresh token twice. When the refresh response includes an `id_token`, the SDK verifies it with no nonce and requires `iss`, `sub`, and `aud` to match the stored ID token before saving it. The stored token is not signature-checked again, so a signing-key rotation does not sign the person out. A second use of an already-rotated token is `invalid_grant`, and Last1 ID revokes the rest of that grant. The SDK then clears the local session.

Do not loop on a transport failure. If the response is lost after the server has rotated, retrying the old refresh token kills the grant. Ask the person to sign in again.

## Errors

`Last1IDError` is the only error type the SDK throws (plus cancellation). OAuth errors use the server's `error` code, including `invalid_grant`, `invalid_client`, `invalid_token`, `insufficient_scope`, `access_denied`, `login_required`, `consent_required`, `mfa_required`, and `mfa_enrollment_required`. Anything else is `.oauth(code: .other(raw), description:)`.

`invalid_grant` means the refresh chain is dead. `insufficient_scope` means the token is valid but missing a scope. Do not treat that as a reason to sign the person out.

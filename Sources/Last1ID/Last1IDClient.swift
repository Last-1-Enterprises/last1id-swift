import Foundation

public struct Last1IDSession: Sendable, Equatable {
    public let claims: Last1IDIDTokenClaims
    public let scope: String?
    public let accessTokenExpiresAt: Date?
}

/// Values a native app hands to its own backend for a confidential
/// token exchange. The description and mirror redact the code, verifier,
/// and nonce. The device already checked `state`. The backend sends the
/// same `clientID`, `redirectURI`, and `codeVerifier`, plus its client
/// secret. This SDK never takes a client secret.
public struct Last1IDBackendExchange: Sendable, Equatable {
    public let code: String
    public let codeVerifier: String
    public let nonce: String
    public let clientID: String
    public let redirectURI: URL
    public let issuer: URL
}

extension Last1IDBackendExchange: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        "Last1IDBackendExchange(clientID: \(clientID), redirectURI: \(redirectURI.absoluteString), issuer: \(issuer.absoluteString), secrets: redacted)"
    }
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: [], displayStyle: .struct)
    }
}

public struct Last1IDUserInfo: Sendable, Equatable {
    public let sub: String
    public let email: String?
    public let emailVerified: Bool?
    public let name: String?
    public let picture: String?
    public let preferredUsername: String?
    public let identityStatus: String?
    public let last1Verified: Bool?
    public let last1VerifiedAt: String?
}

/// Public-client OIDC session. Refresh calls share one in-flight
/// rotation so a single-use refresh token is not presented twice.
public actor Last1IDClient {
    public nonisolated let configuration: Last1IDConfiguration
    private let tokenStore: any Last1IDTokenStore
    private let session: URLSession
    private let now: @Sendable () -> Date
    private var cachedDiscovery: Last1IDDiscovery?
    private var verifier: Last1IDIDTokenVerifier?
    private var refreshTask: Task<Last1IDTokens, Error>?

    public init(
        configuration: Last1IDConfiguration,
        tokenStore: any Last1IDTokenStore,
        session: URLSession? = nil,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.configuration = configuration
        self.tokenStore = tokenStore
        self.now = now
        if let session {
            self.session = session
        } else {
            let config = URLSessionConfiguration.ephemeral
            config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            config.urlCache = nil
            config.httpCookieAcceptPolicy = .never
            config.httpShouldSetCookies = false
            config.timeoutIntervalForRequest = 30
            self.session = URLSession(configuration: config)
        }
    }

    public func discovery(forceRefresh: Bool = false) async throws -> Last1IDDiscovery {
        if !forceRefresh, let cachedDiscovery { return cachedDiscovery }
        try configuration.validate()
        guard let url = Last1URL.endpoint(configuration.issuerURL, path: "/.well-known/openid-configuration") else {
            throw Last1IDError.configuration("issuerURL is not a URL")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(Last1IDVersion.userAgent, forHTTPHeaderField: "User-Agent")
        let data = try await send(request, success: 200..<300)
        let document = try Last1IDDiscovery.parse(data: data, expectedIssuer: configuration.issuer)
        cachedDiscovery = document
        verifier = nil
        return document
    }

    public func beginAuthorization(prompt: String? = nil, idTokenHint: String? = nil) async throws -> Last1IDAuthorizationAttempt {
        try configuration.validate()
        let document = try await discovery()
        if let prompt, !document.promptValuesSupported.isEmpty, !document.promptValuesSupported.contains(prompt) {
            throw Last1IDError.configuration("prompt \(prompt) is not advertised by the issuer")
        }
        let hint = try await resolvedIDTokenHint(prompt: prompt, explicit: idTokenHint)
        let pkce = Last1IDPKCE.generate()
        let state = Last1Random.token()
        let nonce = Last1Random.token()
        let url = Last1IDAuthorizeURL.make(
            authorizationEndpoint: document.authorizationEndpoint,
            clientID: configuration.clientID,
            redirectURI: configuration.redirectURI,
            scopes: configuration.scopes,
            codeChallenge: pkce.codeChallenge,
            state: state,
            nonce: nonce,
            prompt: prompt,
            idTokenHint: hint
        )
        return Last1IDAuthorizationAttempt(
            url: url,
            state: state,
            nonce: nonce,
            codeVerifier: pkce.codeVerifier,
            codeChallenge: pkce.codeChallenge
        )
    }

    /// Exchanges an authorization code as a public client. No client secret is sent.
    public func exchangeAuthorizationCode(
        code: String,
        codeVerifier: String,
        nonce: String
    ) async throws -> Last1IDSession {
        try configuration.validate()
        try Last1IDPKCE.validate(codeVerifier)
        let document = try await discovery()
        let data = try await postForm(document.tokenEndpoint, [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", configuration.redirectURI.absoluteString),
            ("client_id", configuration.clientID),
            ("code_verifier", codeVerifier),
        ])
        let parsed = try parseTokenResponse(data, previous: nil, requireRefreshToken: false)
        guard let idToken = parsed.idTokenFromResponse else { throw Last1IDError.invalidResponse }
        let claims = try await idTokenVerifier(document).verify(idToken, expectedNonce: nonce)
        try await tokenStore.save(parsed.tokens)
        return Last1IDSession(claims: claims, scope: parsed.tokens.scope, accessTokenExpiresAt: parsed.tokens.expiresAt)
    }

    public func refresh() async throws -> Last1IDTokens {
        if let refreshTask {
            return try await refreshTask.value
        }
        let task = Task { try await self.performRefresh() }
        refreshTask = task
        do {
            let tokens = try await task.value
            refreshTask = nil
            return tokens
        } catch {
            refreshTask = nil
            throw error
        }
    }

    public func userInfo() async throws -> Last1IDUserInfo {
        try await withAccessToken { accessToken in
            let document = try await self.discovery()
            var request = URLRequest(url: document.userinfoEndpoint)
            request.httpMethod = "GET"
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
            request.setValue("application/json", forHTTPHeaderField: "Accept")
            request.setValue(Last1IDVersion.userAgent, forHTTPHeaderField: "User-Agent")
            let data = try await self.send(request, success: 200..<300)
            return try Self.parseUserInfo(data)
        }
    }

    /// Revokes the stored refresh token, or the access token when there
    /// is no refresh token. Leaves the store in place when the request fails
    /// so the caller can retry. Does not send a client secret.
    public func revoke() async throws {
        guard let tokens = try await tokenStore.load() else {
            throw Last1IDError.notAuthenticated
        }
        try await postRevoke(tokens)
    }

    /// Revokes the server token, then always removes the local session.
    /// A revoke failure is thrown after the local session is gone.
    public func signOut() async throws {
        let tokens = try await tokenStore.load()
        var revokeError: Error?
        if let tokens {
            do {
                try await postRevoke(tokens)
            } catch {
                revokeError = error
            }
        }
        try await tokenStore.clear()
        if let revokeError { throw revokeError }
    }

    public func storedTokens() async throws -> Last1IDTokens? {
        try await tokenStore.load()
    }

    private func performRefresh() async throws -> Last1IDTokens {
        let existing = try await tokenStore.load()
        guard let refreshToken = existing?.refreshToken, !refreshToken.isEmpty else {
            throw Last1IDError.notAuthenticated
        }
        let document = try await discovery()
        let data: Data
        do {
            data = try await postForm(document.tokenEndpoint, [
                ("grant_type", "refresh_token"),
                ("refresh_token", refreshToken),
                ("client_id", configuration.clientID),
            ])
        } catch let error as Last1IDError {
            if case .oauth(let code, _) = error, code == .invalidGrant {
                try? await tokenStore.clear()
            }
            throw error
        }
        do {
            let parsed = try parseTokenResponse(data, previous: existing, requireRefreshToken: true)
            if let idToken = parsed.idTokenFromResponse {
                try await validateRefreshedIDToken(idToken, previous: existing, document: document)
            }
            try await tokenStore.save(parsed.tokens)
            return parsed.tokens
        } catch {
            try? await tokenStore.clear()
            throw error
        }
    }

    /// OIDC Core 12.2: a refreshed ID token is verified with no nonce, and
    /// its issuer, subject, and audience must match the stored token.
    /// The stored token is decoded only. Checking its signature again would
    /// sign everyone out once the old signing key leaves the JWKS.
    private func validateRefreshedIDToken(
        _ idToken: String,
        previous: Last1IDTokens?,
        document: Last1IDDiscovery
    ) async throws {
        let claims = try await idTokenVerifier(document).verify(idToken, expectedNonce: nil)
        guard let previousID = previous?.idToken, !previousID.isEmpty else { return }
        let original = try Last1IDIDTokenVerifier.decodeUnverifiedClaims(previousID)
        if claims.issuer != original.issuer {
            throw Last1IDError.idToken(.wrongIssuer)
        }
        if claims.sub != original.sub {
            throw Last1IDError.idToken(.subjectMismatch)
        }
        if Set(claims.audience) != Set(original.audience) {
            throw Last1IDError.idToken(.wrongAudience)
        }
    }

    private func withAccessToken<T>(_ body: (String) async throws -> T) async throws -> T {
        let accessToken = try await validAccessToken()
        do {
            return try await body(accessToken)
        } catch let error as Last1IDError {
            guard case .oauth(let code, _) = error, code == .invalidToken else { throw error }
            let refreshed = try await refresh()
            return try await body(refreshed.accessToken)
        }
    }

    private func validAccessToken() async throws -> String {
        guard let tokens = try await tokenStore.load(), !tokens.accessToken.isEmpty else {
            throw Last1IDError.notAuthenticated
        }
        if let expiresAt = tokens.expiresAt, expiresAt.timeIntervalSince(now()) <= 60 {
            return try await refresh().accessToken
        }
        return tokens.accessToken
    }

    private func resolvedIDTokenHint(prompt: String?, explicit: String?) async throws -> String? {
        guard prompt == "none" else { return explicit }
        if let explicit, !explicit.isEmpty { return explicit }
        if let stored = try await tokenStore.load()?.idToken, !stored.isEmpty { return stored }
        throw Last1IDError.notAuthenticated
    }

    private func idTokenVerifier(_ document: Last1IDDiscovery) -> Last1IDIDTokenVerifier {
        if let verifier { return verifier }
        let created = Last1IDIDTokenVerifier(
            jwksURL: document.jwksURI,
            session: session,
            expectedIssuer: document.issuer,
            clientID: configuration.clientID,
            audience: configuration.audience,
            allowedKeyIDs: configuration.allowedKeyIDs,
            now: now
        )
        verifier = created
        return created
    }

    private func postRevoke(_ tokens: Last1IDTokens) async throws {
        let document = try await discovery()
        let token: String
        let hint: String
        if let refresh = tokens.refreshToken, !refresh.isEmpty {
            token = refresh
            hint = "refresh_token"
        } else {
            token = tokens.accessToken
            hint = "access_token"
        }
        _ = try await postForm(document.revocationEndpoint, [
            ("token", token),
            ("token_type_hint", hint),
            ("client_id", configuration.clientID),
        ])
    }

    private func postForm(_ url: URL, _ fields: [(String, String)]) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded; charset=utf-8", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(Last1IDVersion.userAgent, forHTTPHeaderField: "User-Agent")
        request.httpBody = Last1Form.encode(fields)
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        return try await send(request, success: 200..<300)
    }

    private func send(_ request: URLRequest, success: Range<Int>) async throws -> Data {
        let data: Data
        let status: Int
        do {
            let (body, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse else { throw Last1IDError.invalidResponse }
            data = body
            status = http.statusCode
        } catch let error as Last1IDError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch let error as URLError where error.code == .cancelled {
            throw CancellationError()
        } catch {
            throw Last1IDError.network
        }
        guard success.contains(status) else {
            throw Self.httpError(status: status, data: data)
        }
        return data
    }

    private func parseTokenResponse(
        _ data: Data,
        previous: Last1IDTokens?,
        requireRefreshToken: Bool
    ) throws -> ParsedTokenResponse {
        guard let json = Last1JSON.object(from: data, maximumBytes: 65_536),
              let accessToken = Last1JSON.string(json["access_token"]),
              !accessToken.isEmpty else {
            throw Last1IDError.invalidResponse
        }
        let refreshToken = Last1JSON.string(json["refresh_token"])
        if requireRefreshToken, refreshToken?.isEmpty != false {
            throw Last1IDError.invalidResponse
        }
        let current = now()
        let expiresAt = Last1JSON.int64(json["expires_in"]).map {
            current.addingTimeInterval(TimeInterval($0))
        }
        let refreshExpiresAt = Last1JSON.int64(json["refresh_expires_in"]).map {
            current.addingTimeInterval(TimeInterval($0))
        }
        let idToken = Last1JSON.string(json["id_token"])
        let returnedIDToken = (idToken?.isEmpty == false) ? idToken : nil
        return ParsedTokenResponse(
            tokens: Last1IDTokens(
                accessToken: accessToken,
                refreshToken: (refreshToken?.isEmpty == false ? refreshToken : nil) ?? previous?.refreshToken,
                idToken: returnedIDToken ?? previous?.idToken,
                tokenType: Last1JSON.string(json["token_type"]) ?? previous?.tokenType ?? "Bearer",
                expiresAt: expiresAt ?? previous?.expiresAt,
                refreshExpiresAt: refreshExpiresAt ?? previous?.refreshExpiresAt,
                scope: Last1JSON.string(json["scope"]) ?? previous?.scope
            ),
            idTokenFromResponse: returnedIDToken
        )
    }

    private static func parseUserInfo(_ data: Data) throws -> Last1IDUserInfo {
        guard let json = Last1JSON.object(from: data, maximumBytes: 65_536),
              let sub = Last1JSON.string(json["sub"]), !sub.isEmpty else {
            throw Last1IDError.invalidResponse
        }
        return Last1IDUserInfo(
            sub: sub,
            email: Last1JSON.string(json["email"]),
            emailVerified: Last1JSON.bool(json["email_verified"]),
            name: Last1JSON.string(json["name"]),
            picture: Last1JSON.string(json["picture"]),
            preferredUsername: Last1JSON.string(json["preferred_username"]),
            identityStatus: Last1JSON.string(json["identity_status"]),
            last1Verified: Last1JSON.bool(json["last1_verified"]),
            last1VerifiedAt: Last1JSON.string(json["last1_verified_at"])
        )
    }

    static func httpError(status: Int, data: Data) -> Last1IDError {
        if let json = Last1JSON.object(from: data, maximumBytes: 8_192),
           let code = Last1JSON.string(json["error"]), !code.isEmpty {
            return .oauth(
                code: Last1IDOAuthErrorCode(rawValue: code),
                description: Last1JSON.oauthDescription(json["error_description"])
            )
        }
        if status == 401 { return .oauth(code: .invalidToken, description: nil) }
        if status == 403 { return .oauth(code: .insufficientScope, description: nil) }
        if status >= 500 { return .oauth(code: .serverError, description: nil) }
        return .invalidResponse
    }
}

private struct ParsedTokenResponse: Sendable {
    var tokens: Last1IDTokens
    var idTokenFromResponse: String?
}

enum Last1Form {
    static func encode(_ fields: [(String, String)]) -> Data {
        let body = fields.map { key, value in
            escape(key) + "=" + escape(value)
        }.joined(separator: "&")
        return Data(body.utf8)
    }

    private static func escape(_ value: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
    }
}

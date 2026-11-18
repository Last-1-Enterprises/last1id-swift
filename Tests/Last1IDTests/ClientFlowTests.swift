import XCTest
@testable import Last1ID

final class ClientFlowTests: XCTestCase {
    func testDiscoveryRejectsATokenEndpointOnAnotherHost() throws {
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: discoveryDocument(issuer: "https://auth.last1.id")) as? [String: Any])
        object["token_endpoint"] = "https://evil.example/oauth/token"
        XCTAssertThrowsError(try Last1IDDiscovery.parse(data: jsonData(object), expectedIssuer: "https://auth.last1.id")) { error in
            guard case Last1IDError.discovery = error else {
                XCTFail("unexpected \(error)")
                return
            }
        }
    }

    func testDiscoveryIsCachedAndIssuerMustMatch() async throws {
        let app = TestApp()
        var hits = 0
        MockURLProtocol.register(host: app.host) { request in
            hits += 1
            if request.url.path.contains("openid-configuration") {
                return MockResponse(body: discoveryDocument(issuer: app.issuer.absoluteString))
            }
            return MockResponse(status: 404)
        }
        defer { MockURLProtocol.unregister(host: app.host) }
        let client = app.client()
        _ = try await client.beginAuthorization()
        _ = try await client.beginAuthorization()
        XCTAssertEqual(hits, 1)

        let evil = TestApp()
        MockURLProtocol.register(host: evil.host) { _ in
            MockResponse(body: discoveryDocument(issuer: "https://evil.example"))
        }
        defer { MockURLProtocol.unregister(host: evil.host) }
        do {
            _ = try await evil.client().discovery()
            XCTFail("expected issuer mismatch")
        } catch let error as Last1IDError {
            guard case .discovery = error else {
                XCTFail("unexpected \(error)")
                return
            }
        }
    }

    func testExchangeVerifiesNonceAndOmitsClientSecret() async throws {
        let app = TestApp()
        let keys = try RSAFixture.make(kid: "test-key")
        let nonce = "nonce-from-app"
        let idToken = try keys.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "test-key"],
            payload: idTokenPayload(issuer: app.issuer.absoluteString, nonce: nonce)
        )
        var tokenBody: [String: String] = [:]
        MockURLProtocol.register(host: app.host) { request in
            if request.url.path.contains("openid-configuration") {
                return MockResponse(body: discoveryDocument(issuer: app.issuer.absoluteString))
            }
            if request.url.path.contains("jwks") {
                return MockResponse(body: jwks([keys.jwk]))
            }
            tokenBody = formFields(request.body)
            return MockResponse(body: tokenJSON(idToken: idToken))
        }
        defer { MockURLProtocol.unregister(host: app.host) }

        let session = try await app.client().exchangeAuthorizationCode(
            code: "auth-code",
            codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            nonce: nonce
        )
        XCTAssertEqual(session.claims.sub, "11111111-1111-1111-1111-111111111111")
        XCTAssertEqual(session.claims.last1Verified, true)
        XCTAssertEqual(tokenBody["grant_type"], "authorization_code")
        XCTAssertEqual(tokenBody["code"], "auth-code")
        XCTAssertEqual(tokenBody["code_verifier"], "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        XCTAssertNil(tokenBody["client_secret"])
        let stored = try await app.store.load()
        XCTAssertEqual(stored?.accessToken, "access-new")
        XCTAssertEqual(stored?.refreshToken, "refresh-new")
    }

    func testNonceMismatchDoesNotSaveTokens() async throws {
        let app = TestApp()
        let keys = try RSAFixture.make(kid: "test-key")
        let idToken = try keys.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "test-key"],
            payload: idTokenPayload(issuer: app.issuer.absoluteString, nonce: "server-nonce")
        )
        MockURLProtocol.register(host: app.host) { request in
            if request.url.path.contains("openid-configuration") {
                return MockResponse(body: discoveryDocument(issuer: app.issuer.absoluteString))
            }
            if request.url.path.contains("jwks") {
                return MockResponse(body: jwks([keys.jwk]))
            }
            return MockResponse(body: tokenJSON(idToken: idToken))
        }
        defer { MockURLProtocol.unregister(host: app.host) }
        do {
            _ = try await app.client().exchangeAuthorizationCode(
                code: "auth-code",
                codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
                nonce: "app-nonce"
            )
            XCTFail("expected nonce mismatch")
        } catch let error as Last1IDError {
            XCTAssertEqual(error, .idToken(.nonceMismatch))
        }
        let stored = try await app.store.load()
        XCTAssertNil(stored)
    }

    func testUserInfoAndSignOut() async throws {
        let app = TestApp()
        var revoked = false
        var revokeBody: [String: String] = [:]
        MockURLProtocol.register(host: app.host) { request in
            if request.url.path.contains("openid-configuration") {
                return MockResponse(body: discoveryDocument(issuer: app.issuer.absoluteString))
            }
            if request.url.path.contains("userinfo") {
                XCTAssertEqual(request.headers["authorization"], "Bearer access-1")
                return MockResponse(body: jsonData([
                    "sub": "person-1",
                    "email": "ada@example.com",
                    "email_verified": true,
                    "name": "Ada",
                    "last1_verified": true,
                    "last1_verified_at": "2026-03-01T00:00:00.000Z",
                ]))
            }
            if request.url.path.contains("revoke") {
                revoked = true
                revokeBody = formFields(request.body)
                return MockResponse(status: 200, body: Data())
            }
            return MockResponse(status: 404)
        }
        defer { MockURLProtocol.unregister(host: app.host) }
        try await app.store.save(Last1IDTokens(
            accessToken: "access-1",
            refreshToken: "refresh-1",
            expiresAt: testNow.addingTimeInterval(3600)
        ))
        let profile = try await app.client().userInfo()
        XCTAssertEqual(profile.sub, "person-1")
        XCTAssertEqual(profile.emailVerified, true)
        XCTAssertEqual(profile.last1Verified, true)
        try await app.client().signOut()
        XCTAssertTrue(revoked)
        XCTAssertEqual(revokeBody["token"], "refresh-1")
        XCTAssertEqual(revokeBody["token_type_hint"], "refresh_token")
        XCTAssertEqual(revokeBody["client_id"], "example-app")
        XCTAssertNil(revokeBody["client_secret"])
        let stored = try await app.store.load()
        XCTAssertNil(stored)
    }

    func testSignOutClearsLocalSessionWhenRevokeFails() async throws {
        let app = TestApp()
        MockURLProtocol.register(host: app.host) { request in
            if request.url.path.contains("openid-configuration") {
                return MockResponse(body: discoveryDocument(issuer: app.issuer.absoluteString))
            }
            return MockResponse(status: 500, body: jsonData(["error": "server_error"]))
        }
        defer { MockURLProtocol.unregister(host: app.host) }
        try await app.store.save(Last1IDTokens(accessToken: "access-1", refreshToken: "refresh-1"))
        do {
            try await app.client().signOut()
            XCTFail("expected revoke failure")
        } catch let error as Last1IDError {
            XCTAssertEqual(error, .oauth(code: .serverError, description: nil))
        }
        let stored = try await app.store.load()
        XCTAssertNil(stored)
    }

    func testRefreshVerifiesTheReturnedIDToken() async throws {
        let app = TestApp()
        let keys = try RSAFixture.make(kid: "test-key")
        let original = try keys.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "test-key"],
            payload: idTokenPayload(
                issuer: app.issuer.absoluteString,
                nonce: "original-nonce",
                iat: 1_700_000_000 - 3600,
                exp: 1_700_000_000 - 120,
                nbf: nil
            )
        )
        let refreshed = try keys.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "test-key"],
            payload: idTokenPayload(
                issuer: app.issuer.absoluteString,
                nonce: "not-checked-on-refresh"
            )
        )
        MockURLProtocol.register(host: app.host) { request in
            if request.url.path.contains("openid-configuration") {
                return MockResponse(body: discoveryDocument(issuer: app.issuer.absoluteString))
            }
            if request.url.path.contains("jwks") {
                return MockResponse(body: jwks([keys.jwk]))
            }
            return MockResponse(body: tokenJSON(idToken: refreshed))
        }
        defer { MockURLProtocol.unregister(host: app.host) }
        try await app.store.save(Last1IDTokens(
            accessToken: "access-old",
            refreshToken: "refresh-old",
            idToken: original,
            expiresAt: testNow.addingTimeInterval(-10)
        ))
        let tokens = try await app.client().refresh()
        XCTAssertEqual(tokens.idToken, refreshed)
        let stored = try await app.store.load()
        XCTAssertEqual(stored?.idToken, refreshed)
        XCTAssertEqual(stored?.accessToken, "access-new")
    }

    func testRefreshRejectsAnIDTokenWithADifferentSubject() async throws {
        let app = TestApp()
        let keys = try RSAFixture.make(kid: "test-key")
        let original = try keys.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "test-key"],
            payload: idTokenPayload(issuer: app.issuer.absoluteString)
        )
        let refreshed = try keys.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "test-key"],
            payload: idTokenPayload(
                issuer: app.issuer.absoluteString,
                sub: "22222222-2222-2222-2222-222222222222"
            )
        )
        MockURLProtocol.register(host: app.host) { request in
            if request.url.path.contains("openid-configuration") {
                return MockResponse(body: discoveryDocument(issuer: app.issuer.absoluteString))
            }
            if request.url.path.contains("jwks") {
                return MockResponse(body: jwks([keys.jwk]))
            }
            return MockResponse(body: tokenJSON(idToken: refreshed))
        }
        defer { MockURLProtocol.unregister(host: app.host) }
        try await app.store.save(Last1IDTokens(
            accessToken: "access-old",
            refreshToken: "refresh-old",
            idToken: original
        ))
        do {
            _ = try await app.client().refresh()
            XCTFail("expected subject mismatch")
        } catch let error as Last1IDError {
            XCTAssertEqual(error, .idToken(.subjectMismatch))
        }
        let stored = try await app.store.load()
        XCTAssertNil(stored)
    }

    func testRefreshSurvivesASigningKeyRotation() async throws {
        let app = TestApp()
        let oldKey = try RSAFixture.make(kid: "old-key")
        let newKey = try RSAFixture.make(kid: "new-key")
        let original = try oldKey.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "old-key"],
            payload: idTokenPayload(issuer: app.issuer.absoluteString, nonce: "original-nonce")
        )
        let refreshed = try newKey.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "new-key"],
            payload: idTokenPayload(issuer: app.issuer.absoluteString, nonce: "not-checked-on-refresh")
        )
        MockURLProtocol.register(host: app.host) { request in
            if request.url.path.contains("openid-configuration") {
                return MockResponse(body: discoveryDocument(issuer: app.issuer.absoluteString))
            }
            if request.url.path.contains("jwks") {
                return MockResponse(body: jwks([newKey.jwk]))
            }
            return MockResponse(body: tokenJSON(idToken: refreshed))
        }
        defer { MockURLProtocol.unregister(host: app.host) }
        try await app.store.save(Last1IDTokens(
            accessToken: "access-old",
            refreshToken: "refresh-old",
            idToken: original
        ))
        let tokens = try await app.client().refresh()
        XCTAssertEqual(tokens.idToken, refreshed)
        let stored = try await app.store.load()
        XCTAssertEqual(stored?.idToken, refreshed)
        XCTAssertEqual(stored?.accessToken, "access-new")
    }

    func testForceRefreshDropsTheCachedVerifier() async throws {
        let app = TestApp()
        let oldKey = try RSAFixture.make(kid: "old-key")
        let newKey = try RSAFixture.make(kid: "new-key")
        let phase = PhaseBox()
        let firstID = try oldKey.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "old-key"],
            payload: idTokenPayload(issuer: app.issuer.absoluteString)
        )
        let rotated = try newKey.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "new-key"],
            payload: idTokenPayload(issuer: app.issuer.absoluteString, nonce: "not-checked-on-refresh")
        )
        MockURLProtocol.register(host: app.host) { request in
            if request.url.path.contains("openid-configuration") {
                guard var document = try? JSONSerialization.jsonObject(
                    with: discoveryDocument(issuer: app.issuer.absoluteString)
                ) as? [String: Any] else {
                    return MockResponse(status: 500)
                }
                if phase.value == 1 {
                    document["jwks_uri"] = "\(app.issuer.absoluteString)/.well-known/jwks-rotated.json"
                }
                return MockResponse(body: jsonData(document))
            }
            if request.url.path.contains("jwks-rotated") {
                return MockResponse(body: jwks([newKey.jwk]))
            }
            if request.url.path.contains("jwks") {
                return MockResponse(body: jwks([oldKey.jwk]))
            }
            if phase.value == 0 {
                return MockResponse(body: tokenJSON(access: "access-1", refresh: "refresh-1", idToken: firstID))
            }
            return MockResponse(body: tokenJSON(access: "access-2", refresh: "refresh-2", idToken: rotated))
        }
        defer { MockURLProtocol.unregister(host: app.host) }
        try await app.store.save(Last1IDTokens(
            accessToken: "access-old",
            refreshToken: "refresh-old",
            idToken: firstID
        ))
        let client = app.client()
        let first = try await client.refresh()
        XCTAssertEqual(first.idToken, firstID)
        phase.value = 1
        _ = try await client.discovery(forceRefresh: true)
        let second = try await client.refresh()
        XCTAssertEqual(second.idToken, rotated)
        let stored = try await app.store.load()
        XCTAssertEqual(stored?.idToken, rotated)
    }
}

private final class PhaseBox: @unchecked Sendable {
    var value = 0
}

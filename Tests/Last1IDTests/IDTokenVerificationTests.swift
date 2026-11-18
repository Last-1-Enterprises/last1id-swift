import Security
import XCTest
@testable import Last1ID

final class IDTokenVerificationTests: XCTestCase {
    private var host = ""
    private var session: URLSession!
    private var fixture: RSAFixture!

    override func setUpWithError() throws {
        host = "jwks-\(UUID().uuidString.lowercased()).test"
        session = ephemeralSession()
        fixture = try RSAFixture.make(kid: "test-key")
    }

    override func tearDown() {
        MockURLProtocol.unregister(host: host)
        session = nil
        fixture = nil
    }

    func testRSAKeyRoundTrip() throws {
        let key = try RSAPublicKey.fromJWK(fixture.jwk)?.secKey()
        let message = Data("last1".utf8)
        var error: Unmanaged<CFError>?
        let signature = SecKeyCreateSignature(
            fixture.privateKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            message as CFData,
            &error
        )
        XCTAssertNotNil(key)
        XCTAssertNotNil(signature)
        guard let key, let signature else { return }
        XCTAssertTrue(SecKeyVerifySignature(
            key,
            .rsaSignatureMessagePKCS1v15SHA256,
            message as CFData,
            signature,
            &error
        ))
    }

    func testValidToken() async throws {
        var fetches = 0
        MockURLProtocol.register(host: host) { request in
            XCTAssertTrue(request.url.path.contains("jwks"))
            fetches += 1
            return MockResponse(body: jwks([self.fixture.jwk]))
        }
        let token = try token(payload: idTokenPayload(issuer: issuer))
        let verifier = makeVerifier()
        let claims = try await verifier.verify(token, expectedNonce: "nonce-1")
        XCTAssertEqual(claims.sub, "11111111-1111-1111-1111-111111111111")
        XCTAssertEqual(claims.email, "ada@example.com")
        XCTAssertEqual(claims.emailVerified, true)
        XCTAssertEqual(claims.name, "Ada")
        XCTAssertEqual(claims.amr, ["pwd"])
        XCTAssertEqual(claims.acr, "aal1")
        XCTAssertEqual(claims.last1Verified, true)
        XCTAssertEqual(claims.last1VerifiedAt, "2026-03-01T00:00:00.000Z")
        let again = try await verifier.verify(token, expectedNonce: "nonce-1")
        XCTAssertEqual(again.sub, claims.sub)
        XCTAssertEqual(fetches, 1)
    }

    func testStringEmailVerifiedIsDropped() async throws {
        serveKey()
        var payload = idTokenPayload(issuer: issuer)
        payload["email_verified"] = "true"
        let token = try token(payload: payload)
        let claims = try await makeVerifier().verify(token, expectedNonce: "nonce-1")
        XCTAssertNil(claims.emailVerified)
        XCTAssertEqual(claims.sub, "11111111-1111-1111-1111-111111111111")
    }

    func testWrongIssuer() async throws {
        serveKey()
        let token = try token(payload: idTokenPayload(issuer: "https://evil.example"))
        await XCTAssertThrowsIDToken(.wrongIssuer) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
    }

    func testWrongAudience() async throws {
        serveKey()
        let token = try token(payload: idTokenPayload(issuer: issuer, audience: "other-app"))
        await XCTAssertThrowsIDToken(.wrongAudience) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
    }

    func testAuthorizedPartyMustMatchWhenPresent() async throws {
        serveKey()
        var payload = idTokenPayload(issuer: issuer)
        payload["azp"] = "other-app"
        let token = try token(payload: payload)
        await XCTAssertThrowsIDToken(.wrongAudience) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
    }

    func testMultipleAudiencesRequireAuthorizedParty() async throws {
        serveKey()
        let token = try token(payload: idTokenPayload(issuer: issuer, audience: ["example-app", "other"]))
        await XCTAssertThrowsIDToken(.wrongAudience) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
    }

    func testAudienceDefaultsToClientID() async throws {
        serveKey()
        let slug = "example-app"
        let uuid = "11111111-1111-4111-8111-111111111111"
        let token = try token(payload: idTokenPayload(issuer: issuer, audience: slug))
        await XCTAssertThrowsIDToken(.wrongAudience) {
            _ = try await self.makeVerifier(clientID: uuid).verify(token, expectedNonce: "nonce-1")
        }
        let claims = try await makeVerifier(clientID: uuid, audience: [slug]).verify(token, expectedNonce: "nonce-1")
        XCTAssertEqual(claims.audience, [slug])
    }

    func testAudienceOverrideAcceptsAuthorizedParty() async throws {
        serveKey()
        let slug = "example-app"
        let uuid = "11111111-1111-4111-8111-111111111111"
        var payload = idTokenPayload(issuer: issuer, audience: [slug, "other"])
        payload["azp"] = slug
        let signed = try token(payload: payload)
        let claims = try await makeVerifier(clientID: uuid, audience: [slug]).verify(signed, expectedNonce: "nonce-1")
        XCTAssertEqual(claims.authorizedParty, slug)
        var mismatched = payload
        mismatched["azp"] = uuid
        let rejected = try token(payload: mismatched)
        await XCTAssertThrowsIDToken(.wrongAudience) {
            _ = try await self.makeVerifier(clientID: uuid, audience: [slug]).verify(rejected, expectedNonce: "nonce-1")
        }
    }

    func testExpired() async throws {
        serveKey()
        let token = try token(payload: idTokenPayload(issuer: issuer, iat: 1_700_000_000 - 3600, exp: 1_700_000_000 - 61, nbf: nil))
        await XCTAssertThrowsIDToken(.expired) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
    }

    func testExpirationAtTheSkewBoundaryIsValid() async throws {
        serveKey()
        let token = try token(payload: idTokenPayload(issuer: issuer, iat: 1_700_000_000 - 120, exp: 1_700_000_000 - 60, nbf: nil))
        let claims = try await makeVerifier().verify(token, expectedNonce: "nonce-1")
        XCTAssertEqual(claims.sub, "11111111-1111-1111-1111-111111111111")
    }

    func testFutureIssuedAt() async throws {
        serveKey()
        let token = try token(payload: idTokenPayload(issuer: issuer, iat: 1_700_000_000 + 61, exp: 1_700_000_000 + 3600))
        await XCTAssertThrowsIDToken(.issuedInFuture) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
    }

    func testIssuedAtAtTheSkewBoundaryIsValid() async throws {
        serveKey()
        let token = try token(payload: idTokenPayload(issuer: issuer, iat: 1_700_000_000 + 60, exp: 1_700_000_000 + 3600))
        _ = try await makeVerifier().verify(token, expectedNonce: "nonce-1")
    }

    func testNotYetValid() async throws {
        serveKey()
        let token = try token(payload: idTokenPayload(issuer: issuer, nbf: 1_700_000_000 + 61))
        await XCTAssertThrowsIDToken(.notYetValid) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
    }

    func testBadNonce() async throws {
        serveKey()
        let token = try token(payload: idTokenPayload(issuer: issuer, nonce: "other"))
        await XCTAssertThrowsIDToken(.nonceMismatch) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
    }

    func testAlgorithmNone() async throws {
        var fetches = 0
        MockURLProtocol.register(host: host) { _ in
            fetches += 1
            return MockResponse(body: jwks([self.fixture.jwk]))
        }
        let header = Base64URL.encode(jsonData(["alg": "none", "typ": "JWT"]))
        let payload = Base64URL.encode(jsonData(idTokenPayload(issuer: issuer)))
        let token = "\(header).\(payload)."
        await XCTAssertThrowsIDToken(.unsupportedAlgorithm) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches, 0)
    }

    func testHS256IsRejected() async throws {
        var fetches = 0
        MockURLProtocol.register(host: host) { _ in
            fetches += 1
            return MockResponse(body: jwks([self.fixture.jwk]))
        }
        let header = Base64URL.encode(jsonData(["alg": "HS256", "typ": "JWT", "kid": "test-key"]))
        let payload = Base64URL.encode(jsonData(idTokenPayload(issuer: issuer)))
        let token = "\(header).\(payload).\(Base64URL.encode(Data("not-an-rsa-signature".utf8)))"
        await XCTAssertThrowsIDToken(.unsupportedAlgorithm) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches, 0)
    }

    func testCritHeaderIsRejected() async throws {
        let fetches = FetchCount()
        MockURLProtocol.register(host: host) { _ in
            _ = fetches.increment()
            return MockResponse(body: jwks([self.fixture.jwk]))
        }
        let header = Base64URL.encode(jsonData([
            "alg": "RS256",
            "typ": "JWT",
            "kid": "test-key",
            "crit": ["b64"],
        ]))
        let payload = Base64URL.encode(jsonData(idTokenPayload(issuer: issuer)))
        let token = "\(header).\(payload).\(Base64URL.encode(Data("not-checked".utf8)))"
        await XCTAssertThrowsIDToken(.unsupportedAlgorithm) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches.value, 0)
    }

    func testMissingKidIsRejected() async throws {
        let fetches = FetchCount()
        MockURLProtocol.register(host: host) { _ in
            _ = fetches.increment()
            return MockResponse(body: jwks([self.fixture.jwk]))
        }
        let header = Base64URL.encode(jsonData(["alg": "RS256", "typ": "JWT"]))
        let payload = Base64URL.encode(jsonData(idTokenPayload(issuer: issuer)))
        let token = "\(header).\(payload).\(Base64URL.encode(Data("not-checked".utf8)))"
        await XCTAssertThrowsIDToken(.unknownKeyID) {
            _ = try await self.makeVerifier().verify(token, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches.value, 0)
    }

    func testUnknownKidDoesNotFetchTwiceUntilTheCooldown() async throws {
        let clock = MutableClock(testNow)
        let fetches = FetchCount()
        MockURLProtocol.register(host: host) { _ in
            let count = fetches.increment()
            if count == 1 {
                var other = self.fixture.jwk
                other["kid"] = "other-key"
                return MockResponse(body: jwks([other]))
            }
            return MockResponse(body: jwks([self.fixture.jwk]))
        }
        let verifier = makeVerifier(now: { clock.date })
        let token = try token(payload: idTokenPayload(issuer: issuer))
        await XCTAssertThrowsIDToken(.unknownKeyID) {
            _ = try await verifier.verify(token, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches.value, 1)
        await XCTAssertThrowsIDToken(.unknownKeyID) {
            _ = try await verifier.verify(token, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches.value, 1)

        clock.date = testNow.addingTimeInterval(45)
        let claims = try await verifier.verify(token, expectedNonce: "nonce-1")
        XCTAssertEqual(claims.emailVerified, true)
        XCTAssertEqual(fetches.value, 2)
    }

    func testInFlightJWKSFetchesAreCoalesced() async throws {
        let fetches = FetchCount()
        MockURLProtocol.register(host: host) { _ in
            _ = fetches.increment()
            return MockResponse(body: jwks([self.fixture.jwk]), delay: 0.3)
        }
        let verifier = makeVerifier()
        let token = try token(payload: idTokenPayload(issuer: issuer))
        async let first = verifier.verify(token, expectedNonce: "nonce-1")
        async let second = verifier.verify(token, expectedNonce: "nonce-1")
        let (left, right) = try await (first, second)
        XCTAssertEqual(left.sub, right.sub)
        XCTAssertEqual(fetches.value, 1)
    }

    func testJWKSFetchFailureBacksOff() async throws {
        let clock = MutableClock(testNow)
        let fetches = FetchCount()
        MockURLProtocol.register(host: host) { _ in
            _ = fetches.increment()
            return MockResponse(status: 500)
        }
        let verifier = makeVerifier(now: { clock.date })
        let token = try token(payload: idTokenPayload(issuer: issuer))
        await XCTAssertThrowsIDToken(.unknownKeyID) {
            _ = try await verifier.verify(token, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches.value, 1)
        clock.date = testNow.addingTimeInterval(4)
        await XCTAssertThrowsIDToken(.unknownKeyID) {
            _ = try await verifier.verify(token, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches.value, 1)
        clock.date = testNow.addingTimeInterval(5)
        await XCTAssertThrowsIDToken(.unknownKeyID) {
            _ = try await verifier.verify(token, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches.value, 2)
    }

    func testRefetchReplacesTheKeySet() async throws {
        let clock = MutableClock(testNow)
        let phase = PhaseFlag()
        let fetches = FetchCount()
        MockURLProtocol.register(host: host) { _ in
            _ = fetches.increment()
            if phase.value == 0 {
                return MockResponse(body: jwks([self.fixture.jwk]))
            }
            var other = self.fixture.jwk
            other["kid"] = "other-key"
            return MockResponse(body: jwks([other]))
        }
        let verifier = makeVerifier(now: { clock.date })
        let original = try token(payload: idTokenPayload(issuer: issuer))
        _ = try await verifier.verify(original, expectedNonce: "nonce-1")
        XCTAssertEqual(fetches.value, 1)

        clock.date = testNow.addingTimeInterval(46)
        phase.value = 1
        let rotated = try fixture.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "other-key"],
            payload: idTokenPayload(issuer: issuer)
        )
        _ = try await verifier.verify(rotated, expectedNonce: "nonce-1")
        XCTAssertEqual(fetches.value, 2)
        await XCTAssertThrowsIDToken(.unknownKeyID) {
            _ = try await verifier.verify(original, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches.value, 2)
    }

    func testKeyNotOnTheAllowList() async throws {
        var fetches = 0
        MockURLProtocol.register(host: host) { _ in
            fetches += 1
            return MockResponse(body: jwks([self.fixture.jwk]))
        }
        let token = try token(payload: idTokenPayload(issuer: issuer))
        await XCTAssertThrowsIDToken(.keyNotAllowed) {
            _ = try await self.makeVerifier(allowedKeyIDs: ["other-key"]).verify(token, expectedNonce: "nonce-1")
        }
        XCTAssertEqual(fetches, 0)
    }

    func testTamperedSignature() async throws {
        serveKey()
        let token = try token(payload: idTokenPayload(issuer: issuer))
        let parts = token.split(separator: ".")
        var signature = Data(base64URL: String(parts[2]))
        signature[signature.count - 1] ^= 0x01
        let tampered = "\(parts[0]).\(parts[1]).\(Base64URL.encode(signature))"
        await XCTAssertThrowsIDToken(.badSignature) {
            _ = try await self.makeVerifier().verify(tampered, expectedNonce: "nonce-1")
        }
    }

    private var issuer: String { "https://\(host)" }

    private func makeVerifier(
        clientID: String = "example-app",
        audience: [String]? = nil,
        allowedKeyIDs: [String]? = nil,
        now: @escaping @Sendable () -> Date = { testNow }
    ) -> Last1IDIDTokenVerifier {
        Last1IDIDTokenVerifier(
            jwksURL: URL(string: "\(issuer)/.well-known/jwks.json")!,
            session: session,
            expectedIssuer: issuer,
            clientID: clientID,
            audience: audience,
            allowedKeyIDs: allowedKeyIDs,
            now: now
        )
    }

    private func token(payload: [String: Any]) throws -> String {
        try fixture.sign(
            header: ["alg": "RS256", "typ": "JWT", "kid": "test-key"],
            payload: payload
        )
    }

    private func serveKey() {
        MockURLProtocol.register(host: host) { _ in
            MockResponse(body: jwks([self.fixture.jwk]))
        }
    }
}

private extension Data {
    init(base64URL string: String) {
        self = Base64URL.decode(string) ?? Data()
    }
}

private final class MutableClock: @unchecked Sendable {
    var date: Date
    init(_ date: Date) { self.date = date }
}

private final class FetchCount: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    func increment() -> Int {
        lock.lock()
        defer { lock.unlock() }
        count += 1
        return count
    }

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }
}

private final class PhaseFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var stored = 0

    var value: Int {
        get {
            lock.lock()
            defer { lock.unlock() }
            return stored
        }
        set {
            lock.lock()
            stored = newValue
            lock.unlock()
        }
    }
}

private extension XCTestCase {
    func XCTAssertThrowsIDToken(
        _ failure: Last1IDTokenFailure,
        _ body: () async throws -> Void
    ) async {
        do {
            try await body()
            XCTFail("expected \(failure.rawValue)")
        } catch let error as Last1IDError {
            XCTAssertEqual(error, .idToken(failure))
        } catch {
            XCTFail("unexpected error \(error)")
        }
    }
}

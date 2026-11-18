import XCTest
@testable import Last1ID

final class CallbackTests: XCTestCase {
    func testStateMismatch() {
        XCTAssertThrowsError(
            try Last1IDCallbackParser.authorizationCode(
                from: URL(string: "myapp://callback?code=abc&state=wrong")!,
                redirectURI: URL(string: "myapp://callback")!,
                expectedState: "right"
            )
        ) { error in
            XCTAssertEqual(error as? Last1IDError, .stateMismatch)
        }
    }

    func testMatchingStateReturnsCode() throws {
        let code = try Last1IDCallbackParser.authorizationCode(
            from: URL(string: "myapp://callback?code=abc&state=right")!,
            redirectURI: URL(string: "myapp://callback")!,
            expectedState: "right"
        )
        XCTAssertEqual(code, "abc")
    }

    func testOAuthErrorRequiresMatchingState() {
        XCTAssertThrowsError(
            try Last1IDCallbackParser.authorizationCode(
                from: URL(string: "myapp://callback?error=access_denied&error_description=no&state=right")!,
                redirectURI: URL(string: "myapp://callback")!,
                expectedState: "right"
            )
        ) { error in
            XCTAssertEqual(
                error as? Last1IDError,
                .oauth(code: .accessDenied, description: "no")
            )
        }
        XCTAssertThrowsError(
            try Last1IDCallbackParser.authorizationCode(
                from: URL(string: "myapp://callback?error=login_required&state=wrong")!,
                redirectURI: URL(string: "myapp://callback")!,
                expectedState: "right"
            )
        ) { error in
            XCTAssertEqual(error as? Last1IDError, .stateMismatch)
        }
    }

    func testRejectsADifferentRedirect() {
        XCTAssertThrowsError(
            try Last1IDCallbackParser.authorizationCode(
                from: URL(string: "https://evil.example/auth/callback?code=abc&state=right")!,
                redirectURI: URL(string: "https://app.example.com/auth/callback")!,
                expectedState: "right"
            )
        ) { error in
            XCTAssertEqual(error as? Last1IDError, .invalidCallback)
        }
    }

    func testRejectsAFragment() {
        XCTAssertThrowsError(
            try Last1IDCallbackParser.authorizationCode(
                from: URL(string: "myapp://callback?code=abc&state=right#token")!,
                redirectURI: URL(string: "myapp://callback")!,
                expectedState: "right"
            )
        ) { error in
            XCTAssertEqual(error as? Last1IDError, .invalidCallback)
        }
    }

    func testRepeatedCodeStateOrErrorIsInvalid() {
        let redirect = URL(string: "com.example.app:/callback")!
        let urls = [
            "com.example.app:/callback?code=a&code=b&state=s",
            "com.example.app:/callback?code=a&state=s&state=t",
            "com.example.app:/callback?error=access_denied&error=server_error&state=s",
        ]
        for raw in urls {
            XCTAssertThrowsError(
                try Last1IDCallbackParser.parse(callback: URL(string: raw)!, redirectURI: redirect)
            ) { error in
                XCTAssertEqual(error as? Last1IDError, .invalidCallback)
            }
        }
    }

    func testParseReturnsCodeStateAndErrorWithoutCheckingState() throws {
        let redirect = URL(string: "myapp://callback")!
        let ok = try Last1IDCallbackParser.parse(
            callback: URL(string: "myapp://callback?code=abc&state=from-app")!,
            redirectURI: redirect
        )
        XCTAssertEqual(ok.code, "abc")
        XCTAssertEqual(ok.state, "from-app")
        XCTAssertNil(ok.error)
        XCTAssertNil(ok.errorDescription)

        let failed = try Last1IDCallbackParser.parse(
            callback: URL(string: "myapp://callback?error=access_denied&error_description=no&state=other")!,
            redirectURI: redirect
        )
        XCTAssertNil(failed.code)
        XCTAssertEqual(failed.state, "other")
        XCTAssertEqual(failed.error, "access_denied")
        XCTAssertEqual(failed.errorDescription, "no")
    }

    func testBackendExchangeDescriptionRedactsSecrets() {
        let handoff = Last1IDBackendExchange(
            code: "secret-code",
            codeVerifier: "secret-verifier",
            nonce: "secret-nonce",
            clientID: "example-app",
            redirectURI: URL(string: "myapp://callback")!,
            issuer: URL(string: "https://auth.last1.id")!
        )
        XCTAssertFalse(handoff.description.contains("secret-code"))
        XCTAssertFalse(handoff.debugDescription.contains("secret-verifier"))
        XCTAssertFalse(handoff.debugDescription.contains("secret-nonce"))
        var dumped = ""
        dump(handoff, to: &dumped)
        XCTAssertFalse(dumped.contains("secret-code"))
        XCTAssertFalse(dumped.contains("secret-verifier"))
        XCTAssertFalse(dumped.contains("secret-nonce"))
        let tokens = Last1IDTokens(accessToken: "access-1", refreshToken: "refresh-1", idToken: "id-1")
        XCTAssertFalse(String(reflecting: tokens).contains("access-1"))
        dumped = ""
        dump(tokens, to: &dumped)
        XCTAssertFalse(dumped.contains("access-1"))
        XCTAssertFalse(dumped.contains("refresh-1"))
        XCTAssertFalse(dumped.contains("id-1"))
    }
}

import XCTest
@testable import Last1ID

final class AuthorizeURLTests: XCTestCase {
    func testBuildsCodeFlowURL() throws {
        let endpoint = URL(string: "https://auth.last1.id/oauth/authorize")!
        let redirect = URL(string: "https://app.example.com/auth/callback")!
        let pkce = try Last1IDPKCE(codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
        let url = Last1IDAuthorizeURL.make(
            authorizationEndpoint: endpoint,
            clientID: "example-app",
            redirectURI: redirect,
            scopes: ["openid", "profile", "email"],
            codeChallenge: pkce.codeChallenge,
            state: "state-1",
            nonce: "nonce-1",
            prompt: "none",
            idTokenHint: "hint-token"
        )
        let items = Dictionary(uniqueKeysWithValues: (URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []).map {
            ($0.name, $0.value)
        })
        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "auth.last1.id")
        XCTAssertEqual(url.path, "/oauth/authorize")
        XCTAssertEqual(items["response_type"], "code")
        XCTAssertEqual(items["client_id"], "example-app")
        XCTAssertEqual(items["redirect_uri"], redirect.absoluteString)
        XCTAssertEqual(items["scope"], "openid profile email")
        XCTAssertEqual(items["state"], "state-1")
        XCTAssertEqual(items["nonce"], "nonce-1")
        XCTAssertEqual(items["code_challenge"], pkce.codeChallenge)
        XCTAssertEqual(items["code_challenge_method"], "S256")
        XCTAssertEqual(items["prompt"], "none")
        XCTAssertEqual(items["id_token_hint"], "hint-token")
        XCTAssertNil(items["client_secret"] ?? nil)
    }

    func testIssuerEndpointStripsTrailingSlash() {
        let issuer = URL(string: "https://auth.last1.id/")!
        XCTAssertEqual(
            Last1IDAuthorizeURL.authorizationEndpoint(forIssuer: issuer)?.absoluteString,
            "https://auth.last1.id/oauth/authorize"
        )
    }
}

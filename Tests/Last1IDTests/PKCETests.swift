import XCTest
@testable import Last1ID

final class PKCETests: XCTestCase {
    func testRFC7636AppendixB() throws {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        XCTAssertEqual(
            Last1IDPKCE.challenge(for: verifier),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        )
        let pair = try Last1IDPKCE(codeVerifier: verifier)
        XCTAssertEqual(Last1IDPKCE.codeChallengeMethod, "S256")
        XCTAssertEqual(pair.codeChallenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    func testGeneratedVerifierIsS256() throws {
        let pair = Last1IDPKCE.generate()
        XCTAssertEqual(pair.codeChallenge, Last1IDPKCE.challenge(for: pair.codeVerifier))
        XCTAssertTrue((43...128).contains(pair.codeVerifier.count))
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        XCTAssertTrue(pair.codeVerifier.unicodeScalars.allSatisfy { allowed.contains($0) })
        XCTAssertFalse(pair.codeChallenge.contains("="))
        XCTAssertFalse(pair.codeChallenge.contains("+"))
        XCTAssertFalse(pair.codeChallenge.contains("/"))
    }

    func testSDKVersion() {
        XCTAssertEqual(Last1IDVersion.current, "0.4.0")
    }
}

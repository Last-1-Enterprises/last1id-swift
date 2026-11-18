import XCTest
@testable import Last1ID

final class RefreshCoalescingTests: XCTestCase {
    func testConcurrentRefreshesShareOneRequest() async throws {
        let app = TestApp()
        let hits = HitCounter()
        MockURLProtocol.register(host: app.host) { request in
            if request.url.path.contains("openid-configuration") {
                return MockResponse(body: discoveryDocument(issuer: app.issuer.absoluteString))
            }
            if request.url.path.contains("/oauth/token") {
                hits.increment()
                let fields = formFields(request.body)
                XCTAssertEqual(fields["grant_type"], "refresh_token")
                XCTAssertEqual(fields["refresh_token"], "refresh-old")
                XCTAssertNil(fields["client_secret"])
                return MockResponse(body: tokenJSON(access: "access-rotated", refresh: "refresh-rotated"), delay: 0.25)
            }
            return MockResponse(status: 404)
        }
        defer { MockURLProtocol.unregister(host: app.host) }
        try await app.store.save(Last1IDTokens(
            accessToken: "access-old",
            refreshToken: "refresh-old",
            idToken: "keep-me",
            expiresAt: testNow.addingTimeInterval(-10)
        ))
        let client = app.client()
        let results = try await withThrowingTaskGroup(of: Last1IDTokens.self) { group in
            for _ in 0..<8 {
                group.addTask { try await client.refresh() }
            }
            var collected: [Last1IDTokens] = []
            for try await tokens in group {
                collected.append(tokens)
            }
            return collected
        }
        XCTAssertEqual(results.count, 8)
        XCTAssertEqual(Set(results.map(\.accessToken)), ["access-rotated"])
        XCTAssertEqual(Set(results.map(\.refreshToken)), ["refresh-rotated"])
        XCTAssertEqual(hits.value, 1)
        let stored = try await app.store.load()
        XCTAssertEqual(stored?.refreshToken, "refresh-rotated")
        XCTAssertEqual(stored?.idToken, "keep-me")
    }

    func testInvalidGrantClearsTheStoredSession() async throws {
        let app = TestApp()
        MockURLProtocol.register(host: app.host) { request in
            if request.url.path.contains("openid-configuration") {
                return MockResponse(body: discoveryDocument(issuer: app.issuer.absoluteString))
            }
            return MockResponse(status: 400, body: jsonData([
                "error": "invalid_grant",
                "error_description": "refresh token reuse",
            ]))
        }
        defer { MockURLProtocol.unregister(host: app.host) }
        try await app.store.save(Last1IDTokens(accessToken: "access-old", refreshToken: "refresh-old"))
        do {
            _ = try await app.client().refresh()
            XCTFail("expected invalid_grant")
        } catch let error as Last1IDError {
            XCTAssertEqual(error, .oauth(code: .invalidGrant, description: "refresh token reuse"))
        }
        let stored = try await app.store.load()
        XCTAssertNil(stored)
    }
}

private final class HitCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    func increment() {
        lock.lock()
        count += 1
        lock.unlock()
    }

    var value: Int {
        lock.lock()
        defer { lock.unlock() }
        return count
    }
}

import Foundation
@testable import Last1ID
@preconcurrency import Security
import XCTest

struct MockResponse {
    var status: Int = 200
    var body: Data = Data()
    var headers: [String: String] = ["Content-Type": "application/json"]
    var delay: TimeInterval = 0
}

struct MockRequest {
    var url: URL
    var method: String
    var headers: [String: String]
    var body: Data
}

final class MockURLProtocol: URLProtocol, @unchecked Sendable {
    private static let lock = NSLock()
    private nonisolated(unsafe) static var handlers: [String: (MockRequest) -> MockResponse] = [:]

    static func register(host: String, handler: @escaping (MockRequest) -> MockResponse) {
        lock.lock()
        handlers[host.lowercased()] = handler
        lock.unlock()
    }

    static func unregister(host: String) {
        lock.lock()
        handlers.removeValue(forKey: host.lowercased())
        lock.unlock()
    }

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let client, let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }
        let host = url.host?.lowercased() ?? ""
        let handler = Self.lock.withLock { Self.handlers[host] }
        guard let handler else {
            client.urlProtocol(self, didFailWithError: URLError(.cannotConnectToHost))
            return
        }
        let mock = MockRequest(
            url: url,
            method: request.httpMethod ?? "GET",
            headers: (request.allHTTPHeaderFields ?? [:]).reduce(into: [:]) { result, item in
                result[item.key.lowercased()] = item.value
            },
            body: Self.readBody(request)
        )
        let response = handler(mock)
        nonisolated(unsafe) let protocolClient = client
        let statusCode = response.status
        let headerFields = response.headers
        let body = response.body
        let deliver: @Sendable () -> Void = {
            let http = HTTPURLResponse(
                url: url,
                statusCode: statusCode,
                httpVersion: "HTTP/1.1",
                headerFields: headerFields
            )!
            protocolClient.urlProtocol(self, didReceive: http, cacheStoragePolicy: .notAllowed)
            if !body.isEmpty {
                protocolClient.urlProtocol(self, didLoad: body)
            }
            protocolClient.urlProtocolDidFinishLoading(self)
        }
        if response.delay > 0 {
            DispatchQueue.global().asyncAfter(deadline: .now() + response.delay, execute: deliver)
        } else {
            deliver()
        }
    }

    override func stopLoading() {}

    private static func readBody(_ request: URLRequest) -> Data {
        if let body = request.httpBody { return body }
        guard let stream = request.httpBodyStream else { return Data() }
        stream.open()
        defer { stream.close() }
        var data = Data()
        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: 4096)
        defer { buffer.deallocate() }
        while true {
            let count = stream.read(buffer, maxLength: 4096)
            if count <= 0 { break }
            data.append(buffer, count: count)
        }
        return data
    }
}

func jsonData(_ object: Any) -> Data {
    try! JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

func formFields(_ data: Data) -> [String: String] {
    guard let text = String(data: data, encoding: .utf8) else { return [:] }
    var fields: [String: String] = [:]
    for pair in text.split(separator: "&") {
        let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
        guard parts.count == 2 else { continue }
        let name = parts[0].removingPercentEncoding ?? parts[0]
        let value = parts[1].removingPercentEncoding ?? parts[1]
        fields[name] = value
    }
    return fields
}

func ephemeralSession() -> URLSession {
    let config = URLSessionConfiguration.ephemeral
    config.protocolClasses = [MockURLProtocol.self]
    config.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
    config.urlCache = nil
    config.timeoutIntervalForRequest = 5
    return URLSession(configuration: config)
}

struct RSAFixture {
    let privateKey: SecKey
    let jwk: [String: Any]

    static func make(kid: String) throws -> RSAFixture {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: false,
            ],
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
              let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw error?.takeRetainedValue() ?? URLError(.cannotCreateFile)
        }
        guard let external = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error?.takeRetainedValue() ?? URLError(.cannotDecodeRawData)
        }
        let parts = try rsaNumbers(from: external)
        let jwk: [String: Any] = [
            "kty": "RSA",
            "n": Base64URL.encode(parts.modulus),
            "e": Base64URL.encode(parts.exponent),
            "alg": "RS256",
            "use": "sig",
            "kid": kid,
        ]
        return RSAFixture(privateKey: privateKey, jwk: jwk)
    }

    func sign(header: [String: Any], payload: [String: Any]) throws -> String {
        let encodedHeader = Base64URL.encode(jsonData(header))
        let encodedPayload = Base64URL.encode(jsonData(payload))
        let signingInput = Data((encodedHeader + "." + encodedPayload).utf8)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            signingInput as CFData,
            &error
        ) as Data? else {
            throw error?.takeRetainedValue() ?? URLError(.cannotDecodeRawData)
        }
        return encodedHeader + "." + encodedPayload + "." + Base64URL.encode(signature)
    }
}

func rsaNumbers(from external: Data) throws -> (modulus: Data, exponent: Data) {
    if let parsed = try? DER.modulusAndExponent(fromPKCS1: external), parsed.modulus.count >= 200 {
        return parsed
    }
    let bytes = [UInt8](external)
    let oid: [UInt8] = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01]
    var index = 0
    while index + oid.count <= bytes.count {
        if Array(bytes[index..<(index + oid.count)]) == oid { break }
        index += 1
    }
    guard index + oid.count <= bytes.count else { throw Last1IDError.idToken(.keyImportFailed) }
    index += oid.count
    while index < bytes.count, bytes[index] != 0x03 { index += 1 }
    guard index + 2 < bytes.count, bytes[index] == 0x03 else { throw Last1IDError.idToken(.keyImportFailed) }
    index += 1
    var length = Int(bytes[index])
    index += 1
    if length & 0x80 != 0 {
        let count = length & 0x7F
        length = 0
        for _ in 0..<count {
            guard index < bytes.count else { throw Last1IDError.idToken(.keyImportFailed) }
            length = (length << 8) | Int(bytes[index])
            index += 1
        }
    }
    guard length >= 1, index + length <= bytes.count else { throw Last1IDError.idToken(.keyImportFailed) }
    let inner = Data(bytes[(index + 1)..<(index + length)])
    return try DER.modulusAndExponent(fromPKCS1: inner)
}

func jwks(_ keys: [[String: Any]]) -> Data {
    jsonData(["keys": keys])
}

let testNow = Date(timeIntervalSince1970: 1_700_000_000)

func idTokenPayload(
    issuer: String,
    audience: Any = "example-app",
    nonce: String = "nonce-1",
    iat: Int = 1_700_000_000,
    exp: Int = 1_700_003_600,
    nbf: Int? = 1_699_999_990,
    sub: String = "11111111-1111-1111-1111-111111111111"
) -> [String: Any] {
    var payload: [String: Any] = [
        "iss": issuer,
        "aud": audience,
        "sub": sub,
        "iat": iat,
        "exp": exp,
        "nonce": nonce,
        "email": "ada@example.com",
        "email_verified": true,
        "name": "Ada",
        "amr": ["pwd"],
        "acr": "aal1",
        "last1_verified": true,
        "last1_verified_at": "2026-03-01T00:00:00.000Z",
    ]
    if let nbf { payload["nbf"] = nbf }
    return payload
}

func discoveryDocument(issuer: String) -> Data {
    jsonData([
        "issuer": issuer,
        "authorization_endpoint": "\(issuer)/oauth/authorize",
        "token_endpoint": "\(issuer)/oauth/token",
        "userinfo_endpoint": "\(issuer)/oauth/userinfo",
        "revocation_endpoint": "\(issuer)/oauth/revoke",
        "jwks_uri": "\(issuer)/.well-known/jwks.json",
        "response_types_supported": ["code"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "prompt_values_supported": ["none"],
        "end_session_endpoint": "\(issuer)/oauth/logout",
    ])
}

actor MemoryTokenStore: Last1IDTokenStore {
    private var value: Last1IDTokens?
    func load() async throws -> Last1IDTokens? { value }
    func save(_ tokens: Last1IDTokens) async throws { value = tokens }
    func clear() async throws { value = nil }
}

struct TestApp {
    let host: String
    let issuer: URL
    let configuration: Last1IDConfiguration
    let store: MemoryTokenStore
    let session: URLSession

    init() {
        host = "auth-\(UUID().uuidString.lowercased()).test"
        issuer = URL(string: "https://\(host)")!
        configuration = Last1IDConfiguration(
            clientID: "example-app",
            redirectURI: URL(string: "myapp://callback")!,
            callback: .customScheme("myapp"),
            issuerURL: issuer,
            scopes: ["openid", "profile", "email", "offline_access", "identity_proof:read"]
        )
        store = MemoryTokenStore()
        session = ephemeralSession()
    }

    func client(now: Date = testNow) -> Last1IDClient {
        Last1IDClient(configuration: configuration, tokenStore: store, session: session, now: { now })
    }
}

func tokenJSON(access: String = "access-new", refresh: String = "refresh-new", idToken: String? = nil) -> Data {
    var body: [String: Any] = [
        "access_token": access,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": refresh,
        "refresh_expires_in": 2_592_000,
        "scope": "openid profile email",
    ]
    if let idToken { body["id_token"] = idToken }
    return jsonData(body)
}

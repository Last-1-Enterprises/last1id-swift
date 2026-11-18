import Foundation
@preconcurrency import Security

/// Claims from a verified Last1 ID token.
///
/// `emailVerified` is `email_verified` when that claim is a JSON boolean.
/// A string value is ignored. `last1Verified` and
/// `last1VerifiedAt` are present when the token was issued with
/// `identity_proof:read`. `amr` and `acr` describe the sign-in factors
/// (`aal1` password, `aal2` with a second factor).
public struct Last1IDIDTokenClaims: Sendable, Equatable {
    public let sub: String
    public let email: String?
    public let emailVerified: Bool?
    public let name: String?
    public let amr: [String]
    public let acr: String?
    public let last1Verified: Bool?
    public let last1VerifiedAt: String?
    public let issuer: String
    public let audience: [String]
    public let authorizedParty: String?
    public let issuedAt: Date
    public let expiration: Date
    public let nonce: String?
}

public struct Last1IDIDTokenVerifier: Sendable {
    public static let defaultLeeway: TimeInterval = 60

    private let jwksURL: URL
    private let session: URLSession
    private let expectedIssuer: String
    /// Values accepted for `aud` and `azp`. Defaults to `clientID`.
    private let expectedAudiences: [String]
    private let allowedKeyIDs: [String]?
    private let leeway: TimeInterval
    private let now: @Sendable () -> Date
    private let cache: JWKSCache

    /// `audience` overrides the values checked against `aud` and `azp`.
    /// Nil uses `clientID`. The issuer puts the App ID slug in `aud`.
    /// Pass that slug when `clientID` is still the client row UUID.
    public init(
        jwksURL: URL,
        session: URLSession = .shared,
        expectedIssuer: String,
        clientID: String,
        audience: [String]? = nil,
        allowedKeyIDs: [String]? = nil,
        leeway: TimeInterval = Last1IDIDTokenVerifier.defaultLeeway,
        now: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.jwksURL = jwksURL
        self.session = session
        self.expectedIssuer = Last1URL.issuerString(URL(string: expectedIssuer) ?? URL(fileURLWithPath: "/"))
        if let audience {
            self.expectedAudiences = audience.map {
                $0.trimmingCharacters(in: .whitespacesAndNewlines)
            }.filter { !$0.isEmpty }
        } else {
            self.expectedAudiences = [clientID]
        }
        self.allowedKeyIDs = allowedKeyIDs
        self.leeway = leeway
        self.now = now
        self.cache = JWKSCache(now: now)
    }

    public func verify(_ token: String, expectedNonce: String?) async throws -> Last1IDIDTokenClaims {
        guard token.utf8.count <= 16_384 else { throw Last1IDError.idToken(.malformed) }
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3 else { throw Last1IDError.idToken(.malformed) }
        guard let headerData = Base64URL.decode(String(parts[0])),
              let header = Last1JSON.object(from: headerData, maximumBytes: 8_192) else {
            throw Last1IDError.idToken(.malformed)
        }
        let algorithm = Last1JSON.string(header["alg"]) ?? ""
        guard algorithm == "RS256" else {
            throw Last1IDError.idToken(.unsupportedAlgorithm)
        }
        if header["crit"] != nil {
            throw Last1IDError.idToken(.unsupportedAlgorithm)
        }
        guard let payloadData = Base64URL.decode(String(parts[1])),
              let signature = Base64URL.decode(String(parts[2])),
              !signature.isEmpty,
              signature.count <= 1024,
              let payload = Last1JSON.object(from: payloadData, maximumBytes: 16_384) else {
            throw Last1IDError.idToken(.malformed)
        }
        guard let kid = Last1JSON.string(header["kid"]), !kid.isEmpty, kid.count <= 256 else {
            throw Last1IDError.idToken(.unknownKeyID)
        }
        if let allowedKeyIDs, !allowedKeyIDs.contains(kid) {
            throw Last1IDError.idToken(.keyNotAllowed)
        }

        let key = try await cache.key(kid: kid) { [self] in
            try await self.fetchJWKS()
        }
        let signingInput = Data((String(parts[0]) + "." + String(parts[1])).utf8)
        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(
            key,
            .rsaSignatureMessagePKCS1v15SHA256,
            signingInput as CFData,
            signature as CFData,
            &error
        )
        guard verified else { throw Last1IDError.idToken(.badSignature) }
        return try claims(from: payload, expectedNonce: expectedNonce)
    }

    /// Reads `iss`, `sub`, and `aud` without checking the signature or lifetime.
    /// Refresh uses this on the stored ID token so a signing-key rotation
    /// does not fail the comparison.
    static func decodeUnverifiedClaims(_ token: String) throws -> Last1IDUnverifiedIdentity {
        guard token.utf8.count <= 16_384 else { throw Last1IDError.idToken(.malformed) }
        let parts = token.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 3,
              let payloadData = Base64URL.decode(String(parts[1])),
              let payload = Last1JSON.object(from: payloadData, maximumBytes: 16_384) else {
            throw Last1IDError.idToken(.malformed)
        }
        guard let issuer = Last1JSON.string(payload["iss"]), !issuer.isEmpty else {
            throw Last1IDError.idToken(.wrongIssuer)
        }
        guard let sub = Last1JSON.string(payload["sub"]), !sub.isEmpty else {
            throw Last1IDError.idToken(.malformed)
        }
        guard let audience = Last1JSON.stringArray(payload["aud"]), !audience.isEmpty else {
            throw Last1IDError.idToken(.wrongAudience)
        }
        let normalized = Last1URL.issuerString(URL(string: issuer) ?? URL(fileURLWithPath: "/"))
        return Last1IDUnverifiedIdentity(issuer: normalized, sub: sub, audience: audience)
    }

    private func claims(
        from payload: [String: Any],
        expectedNonce: String?
    ) throws -> Last1IDIDTokenClaims {
        guard let issuer = Last1JSON.string(payload["iss"]) else {
            throw Last1IDError.idToken(.wrongIssuer)
        }
        let normalized = Last1URL.issuerString(URL(string: issuer) ?? URL(fileURLWithPath: "/"))
        guard normalized == expectedIssuer else { throw Last1IDError.idToken(.wrongIssuer) }

        guard let audience = Last1JSON.stringArray(payload["aud"]), !audience.isEmpty else {
            throw Last1IDError.idToken(.wrongAudience)
        }
        let authorizedParty = Last1JSON.string(payload["azp"])
        guard audience.contains(where: { expectedAudiences.contains($0) }) else {
            throw Last1IDError.idToken(.wrongAudience)
        }
        if audience.count > 1 {
            guard let authorizedParty, expectedAudiences.contains(authorizedParty) else {
                throw Last1IDError.idToken(.wrongAudience)
            }
        } else if let authorizedParty, !expectedAudiences.contains(authorizedParty) {
            throw Last1IDError.idToken(.wrongAudience)
        }

        guard let exp = Last1JSON.int64(payload["exp"]),
              let iat = Last1JSON.int64(payload["iat"]) else {
            throw Last1IDError.idToken(.malformed)
        }
        let skew = Int64(leeway.rounded())
        let current = Int64(now().timeIntervalSince1970)
        if saturatingAdd(exp, skew) < current { throw Last1IDError.idToken(.expired) }
        if iat > saturatingAdd(current, skew) { throw Last1IDError.idToken(.issuedInFuture) }
        if let nbf = Last1JSON.int64(payload["nbf"]), nbf > saturatingAdd(current, skew) {
            throw Last1IDError.idToken(.notYetValid)
        }

        let nonce = Last1JSON.string(payload["nonce"])
        if let expectedNonce {
            guard let nonce, constantTimeEquals(nonce, expectedNonce) else {
                throw Last1IDError.idToken(.nonceMismatch)
            }
        }

        guard let sub = Last1JSON.string(payload["sub"]), !sub.isEmpty else {
            throw Last1IDError.idToken(.malformed)
        }
        let amr = Last1JSON.stringArray(payload["amr"]) ?? []
        if payload["amr"] != nil && Last1JSON.stringArray(payload["amr"]) == nil {
            throw Last1IDError.idToken(.malformed)
        }
        if payload["last1_verified"] != nil && Last1JSON.bool(payload["last1_verified"]) == nil {
            throw Last1IDError.idToken(.malformed)
        }

        return Last1IDIDTokenClaims(
            sub: sub,
            email: Last1JSON.string(payload["email"]),
            emailVerified: Last1JSON.bool(payload["email_verified"]),
            name: Last1JSON.string(payload["name"]),
            amr: amr,
            acr: Last1JSON.string(payload["acr"]),
            last1Verified: Last1JSON.bool(payload["last1_verified"]),
            last1VerifiedAt: Last1JSON.string(payload["last1_verified_at"]),
            issuer: normalized,
            audience: audience,
            authorizedParty: authorizedParty,
            issuedAt: Date(timeIntervalSince1970: TimeInterval(iat)),
            expiration: Date(timeIntervalSince1970: TimeInterval(exp)),
            nonce: nonce
        )
    }

    private func fetchJWKS() async throws -> [String: SecKey] {
        var request = URLRequest(url: jwksURL)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(Last1IDVersion.userAgent, forHTTPHeaderField: "User-Agent")
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        let data: Data
        do {
            let (body, response) = try await session.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                throw Last1IDError.idToken(.unknownKeyID)
            }
            data = body
        } catch let error as Last1IDError {
            throw error
        } catch is CancellationError {
            throw CancellationError()
        } catch {
            throw Last1IDError.network
        }
        guard let json = Last1JSON.object(from: data, maximumBytes: 262_144),
              let keys = json["keys"] as? [Any] else {
            throw Last1IDError.idToken(.unknownKeyID)
        }
        var parsed: [String: SecKey] = [:]
        for item in keys.prefix(32) {
            guard let object = item as? [String: Any], let rsa = RSAPublicKey.fromJWK(object) else { continue }
            if parsed[rsa.kid] != nil { continue }
            guard let key = try? rsa.secKey() else { continue }
            parsed[rsa.kid] = key
        }
        return parsed
    }

    private func saturatingAdd(_ value: Int64, _ delta: Int64) -> Int64 {
        let (result, overflow) = value.addingReportingOverflow(delta)
        if overflow { return delta < 0 ? Int64.min : Int64.max }
        return result
    }
}

struct Last1IDUnverifiedIdentity: Sendable, Equatable {
    let issuer: String
    let sub: String
    let audience: [String]
}

private final class JWKSCache: @unchecked Sendable {
    /// Wait this long before fetching again for a kid that was missing.
    static let unknownKidCooldown: TimeInterval = 45
    /// Wait this long after a failed fetch before hitting the endpoint again.
    static let failureBackoff: TimeInterval = 5

    private let lock = NSLock()
    private let now: @Sendable () -> Date
    private var keys: [String: SecKey] = [:]
    private var fetched = false
    private var fetchedAt: Date?
    private var failedAt: Date?
    private var inFlight: Task<[String: SecKey], Error>?
    private var generation = 0

    init(now: @escaping @Sendable () -> Date) {
        self.now = now
    }

    func key(
        kid: String,
        fetch: @escaping @Sendable () async throws -> [String: SecKey]
    ) async throws -> SecKey {
        if let cached = existing(kid) { return cached }
        let loaded = try await load(fetch)
        if let key = loaded[kid] { return key }
        throw Last1IDError.idToken(.unknownKeyID)
    }

    private enum FetchPlan {
        case cached([String: SecKey])
        case join(Task<[String: SecKey], Error>)
        case started(Int, Task<[String: SecKey], Error>)
    }

    private func load(
        _ fetch: @escaping @Sendable () async throws -> [String: SecKey]
    ) async throws -> [String: SecKey] {
        switch plan(fetch) {
        case .cached(let snapshot):
            return snapshot
        case .join(let task):
            return try await task.value
        case .started(let id, let task):
            do {
                let loaded = try await task.value
                commit(id: id, loaded: loaded)
                return loaded
            } catch is CancellationError {
                abandon(id: id, recordFailure: false)
                throw CancellationError()
            } catch {
                abandon(id: id, recordFailure: true)
                throw error
            }
        }
    }

    /// Synchronous so the lock is not taken from an async function.
    private func plan(
        _ fetch: @escaping @Sendable () async throws -> [String: SecKey]
    ) -> FetchPlan {
        lock.lock()
        defer { lock.unlock() }
        if let failedAt, now().timeIntervalSince(failedAt) < Self.failureBackoff {
            return .cached(keys)
        }
        if fetched, let fetchedAt, now().timeIntervalSince(fetchedAt) < Self.unknownKidCooldown {
            return .cached(keys)
        }
        if let inFlight {
            return .join(inFlight)
        }
        generation += 1
        let id = generation
        let task = Task { try await fetch() }
        inFlight = task
        return .started(id, task)
    }

    private func existing(_ kid: String) -> SecKey? {
        lock.lock()
        defer { lock.unlock() }
        return keys[kid]
    }

    /// Replaces the whole set. A kid that is gone from the new JWKS is no longer trusted.
    private func commit(id: Int, loaded: [String: SecKey]) {
        lock.lock()
        defer { lock.unlock() }
        guard id == generation else { return }
        keys = loaded
        fetched = true
        fetchedAt = now()
        failedAt = nil
        inFlight = nil
    }

    private func abandon(id: Int, recordFailure: Bool) {
        lock.lock()
        defer { lock.unlock() }
        guard id == generation else { return }
        inFlight = nil
        if recordFailure {
            failedAt = now()
        }
    }
}

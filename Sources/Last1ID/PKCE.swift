import CryptoKit
import Foundation

/// PKCE S256 pair. Last1 ID accepts this method only.
public struct Last1IDPKCE: Sendable, Equatable {
    public static let codeChallengeMethod = "S256"

    public let codeVerifier: String
    public let codeChallenge: String

    public init(codeVerifier: String) throws {
        try Self.validate(codeVerifier)
        self.codeVerifier = codeVerifier
        self.codeChallenge = Self.challenge(for: codeVerifier)
    }

    /// 32 cryptographically random octets, base64url, which is 43 characters.
    public static func generate() -> Last1IDPKCE {
        let verifier = Last1Random.token(byteCount: 32)
        return try! Last1IDPKCE(codeVerifier: verifier)
    }

    /// SHA-256 of the verifier, base64url without padding. RFC 7636 section 4.2.
    public static func challenge(for codeVerifier: String) -> String {
        let digest = SHA256.hash(data: Data(codeVerifier.utf8))
        return Base64URL.encode(Data(digest))
    }

    /// Caller verifier, or a pair. A pair's challenge must be the S256
    /// digest of its verifier. A challenge with no verifier is rejected.
    static func resolve(codeVerifier: String?, pair: Last1IDPKCE?) throws -> Last1IDPKCE {
        if pair == nil && codeVerifier == nil {
            return generate()
        }
        if let pair, let codeVerifier, pair.codeVerifier != codeVerifier {
            throw Last1IDError.configuration("PKCE code verifier does not match the supplied pair")
        }
        if let codeVerifier, pair == nil {
            return try Last1IDPKCE(codeVerifier: codeVerifier)
        }
        guard let pair else {
            return generate()
        }
        try validate(pair.codeVerifier)
        guard pair.codeChallenge == challenge(for: pair.codeVerifier) else {
            throw Last1IDError.configuration("PKCE code challenge does not match the verifier")
        }
        return pair
    }

    /// Uses a caller value unchanged. Empty and values over 1024 bytes
    /// are rejected because the callback state check cannot accept them.
    static func suppliedOpaque(_ value: String?, name: String) throws -> String {
        guard let value else { return Last1Random.token() }
        let count = value.utf8.count
        guard (1...1024).contains(count) else {
            throw Last1IDError.configuration("\(name) must be 1 to 1024 bytes")
        }
        return value
    }

    static func validate(_ verifier: String) throws {
        let count = verifier.utf8.count
        guard (43...128).contains(count) else {
            throw Last1IDError.configuration("PKCE code verifier must be 43 to 128 characters")
        }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
        guard verifier.unicodeScalars.allSatisfy({ allowed.contains($0) }) else {
            throw Last1IDError.configuration("PKCE code verifier has a character outside the unreserved set")
        }
    }
}

enum Last1Random {
    static func token(byteCount: Int = 32) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        var generator = SystemRandomNumberGenerator()
        for index in bytes.indices {
            bytes[index] = UInt8.random(in: .min ... .max, using: &generator)
        }
        return Base64URL.encode(Data(bytes))
    }
}

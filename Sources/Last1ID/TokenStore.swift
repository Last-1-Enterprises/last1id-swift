import Foundation

/// Tokens held for one signed-in person. Descriptions are redacted.
/// Do not print the properties.
public struct Last1IDTokens: Codable, Sendable, Equatable {
    public var accessToken: String
    public var refreshToken: String?
    public var idToken: String?
    public var tokenType: String
    public var expiresAt: Date?
    public var refreshExpiresAt: Date?
    public var scope: String?

    public init(
        accessToken: String,
        refreshToken: String? = nil,
        idToken: String? = nil,
        tokenType: String = "Bearer",
        expiresAt: Date? = nil,
        refreshExpiresAt: Date? = nil,
        scope: String? = nil
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.idToken = idToken
        self.tokenType = tokenType
        self.expiresAt = expiresAt
        self.refreshExpiresAt = refreshExpiresAt
        self.scope = scope
    }
}

extension Last1IDTokens: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String { "Last1IDTokens(redacted)" }
    public var debugDescription: String { "Last1IDTokens(redacted)" }
    public var customMirror: Mirror {
        Mirror(self, children: [], displayStyle: .struct)
    }
}

public protocol Last1IDTokenStore: Sendable {
    func load() async throws -> Last1IDTokens?
    func save(_ tokens: Last1IDTokens) async throws
    func clear() async throws
}

enum Last1TokenCoding {
    static func encoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }

    static func decoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}

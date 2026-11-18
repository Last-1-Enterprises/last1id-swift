import Foundation

/// How `ASWebAuthenticationSession` should receive the redirect.
public enum Last1IDCallback: Sendable, Equatable {
    /// Custom URL scheme, for example `myapp` with redirect `myapp://callback`.
    case customScheme(String)
    /// Universal-link callback. Requires iOS 17.4 or macOS 14.4.
    /// `path` is the path component, such as `/auth/callback`.
    case https(host: String, path: String)
}

/// Static settings for one Last1 ID app client.
///
/// `clientID` is the App ID slug. That slug is the public Client ID.
/// The authorize and token endpoints still accept the client row UUID
/// for backward compatibility. The ID token `aud` is the slug.
/// `audience` overrides the values checked against `aud` and `azp`.
/// Leave it nil to use `clientID`. Set it to the slug when `clientID`
/// is still a UUID.
public struct Last1IDConfiguration: Sendable, Equatable {
    public var issuerURL: URL
    public var clientID: String
    public var redirectURI: URL
    public var scopes: [String]
    public var audience: [String]?
    /// When set, an ID token `kid` outside this list is rejected even if
    /// the JWKS publishes it. Leave nil unless you ship kid updates with
    /// the app. A stale pin breaks sign-in at the next key rotation.
    public var allowedKeyIDs: [String]?
    public var callback: Last1IDCallback
    public var prefersEphemeralSession: Bool

    public init(
        clientID: String,
        redirectURI: URL,
        callback: Last1IDCallback,
        issuerURL: URL = URL(string: "https://auth.last1.id")!,
        scopes: [String] = ["openid", "profile", "email", "offline_access"],
        audience: [String]? = nil,
        allowedKeyIDs: [String]? = nil,
        prefersEphemeralSession: Bool = false
    ) {
        self.issuerURL = issuerURL
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scopes = scopes
        self.audience = audience
        self.allowedKeyIDs = allowedKeyIDs
        self.callback = callback
        self.prefersEphemeralSession = prefersEphemeralSession
    }

    public var issuer: String {
        Last1URL.issuerString(issuerURL)
    }

    func validate() throws {
        let trimmedClient = clientID.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedClient.isEmpty {
            throw Last1IDError.configuration("clientID is empty")
        }
        if scopes.isEmpty || scopes.contains(where: { $0.isEmpty || $0.contains(" ") }) {
            throw Last1IDError.configuration("scopes must be a non-empty list of individual scope values")
        }
        if !scopes.contains("openid") {
            throw Last1IDError.configuration("scopes must include openid")
        }
        if let audience {
            let values = audience.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
            if values.isEmpty {
                throw Last1IDError.configuration("audience is empty")
            }
        }
        guard let scheme = issuerURL.scheme?.lowercased(), scheme == "https", issuerURL.host != nil else {
            throw Last1IDError.configuration("issuerURL must be https")
        }
        if issuerURL.user != nil || issuerURL.password != nil {
            throw Last1IDError.configuration("issuerURL must not include credentials")
        }
        try validateCallback()
    }

    func validateCallback() throws {
        switch callback {
        case .customScheme(let scheme):
            let normalized = scheme.lowercased()
            guard Self.isCustomScheme(normalized) else {
                throw Last1IDError.configuration("callback scheme is not a custom URL scheme")
            }
            guard redirectURI.scheme?.lowercased() == normalized else {
                throw Last1IDError.configuration("redirectURI scheme does not match the custom scheme callback")
            }
        case .https(let host, let path):
            guard redirectURI.scheme?.lowercased() == "https" else {
                throw Last1IDError.configuration("redirectURI must be https for a universal-link callback")
            }
            guard redirectURI.host?.lowercased() == host.lowercased() else {
                throw Last1IDError.configuration("redirectURI host does not match the universal-link callback")
            }
            if let port = redirectURI.port, port != 443 {
                throw Last1IDError.configuration("universal-link callbacks use port 443")
            }
            guard Last1URL.normalizePath(redirectURI.path) == Last1URL.normalizePath(path) else {
                throw Last1IDError.configuration("redirectURI path does not match the universal-link callback")
            }
        }
    }

    static func isCustomScheme(_ scheme: String) -> Bool {
        if scheme == "http" || scheme == "https" || scheme.isEmpty { return false }
        let scalars = Array(scheme.unicodeScalars)
        guard let first = scalars.first, ("a"..."z").contains(Character(first)) else { return false }
        return scalars.allSatisfy { scalar in
            let character = Character(scalar)
            return ("a"..."z").contains(character)
                || ("0"..."9").contains(character)
                || character == "+"
                || character == "-"
                || character == "."
        }
    }
}

enum Last1URL {
    static func issuerString(_ url: URL) -> String {
        var text = url.absoluteString
        while text.hasSuffix("/") { text.removeLast() }
        return text
    }

    static func normalizePath(_ path: String) -> String {
        if path.isEmpty || path == "/" { return "/" }
        var text = path
        if !text.hasPrefix("/") { text = "/" + text }
        while text.count > 1 && text.hasSuffix("/") { text.removeLast() }
        return text
    }

    static func endpoint(_ issuer: URL, path: String) -> URL? {
        let base = issuerString(issuer)
        return URL(string: base + path)
    }

    static func sameOrigin(_ url: URL, issuerHost: String) -> Bool {
        guard url.scheme?.lowercased() == "https" else { return false }
        guard url.user == nil, url.password == nil else { return false }
        guard url.host?.lowercased() == issuerHost.lowercased() else { return false }
        return true
    }
}

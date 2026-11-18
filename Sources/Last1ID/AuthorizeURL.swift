import Foundation

public enum Last1IDAuthorizeURL {
    public static func authorizationEndpoint(forIssuer issuer: URL) -> URL? {
        Last1URL.endpoint(issuer, path: "/oauth/authorize")
    }

    /// Builds `response_type=code` with PKCE S256, state, and nonce.
    /// `prompt` of `none` is the only prompt value Last1 ID advertises.
    /// Pass `idTokenHint` with it.
    public static func make(
        authorizationEndpoint: URL,
        clientID: String,
        redirectURI: URL,
        scopes: [String],
        codeChallenge: String,
        state: String,
        nonce: String,
        prompt: String? = nil,
        idTokenHint: String? = nil
    ) -> URL {
        var components = URLComponents(url: authorizationEndpoint, resolvingAgainstBaseURL: false) ?? URLComponents()
        components.scheme = authorizationEndpoint.scheme
        components.host = authorizationEndpoint.host
        components.port = authorizationEndpoint.port
        components.path = authorizationEndpoint.path
        var items = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI.absoluteString),
            URLQueryItem(name: "scope", value: scopes.joined(separator: " ")),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "nonce", value: nonce),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: Last1IDPKCE.codeChallengeMethod),
        ]
        if let prompt, !prompt.isEmpty {
            items.append(URLQueryItem(name: "prompt", value: prompt))
        }
        if let idTokenHint, !idTokenHint.isEmpty {
            items.append(URLQueryItem(name: "id_token_hint", value: idTokenHint))
        }
        components.queryItems = items
        return components.url ?? authorizationEndpoint
    }
}

/// In-memory authorization request. The description redacts the verifier,
/// state, and nonce. Do not log `url` when it carries `id_token_hint`.
public struct Last1IDAuthorizationAttempt: Sendable, Equatable {
    public let url: URL
    public let state: String
    public let nonce: String
    public let codeVerifier: String
    public let codeChallenge: String

    public var description: String { "Last1IDAuthorizationAttempt(redacted)" }
}

extension Last1IDAuthorizationAttempt: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var debugDescription: String { description }
    public var customMirror: Mirror {
        Mirror(self, children: [], displayStyle: .struct)
    }
}

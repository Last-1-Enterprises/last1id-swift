import Foundation

/// Query fields from an authorization redirect. `parse` does not check
/// `state`. Call `authorizationCode` when this request's state must match.
public struct Last1IDAuthorizationCallback: Sendable, Equatable {
    public let code: String?
    public let state: String?
    public let error: String?
    public let errorDescription: String?

    public init(code: String?, state: String?, error: String?, errorDescription: String?) {
        self.code = code
        self.state = state
        self.error = error
        self.errorDescription = errorDescription
    }
}

public enum Last1IDCallbackParser {
    /// Reads `code`, `state`, and `error` from a redirect that matches
    /// `redirectURI`. A fragment is rejected. State is not checked.
    public static func parse(callback: URL, redirectURI: URL) throws -> Last1IDAuthorizationCallback {
        guard matches(callback, redirectURI: redirectURI) else {
            throw Last1IDError.invalidCallback
        }
        guard let components = URLComponents(url: callback, resolvingAgainstBaseURL: false),
              components.fragment == nil || components.fragment?.isEmpty == true else {
            throw Last1IDError.invalidCallback
        }
        let items = components.queryItems ?? []
        return Last1IDAuthorizationCallback(
            code: try single("code", in: items),
            state: try single("state", in: items),
            error: try single("error", in: items),
            errorDescription: first("error_description", in: items)
        )
    }

    public static func authorizationCode(
        from callback: URL,
        redirectURI: URL,
        expectedState: String
    ) throws -> String {
        let parsed = try parse(callback: callback, redirectURI: redirectURI)
        let returnedState = parsed.state ?? ""
        guard constantTimeEquals(returnedState, expectedState), expectedState.count <= 1024 else {
            throw Last1IDError.stateMismatch
        }
        if let error = parsed.error, !error.isEmpty {
            throw Last1IDError.oauth(
                code: Last1IDOAuthErrorCode(rawValue: error),
                description: Last1JSON.oauthDescription(parsed.errorDescription)
            )
        }
        guard let code = parsed.code, !code.isEmpty else {
            throw Last1IDError.missingAuthorizationCode
        }
        return code
    }

    private static func first(_ name: String, in items: [URLQueryItem]) -> String? {
        guard let value = items.first(where: { $0.name == name })?.value, !value.isEmpty else { return nil }
        return value
    }

    /// RFC 6749 section 3.1: `code`, `state`, and `error` must not appear more than once.
    private static func single(_ name: String, in items: [URLQueryItem]) throws -> String? {
        let matches = items.filter { $0.name == name }
        if matches.count > 1 {
            throw Last1IDError.invalidCallback
        }
        guard let value = matches.first?.value, !value.isEmpty else { return nil }
        return value
    }

    static func matches(_ callback: URL, redirectURI: URL) -> Bool {
        guard callback.scheme?.lowercased() == redirectURI.scheme?.lowercased() else { return false }
        let callbackHost = callback.host?.lowercased() ?? ""
        let redirectHost = redirectURI.host?.lowercased() ?? ""
        guard callbackHost == redirectHost else { return false }
        if callback.port != redirectURI.port { return false }
        return Last1URL.normalizePath(callback.path) == Last1URL.normalizePath(redirectURI.path)
    }
}

func constantTimeEquals(_ lhs: String, _ rhs: String) -> Bool {
    let left = Array(lhs.utf8)
    let right = Array(rhs.utf8)
    if left.count != right.count || left.count > 1024 { return false }
    var difference: UInt8 = 0
    for index in left.indices {
        difference |= left[index] ^ right[index]
    }
    return difference == 0
}

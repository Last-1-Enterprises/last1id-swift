import Foundation

enum Last1IDCallbackParser {
    static func authorizationCode(
        from callback: URL,
        redirectURI: URL,
        expectedState: String
    ) throws -> String {
        guard matches(callback, redirectURI: redirectURI) else {
            throw Last1IDError.invalidCallback
        }
        guard let components = URLComponents(url: callback, resolvingAgainstBaseURL: false),
              components.fragment == nil || components.fragment?.isEmpty == true else {
            throw Last1IDError.invalidCallback
        }
        let items = components.queryItems ?? []
        let returnedState = items.first(where: { $0.name == "state" })?.value ?? ""
        guard constantTimeEquals(returnedState, expectedState), expectedState.count <= 1024 else {
            throw Last1IDError.stateMismatch
        }
        if let error = items.first(where: { $0.name == "error" })?.value, !error.isEmpty {
            let description = items.first(where: { $0.name == "error_description" })?.value
            throw Last1IDError.oauth(
                code: Last1IDOAuthErrorCode(rawValue: error),
                description: Last1JSON.oauthDescription(description)
            )
        }
        guard let code = items.first(where: { $0.name == "code" })?.value, !code.isEmpty else {
            throw Last1IDError.missingAuthorizationCode
        }
        return code
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

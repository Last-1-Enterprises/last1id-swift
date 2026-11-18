import Foundation

/// OAuth and OIDC error codes Last1 ID returns, plus the standard codes
/// a client must be ready to receive on the authorize redirect.
public enum Last1IDOAuthErrorCode: Equatable, Sendable {
    case invalidRequest
    case unauthorizedClient
    case accessDenied
    case unsupportedResponseType
    case invalidScope
    case serverError
    case temporarilyUnavailable
    case invalidClient
    case invalidGrant
    case unsupportedGrantType
    case invalidToken
    case insufficientScope
    case unsupportedTokenType
    case loginRequired
    case consentRequired
    case interactionRequired
    case accountSelectionRequired
    case mfaRequired
    case mfaEnrollmentRequired
    case other(String)

    public var rawValue: String {
        switch self {
        case .invalidRequest: return "invalid_request"
        case .unauthorizedClient: return "unauthorized_client"
        case .accessDenied: return "access_denied"
        case .unsupportedResponseType: return "unsupported_response_type"
        case .invalidScope: return "invalid_scope"
        case .serverError: return "server_error"
        case .temporarilyUnavailable: return "temporarily_unavailable"
        case .invalidClient: return "invalid_client"
        case .invalidGrant: return "invalid_grant"
        case .unsupportedGrantType: return "unsupported_grant_type"
        case .invalidToken: return "invalid_token"
        case .insufficientScope: return "insufficient_scope"
        case .unsupportedTokenType: return "unsupported_token_type"
        case .loginRequired: return "login_required"
        case .consentRequired: return "consent_required"
        case .interactionRequired: return "interaction_required"
        case .accountSelectionRequired: return "account_selection_required"
        case .mfaRequired: return "mfa_required"
        case .mfaEnrollmentRequired: return "mfa_enrollment_required"
        case .other(let value): return value
        }
    }

    public init(rawValue: String) {
        switch rawValue {
        case "invalid_request": self = .invalidRequest
        case "unauthorized_client": self = .unauthorizedClient
        case "access_denied": self = .accessDenied
        case "unsupported_response_type": self = .unsupportedResponseType
        case "invalid_scope": self = .invalidScope
        case "server_error": self = .serverError
        case "temporarily_unavailable": self = .temporarilyUnavailable
        case "invalid_client": self = .invalidClient
        case "invalid_grant": self = .invalidGrant
        case "unsupported_grant_type": self = .unsupportedGrantType
        case "invalid_token": self = .invalidToken
        case "insufficient_scope": self = .insufficientScope
        case "unsupported_token_type": self = .unsupportedTokenType
        case "login_required": self = .loginRequired
        case "consent_required": self = .consentRequired
        case "interaction_required": self = .interactionRequired
        case "account_selection_required": self = .accountSelectionRequired
        case "mfa_required": self = .mfaRequired
        case "mfa_enrollment_required": self = .mfaEnrollmentRequired
        default: self = .other(rawValue)
        }
    }
}

public enum Last1IDTokenFailure: String, Equatable, Sendable {
    case malformed
    case unsupportedAlgorithm
    case unknownKeyID
    case keyNotAllowed
    case keyImportFailed
    case badSignature
    case wrongIssuer
    case wrongAudience
    case subjectMismatch
    case expired
    case issuedInFuture
    case notYetValid
    case nonceMismatch
}

public enum Last1IDError: Error, Equatable, Sendable {
    case oauth(code: Last1IDOAuthErrorCode, description: String?)
    case stateMismatch
    case missingAuthorizationCode
    case userCancelled
    case invalidCallback
    case httpsCallbackUnavailable
    case presentationAnchorRequired
    case configuration(String)
    case discovery(String)
    case idToken(Last1IDTokenFailure)
    case keychain(Int32)
    /// A response was not usable. The body is never included.
    case invalidResponse
    /// A transport failure. The URL is never included, because authorize
    /// and token URLs can carry codes and tokens.
    case network
    case notAuthenticated
    case storeFailed
    case signInInProgress
}

extension Last1IDError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .oauth(let code, let description):
            if let description, !description.isEmpty {
                return "Last1 ID OAuth error \(code.rawValue): \(description)"
            }
            return "Last1 ID OAuth error \(code.rawValue)."
        case .stateMismatch:
            return "The sign-in response state did not match this request."
        case .missingAuthorizationCode:
            return "The sign-in response did not include an authorization code."
        case .userCancelled:
            return "Sign-in was cancelled."
        case .invalidCallback:
            return "The sign-in callback was not the redirect URI for this app."
        case .httpsCallbackUnavailable:
            return "HTTPS sign-in callbacks require iOS 17.4 or macOS 14.4."
        case .presentationAnchorRequired:
            return "iOS sign-in needs a window to present the browser session."
        case .configuration(let reason):
            return "Last1 ID configuration: \(reason)"
        case .discovery(let reason):
            return "Last1 ID discovery: \(reason)"
        case .idToken(let failure):
            return "ID token verification failed (\(failure.rawValue))."
        case .keychain(let status):
            return "Keychain error \(status)."
        case .invalidResponse:
            return "Last1 ID returned a response the SDK could not use."
        case .network:
            return "The request to Last1 ID failed."
        case .notAuthenticated:
            return "There is no Last1 ID session on this device."
        case .storeFailed:
            return "The saved Last1 ID session could not be read."
        case .signInInProgress:
            return "A Last1 ID sign-in is already in progress."
        }
    }
}

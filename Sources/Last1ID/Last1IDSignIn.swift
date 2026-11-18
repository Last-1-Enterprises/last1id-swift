@preconcurrency import AuthenticationServices
import Foundation
#if os(iOS)
import UIKit
#elseif os(macOS)
import AppKit
#endif

/// Presents Sign in with Last1 ID.
///
/// Create and use this object on the main actor. Pass a window on iOS.
/// The system browser returns either an HTTPS universal link (iOS 17.4 /
/// macOS 14.4 and later) or a custom scheme.
@MainActor
public final class Last1IDSignIn: NSObject, ASWebAuthenticationPresentationContextProviding {
    private let client: Last1IDClient
    private let defaultAnchor: (() -> ASPresentationAnchor)?
    private var anchorOverride: (() -> ASPresentationAnchor)?
    private var activeSession: ASWebAuthenticationSession?
    private var signInInProgress = false

    public init(
        client: Last1IDClient,
        presentationAnchor: (() -> ASPresentationAnchor)? = nil
    ) {
        self.client = client
        self.defaultAnchor = presentationAnchor
        super.init()
    }

    /// Presents the browser and exchanges the code on this device.
    ///
    /// `state`, `nonce`, and PKCE are optional. When you pass them, those
    /// exact values are sent and then checked: the callback `state` must
    /// match, and the ID token `nonce` must match. A PKCE value is either
    /// a verifier or a pair. The verifier is 43 to 128 unreserved
    /// characters, and the challenge is the S256 digest of that verifier.
    public func signIn(
        prefersEphemeralSession: Bool? = nil,
        prompt: String? = nil,
        idTokenHint: String? = nil,
        state: String? = nil,
        nonce: String? = nil,
        codeVerifier: String? = nil,
        pkce: Last1IDPKCE? = nil,
        presentationAnchor: (() -> ASPresentationAnchor)? = nil
    ) async throws -> Last1IDSession {
        let attempt = try await client.beginAuthorization(
            prompt: prompt,
            idTokenHint: idTokenHint,
            state: state,
            nonce: nonce,
            codeVerifier: codeVerifier,
            pkce: pkce
        )
        let configuration = client.configuration
        let callback = try await authenticate(
            url: attempt.url,
            callback: configuration.callback,
            ephemeral: prefersEphemeralSession ?? configuration.prefersEphemeralSession,
            anchor: presentationAnchor
        )
        let code = try Last1IDCallbackParser.authorizationCode(
            from: callback,
            redirectURI: configuration.redirectURI,
            expectedState: attempt.state
        )
        return try await client.exchangeAuthorizationCode(
            code: code,
            codeVerifier: attempt.codeVerifier,
            nonce: attempt.nonce
        )
    }

    /// Browser sign-in that does not exchange the code on the device.
    ///
    /// Hand the result to your backend. A confidential backend sends its
    /// client secret with the code and this verifier. A public backend
    /// calls `exchangeAuthorizationCode` with the code and verifier and
    /// sends no client secret. `state` and `nonce` follow the same rules
    /// as `signIn`: supplied values are used exactly and then checked.
    public func signInForBackendExchange(
        prefersEphemeralSession: Bool? = nil,
        prompt: String? = nil,
        idTokenHint: String? = nil,
        state: String? = nil,
        nonce: String? = nil,
        codeVerifier: String? = nil,
        pkce: Last1IDPKCE? = nil,
        presentationAnchor: (() -> ASPresentationAnchor)? = nil
    ) async throws -> Last1IDBackendExchange {
        let attempt = try await client.beginAuthorization(
            prompt: prompt,
            idTokenHint: idTokenHint,
            state: state,
            nonce: nonce,
            codeVerifier: codeVerifier,
            pkce: pkce
        )
        let configuration = client.configuration
        let callback = try await authenticate(
            url: attempt.url,
            callback: configuration.callback,
            ephemeral: prefersEphemeralSession ?? configuration.prefersEphemeralSession,
            anchor: presentationAnchor
        )
        let code = try Last1IDCallbackParser.authorizationCode(
            from: callback,
            redirectURI: configuration.redirectURI,
            expectedState: attempt.state
        )
        return Last1IDBackendExchange(
            code: code,
            codeVerifier: attempt.codeVerifier,
            nonce: attempt.nonce,
            clientID: configuration.clientID,
            redirectURI: configuration.redirectURI,
            issuer: configuration.issuerURL
        )
    }

    nonisolated public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        if Thread.isMainThread {
            return MainActor.assumeIsolated { self.resolvedAnchor() }
        }
        return DispatchQueue.main.sync {
            MainActor.assumeIsolated { self.resolvedAnchor() }
        }
    }

    private func authenticate(
        url: URL,
        callback: Last1IDCallback,
        ephemeral: Bool,
        anchor: (() -> ASPresentationAnchor)?
    ) async throws -> URL {
        if signInInProgress { throw Last1IDError.signInInProgress }
        #if os(iOS)
        if anchor == nil && defaultAnchor == nil {
            throw Last1IDError.presentationAnchorRequired
        }
        #endif
        signInInProgress = true
        defer {
            signInInProgress = false
            anchorOverride = nil
            activeSession = nil
        }
        anchorOverride = anchor

        let box = ResumeOnce()
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
                let session: ASWebAuthenticationSession
                do {
                    session = try makeSession(url: url, callback: callback, ephemeral: ephemeral) { @Sendable callbackURL, error in
                        let result: Result<URL, Error>
                        if let error {
                            result = .failure(Self.map(error))
                        } else if let callbackURL {
                            result = .success(callbackURL)
                        } else {
                            result = .failure(Last1IDError.invalidCallback)
                        }
                        guard box.claim() else { return }
                        continuation.resume(with: result)
                    }
                } catch {
                    guard box.claim() else { return }
                    continuation.resume(throwing: error)
                    return
                }
                activeSession = session
                if !session.start() {
                    guard box.claim() else { return }
                    continuation.resume(throwing: Last1IDError.invalidCallback)
                }
            }
        } onCancel: {
            Task { @MainActor in
                self.activeSession?.cancel()
            }
        }
    }

    private func makeSession(
        url: URL,
        callback: Last1IDCallback,
        ephemeral: Bool,
        completion: @escaping @Sendable (URL?, Error?) -> Void
    ) throws -> ASWebAuthenticationSession {
        let session: ASWebAuthenticationSession
        switch callback {
        case .https(let host, let path):
            guard #available(iOS 17.4, macOS 14.4, *) else {
                throw Last1IDError.httpsCallbackUnavailable
            }
            session = ASWebAuthenticationSession(
                url: url,
                callback: .https(host: host, path: Last1URL.normalizePath(path)),
                completionHandler: completion
            )
        case .customScheme(let scheme):
            let normalized = scheme.lowercased()
            if #available(iOS 17.4, macOS 14.4, *) {
                session = ASWebAuthenticationSession(
                    url: url,
                    callback: .customScheme(normalized),
                    completionHandler: completion
                )
            } else {
                session = ASWebAuthenticationSession(
                    url: url,
                    callbackURLScheme: normalized,
                    completionHandler: completion
                )
            }
        }
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = ephemeral
        return session
    }

    private func resolvedAnchor() -> ASPresentationAnchor {
        if let anchorOverride { return anchorOverride() }
        if let defaultAnchor { return defaultAnchor() }
        #if os(macOS)
        return NSApplication.shared.windows.first(where: { $0.isKeyWindow }) ?? NSWindow()
        #else
        return UIWindow()
        #endif
    }

    nonisolated private static func map(_ error: Error) -> Error {
        let nsError = error as NSError
        guard nsError.domain == ASWebAuthenticationSessionError.errorDomain,
              let code = ASWebAuthenticationSessionError.Code(rawValue: nsError.code) else {
            return Last1IDError.invalidCallback
        }
        switch code {
        case .canceledLogin:
            return Last1IDError.userCancelled
        case .presentationContextNotProvided, .presentationContextInvalid:
            return Last1IDError.presentationAnchorRequired
        @unknown default:
            return Last1IDError.invalidCallback
        }
    }
}

private final class ResumeOnce: @unchecked Sendable {
    private let lock = NSLock()
    private var claimed = false

    func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if claimed { return false }
        claimed = true
        return true
    }
}
